use alloy_primitives::{B256, B512};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use k256::{SecretKey, PublicKey};
use k256::ecdsa::{SigningKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use anyhow::{Result, Context};
use sha2::{Sha256};
use sha3::{Keccak256, Digest};
use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::rand_core::RngCore;

type HmacSha256 = Hmac<Sha256>;
type Aes128Ctr = ctr::Ctr128BE<Aes128>;

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct AuthInitiate {
    pub signature: alloy_rlp::Bytes, // 65 bytes: [R(32), S(32), V(1)]
    pub public_key: B512,           // 64 bytes
    pub nonce: B256,                // 32 bytes
    pub version: u64,               // Typically 4
}

impl AuthInitiate {
    pub fn new(my_sk: &SecretKey, remote_pk: &B512, my_ephemeral_sk: &SecretKey, nonce: B256) -> Result<Self> {
        let mut pub_bytes = [0u8; 65];
        pub_bytes[0] = 0x04;
        pub_bytes[1..].copy_from_slice(remote_pk.as_slice());
        let receiver_pk = PublicKey::from_sec1_bytes(&pub_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid remote public key: {:?}", e))?;

        let shared_secret = k256::elliptic_curve::ecdh::diffie_hellman(
            my_sk.to_nonzero_scalar(),
            receiver_pk.as_affine()
        );
        let token = shared_secret.raw_secret_bytes();
        
        let mut signed_data = [0u8; 32];
        for i in 0..32 {
            signed_data[i] = token[i] ^ nonce[i];
        }

        // Sign with ephemeral key
        let signing_key = SigningKey::from(my_ephemeral_sk);
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&signed_data)
            .map_err(|e| anyhow::anyhow!("Failed to sign auth initiate: {:?}", e))?;
        
        // signature is [R(32), S(32), V(1)]
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&signature.to_bytes());
        sig_bytes.push(recovery_id.to_byte());

        // My public key (64 bytes)
        let my_pk_encoded = my_sk.public_key().to_encoded_point(false);
        let mut my_pk_64 = [0u8; 64];
        my_pk_64.copy_from_slice(&my_pk_encoded.as_bytes()[1..]);

        Ok(Self {
            signature: sig_bytes.into(),
            public_key: B512::from_slice(&my_pk_64),
            nonce,
            version: 4,
        })
    }

    pub fn recover_ephemeral_public_key(&self, my_sk: &SecretKey) -> Result<B512> {
        let mut pub_bytes = [0u8; 65];
        pub_bytes[0] = 0x04;
        pub_bytes[1..].copy_from_slice(self.public_key.as_slice());
        let initiator_static_pk = PublicKey::from_sec1_bytes(&pub_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid initiator static public key: {:?}", e))?;

        let shared_secret = k256::elliptic_curve::ecdh::diffie_hellman(
            my_sk.to_nonzero_scalar(),
            initiator_static_pk.as_affine()
        );
        let token = shared_secret.raw_secret_bytes();
        
        let mut signed_data = [0u8; 32];
        for i in 0..32 {
            signed_data[i] = token[i] ^ self.nonce[i];
        }

        // Recover ephemeral public key from signature
        let signature_bytes = k256::ecdsa::Signature::from_slice(&self.signature[..64])
            .map_err(|e| anyhow::anyhow!("Invalid signature format: {:?}", e))?;
        let recovery_id = k256::ecdsa::RecoveryId::from_byte(self.signature[64])
            .ok_or_else(|| anyhow::anyhow!("Invalid recovery ID"))?;
            
        let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(&signed_data, &signature_bytes, recovery_id)
            .map_err(|e| anyhow::anyhow!("Failed to recover ephemeral public key: {:?}", e))?;
            
        let mut pk_64 = [0u8; 64];
        pk_64.copy_from_slice(&vk.to_encoded_point(false).as_bytes()[1..]);
        Ok(B512::from_slice(&pk_64))
    }
}

#[derive(Debug, Clone, RlpEncodable, RlpDecodable)]
pub struct AuthResponse {
    pub public_key: B512,           // 64 bytes (ephemeral)
    pub nonce: B256,                // 32 bytes
    pub version: u64,
}

impl AuthResponse {
    pub fn new(my_ephemeral_pk: &B512, nonce: B256) -> Self {
        Self {
            public_key: *my_ephemeral_pk,
            nonce,
            version: 4,
        }
    }
}

pub struct RLPxSecrets {
    pub aes: B256,
    pub mac: B256,
    pub token: B256,
    pub egress_mac: Keccak256,
    pub ingress_mac: Keccak256,
}

pub struct ECIES;

impl ECIES {
    pub fn agree_secret(
        is_initiator: bool,
        my_ephemeral_sk: &SecretKey,
        remote_ephemeral_pk: &B512,
        initiator_nonce: &B256,
        responder_nonce: &B256,
        initiate_packet: &[u8],
        response_packet: &[u8],
    ) -> Result<RLPxSecrets> {
        let mut pub_bytes = [0u8; 65];
        pub_bytes[0] = 0x04;
        pub_bytes[1..].copy_from_slice(remote_ephemeral_pk.as_slice());
        let eph_pub = PublicKey::from_sec1_bytes(&pub_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid remote ephemeral public key: {:?}", e))?;

        let agreed_secret = k256::elliptic_curve::ecdh::diffie_hellman(
            my_ephemeral_sk.to_nonzero_scalar(),
            eph_pub.as_affine()
        );
        let z = agreed_secret.raw_secret_bytes();

        // shared_secret = keccak256(agreed_secret || keccak256(responder_nonce || initiator_nonce))
        let mut hasher = Keccak256::new();
        hasher.update(responder_nonce);
        hasher.update(initiator_nonce);
        let nonce_hash = hasher.finalize();

        let mut hasher = Keccak256::new();
        hasher.update(&z[..]);
        hasher.update(nonce_hash);
        let shared_secret = hasher.finalize();

        // aes_secret = keccak256(agreed_secret || shared_secret)
        let mut hasher = Keccak256::new();
        hasher.update(&z[..]);
        hasher.update(shared_secret);
        let aes_secret = hasher.finalize();

        // mac_secret = keccak256(agreed_secret || aes_secret)
        let mut hasher = Keccak256::new();
        hasher.update(&z[..]);
        hasher.update(aes_secret);
        let mac_secret = hasher.finalize();

        // token = keccak256(shared_secret)
        let mut hasher = Keccak256::new();
        hasher.update(shared_secret);
        let token = hasher.finalize();

        // Initialize MACs
        // mac1 = keccak256(mac_secret ^ responder_nonce || initiate_packet)
        let mut mac1 = Keccak256::new();
        let mut mac_xor_res = [0u8; 32];
        for i in 0..32 {
            mac_xor_res[i] = mac_secret[i] ^ responder_nonce[i];
        }
        mac1.update(mac_xor_res);
        mac1.update(initiate_packet);

        // mac2 = keccak256(mac_secret ^ initiator_nonce || response_packet)
        let mut mac2 = Keccak256::new();
        let mut mac_xor_ini = [0u8; 32];
        for i in 0..32 {
            mac_xor_ini[i] = mac_secret[i] ^ initiator_nonce[i];
        }
        mac2.update(mac_xor_ini);
        mac2.update(response_packet);

        let (egress_mac, ingress_mac) = if is_initiator {
            (mac1, mac2)
        } else {
            (mac2, mac1)
        };

        Ok(RLPxSecrets {
            aes: B256::from_slice(&aes_secret[..]),
            mac: B256::from_slice(&mac_secret[..]),
            token: B256::from_slice(&token[..]),
            egress_mac,
            ingress_mac,
        })
    }

    pub fn encrypt(receiver_pub: &B512, msg: &[u8], shared_info: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut rng = k256::elliptic_curve::rand_core::OsRng;
        let ephemeral_sk = SecretKey::random(&mut rng);
        let ephemeral_pk = ephemeral_sk.public_key();
        
        // Convert B512 to PublicKey
        let mut pub_bytes = [0u8; 65];
        pub_bytes[0] = 0x04;
        pub_bytes[1..].copy_from_slice(receiver_pub.as_slice());
        let receiver_pk = PublicKey::from_sec1_bytes(&pub_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid receiver public key: {:?}", e))?;

        // ECDH
        let shared_secret = k256::elliptic_curve::ecdh::diffie_hellman(
            ephemeral_sk.to_nonzero_scalar(),
            receiver_pk.as_affine()
        );
        let z = shared_secret.raw_secret_bytes();
        
        // KDF (Concat KDF NIST SP 800-56A)
        // Order: counter || shared || other
        let mut kdf_bytes = vec![0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&1u32.to_be_bytes()); // counter = 1
        hasher.update(&z[..]);
        if let Some(info) = shared_info {
            hasher.update(info);
        }
        kdf_bytes.copy_from_slice(&hasher.finalize());

        let encryption_key = &kdf_bytes[0..16];
        let mac_key_raw = &kdf_bytes[16..32];
        
        // Ethereum hashes the MAC key before use
        let mut mac_key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(mac_key_raw);
        mac_key.copy_from_slice(&hasher.finalize());

        // AES-CTR
        let mut iv = [0u8; 16];
        rng.fill_bytes(&mut iv); // Random IV
        let encryption_key: &[u8; 16] = encryption_key.try_into()?;
        let mut cipher = Aes128Ctr::new(encryption_key.into(), &iv.into());
        let mut ciphertext = msg.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        // HMAC
        let mut hmac = HmacSha256::new_from_slice(&mac_key)?;
        hmac.update(&iv);
        hmac.update(&ciphertext);
        if let Some(info) = shared_info {
            hmac.update(info);
        }
        let mac = hmac.finalize().into_bytes();

        // Result: EphemeralPubKey (65 bytes) || IV (16) || Ciphertext || MAC (32)
        let eph_pub_sec1 = ephemeral_pk.to_encoded_point(false);
        let mut out = Vec::new();
        out.extend_from_slice(eph_pub_sec1.as_bytes());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&mac);

        Ok(out)
    }

    pub fn decrypt(my_sk: &SecretKey, data: &[u8], shared_info: Option<&[u8]>) -> Result<Vec<u8>> {
        if data.len() < 65 + 16 + 32 {
            return Err(anyhow::anyhow!("Data too short for ECIES decrypt"));
        }

        let eph_pub_bytes = &data[0..65];
        let iv = &data[65..81];
        let mac_offset = data.len() - 32;
        let ciphertext = &data[81..mac_offset];
        let provided_mac = &data[mac_offset..];

        let eph_pub = PublicKey::from_sec1_bytes(eph_pub_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid ephemeral public key: {:?}", e))?;

        // ECDH
        let shared_secret = k256::elliptic_curve::ecdh::diffie_hellman(
            my_sk.to_nonzero_scalar(),
            eph_pub.as_affine()
        );
        let z = shared_secret.raw_secret_bytes();

        // KDF
        let mut kdf_bytes = vec![0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&1u32.to_be_bytes());
        hasher.update(&z[..]);
        if let Some(info) = shared_info {
            hasher.update(info);
        }
        kdf_bytes.copy_from_slice(&hasher.finalize());

        let encryption_key = &kdf_bytes[0..16];
        let mac_key_raw = &kdf_bytes[16..32];

        // Hash MAC key
        let mut mac_key = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(mac_key_raw);
        mac_key.copy_from_slice(&hasher.finalize());

        // Verify HMAC
        let mut hmac = HmacSha256::new_from_slice(&mac_key)?;
        hmac.update(iv);
        hmac.update(ciphertext);
        if let Some(info) = shared_info {
            hmac.update(info);
        }
        hmac.verify_slice(provided_mac).context("HMAC verification failed")?;

        // AES-CTR Decrypt
        let encryption_key: &[u8; 16] = encryption_key.try_into()?;
        let iv: &[u8; 16] = iv.try_into()?;
        let mut cipher = Aes128Ctr::new(encryption_key.into(), iv.into());
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecies_roundtrip() {
        let mut rng = k256::elliptic_curve::rand_core::OsRng;
        let sk = SecretKey::random(&mut rng);
        let pk_encoded = sk.public_key().to_encoded_point(false);
        let mut pk_64 = [0u8; 64];
        pk_64.copy_from_slice(&pk_encoded.as_bytes()[1..]);
        let pk = B512::from_slice(&pk_64);

        let msg = b"Hello RLPx!";
        let shared_info = Some(b"RSK-V1");
        
        let encrypted = ECIES::encrypt(&pk, msg, shared_info.map(|s| s.as_slice())).unwrap();
        let decrypted = ECIES::decrypt(&sk, &encrypted, shared_info.map(|s| s.as_slice())).unwrap();
        
        assert_eq!(msg, decrypted.as_slice());
    }

    #[test]
    fn test_auth_messages() {
        let mut rng = k256::elliptic_curve::rand_core::OsRng;
        let my_sk = SecretKey::random(&mut rng);
        let my_ephemeral_sk = SecretKey::random(&mut rng);
        
        let remote_sk = SecretKey::random(&mut rng);
        let remote_pk_encoded = remote_sk.public_key().to_encoded_point(false);
        let mut remote_pk_64 = [0u8; 64];
        remote_pk_64.copy_from_slice(&remote_pk_encoded.as_bytes()[1..]);
        let remote_pk = B512::from_slice(&remote_pk_64);

        let nonce = B256::repeat_byte(0xcc);

        let auth_init = AuthInitiate::new(&my_sk, &remote_pk, &my_ephemeral_sk, nonce).unwrap();
        assert_eq!(auth_init.version, 4);
        assert_eq!(auth_init.nonce, nonce);
        
        let my_ephemeral_pk_encoded = my_ephemeral_sk.public_key().to_encoded_point(false);
        let mut my_ephemeral_pk_64 = [0u8; 64];
        my_ephemeral_pk_64.copy_from_slice(&my_ephemeral_pk_encoded.as_bytes()[1..]);
        let my_ephemeral_pk = B512::from_slice(&my_ephemeral_pk_64);
        
        let auth_resp = AuthResponse::new(&my_ephemeral_pk, nonce);
        assert_eq!(auth_resp.public_key, my_ephemeral_pk);
    }
}
