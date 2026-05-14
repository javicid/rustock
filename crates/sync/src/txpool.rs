use alloy_primitives::{Address, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use rustock_core::{Header, Transaction};
use rustock_storage::BlockStore;
use rustock_trie::{account_key, AccountState, TrieKeySlice, TrieNode, TrieStore};
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::debug;

const TRANSACTION_GAS_CAP: u64 = 1u64 << 60;
const MAX_TX_SIZE: usize = 128 * 1024;

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub account_slots: u64,
    pub gas_price_bump: u64,
    pub outdated_threshold: u64,
    pub outdated_timeout_secs: u64,
    pub max_tx_size: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            account_slots: 16,
            gas_price_bump: 40,
            outdated_threshold: 10,
            outdated_timeout_secs: 650,
            max_tx_size: MAX_TX_SIZE,
        }
    }
}

#[derive(Debug)]
pub enum PoolError {
    AlreadyKnown,
    NonceTooLow,
    NonceTooHigh,
    InsufficientFunds,
    GasLimitExceeded,
    GasPriceTooLow,
    IntrinsicGasTooHigh,
    ReplacementGasPriceTooLow,
    TxTooLarge,
    InvalidSignature(String),
    InsufficientFundsForPendingAndNew,
    IsRemascTransaction,
    RlpDecode(String),
    StoreError(String),
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyKnown => write!(f, "transaction with same hash already exists"),
            Self::NonceTooLow => write!(f, "transaction nonce too low"),
            Self::NonceTooHigh => write!(f, "transaction nonce too high"),
            Self::InsufficientFunds => write!(f, "insufficient funds"),
            Self::GasLimitExceeded => write!(f, "transaction's gas limit exceeds block gas limit"),
            Self::GasPriceTooLow => write!(f, "transaction's gas price lower than block's minimum"),
            Self::IntrinsicGasTooHigh => write!(f, "transaction's basic cost is above the gas limit"),
            Self::ReplacementGasPriceTooLow => write!(f, "gas price not enough to bump transaction"),
            Self::TxTooLarge => write!(f, "transaction's size is higher than defined maximum"),
            Self::InvalidSignature(e) => write!(f, "invalid signature: {e}"),
            Self::InsufficientFundsForPendingAndNew => {
                write!(f, "insufficient funds to pay for pending and new transactions")
            }
            Self::IsRemascTransaction => write!(f, "transaction is a remasc transaction"),
            Self::RlpDecode(e) => write!(f, "RLP decode error: {e}"),
            Self::StoreError(e) => write!(f, "store error: {e}"),
        }
    }
}

impl std::error::Error for PoolError {}

#[derive(Clone, Debug)]
pub struct PooledTx {
    pub tx: Transaction,
    pub hash: B256,
    pub sender: Address,
    pub added_block: u64,
    pub added_time: Instant,
    pub encoded_size: usize,
}

struct PoolInner {
    pending: HashMap<Address, BTreeMap<u64, PooledTx>>,
    queued: HashMap<Address, BTreeMap<u64, PooledTx>>,
    by_hash: HashMap<B256, Address>,
}

impl PoolInner {
    fn new() -> Self {
        Self {
            pending: HashMap::new(),
            queued: HashMap::new(),
            by_hash: HashMap::new(),
        }
    }
}

pub struct TransactionPool {
    inner: RwLock<PoolInner>,
    config: PoolConfig,
    chain_id: u64,
    store: Arc<BlockStore>,
    trie_store: Arc<dyn TrieStore>,
}

impl TransactionPool {
    pub fn new(
        config: PoolConfig,
        chain_id: u64,
        store: Arc<BlockStore>,
        trie_store: Arc<dyn TrieStore>,
    ) -> Self {
        Self {
            inner: RwLock::new(PoolInner::new()),
            config,
            chain_id,
            store,
            trie_store,
        }
    }

    /// Add a raw RLP-encoded transaction to the pool.
    pub fn add_transaction(&self, raw: &[u8]) -> Result<B256, PoolError> {
        let tx = Transaction::decode(&mut &raw[..])
            .map_err(|e| PoolError::RlpDecode(format!("{e}")))?;

        let hash = tx_hash(raw);

        let mut encoded = Vec::new();
        tx.encode(&mut encoded);
        let encoded_size = encoded.len();

        let sender = tx
            .recover_sender(self.chain_id)
            .map_err(|e| PoolError::InvalidSignature(format!("{e}")))?;

        let head_header = self.head_header()?;
        let (state_nonce, balance) = self.account_state(&head_header, &sender);

        self.validate_tx(&tx, encoded_size, &head_header, state_nonce, balance)?;

        let current_block = head_header.number;
        let pooled = PooledTx {
            tx: tx.clone(),
            hash,
            sender,
            added_block: current_block,
            added_time: Instant::now(),
            encoded_size,
        };

        let mut inner = self.inner.write().unwrap();

        if inner.by_hash.contains_key(&hash) {
            return Err(PoolError::AlreadyKnown);
        }

        let goes_to_pending = if tx.nonce == state_nonce {
            true
        } else if let Some(pending_map) = inner.pending.get(&sender) {
            pending_map
                .keys()
                .last()
                .is_some_and(|&last| tx.nonce == last + 1)
        } else {
            false
        };

        // Check for replacement (same nonce, different hash)
        let target_map = if goes_to_pending {
            &inner.pending
        } else {
            &inner.queued
        };
        let mut old_hash_to_remove: Option<B256> = None;
        if let Some(nonce_map) = target_map.get(&sender) {
            if let Some(existing) = nonce_map.get(&tx.nonce) {
                if existing.hash == hash {
                    return Err(PoolError::AlreadyKnown);
                }
                let bump_threshold = existing.tx.gas_price
                    * U256::from(100 + self.config.gas_price_bump)
                    / U256::from(100);
                if tx.gas_price < bump_threshold {
                    return Err(PoolError::ReplacementGasPriceTooLow);
                }
                old_hash_to_remove = Some(existing.hash);
            }
        }

        // Aggregate balance check for pending txs
        if goes_to_pending {
            let mut total_cost = tx_cost(&tx);
            if let Some(pending_map) = inner.pending.get(&sender) {
                for (nonce, ptx) in pending_map {
                    if *nonce != tx.nonce {
                        total_cost += tx_cost(&ptx.tx);
                    }
                }
            }
            if total_cost > balance {
                return Err(PoolError::InsufficientFundsForPendingAndNew);
            }
        }

        // All checks passed — mutate the pool
        if let Some(old_hash) = old_hash_to_remove {
            inner.by_hash.remove(&old_hash);
        }

        let sender_map = if goes_to_pending {
            inner.pending.entry(sender).or_default()
        } else {
            inner.queued.entry(sender).or_default()
        };
        sender_map.insert(tx.nonce, pooled);
        inner.by_hash.insert(hash, sender);

        if goes_to_pending {
            self.promote_queued(&mut inner, sender, state_nonce);
        }

        debug!(tx_hash = %hash, sender = %sender, nonce = tx.nonce, "Transaction added to pool");
        Ok(hash)
    }

    fn validate_tx(
        &self,
        tx: &Transaction,
        encoded_size: usize,
        header: &Header,
        state_nonce: u64,
        balance: U256,
    ) -> Result<(), PoolError> {
        // 1. Not REMASC
        if is_remasc_tx(tx) {
            return Err(PoolError::IsRemascTransaction);
        }

        // 2. Size limit
        if encoded_size > self.config.max_tx_size {
            return Err(PoolError::TxTooLarge);
        }

        // 3. Gas limit checks
        let gas_limit = tx.gas_limit.to::<u64>();
        let block_gas_limit = header.gas_limit.to::<u64>();
        if gas_limit > block_gas_limit || gas_limit > TRANSACTION_GAS_CAP {
            return Err(PoolError::GasLimitExceeded);
        }

        // 4. Nonce range
        if tx.nonce < state_nonce {
            return Err(PoolError::NonceTooLow);
        }
        if tx.nonce >= state_nonce + self.config.account_slots {
            return Err(PoolError::NonceTooHigh);
        }

        // 5. Balance >= gas cost
        let gas_cost = tx.gas_price * tx.gas_limit;
        if balance < gas_cost {
            return Err(PoolError::InsufficientFunds);
        }

        // 6. Minimum gas price
        if tx.gas_price < header.minimum_gas_price {
            return Err(PoolError::GasPriceTooLow);
        }

        // 7. Intrinsic gas
        let intrinsic = intrinsic_gas(tx);
        if U256::from(intrinsic) > tx.gas_limit {
            return Err(PoolError::IntrinsicGasTooHigh);
        }

        Ok(())
    }

    /// Remove transactions that are included in a newly imported block.
    pub fn remove_mined(&self, transactions: &[Transaction]) {
        let mut inner = self.inner.write().unwrap();
        for tx in transactions {
            let mut buf = Vec::new();
            tx.encode(&mut buf);
            let hash = tx_hash(&buf);
            if let Some(sender) = inner.by_hash.remove(&hash) {
                if let Some(map) = inner.pending.get_mut(&sender) {
                    map.remove(&tx.nonce);
                    if map.is_empty() {
                        inner.pending.remove(&sender);
                    }
                }
                if let Some(map) = inner.queued.get_mut(&sender) {
                    map.remove(&tx.nonce);
                    if map.is_empty() {
                        inner.queued.remove(&sender);
                    }
                }
            }
        }
    }

    /// Evict transactions older than the configured thresholds.
    pub fn evict_outdated(&self, current_block: u64) {
        let mut inner = self.inner.write().unwrap();
        let threshold = self.config.outdated_threshold;
        let timeout = std::time::Duration::from_secs(self.config.outdated_timeout_secs);
        let now = Instant::now();

        let mut to_remove = Vec::new();

        for map in [&inner.pending, &inner.queued] {
            for (sender, nonce_map) in map {
                for (nonce, ptx) in nonce_map {
                    let by_block = current_block > ptx.added_block + threshold;
                    let by_time = now.duration_since(ptx.added_time) > timeout;
                    if by_block || by_time {
                        to_remove.push((*sender, *nonce, ptx.hash));
                    }
                }
            }
        }

        for (sender, nonce, hash) in to_remove {
            inner.by_hash.remove(&hash);
            if let Some(map) = inner.pending.get_mut(&sender) {
                map.remove(&nonce);
                if map.is_empty() {
                    inner.pending.remove(&sender);
                }
            }
            if let Some(map) = inner.queued.get_mut(&sender) {
                map.remove(&nonce);
                if map.is_empty() {
                    inner.queued.remove(&sender);
                }
            }
        }
    }

    /// Promote any consecutive queued txs for a sender into pending.
    fn promote_queued(&self, inner: &mut PoolInner, sender: Address, state_nonce: u64) {
        let pending_map = inner.pending.entry(sender).or_default();
        let next_nonce = pending_map
            .keys()
            .last()
            .map(|n| n + 1)
            .unwrap_or(state_nonce);

        if let Some(queued_map) = inner.queued.get_mut(&sender) {
            let mut nonce = next_nonce;
            while let Some(ptx) = queued_map.remove(&nonce) {
                pending_map.insert(nonce, ptx);
                nonce += 1;
            }
            if queued_map.is_empty() {
                inner.queued.remove(&sender);
            }
        }
    }

    /// Get a transaction from the pool by hash.
    pub fn get(&self, hash: &B256) -> Option<PooledTx> {
        let inner = self.inner.read().unwrap();
        let sender = inner.by_hash.get(hash)?;
        for map in [&inner.pending, &inner.queued] {
            if let Some(nonce_map) = map.get(sender) {
                for ptx in nonce_map.values() {
                    if ptx.hash == *hash {
                        return Some(ptx.clone());
                    }
                }
            }
        }
        None
    }

    /// Return all pending transactions ordered by gas price (desc), nonce (asc) per sender.
    pub fn pending_transactions(&self) -> Vec<PooledTx> {
        let inner = self.inner.read().unwrap();
        let mut result = Vec::new();
        for nonce_map in inner.pending.values() {
            for ptx in nonce_map.values() {
                result.push(ptx.clone());
            }
        }
        result.sort_by(|a, b| {
            b.tx.gas_price.cmp(&a.tx.gas_price).then(a.tx.nonce.cmp(&b.tx.nonce))
        });
        result
    }

    /// Return counts of pending and queued transactions.
    pub fn status(&self) -> (usize, usize) {
        let inner = self.inner.read().unwrap();
        let pending: usize = inner.pending.values().map(|m| m.len()).sum();
        let queued: usize = inner.queued.values().map(|m| m.len()).sum();
        (pending, queued)
    }

    /// Return the pending nonce for an address (state nonce + pending count).
    pub fn pending_nonce(&self, addr: &Address) -> Option<u64> {
        let inner = self.inner.read().unwrap();
        inner
            .pending
            .get(addr)
            .and_then(|m| m.keys().last().map(|n| n + 1))
    }

    fn head_header(&self) -> Result<Header, PoolError> {
        let hash = self
            .store
            .head()
            .map_err(|e| PoolError::StoreError(format!("{e}")))?
            .ok_or_else(|| PoolError::StoreError("no head".into()))?;
        self.store
            .header(hash)
            .map_err(|e| PoolError::StoreError(format!("{e}")))?
            .ok_or_else(|| PoolError::StoreError("head header not found".into()))
    }

    fn account_state(&self, header: &Header, addr: &Address) -> (u64, U256) {
        let root_hash = header.state_root;
        let root_data = match self.trie_store.get(root_hash.as_slice()) {
            Some(d) => d,
            None => return (0, U256::ZERO),
        };
        let root = TrieNode::from_message(&root_data, &*self.trie_store);
        let key = account_key(addr);
        let expanded = TrieKeySlice::from_key(&key);
        match root.get(&expanded, &*self.trie_store) {
            Some(data) => match AccountState::decode(&data) {
                Ok(acct) => (acct.nonce.to::<u64>(), acct.balance),
                Err(_) => (0, U256::ZERO),
            },
            None => (0, U256::ZERO),
        }
    }
}

/// Compute the cost of a transaction: value + gas_price * gas_limit.
fn tx_cost(tx: &Transaction) -> U256 {
    tx.value + tx.gas_price * tx.gas_limit
}

/// Compute the keccak256 hash of raw transaction bytes.
pub fn tx_hash(raw: &[u8]) -> B256 {
    B256::from_slice(&Keccak256::digest(raw))
}

/// Check if a transaction is a REMASC transaction.
fn is_remasc_tx(tx: &Transaction) -> bool {
    if tx.to.len() != 20 {
        return false;
    }
    let remasc_bytes: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 8];
    tx.to.as_ref() == remasc_bytes
        && tx.gas_price.is_zero()
        && tx.gas_limit.is_zero()
        && tx.value.is_zero()
}

/// Compute the intrinsic gas cost of a transaction (matching rskj).
pub fn intrinsic_gas(tx: &Transaction) -> u64 {
    let base = if tx.to.is_empty() { 53_000u64 } else { 21_000u64 };

    let calldata_cost: u64 = tx
        .input
        .iter()
        .map(|&b| if b == 0 { 4u64 } else { 16u64 })
        .sum();

    base + calldata_cost
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bloom, Bytes, U256};
    use k256::ecdsa::SigningKey;
    use rustock_trie::MemoryTrieStore;
    use tempfile::tempdir;

    fn test_config() -> PoolConfig {
        PoolConfig {
            account_slots: 16,
            gas_price_bump: 40,
            outdated_threshold: 10,
            outdated_timeout_secs: 650,
            max_tx_size: MAX_TX_SIZE,
        }
    }

    fn test_header() -> Header {
        Header {
            number: 100,
            parent_hash: B256::ZERO,
            ommers_hash: B256::ZERO,
            beneficiary: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bloom::ZERO,
            extension_data: None,
            difficulty: U256::ZERO,
            gas_limit: U256::from(8_000_000),
            gas_used: 0,
            timestamp: 1_700_000_000,
            extra_data: Bytes::new(),
            paid_fees: U256::ZERO,
            minimum_gas_price: U256::from(59_240_000),
            uncle_count: 0,
            umm_root: None,
            bitcoin_merged_mining_header: None,
            bitcoin_merged_mining_merkle_proof: None,
            bitcoin_merged_mining_coinbase_transaction: None,
            cached_hash: None,
            cached_hash_for_merged_mining: None,
        }
    }

    fn setup_pool_with_account(
        balance: U256,
        nonce: u64,
    ) -> (TransactionPool, SigningKey, Address) {
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());

        let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let vk = signing_key.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let addr = Address::from_slice(&Keccak256::digest(&pubkey.as_bytes()[1..])[12..]);

        let acct = AccountState::new(U256::from(nonce), balance);
        let key = account_key(&addr);
        let mut root = TrieNode::empty();
        root = root.put(&TrieKeySlice::from_key(&key), &acct.encode(), &*trie_store);
        root.save(&*trie_store, true);
        let state_root = root.compute_hash(&*trie_store);
        let root_data = root.to_message(&*trie_store);
        rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

        let mut header = test_header();
        header.state_root = state_root;
        store.update_head(&header, U256::from(100_000)).unwrap();

        // Keep dir alive by leaking it (temp dir will be cleaned up on process exit)
        let pool = TransactionPool::new(test_config(), 33, store, trie_store);
        std::mem::forget(dir);
        (pool, signing_key, addr)
    }

    fn sign_tx(tx: &mut Transaction, key: &SigningKey, chain_id: u64) {
        let hash = tx.signing_hash_eip155(chain_id);
        let (signature, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = key
            .sign_prehash_recoverable(hash.as_slice())
            .unwrap();
        let sig_bytes = signature.to_bytes();
        tx.r = U256::from_be_slice(&sig_bytes[..32]);
        tx.s = U256::from_be_slice(&sig_bytes[32..]);
        tx.v = chain_id * 2 + 35 + recid.to_byte() as u64;
    }

    fn make_tx(nonce: u64, gas_price: u64) -> Transaction {
        Transaction {
            nonce,
            gas_price: U256::from(gas_price),
            gas_limit: U256::from(21_000),
            to: Bytes::from(vec![0xBB; 20]),
            value: U256::from(1000),
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        }
    }

    fn encode_tx(tx: &Transaction) -> Vec<u8> {
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        buf
    }

    // ========== Intrinsic gas ==========

    #[test]
    fn test_intrinsic_gas_simple_transfer() {
        let tx = make_tx(0, 1);
        assert_eq!(intrinsic_gas(&tx), 21_000);
    }

    #[test]
    fn test_intrinsic_gas_contract_creation() {
        let mut tx = make_tx(0, 1);
        tx.to = Bytes::new();
        assert_eq!(intrinsic_gas(&tx), 53_000);
    }

    #[test]
    fn test_intrinsic_gas_with_calldata() {
        let mut tx = make_tx(0, 1);
        tx.input = Bytes::from(vec![0x00, 0x01, 0x00, 0xff]);
        // 21000 + 4(zero) + 16(non-zero) + 4(zero) + 16(non-zero)
        assert_eq!(intrinsic_gas(&tx), 21_000 + 4 + 16 + 4 + 16);
    }

    // ========== rskj: addAndGetPendingTransaction ==========

    #[test]
    fn test_add_pending_transaction() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let raw = encode_tx(&tx);

        let hash = pool.add_transaction(&raw).unwrap();
        assert!(pool.get(&hash).is_some());
        let (pending, queued) = pool.status();
        assert_eq!(pending, 1);
        assert_eq!(queued, 0);
    }

    // ========== rskj: addAndGetQueuedTransaction ==========

    #[test]
    fn test_add_queued_transaction() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(4, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let raw = encode_tx(&tx);

        let hash = pool.add_transaction(&raw).unwrap();
        assert!(pool.get(&hash).is_some());
        let (pending, queued) = pool.status();
        assert_eq!(pending, 0);
        assert_eq!(queued, 1);
    }

    // ========== rskj: addAndGetTwoQueuedTransactionAsPendingOnes ==========

    #[test]
    fn test_promotion_queued_to_pending() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);

        // Add nonce 1 and 2 first — they go to queued
        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        let mut tx2 = make_tx(2, 59_240_000);
        sign_tx(&mut tx2, &key, 33);
        pool.add_transaction(&encode_tx(&tx2)).unwrap();

        let (pending, queued) = pool.status();
        assert_eq!(pending, 0);
        assert_eq!(queued, 2);

        // Add nonce 0 — it goes to pending and promotes 1, 2
        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        let (pending, queued) = pool.status();
        assert_eq!(pending, 3);
        assert_eq!(queued, 0);
    }

    // ========== rskj: addTwiceAndGetPendingTransaction ==========

    #[test]
    fn test_duplicate_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let raw = encode_tx(&tx);

        pool.add_transaction(&raw).unwrap();
        let err = pool.add_transaction(&raw).unwrap_err();
        assert!(matches!(err, PoolError::AlreadyKnown));
    }

    // ========== rskj: checkTxWithSameNonceIsRejected ==========

    #[test]
    fn test_same_nonce_low_gas_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx1 = make_tx(0, 100_000_000);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        // Same nonce, same gas price — should be rejected (needs 140%)
        let mut tx2 = make_tx(0, 100_000_000);
        tx2.value = U256::from(2000); // different tx, different hash
        sign_tx(&mut tx2, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx2)).unwrap_err();
        assert!(matches!(err, PoolError::ReplacementGasPriceTooLow));
    }

    // ========== rskj: checkTxWithSameNonceBumpedIsAccepted ==========

    #[test]
    fn test_same_nonce_bumped_accepted() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx1 = make_tx(0, 100_000_000);
        sign_tx(&mut tx1, &key, 33);
        let hash1 = pool.add_transaction(&encode_tx(&tx1)).unwrap();

        // 2x gas price — should replace
        let mut tx2 = make_tx(0, 200_000_000);
        sign_tx(&mut tx2, &key, 33);
        let hash2 = pool.add_transaction(&encode_tx(&tx2)).unwrap();

        assert_ne!(hash1, hash2);
        assert!(pool.get(&hash1).is_none());
        assert!(pool.get(&hash2).is_some());
    }

    // ========== rskj: checkTxWithHighGasLimitIsRejected ==========

    #[test]
    fn test_high_gas_limit_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        tx.gas_limit = U256::from(9_000_000); // > 8M block gas limit
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::GasLimitExceeded));
    }

    // ========== rskj: checkTxWithHighNonceIsRejected ==========

    #[test]
    fn test_high_nonce_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(16, 59_240_000); // account_slots = 16, so nonce 16 is out of range
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::NonceTooHigh));
    }

    // ========== rskj: checkTxWithLowNonceIsRejected ==========

    #[test]
    fn test_low_nonce_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 5);
        let mut tx = make_tx(4, 59_240_000); // state nonce is 5
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::NonceTooLow));
    }

    // ========== rskj: checkRemascTxIsRejected ==========

    #[test]
    fn test_remasc_tx_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let remasc_addr: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 8];
        let mut tx = Transaction {
            nonce: 0,
            gas_price: U256::ZERO,
            gas_limit: U256::ZERO,
            to: Bytes::from(remasc_addr.to_vec()),
            value: U256::ZERO,
            input: Bytes::new(),
            v: 0,
            r: U256::ZERO,
            s: U256::ZERO,
            cached_rlp: None,
        };
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::IsRemascTransaction));
    }

    // ========== rskj: checkTxWithLowGasPriceIsRejected ==========

    #[test]
    fn test_low_gas_price_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 1); // below min gas price of 59_240_000
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::GasPriceTooLow));
    }

    // ========== rskj: checkTxFromAccountWithLowBalanceIsRejected ==========

    #[test]
    fn test_insufficient_balance_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(100), 0);
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::InsufficientFunds));
    }

    // ========== rskj: checkTxWithHighIntrinsicGasIsRejected ==========

    #[test]
    fn test_intrinsic_gas_exceeded() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        tx.gas_limit = U256::from(100); // way below 21000
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::IntrinsicGasTooHigh));
    }

    // ========== rskj: checkTxWhichCanNotBePaidIsRejected ==========

    #[test]
    fn test_aggregate_balance_exceeded() {
        // Balance enough for 1 tx but not 2
        let gas_price = 59_240_000u64;
        let gas_limit = 21_000u64;
        let cost_per_tx = gas_price as u128 * gas_limit as u128 + 1000; // gas + value
        let balance = U256::from(cost_per_tx * 3 / 2); // enough for 1.5 txs

        let (pool, key, _addr) = setup_pool_with_account(balance, 0);

        let mut tx1 = make_tx(0, gas_price);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        let mut tx2 = make_tx(1, gas_price);
        sign_tx(&mut tx2, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx2)).unwrap_err();
        assert!(matches!(err, PoolError::InsufficientFundsForPendingAndNew));
    }

    // ========== rskj: removeObsoletePendingTransactionsByBlock ==========

    #[test]
    fn test_evict_outdated_by_block() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let hash = pool.add_transaction(&encode_tx(&tx)).unwrap();

        assert!(pool.get(&hash).is_some());
        // Current block is 100, outdated_threshold is 10, so at block 111 the tx should be evicted
        pool.evict_outdated(111);
        assert!(pool.get(&hash).is_none());
    }

    // ========== rskj: processBestBlockRemovesTransactionsInBlock ==========

    #[test]
    fn test_remove_mined_transactions() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let hash = pool.add_transaction(&encode_tx(&tx)).unwrap();

        assert!(pool.get(&hash).is_some());
        pool.remove_mined(&[tx]);
        assert!(pool.get(&hash).is_none());
        let (pending, queued) = pool.status();
        assert_eq!(pending, 0);
        assert_eq!(queued, 0);
    }

    // ========== Nonce range boundary tests ==========

    #[test]
    fn test_nonce_range_one_slot() {
        let config = PoolConfig {
            account_slots: 1,
            ..test_config()
        };
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());

        let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let vk = signing_key.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let addr = Address::from_slice(&Keccak256::digest(&pubkey.as_bytes()[1..])[12..]);

        let acct = AccountState::new(U256::from(1), U256::from(10u64.pow(18)));
        let key_bytes = account_key(&addr);
        let mut root = TrieNode::empty();
        root = root.put(&TrieKeySlice::from_key(&key_bytes), &acct.encode(), &*trie_store);
        root.save(&*trie_store, true);
        let state_root = root.compute_hash(&*trie_store);
        let root_data = root.to_message(&*trie_store);
        rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

        let mut header = test_header();
        header.state_root = state_root;
        store.update_head(&header, U256::from(100_000)).unwrap();

        let pool = TransactionPool::new(config, 33, store, trie_store);

        // nonce 0 should be rejected (< state_nonce=1)
        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &signing_key, 33);
        assert!(matches!(pool.add_transaction(&encode_tx(&tx0)), Err(PoolError::NonceTooLow)));

        // nonce 1 should be accepted (= state_nonce)
        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &signing_key, 33);
        assert!(pool.add_transaction(&encode_tx(&tx1)).is_ok());

        // nonce 2 should be rejected (>= state_nonce + account_slots = 2)
        let mut tx2 = make_tx(2, 59_240_000);
        sign_tx(&mut tx2, &signing_key, 33);
        assert!(matches!(pool.add_transaction(&encode_tx(&tx2)), Err(PoolError::NonceTooHigh)));

        std::mem::forget(dir);
    }

    // ========== Gas price bump math ==========

    #[test]
    fn test_gas_price_bump_exact_threshold() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let base_price = 100_000_000u64;

        let mut tx1 = make_tx(0, base_price);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        // 139% should be rejected (bump is 40%, need >= 140%)
        let mut tx2 = make_tx(0, base_price * 139 / 100);
        tx2.value = U256::from(2000);
        sign_tx(&mut tx2, &key, 33);
        assert!(matches!(
            pool.add_transaction(&encode_tx(&tx2)),
            Err(PoolError::ReplacementGasPriceTooLow)
        ));

        // 140% should be accepted
        let mut tx3 = make_tx(0, base_price * 140 / 100);
        tx3.value = U256::from(3000);
        sign_tx(&mut tx3, &key, 33);
        assert!(pool.add_transaction(&encode_tx(&tx3)).is_ok());
    }

    // ========== pending_nonce ==========

    #[test]
    fn test_pending_nonce() {
        let (pool, key, addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        assert_eq!(pool.pending_nonce(&addr), None);

        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        assert_eq!(pool.pending_nonce(&addr), Some(1));

        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        assert_eq!(pool.pending_nonce(&addr), Some(2));
    }

    // ========== status ==========

    #[test]
    fn test_pool_status() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);

        let (p, q) = pool.status();
        assert_eq!(p, 0);
        assert_eq!(q, 0);

        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        let (p, q) = pool.status();
        assert_eq!(p, 1);
        assert_eq!(q, 0);

        let mut tx5 = make_tx(5, 59_240_000);
        sign_tx(&mut tx5, &key, 33);
        pool.add_transaction(&encode_tx(&tx5)).unwrap();

        let (p, q) = pool.status();
        assert_eq!(p, 1);
        assert_eq!(q, 1);
    }

    // ========== Invalid signature ==========

    #[test]
    fn test_invalid_signature_rejected() {
        let (pool, _key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        tx.v = 27;
        tx.r = U256::ZERO;
        tx.s = U256::ZERO;
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::InvalidSignature(_)));
    }

    // ========== Size limit ==========

    #[test]
    fn test_tx_too_large() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        tx.input = Bytes::from(vec![0xAA; 129 * 1024]); // > 128KB
        tx.gas_limit = U256::from(8_000_000); // high enough for calldata
        sign_tx(&mut tx, &key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::TxTooLarge));
    }

    // ========== rskj: checkTxMaxSizeAccepted ==========

    #[test]
    fn test_tx_size_exactly_at_limit() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(0, 59_240_000);
        // RLP overhead is ~100 bytes; fill input with enough data to be just under the limit
        tx.input = Bytes::from(vec![0xAA; 127 * 1024]);
        tx.gas_limit = U256::from(8_000_000);
        sign_tx(&mut tx, &key, 33);
        let raw = encode_tx(&tx);
        assert!(raw.len() <= MAX_TX_SIZE, "encoded size {} should be <= {}", raw.len(), MAX_TX_SIZE);
        assert!(pool.add_transaction(&raw).is_ok());
    }

    // ========== rskj: checkTxBumpIsNotConsideredOnTotalCosts ==========

    #[test]
    fn test_bump_excluded_from_aggregate_balance() {
        // balance just enough for one tx at the bump price, not two
        let gas_price = 100_000_000u64;
        let gas_limit = 21_000u64;
        let bumped_price = gas_price * 140 / 100;
        let tx_cost_bumped = bumped_price as u128 * gas_limit as u128 + 1000;
        // enough for bumped tx0 + tx1, but NOT for two tx1s at once
        let balance = U256::from(tx_cost_bumped * 2 + 1);

        let (pool, key, _addr) = setup_pool_with_account(balance, 0);

        // tx0 at base price
        let mut tx0 = make_tx(0, gas_price);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        // Replace tx0 with bumped price
        let mut tx0_bumped = make_tx(0, bumped_price);
        tx0_bumped.value = U256::from(1000);
        sign_tx(&mut tx0_bumped, &key, 33);
        pool.add_transaction(&encode_tx(&tx0_bumped)).unwrap();

        // tx1 should succeed since only the replacement's cost is counted
        let mut tx1 = make_tx(1, gas_price);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        let (pending, _queued) = pool.status();
        assert_eq!(pending, 2);
    }

    // ========== rskj: checkTxFromNullStateIsRejected ==========

    #[test]
    fn test_null_sender_insufficient_funds() {
        // An account not in the trie has balance=0. Any tx requiring gas should fail.
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());

        // Put an empty trie root
        let mut root = TrieNode::empty();
        root.save(&*trie_store, true);
        let state_root = root.compute_hash(&*trie_store);
        let root_data = root.to_message(&*trie_store);
        rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

        let mut header = test_header();
        header.state_root = state_root;
        store.update_head(&header, U256::from(100_000)).unwrap();

        let pool = TransactionPool::new(test_config(), 33, store, trie_store);

        let signing_key = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &signing_key, 33);
        let err = pool.add_transaction(&encode_tx(&tx)).unwrap_err();
        assert!(matches!(err, PoolError::InsufficientFunds));

        std::mem::forget(dir);
    }

    // ========== rskj: removeObsoleteQueuedTransactionsByBlock ==========

    #[test]
    fn test_evict_queued_by_block() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(5, 59_240_000); // queued (nonce gap)
        sign_tx(&mut tx, &key, 33);
        let hash = pool.add_transaction(&encode_tx(&tx)).unwrap();

        let (_, queued) = pool.status();
        assert_eq!(queued, 1);

        pool.evict_outdated(111);
        assert!(pool.get(&hash).is_none());
        let (_, queued) = pool.status();
        assert_eq!(queued, 0);
    }

    // ========== rskj: addTwiceAndGetQueuedTransaction ==========

    #[test]
    fn test_duplicate_queued_rejected() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);
        let mut tx = make_tx(5, 59_240_000);
        sign_tx(&mut tx, &key, 33);
        let raw = encode_tx(&tx);

        pool.add_transaction(&raw).unwrap();
        let err = pool.add_transaction(&raw).unwrap_err();
        assert!(matches!(err, PoolError::AlreadyKnown));
    }

    // ========== rskj: pending sorted by nonce ==========

    #[test]
    fn test_pending_sorted_by_nonce() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);

        // Add nonce 1 first (queued), then nonce 0 (triggers promotion)
        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        let pending = pool.pending_transactions();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].tx.nonce, 0);
        assert_eq!(pending[1].tx.nonce, 1);
    }

    // ========== rskj: processBestBlockRemovesTransactionsInBlock (partial) ==========

    #[test]
    fn test_partial_remove_mined() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);

        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &key, 33);
        pool.add_transaction(&encode_tx(&tx0)).unwrap();

        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &key, 33);
        let hash1 = pool.add_transaction(&encode_tx(&tx1)).unwrap();

        let (pending, _) = pool.status();
        assert_eq!(pending, 2);

        // Only mine tx0
        pool.remove_mined(&[tx0]);
        let (pending, _) = pool.status();
        assert_eq!(pending, 1);
        assert!(pool.get(&hash1).is_some());
    }

    // ========== rskj: fiveSlotsRange ==========

    #[test]
    fn test_nonce_range_five_slots() {
        let config = PoolConfig {
            account_slots: 5,
            ..test_config()
        };
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());

        let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let vk = signing_key.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let addr = Address::from_slice(&Keccak256::digest(&pubkey.as_bytes()[1..])[12..]);

        let acct = AccountState::new(U256::from(1), U256::from(10u64.pow(18)));
        let key_bytes = account_key(&addr);
        let mut root = TrieNode::empty();
        root = root.put(&TrieKeySlice::from_key(&key_bytes), &acct.encode(), &*trie_store);
        root.save(&*trie_store, true);
        let state_root = root.compute_hash(&*trie_store);
        let root_data = root.to_message(&*trie_store);
        rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

        let mut header = test_header();
        header.state_root = state_root;
        store.update_head(&header, U256::from(100_000)).unwrap();

        let pool = TransactionPool::new(config, 33, store, trie_store);

        // nonce 0 should be rejected (< state_nonce=1)
        let mut tx0 = make_tx(0, 59_240_000);
        sign_tx(&mut tx0, &signing_key, 33);
        assert!(matches!(pool.add_transaction(&encode_tx(&tx0)), Err(PoolError::NonceTooLow)));

        // nonces 1-5 should be accepted
        for n in 1..=5 {
            let mut tx = make_tx(n, 59_240_000);
            tx.value = U256::from(n); // unique value per nonce
            sign_tx(&mut tx, &signing_key, 33);
            assert!(pool.add_transaction(&encode_tx(&tx)).is_ok(), "nonce {} should be accepted", n);
        }

        // nonce 6 should be rejected (>= state_nonce + account_slots = 6)
        let mut tx6 = make_tx(6, 59_240_000);
        sign_tx(&mut tx6, &signing_key, 33);
        assert!(matches!(pool.add_transaction(&encode_tx(&tx6)), Err(PoolError::NonceTooHigh)));

        std::mem::forget(dir);
    }

    // ========== rskj: eviction by timeout ==========

    #[test]
    fn test_evict_outdated_by_timeout() {
        let config = PoolConfig {
            outdated_timeout_secs: 0, // 0 seconds means any tx is immediately evictable
            ..test_config()
        };
        let dir = tempdir().unwrap();
        let store = Arc::new(BlockStore::open(dir.path()).unwrap());
        let trie_store: Arc<dyn TrieStore> = Arc::new(MemoryTrieStore::new());

        let signing_key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let vk = signing_key.verifying_key();
        let pubkey = vk.to_encoded_point(false);
        let addr = Address::from_slice(&Keccak256::digest(&pubkey.as_bytes()[1..])[12..]);

        let acct = AccountState::new(U256::from(0), U256::from(10u64.pow(18)));
        let key_bytes = account_key(&addr);
        let mut root = TrieNode::empty();
        root = root.put(&TrieKeySlice::from_key(&key_bytes), &acct.encode(), &*trie_store);
        root.save(&*trie_store, true);
        let state_root = root.compute_hash(&*trie_store);
        let root_data = root.to_message(&*trie_store);
        rustock_trie::TrieStore::put(&*trie_store, state_root.as_slice(), &root_data);

        let mut header = test_header();
        header.state_root = state_root;
        store.update_head(&header, U256::from(100_000)).unwrap();

        let pool = TransactionPool::new(config, 33, store, trie_store);

        let mut tx = make_tx(0, 59_240_000);
        sign_tx(&mut tx, &signing_key, 33);
        let hash = pool.add_transaction(&encode_tx(&tx)).unwrap();
        assert!(pool.get(&hash).is_some());

        // Wait a tiny bit to ensure elapsed > 0 seconds
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Evict with a current block that doesn't trigger block-based eviction
        pool.evict_outdated(100);
        assert!(pool.get(&hash).is_none());

        std::mem::forget(dir);
    }

    // ========== rskj: two queued transactions ==========

    #[test]
    fn test_two_queued_transactions() {
        let (pool, key, _addr) = setup_pool_with_account(U256::from(10u64.pow(18)), 0);

        let mut tx1 = make_tx(1, 59_240_000);
        sign_tx(&mut tx1, &key, 33);
        pool.add_transaction(&encode_tx(&tx1)).unwrap();

        let mut tx2 = make_tx(2, 59_240_000);
        sign_tx(&mut tx2, &key, 33);
        pool.add_transaction(&encode_tx(&tx2)).unwrap();

        let (pending, queued) = pool.status();
        assert_eq!(pending, 0);
        assert_eq!(queued, 2);
    }

    // ========== PoolError Display ==========

    #[test]
    fn test_pool_error_display() {
        assert_eq!(PoolError::AlreadyKnown.to_string(), "transaction with same hash already exists");
        assert_eq!(PoolError::NonceTooLow.to_string(), "transaction nonce too low");
        assert_eq!(PoolError::NonceTooHigh.to_string(), "transaction nonce too high");
        assert_eq!(PoolError::InsufficientFunds.to_string(), "insufficient funds");
        assert_eq!(PoolError::GasLimitExceeded.to_string(), "transaction's gas limit exceeds block gas limit");
        assert_eq!(PoolError::GasPriceTooLow.to_string(), "transaction's gas price lower than block's minimum");
        assert_eq!(PoolError::IntrinsicGasTooHigh.to_string(), "transaction's basic cost is above the gas limit");
        assert_eq!(PoolError::ReplacementGasPriceTooLow.to_string(), "gas price not enough to bump transaction");
        assert_eq!(PoolError::TxTooLarge.to_string(), "transaction's size is higher than defined maximum");
        assert_eq!(PoolError::IsRemascTransaction.to_string(), "transaction is a remasc transaction");
        assert_eq!(
            PoolError::InsufficientFundsForPendingAndNew.to_string(),
            "insufficient funds to pay for pending and new transactions"
        );
    }
}
