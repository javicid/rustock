# RSKIP305 P2SH-P2WSH (segwit) federations — reed800

**Hit at #8,107,002**: a new federation change (`commitFederation`) creates a
proposed federation of **format 4000 (P2SH-P2WSH-ERP)** because reed800 (#8,052,200)
activates RSKIP305. State matches (the stored proposed fed is keys + format-version
cell + redeem, all identical); only the `commit_federation` event's NEW-fed
**address** diverges — rustock derives a P2SH address, rskj a P2SH-P2WSH address.

## Immediate fix (small)
`federation address for format 4000` = `Address.fromP2SHScript(createP2SHP2WSHOutputScript(redeem))`:
- witnessScript = `OP_0 PUSH32 sha256(redeem)` (34 bytes: `0x0020 || sha256(redeem)`)
- address = base58check(version 0x05, hash160(witnessScript))
Used in the commit_federation event (governance.rs) and everywhere a format-4000
fed's address/output script is derived.

## Full feature (large — like the SVP)
This proposed fed will run a full SVP again, now SEGWIT:
- SVP fund tx outputs pay the P2SH-P2WSH proposed fed + its flyover variant.
- The proposed fed's redeem is spent via **segwit**: scriptSig = just the P2WSH
  redeem push (`buildSegwitScriptSig` = `0x22 0x0020 sha256(redeem)`), witness
  carries sigs + redeem (`setSpendingBaseScriptSegwit`).
- Spend-tx unsigned hash uses `getMultiSigTransactionHashWithoutSignatures` which
  for a witness tx returns `tx.getHash()` (the legacy txid, witness-stripped).
- Signing: BIP143 segwit sighash (`hashForWitnessSignature`), not legacy.
- `addSpendingFederationBaseScript` / `calculateSvpSpendTxFees` already have the
  segwit branches in rskj (calculateSegwitTxSize).
- Once the fed activates (~40320 blocks later), ALL pegouts/migrations/pegin-change
  to it are segwit (P2SH-P2WSH output script, segwit spend).

rskj refs: PegUtils.getFlyoverFederationOutputScript (P2SH-P2WSH branch),
BitcoinUtils.setSpendingBaseScriptSegwit / buildSegwitScriptSig /
createBaseWitnessThatSpendsFromErpRedeemScript, BridgeUtils.calculateSegwitTxSize,
ReleaseTransactionBuilder (signInputs=false, isSegwitCompatible=true for fmt 4000).

## rustock status
build_committed_federation_redeem_script builds the ERP redeem for both 3000/4000
(redeem identical); the gap is the OUTPUT/ADDRESS derivation + segwit spend/sign.
No P2SH-P2WSH output-script helper or segwit sighash/signing yet.
