use alloy_primitives::{Address, B256, U256};
use rustock_core::{Receipt, Transaction};
use serde::Serialize;
use serde_json::Value;

use crate::helpers::{to_hex_b256, to_hex_bytes, to_hex_u256, to_hex_u64};

/// Transaction result DTO matching rskj's `TransactionResultDTO`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionDto {
    pub hash: String,
    pub nonce: String,
    pub block_hash: Value,
    pub block_number: Value,
    pub transaction_index: Value,
    pub from: String,
    pub to: Value,
    pub gas: String,
    pub gas_price: String,
    pub value: String,
    pub input: String,
    pub v: String,
    pub r: String,
    pub s: String,
    #[serde(rename = "type")]
    pub tx_type: String,
}

impl TransactionDto {
    pub fn from_tx(
        tx: &Transaction,
        tx_hash: B256,
        block_hash: Option<B256>,
        block_number: Option<u64>,
        tx_index: Option<u32>,
        sender: Address,
    ) -> Self {
        let to_value = if tx.to.is_empty() {
            Value::Null
        } else if tx.to.len() == 20 {
            Value::String(format!("{:#x}", Address::from_slice(&tx.to)))
        } else {
            Value::String(to_hex_bytes(&tx.to))
        };

        Self {
            hash: to_hex_b256(&tx_hash),
            nonce: to_hex_u256(&U256::from(tx.nonce)),
            block_hash: block_hash.map(|h| Value::String(to_hex_b256(&h))).unwrap_or(Value::Null),
            block_number: block_number.map(|n| Value::String(to_hex_u64(n))).unwrap_or(Value::Null),
            transaction_index: tx_index.map(|i| Value::String(to_hex_u64(i as u64))).unwrap_or(Value::Null),
            from: format!("{:#x}", sender),
            to: to_value,
            gas: to_hex_u256(&tx.gas_limit),
            gas_price: to_hex_u256(&tx.gas_price),
            value: to_hex_u256(&tx.value),
            input: if tx.input.is_empty() { "0x".to_string() } else { to_hex_bytes(&tx.input) },
            v: format!("0x{:02x}", tx.v),
            r: to_hex_u256(&tx.r),
            s: to_hex_u256(&tx.s),
            tx_type: "0x0".to_string(),
        }
    }
}

/// Transaction receipt DTO matching rskj's `TransactionReceiptDTO`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptDto {
    pub transaction_hash: String,
    pub transaction_index: String,
    pub block_hash: String,
    pub block_number: String,
    pub cumulative_gas_used: String,
    pub gas_used: String,
    pub contract_address: Value,
    pub logs: Vec<LogDto>,
    pub from: String,
    pub to: Value,
    pub status: String,
    pub logs_bloom: String,
    #[serde(rename = "type")]
    pub tx_type: String,
}

impl ReceiptDto {
    #[allow(clippy::too_many_arguments)]
    pub fn from_receipt(
        receipt: &Receipt,
        tx: &Transaction,
        tx_hash: B256,
        block_hash: B256,
        block_number: u64,
        tx_index: u32,
        sender: Address,
        log_index_start: u32,
    ) -> Self {
        let to_value = if tx.to.is_empty() {
            Value::Null
        } else if tx.to.len() == 20 {
            Value::String(format!("{:#x}", Address::from_slice(&tx.to)))
        } else {
            Value::String(to_hex_bytes(&tx.to))
        };

        let contract_address = if tx.to.is_empty() && receipt.status {
            let sender_bytes = sender.as_slice();
            let nonce = tx.nonce;
            let contract = compute_contract_address(sender_bytes, nonce);
            Value::String(format!("{:#x}", contract))
        } else {
            Value::Null
        };

        let logs: Vec<LogDto> = receipt.logs.iter().enumerate().map(|(i, log)| {
            LogDto::from_log(
                log,
                block_hash,
                block_number,
                tx_hash,
                tx_index,
                log_index_start + i as u32,
            )
        }).collect();

        Self {
            transaction_hash: to_hex_b256(&tx_hash),
            transaction_index: to_hex_u64(tx_index as u64),
            block_hash: to_hex_b256(&block_hash),
            block_number: to_hex_u64(block_number),
            cumulative_gas_used: to_hex_u64(receipt.cumulative_gas_used),
            gas_used: to_hex_u64(receipt.gas_used),
            contract_address,
            logs,
            from: format!("{:#x}", sender),
            to: to_value,
            status: if receipt.status { "0x1".to_string() } else { "0x0".to_string() },
            logs_bloom: to_hex_bytes(receipt.logs_bloom.as_ref()),
            tx_type: "0x0".to_string(),
        }
    }
}

/// Log DTO matching rskj's log format in receipts.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogDto {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: String,
    pub block_hash: String,
    pub transaction_hash: String,
    pub transaction_index: String,
    pub log_index: String,
    pub removed: bool,
}

impl LogDto {
    pub fn from_log(
        log: &rustock_core::Log,
        block_hash: B256,
        block_number: u64,
        tx_hash: B256,
        tx_index: u32,
        log_index: u32,
    ) -> Self {
        Self {
            address: format!("{:#x}", log.address),
            topics: log.topics.iter().map(to_hex_b256).collect(),
            data: if log.data.is_empty() { "0x".to_string() } else { to_hex_bytes(&log.data) },
            block_number: to_hex_u64(block_number),
            block_hash: to_hex_b256(&block_hash),
            transaction_hash: to_hex_b256(&tx_hash),
            transaction_index: to_hex_u64(tx_index as u64),
            log_index: to_hex_u64(log_index as u64),
            removed: false,
        }
    }
}

/// Call request object for eth_call / eth_estimateGas.
#[derive(Debug)]
pub struct CallRequest {
    pub from: Option<Address>,
    pub to: Option<Address>,
    pub gas: Option<u64>,
    pub gas_price: Option<U256>,
    pub value: Option<U256>,
    pub data: Option<Vec<u8>>,
}

impl CallRequest {
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let obj = v.as_object()?;

        let from = obj.get("from")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<Address>().ok());

        let to = obj.get("to")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<Address>().ok());

        let gas = obj.get("gas")
            .and_then(|v| v.as_str())
            .and_then(parse_hex_u64);

        let gas_price = obj.get("gasPrice")
            .and_then(|v| v.as_str())
            .and_then(parse_hex_u256);

        let value = obj.get("value")
            .and_then(|v| v.as_str())
            .and_then(parse_hex_u256);

        let data = obj.get("data")
            .or_else(|| obj.get("input"))
            .and_then(|v| v.as_str())
            .and_then(|s| {
                let s = s.strip_prefix("0x").unwrap_or(s);
                hex::decode(s).ok()
            });

        Some(Self { from, to, gas, gas_price, value, data })
    }
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

fn parse_hex_u256(s: &str) -> Option<U256> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    U256::from_str_radix(s, 16).ok()
}

fn compute_contract_address(sender: &[u8], nonce: u64) -> Address {
    use alloy_rlp::Encodable;
    use sha3::{Digest, Keccak256};

    let mut payload = Vec::new();
    sender.encode(&mut payload);
    U256::from(nonce).encode(&mut payload);

    let mut buf = Vec::new();
    alloy_rlp::Header { list: true, payload_length: payload.len() }.encode(&mut buf);
    buf.extend_from_slice(&payload);

    let hash = Keccak256::digest(&buf);
    Address::from_slice(&hash[12..])
}
