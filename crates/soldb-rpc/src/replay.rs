//! The `replay` backend's node side: fetching what a replay needs over JSON-RPC.
//!
//! The engine is `soldb_evm`'s `replay` module; this one feeds it. [`ReplayBackend`]
//! gathers a mined transaction's inputs (the transaction, its block with full transaction
//! objects, and the chain id), [`simulate_call_with_replay`] does the same for a call
//! placed on or inside a block, and [`RpcReplayStateProvider`] answers the engine's state
//! reads lazily from the node at the parent block, caching every answer. A preflight
//! reads the sender's account and one storage slot first so a node without the needed
//! state history fails with an archive hint before any opcode runs.
//!
//! Batch JSON-RPC lives here too: account reads take three requests, and one round trip
//! per account is what keeps a replay over a remote node tolerable.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use soldb_core::{SoldbError, SoldbResult, TransactionTrace};
use soldb_evm::{
    account_info_from_rpc, format_quantity, format_u256_quantity, parse_address, parse_b256,
    parse_quantity, parse_u256_quantity, replay_debug_trace_with_state, replay_simulation_trace,
    replay_transaction_trace, AccountInfo, Address, DebugTraceResult, ReplayDbError, ReplayInputs,
    ReplayStateProvider, RpcBlockHeader, RpcBlockWithTransactions, RpcReceipt, RpcTransaction,
    SimulateCallRequest, B256, U256,
};

use crate::{HttpJsonRpcClient, TransactionTraceBackend};

pub struct ReplayBackend<'a> {
    client: &'a HttpJsonRpcClient,
}

impl<'a> ReplayBackend<'a> {
    #[must_use]
    pub fn new(client: &'a HttpJsonRpcClient) -> Self {
        Self { client }
    }
}

impl TransactionTraceBackend for ReplayBackend<'_> {
    fn trace_transaction(&self, tx_hash: &str) -> SoldbResult<TransactionTrace> {
        replay_transaction_with_client(self.client, tx_hash)
    }
}

fn replay_transaction_with_client(
    client: &HttpJsonRpcClient,
    tx_hash: &str,
) -> SoldbResult<TransactionTrace> {
    let tx = client
        .request::<Option<RpcTransaction>>("eth_getTransactionByHash", json!([tx_hash]))?
        .ok_or_else(|| SoldbError::Message(format!("Transaction not found: {tx_hash}")))?;

    let receipt = client
        .request::<Option<RpcReceipt>>("eth_getTransactionReceipt", json!([tx_hash]))?
        .ok_or_else(|| SoldbError::Message(format!("Transaction receipt not found: {tx_hash}")))?;

    let debug_result = replay_debug_trace(client, &tx)?;
    replay_transaction_trace(tx, receipt, &debug_result)
}

/// Simulates a call by re-executing it locally over state read from the node, for nodes
/// that do not answer `debug_traceCall`. See [`ReplayInputs::for_call`] for where the
/// call is placed.
pub fn simulate_call_with_replay(
    client: &HttpJsonRpcClient,
    request: &SimulateCallRequest,
) -> SoldbResult<TransactionTrace> {
    let block_number = match request.block {
        Some(block) => block,
        None => {
            let latest = client.request::<String>("eth_blockNumber", json!([]))?;
            parse_quantity(&latest)?
        }
    };
    let chain_id = client
        .request::<String>("eth_chainId", json!([]))
        .and_then(|chain_id| parse_quantity(&chain_id))
        .map_err(|error| {
            SoldbError::Message(format!(
                "Replay backend preflight failed: could not read eth_chainId: {error}"
            ))
        })?;
    let block = client
        .request::<Option<RpcBlockWithTransactions>>(
            "eth_getBlockByNumber",
            json!([format_quantity(block_number), request.tx_index.is_some()]),
        )?
        .ok_or_else(|| SoldbError::Message(format!("Block {block_number} not found")))?;
    let inputs = ReplayInputs::for_call(request, block, block_number, chain_id)?;
    let provider = RpcReplayStateProvider::new(client.clone(), inputs.parent_block_tag());
    replay_preflight_parent_state(&provider, inputs.transaction())?;
    let debug_result = replay_debug_trace_with_state(&inputs, &provider)?;
    replay_simulation_trace(request, &debug_result)
}

fn replay_debug_trace(
    client: &HttpJsonRpcClient,
    tx: &RpcTransaction,
) -> SoldbResult<DebugTraceResult> {
    let inputs = fetch_replay_inputs(client, tx)?;
    let state_provider = RpcReplayStateProvider::new(client.clone(), inputs.parent_block_tag());
    replay_preflight_parent_state(&state_provider, tx)?;
    replay_debug_trace_with_state(&inputs, &state_provider)
}

/// Gathers a mined transaction's replay inputs over RPC: its chain id and the block it
/// sits in with full transaction objects.
fn fetch_replay_inputs(
    client: &HttpJsonRpcClient,
    tx: &RpcTransaction,
) -> SoldbResult<ReplayInputs> {
    let block_number = ReplayInputs::mined_block_number(tx)?;
    let chain_id = replay_chain_id(client, tx)?;
    let block = client
        .request::<Option<RpcBlockWithTransactions>>(
            "eth_getBlockByNumber",
            json!([format_quantity(block_number), true]),
        )
        .map_err(|error| {
            SoldbError::Message(format!(
                "Replay backend preflight failed: could not load block {block_number} with full transactions: {error}",
            ))
        })?
        .ok_or_else(|| SoldbError::Message(format!("Block {block_number} not found")))?;
    ReplayInputs::new(tx.clone(), block, chain_id)
}

fn replay_chain_id(client: &HttpJsonRpcClient, tx: &RpcTransaction) -> SoldbResult<u64> {
    match client.request::<String>("eth_chainId", json!([])) {
        Ok(chain_id) => parse_quantity(&chain_id).map_err(|error| {
            SoldbError::Message(format!(
                "Replay backend preflight failed: could not parse eth_chainId response {chain_id}: {error}",
            ))
        }),
        Err(error) => {
            let Some(tx_chain_id) = tx.chain_id.as_deref() else {
                return Err(SoldbError::Message(format!(
                    "Replay backend preflight failed: chain id is required, eth_chainId failed, and the transaction has no chainId. Original error: {error}",
                )));
            };
            parse_quantity(tx_chain_id).map_err(|parse_error| {
                SoldbError::Message(format!(
                    "Replay backend preflight failed: could not parse transaction chainId {tx_chain_id}: {parse_error}",
                ))
            })
        }
    }
}

fn replay_preflight_parent_state(
    provider: &RpcReplayStateProvider,
    tx: &RpcTransaction,
) -> SoldbResult<()> {
    let from = parse_address(&tx.from_addr).map_err(|error| {
        SoldbError::Message(format!(
            "Replay backend preflight failed: invalid sender address {}: {error}",
            tx.from_addr
        ))
    })?;
    provider
        .account(from)
        .map_err(|error| replay_parent_state_error("sender account", error))?;

    let storage_probe_address = if let Some(to) = tx.to.as_deref() {
        let to = parse_address(to).map_err(|error| {
            SoldbError::Message(format!(
                "Replay backend preflight failed: invalid recipient address {to}: {error}",
            ))
        })?;
        provider
            .account(to)
            .map_err(|error| replay_parent_state_error("recipient account", error))?;
        to
    } else {
        from
    };

    provider
        .storage(storage_probe_address, U256::ZERO)
        .map_err(|error| replay_parent_state_error("storage slot 0", error))?;
    Ok(())
}

fn replay_parent_state_error(context: &str, error: ReplayDbError) -> SoldbError {
    SoldbError::Message(format!(
        "Replay backend preflight failed: parent-block state is not readable while checking {context}. {error}",
    ))
}

/// Parent-block state read lazily over JSON-RPC, caching every answer.
#[derive(Debug, Clone)]
pub struct RpcReplayStateProvider {
    inner: Rc<RefCell<RpcReplayStateProviderInner>>,
}

#[derive(Debug)]
struct RpcReplayStateProviderInner {
    client: HttpJsonRpcClient,
    block_tag: String,
    accounts: HashMap<Address, AccountInfo>,
    storage: HashMap<(Address, U256), U256>,
    block_hashes: HashMap<u64, B256>,
}

impl RpcReplayStateProvider {
    #[must_use]
    pub fn new(client: HttpJsonRpcClient, block_tag: String) -> Self {
        Self {
            inner: Rc::new(RefCell::new(RpcReplayStateProviderInner {
                client,
                block_tag,
                accounts: HashMap::new(),
                storage: HashMap::new(),
                block_hashes: HashMap::new(),
            })),
        }
    }
}

impl ReplayStateProvider for RpcReplayStateProvider {
    fn account(&self, address: Address) -> Result<AccountInfo, ReplayDbError> {
        if let Some(account) = self.inner.borrow().accounts.get(&address).cloned() {
            return Ok(account);
        }

        let mut inner = self.inner.borrow_mut();
        let account = inner.fetch_account(address)?;
        inner.accounts.insert(address, account.clone());
        Ok(account)
    }

    fn storage(&self, address: Address, index: U256) -> Result<U256, ReplayDbError> {
        if let Some(value) = self.inner.borrow().storage.get(&(address, index)).copied() {
            return Ok(value);
        }

        let mut inner = self.inner.borrow_mut();
        let value = inner.fetch_storage(address, index)?;
        inner.storage.insert((address, index), value);
        Ok(value)
    }

    fn block_hash(&self, number: u64) -> Result<B256, ReplayDbError> {
        if let Some(hash) = self.inner.borrow().block_hashes.get(&number).copied() {
            return Ok(hash);
        }

        let mut inner = self.inner.borrow_mut();
        let hash = inner.fetch_block_hash(number)?;
        inner.block_hashes.insert(number, hash);
        Ok(hash)
    }
}

impl RpcReplayStateProviderInner {
    fn request_at_block<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<T, ReplayDbError> {
        self.client.request(method, params).map_err(|error| {
            ReplayDbError(format!(
                "Replay backend could not read historical state with {method} at block {}; use an archive-capable RPC endpoint or a local node with the needed state history. Original error: {error}",
                self.block_tag
            ))
        })
    }

    fn request_account_batch_at_block(
        &self,
        requests: &[(&str, Value)],
    ) -> Result<Vec<Value>, ReplayDbError> {
        self.client.request_batch_values(requests).map_err(|error| {
            ReplayDbError(format!(
                "Replay backend could not read historical account state at block {}; use an archive-capable RPC endpoint or a local node with the needed state history. Original error: {error}",
                self.block_tag
            ))
        })
    }

    fn fetch_account(&self, address: Address) -> Result<AccountInfo, ReplayDbError> {
        let address_text = address.to_string();
        let block = self.block_tag.clone();
        let results = self.request_account_batch_at_block(&[
            (
                "eth_getBalance",
                json!([address_text.clone(), block.clone()]),
            ),
            (
                "eth_getTransactionCount",
                json!([address_text.clone(), block.clone()]),
            ),
            ("eth_getCode", json!([address_text, block])),
        ])?;
        let balance: String = serde_json::from_value(results[0].clone()).map_err(|error| {
            ReplayDbError(format!(
                "Invalid eth_getBalance response for account {address}: {error}"
            ))
        })?;
        let nonce: String = serde_json::from_value(results[1].clone()).map_err(|error| {
            ReplayDbError(format!(
                "Invalid eth_getTransactionCount response for account {address}: {error}"
            ))
        })?;
        let code: String = serde_json::from_value(results[2].clone()).map_err(|error| {
            ReplayDbError(format!(
                "Invalid eth_getCode response for account {address}: {error}"
            ))
        })?;

        account_info_from_rpc(address, &balance, &nonce, &code)
    }

    fn fetch_storage(&self, address: Address, index: U256) -> Result<U256, ReplayDbError> {
        let value: String = self.request_at_block(
            "eth_getStorageAt",
            json!([
                address.to_string(),
                format_u256_quantity(index),
                self.block_tag
            ]),
        )?;
        parse_u256_quantity(&value).map_err(ReplayDbError::from)
    }

    fn fetch_block_hash(&self, number: u64) -> Result<B256, ReplayDbError> {
        let block = self
            .request_at_block::<Option<RpcBlockHeader>>(
                "eth_getBlockByNumber",
                json!([format_quantity(number), false]),
            )?
            .ok_or_else(|| ReplayDbError(format!("Block {number} not found")))?;
        let hash = block
            .hash
            .as_deref()
            .ok_or_else(|| ReplayDbError(format!("Block {number} did not include a hash")))?;
        parse_b256(hash).map_err(ReplayDbError::from)
    }
}

/// Batch JSON-RPC exists for the replay backend's state reads, which is why it lives with
/// it: the transport in the crate root sends one request at a time.
impl HttpJsonRpcClient {
    fn request_batch_values(&self, requests: &[(&str, Value)]) -> SoldbResult<Vec<Value>> {
        let payload = Value::Array(
            requests
                .iter()
                .enumerate()
                .map(|(index, (method, params))| {
                    json!({
                        "jsonrpc": "2.0",
                        "id": index + 1,
                        "method": method,
                        "params": params,
                    })
                })
                .collect(),
        );
        let method_names = requests
            .iter()
            .map(|(method, _)| *method)
            .collect::<Vec<_>>();
        let body = payload.to_string();
        let response_body = self.request_body("batch", &body)?;
        parse_json_rpc_batch_body(&method_names, &response_body)
    }
}

fn parse_json_rpc_batch_body(methods: &[&str], body: &str) -> SoldbResult<Vec<Value>> {
    let value = serde_json::from_str::<Value>(body.trim())
        .map_err(|error| SoldbError::Message(format!("Invalid JSON batch response: {error}")))?;
    let responses = value.as_array().ok_or_else(|| {
        SoldbError::Message("RPC batch response did not contain an array".to_owned())
    })?;

    let mut by_id = HashMap::<usize, Value>::new();
    for response in responses {
        let id = response.get("id").and_then(Value::as_u64).ok_or_else(|| {
            SoldbError::Message("RPC batch response missing numeric id".to_owned())
        })? as usize;
        let method = methods
            .get(id.saturating_sub(1))
            .copied()
            .unwrap_or("unknown");
        if let Some(error) = response.get("error") {
            return Err(SoldbError::Message(format!(
                "RPC method {method} returned error: {error}"
            )));
        }
        let result = response.get("result").cloned().ok_or_else(|| {
            SoldbError::Message(format!("RPC response for {method} did not contain result"))
        })?;
        by_id.insert(id, result);
    }

    (1..=methods.len())
        .map(|id| {
            by_id.remove(&id).ok_or_else(|| {
                SoldbError::Message(format!(
                    "RPC batch response did not include result for {}",
                    methods[id - 1]
                ))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    use serde_json::{json, Value};

    use soldb_evm::{parse_address, ReplayStateProvider, RpcTransaction, TraceBackend, B256, U256};

    use super::{replay_chain_id, replay_preflight_parent_state, RpcReplayStateProvider};
    use crate::test_support::{read_http_request, start_trace_server};
    use crate::{replay_backend_available, trace_transaction_with_backend, HttpJsonRpcClient};

    #[test]
    fn replay_backend_is_compiled_in_by_default() {
        assert!(replay_backend_available());
    }

    #[test]
    fn parses_json_rpc_batch_bodies_by_id() {
        let result = super::parse_json_rpc_batch_body(
            &["eth_getBalance", "eth_getCode"],
            r#"[
                {"jsonrpc":"2.0","id":2,"result":"0x6000"},
                {"jsonrpc":"2.0","id":1,"result":"0x2a"}
            ]"#,
        )
        .expect("batch result");
        assert_eq!(result, vec![json!("0x2a"), json!("0x6000")]);

        let error = super::parse_json_rpc_batch_body(
            &["eth_getBalance", "eth_getCode"],
            r#"[
                {"jsonrpc":"2.0","id":1,"result":"0x2a"},
                {"jsonrpc":"2.0","id":2,"error":{"message":"missing trie node"}}
            ]"#,
        )
        .expect_err("batch method error");
        assert!(error.to_string().contains("eth_getCode"), "{error}");
        assert!(error.to_string().contains("missing trie node"), "{error}");
    }

    fn count_method(methods: &[String], method: &str) -> usize {
        methods
            .iter()
            .filter(|entry| entry.as_str() == method)
            .count()
    }

    fn mock_rpc_transaction(hash: &str) -> RpcTransaction {
        RpcTransaction {
            hash: hash.to_owned(),
            from_addr: "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".to_owned(),
            to: Some("0x5fbdb2315678afecb367f032d93f642f64180aa3".to_owned()),
            value: "0x0".to_owned(),
            input_data: "0x".to_owned(),
            gas: Some("0x5208".to_owned()),
            gas_price: Some("0x1".to_owned()),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: Some("0x0".to_owned()),
            block_number: Some("0x1".to_owned()),
            transaction_index: Some("0x0".to_owned()),
            transaction_type: Some("0x0".to_owned()),
            chain_id: Some("0x1".to_owned()),
        }
    }

    #[test]
    fn replay_backend_requires_mined_transaction() {
        let rpc_url = start_trace_server(2);
        let error = trace_transaction_with_backend(&rpc_url, "0xabc", TraceBackend::Replay)
            .expect_err("unmined mock transaction should fail replay");

        assert!(error
            .to_string()
            .contains("Replay backend requires a mined transaction"));
    }

    #[test]
    fn replay_chain_id_requires_rpc_or_transaction_chain_id() {
        let rpc_url = start_chain_id_error_server();
        let client = HttpJsonRpcClient::new(&rpc_url).expect("client");
        let mut tx = mock_rpc_transaction("0xabc");
        tx.chain_id = None;

        let error = replay_chain_id(&client, &tx).expect_err("missing chain id should fail");
        let message = error.to_string();
        assert!(message.contains("chain id is required"), "{message}");
        assert!(message.contains("eth_chainId failed"), "{message}");
    }

    #[test]
    fn replay_chain_id_uses_transaction_chain_id_when_rpc_fails() {
        let rpc_url = start_chain_id_error_server();
        let client = HttpJsonRpcClient::new(&rpc_url).expect("client");
        let mut tx = mock_rpc_transaction("0xabc");
        tx.chain_id = Some("0x7a69".to_owned());

        assert_eq!(replay_chain_id(&client, &tx).expect("chain id"), 31_337);
    }

    #[test]
    fn replay_preflight_parent_state_reads_account_and_storage() {
        let (rpc_url, rx) = start_replay_state_server(3);
        let client = HttpJsonRpcClient::new(&rpc_url).expect("client");
        let provider = RpcReplayStateProvider::new(client, "0x10".to_owned());

        replay_preflight_parent_state(&provider, &mock_rpc_transaction("0xabc"))
            .expect("preflight");

        let methods: Vec<String> = rx.try_iter().collect();
        assert_eq!(count_method(&methods, "eth_getBalance"), 2, "{methods:?}");
        assert_eq!(
            count_method(&methods, "eth_getTransactionCount"),
            2,
            "{methods:?}"
        );
        assert_eq!(count_method(&methods, "eth_getCode"), 2, "{methods:?}");
        assert_eq!(count_method(&methods, "eth_getStorageAt"), 1, "{methods:?}");
    }

    #[test]
    fn replay_preflight_parent_state_reports_archive_hint() {
        let rpc_url = start_replay_state_error_server();
        let client = HttpJsonRpcClient::new(&rpc_url).expect("client");
        let provider = RpcReplayStateProvider::new(client, "0x10".to_owned());

        let error = replay_preflight_parent_state(&provider, &mock_rpc_transaction("0xabc"))
            .expect_err("preflight should report state access failures");
        let message = error.to_string();
        assert!(
            message.contains("parent-block state is not readable"),
            "{message}"
        );
        assert!(message.contains("sender account"), "{message}");
        assert!(message.contains("archive-capable RPC"), "{message}");
    }

    #[test]
    fn replay_state_provider_caches_account_storage_and_block_hash_reads() {
        let (rpc_url, rx) = start_replay_state_server(3);
        let client = HttpJsonRpcClient::new(&rpc_url).expect("client");
        let provider = RpcReplayStateProvider::new(client, "0x10".to_owned());
        let address = parse_address("0x5fbdb2315678afecb367f032d93f642f64180aa3").expect("address");

        provider.account(address).expect("account");
        provider.account(address).expect("cached account");
        assert_eq!(
            provider.storage(address, U256::from(1)).expect("storage"),
            U256::from(42)
        );
        assert_eq!(
            provider
                .storage(address, U256::from(1))
                .expect("cached storage"),
            U256::from(42)
        );
        assert_ne!(provider.block_hash(7).expect("block hash"), B256::ZERO);
        assert_eq!(
            provider.block_hash(7).expect("cached block hash"),
            provider.block_hash(7).expect("cached block hash again")
        );

        let methods: Vec<String> = rx.try_iter().collect();
        assert_eq!(count_method(&methods, "eth_getBalance"), 1, "{methods:?}");
        assert_eq!(
            count_method(&methods, "eth_getTransactionCount"),
            1,
            "{methods:?}"
        );
        assert_eq!(count_method(&methods, "eth_getCode"), 1, "{methods:?}");
        assert_eq!(count_method(&methods, "eth_getStorageAt"), 1, "{methods:?}");
        assert_eq!(
            count_method(&methods, "eth_getBlockByNumber"),
            1,
            "{methods:?}"
        );
    }

    #[test]
    fn replay_state_provider_reports_archive_state_hint() {
        let rpc_url = start_replay_state_error_server();
        let client = HttpJsonRpcClient::new(&rpc_url).expect("client");
        let provider = RpcReplayStateProvider::new(client, "0x10".to_owned());
        let address = parse_address("0x5fbdb2315678afecb367f032d93f642f64180aa3").expect("address");

        let error = provider
            .account(address)
            .expect_err("state read should report contextual replay failure");
        let message = error.to_string();
        assert!(message.contains("historical account state"), "{message}");
        assert!(message.contains("archive-capable RPC"), "{message}");
        assert!(message.contains("eth_getBalance"), "{message}");
        assert!(message.contains("0x10"), "{message}");
    }

    fn start_replay_state_server(request_count: usize) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind replay state server");
        let address = listener.local_addr().expect("local addr");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for _ in 0..request_count {
                let (stream, _) = listener.accept().expect("accept rpc request");
                respond_to_replay_state_request(stream, &tx);
            }
        });
        (format!("http://{address}"), rx)
    }

    fn start_replay_state_error_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind replay state error server");
        let address = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept rpc request");
            respond_to_replay_state_error_request(stream);
        });
        format!("http://{address}")
    }

    fn start_chain_id_error_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind chain id error server");
        let address = listener.local_addr().expect("local addr");
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept rpc request");
            respond_to_chain_id_error_request(stream);
        });
        format!("http://{address}")
    }

    fn respond_to_replay_state_request(mut stream: TcpStream, tx: &mpsc::Sender<String>) {
        let request = read_http_request(&mut stream);
        let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
        let payload = serde_json::from_str::<Value>(body).unwrap_or(Value::Null);
        let response = if let Some(batch) = payload.as_array() {
            Value::Array(
                batch
                    .iter()
                    .map(|item| {
                        let method = item
                            .get("method")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown");
                        tx.send(method.to_owned()).expect("record method");
                        json!({
                            "jsonrpc": "2.0",
                            "id": item.get("id").cloned().unwrap_or(json!(null)),
                            "result": replay_state_result(method),
                        })
                    })
                    .collect(),
            )
        } else {
            let method = payload
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            tx.send(method.to_owned()).expect("record method");
            json!({
                "jsonrpc": "2.0",
                "id": payload.get("id").cloned().unwrap_or(json!(1)),
                "result": replay_state_result(method)
            })
        };

        let body = response.to_string();
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(http_response.as_bytes())
            .expect("write response");
    }

    fn replay_state_result(method: &str) -> Value {
        match method {
            "eth_getBalance" => json!("0x2a"),
            "eth_getTransactionCount" => json!("0x3"),
            "eth_getCode" => json!("0x60016000"),
            "eth_getStorageAt" => json!("0x2a"),
            "eth_getBlockByNumber" => json!({
                "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "timestamp": "0x1",
                "gasLimit": "0x1c9c380",
                "baseFeePerGas": "0x1"
            }),
            _ => json!(null),
        }
    }

    fn respond_to_replay_state_error_request(mut stream: TcpStream) {
        let request = read_http_request(&mut stream);
        let body = request.split("\r\n\r\n").nth(1).unwrap_or_default();
        let payload = serde_json::from_str::<Value>(body).unwrap_or(Value::Null);
        let response = if let Some(batch) = payload.as_array() {
            Value::Array(
                batch
                    .iter()
                    .map(|item| {
                        json!({
                            "jsonrpc": "2.0",
                            "id": item.get("id").cloned().unwrap_or(json!(null)),
                            "error": {
                                "code": -32000,
                                "message": "missing trie node"
                            }
                        })
                    })
                    .collect(),
            )
        } else {
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": -32000,
                    "message": "missing trie node"
                }
            })
        };
        let body = response.to_string();
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(http_response.as_bytes())
            .expect("write response");
    }

    fn respond_to_chain_id_error_request(mut stream: TcpStream) {
        let _request = read_http_request(&mut stream);
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32601,
                "message": "method not found"
            }
        });
        let body = response.to_string();
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(http_response.as_bytes())
            .expect("write response");
    }
}
