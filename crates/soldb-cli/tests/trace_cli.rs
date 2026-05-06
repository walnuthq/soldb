use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use soldb_ethdebug::{event_topic, parse_event_abis};

const BALANCE_UPDATED_ABI: &str = r#"[
    {
        "type": "event",
        "name": "BalanceUpdated",
        "inputs": [
            {"name": "user", "type": "address", "indexed": true},
            {"name": "newBalance", "type": "uint256", "indexed": false}
        ]
    }
]"#;

#[test]
fn trace_json_uses_rpc_trace_data() {
    let rpc_url = start_rpc_server(3);
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "trace",
            "0xabc",
            "--rpc",
            &rpc_url,
            "--ethdebug-dir",
            "0x2:TestContract:out",
            "--json",
        ])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"status\": \"success\""));
    assert!(stdout.contains("\"traceCall\""));
    assert!(stdout.contains("\"gasUsed\": 21000"));
    assert!(stdout.contains("\"contracts\""));
}

#[test]
fn trace_raw_prints_instruction_table() {
    let rpc_url = start_rpc_server(3);
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "trace",
            "0xabc",
            "--rpc",
            &rpc_url,
            "--ethdebug-dir",
            "0x2:TestContract:out",
            "--raw",
        ])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Loading transaction"));
    assert!(stdout.contains("Contract: TestContract"));
    assert!(stdout.contains("Execution trace"));
    assert!(stdout.contains("Step | PC"));
    assert!(stdout.contains("PUSH1"));
    assert!(stdout.contains("MSTORE"));
    assert!(stdout.contains("CALLDATASIZE"));
}

#[test]
fn trace_summary_prints_status_and_step_count() {
    let rpc_url = start_rpc_server(3);
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args(["trace", "0xabc", "--rpc", &rpc_url])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Transaction 0xabc"));
    assert!(stdout.contains("Status: SUCCESS"));
    assert!(stdout.contains("Gas used: 21000"));
    assert!(stdout.contains("Steps: 4"));
}

#[test]
fn simulate_json_uses_debug_trace_call() {
    let rpc_url = start_rpc_server(1);
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "simulate",
            "0x2",
            "--from",
            "0x1",
            "--rpc",
            &rpc_url,
            "--ethdebug-dir",
            "0x2:TestContract:out",
            "--raw-data",
            "0x7cf5dab00000000000000000000000000000000000000000000000000000000000000004",
            "--json",
        ])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"status\": \"success\""));
    assert!(stdout.contains("\"type\": \"ENTRY\""));
    assert!(stdout.contains("\"callId\": 0"));
    assert!(stdout.contains("\"function_name\": \"increment\""));
    assert!(stdout.contains("\"isVerified\": false"));
}

#[test]
fn simulate_json_encodes_static_abi_call() {
    let rpc_url = start_rpc_server(1);
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "simulate",
            "0x2",
            "increment(uint256)",
            "4",
            "--from",
            "0x1",
            "--rpc",
            &rpc_url,
            "--ethdebug-dir",
            "0x2:TestContract:out",
            "--json",
        ])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains(
        "\"input\": \"0x7cf5dab00000000000000000000000000000000000000000000000000000000000000004\""
    ));
    assert!(stdout.contains("\"function_name\": \"increment(uint256)\""));
}

#[test]
fn simulate_raw_data_prints_call_summary() {
    let rpc_url = start_rpc_server(1);
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "simulate",
            "0x2",
            "--from",
            "0x1",
            "--rpc",
            &rpc_url,
            "--ethdebug-dir",
            "0x2:TestContract:out",
            "--raw-data",
            "0x7cf5dab00000000000000000000000000000000000000000000000000000000000000004",
        ])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Contract: TestContract"));
    assert!(stdout.contains("Function Call Trace:"));
    assert!(stdout.contains("Gas used: 42000"));
    assert!(stdout.contains("Call Stack:"));
    assert!(stdout.contains("#0 TestContract::runtime_dispatcher"));
    assert!(stdout.contains("#1 increment"));
    assert!(stdout.contains("amount: 4"));
    assert!(stdout.contains("increment2 [internal]"));
    assert!(stdout.contains("increment3 [internal]"));
    assert!(stdout.contains("Use --raw flag to see detailed instruction trace"));
}

#[test]
fn simulate_abi_call_prints_call_summary() {
    let rpc_url = start_rpc_server(1);
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "simulate",
            "0x2",
            "increment(uint256)",
            "4",
            "--from",
            "0x1",
            "--rpc",
            &rpc_url,
            "--ethdebug-dir",
            "0x2:TestContract:out",
        ])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Contract: TestContract"));
    assert!(stdout.contains("#1 increment"));
    assert!(stdout.contains("amount: 4"));
    assert!(stdout.contains("increment2 [internal]"));
    assert!(stdout.contains("increment3 [internal]"));
}

#[test]
fn simulate_raw_prints_instruction_table() {
    let rpc_url = start_rpc_server(1);
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "simulate",
            "0x2",
            "--from",
            "0x1",
            "--rpc",
            &rpc_url,
            "--ethdebug-dir",
            "0x2:TestContract:out",
            "--raw-data",
            "0x7cf5dab00000000000000000000000000000000000000000000000000000000000000004",
            "--raw",
        ])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Simulating call to 0x2"));
    assert!(stdout.contains("Contract: TestContract"));
    assert!(stdout.contains("Execution trace"));
    assert!(stdout.contains("Step | PC"));
    assert!(stdout.contains("CALLDATASIZE"));
}

#[test]
fn simulate_abi_call_validates_argument_count_before_rpc() {
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args(["simulate", "0x2", "increment(uint256)", "--from", "0x1"])
        .output()
        .expect("run soldb");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("Function increment(uint256) expects 1 arguments, got 0"));
}

#[test]
fn simulate_abi_call_reports_unsupported_dynamic_types_before_rpc() {
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args(["simulate", "0x2", "set(string)", "hi", "--from", "0x1"])
        .output()
        .expect("run soldb");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("ABI encoding for type 'string' is not ported yet"));
}

#[test]
fn list_events_prints_raw_receipt_logs() {
    let rpc_url = start_rpc_server(1);
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args(["list-events", "0xabc", "--rpc", &rpc_url])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Events emitted in Transaction:"));
    assert!(stdout.contains("Event #1: Contract Address: 0x2"));
    assert!(stdout
        .contains("topic: 0x3cf8b50771c17d723f2cb711ca7dadde485b222e13c84ba0730a14093fad6d5c"));
    assert!(
        stdout.contains("data: 0x0000000000000000000000000000000000000000000000000000000000000004")
    );
}

#[test]
fn list_events_json_prints_receipt_logs() {
    let rpc_url = start_rpc_server(1);
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args(["list-events", "0xabc", "--rpc", &rpc_url, "--json-events"])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"transaction_hash\": \"0xabc\""));
    assert!(stdout.contains("\"events\""));
    assert!(stdout.contains("\"index\": 0"));
    assert!(stdout.contains("\"address\": \"0x2\""));
    assert!(stdout.contains(
        "\"signature\": \"0x3cf8b50771c17d723f2cb711ca7dadde485b222e13c84ba0730a14093fad6d5c\""
    ));
    assert!(stdout.contains("\"total_events\": 3"));
}

#[test]
fn list_events_decodes_known_abi_logs() {
    let (abi_dir, ethdebug_spec) = write_balance_updated_abi();
    let rpc_url = start_decoded_event_rpc_server();
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "list-events",
            "0xabc",
            "--rpc",
            &rpc_url,
            "--ethdebug-dir",
            &ethdebug_spec,
            "--multi-contract",
        ])
        .output()
        .expect("run soldb");
    fs::remove_dir_all(abi_dir).ok();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Event #1: TestContract::BalanceUpdated(address,uint256)"));
    assert!(stdout.contains("user: 0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266 (address)"));
    assert!(stdout.contains("newBalance: 99 (uint256)"));
}

#[test]
fn list_events_json_decodes_known_abi_logs() {
    let (abi_dir, ethdebug_spec) = write_balance_updated_abi();
    let rpc_url = start_decoded_event_rpc_server();
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "list-events",
            "0xabc",
            "--rpc",
            &rpc_url,
            "--ethdebug-dir",
            &ethdebug_spec,
            "--multi-contract",
            "--json-events",
        ])
        .output()
        .expect("run soldb");
    fs::remove_dir_all(abi_dir).ok();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("\"event\": \"BalanceUpdated\""));
    assert!(stdout.contains("\"signature\": \"BalanceUpdated(address,uint256)\""));
    assert!(stdout.contains("\"contract_name\": \"TestContract\""));
    assert!(stdout.contains("\"name\": \"user\""));
    assert!(stdout.contains("\"value\": \"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\""));
    assert!(stdout.contains("\"name\": \"newBalance\""));
    assert!(stdout.contains("\"value\": 99"));
    assert!(stdout.contains("\"total_events\": 1"));
}

#[test]
fn list_contracts_reports_no_contract_calls() {
    let rpc_url = start_rpc_server(3);
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args(["list-contracts", "0xabc", "--rpc", &rpc_url])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Looking for contracts in transaction: 0xabc"));
    assert!(stdout.contains("Contracts detected in transaction:"));
    assert!(stdout.contains("No contract calls detected in this transaction."));
}

#[test]
fn list_contracts_prints_call_targets() {
    let rpc_url = start_contract_call_rpc_server();
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args(["list-contracts", "0xabc", "--rpc", &rpc_url])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let expected_address = format!("Contract Address: 0x{}aa", "0".repeat(38));
    assert!(stdout.contains(&expected_address));
    assert!(stdout.contains("Gas: 90"));
    assert!(!stdout.contains("No contract calls detected"));
}

fn start_contract_call_rpc_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind rpc server");
    let address = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        for _ in 0..3 {
            let (stream, _) = listener.accept().expect("accept rpc request");
            respond_to_contract_call_rpc_request(stream);
        }
    });
    format!("http://{address}")
}

fn start_decoded_event_rpc_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind rpc server");
    let address = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept rpc request");
        respond_to_decoded_event_rpc_request(stream);
    });
    format!("http://{address}")
}

fn start_rpc_server(request_count: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind rpc server");
    let address = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        for _ in 0..request_count {
            let (stream, _) = listener.accept().expect("accept rpc request");
            respond_to_rpc_request(stream);
        }
    });
    format!("http://{address}")
}

fn respond_to_rpc_request(mut stream: TcpStream) {
    let request = read_http_request(&mut stream);
    let response = if request.contains("\"eth_getTransactionByHash\"") {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "hash": "0xabc",
                "from": "0x1",
                "to": "0x2",
                "value": "0x0",
                "input": "0x1234"
            }
        })
    } else if request.contains("\"eth_getTransactionReceipt\"") {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "gasUsed": "0x5208",
                "status": "0x1",
                "contractAddress": null,
                "logs": [
                    event_log("0x2", "04"),
                    event_log("0x2", "05"),
                    event_log("0x2", "06")
                ]
            }
        })
    } else if request.contains("\"debug_traceTransaction\"") {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "returnValue": "",
                "structLogs": [
                    {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 0, "stack": []},
                    {"pc": 2, "op": "MSTORE", "gas": 97, "gasCost": 3, "depth": 0, "memory": ["aa", "bb"]},
                    {"pc": 3, "op": "CALLDATASIZE", "gas": 94, "gasCost": 2, "depth": 0, "stack": ["0x01"]},
                    {"pc": 4, "op": "STOP", "gas": 92, "gasCost": 0, "depth": 0}
                ]
            }
        })
    } else if request.contains("\"debug_traceCall\"") {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "gas": 42000,
                "returnValue": "",
                "failed": false,
                "structLogs": [
                    {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 0, "stack": []},
                    {"pc": 1, "op": "CALLDATASIZE", "gas": 97, "gasCost": 2, "depth": 0, "stack": ["0x01"]},
                    {"pc": 2, "op": "STOP", "gas": 95, "gasCost": 0, "depth": 0}
                ]
            }
        })
    } else {
        json!({"jsonrpc": "2.0", "id": 1, "error": {"message": "unknown method"}})
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

fn respond_to_decoded_event_rpc_request(mut stream: TcpStream) {
    let request = read_http_request(&mut stream);
    let response = if request.contains("\"eth_getTransactionReceipt\"") {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "gasUsed": "0x5208",
                "status": "0x1",
                "contractAddress": null,
                "transactionHash": "0xabc",
                "logs": [
                    decoded_balance_updated_log()
                ]
            }
        })
    } else {
        json!({"jsonrpc": "2.0", "id": 1, "error": {"message": "unknown method"}})
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

fn respond_to_contract_call_rpc_request(mut stream: TcpStream) {
    let request = read_http_request(&mut stream);
    let call_target = format!("0x{}aa", "0".repeat(62));
    let response = if request.contains("\"eth_getTransactionByHash\"") {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "hash": "0xabc",
                "from": "0x1",
                "to": "0x2",
                "value": "0x0",
                "input": "0x1234"
            }
        })
    } else if request.contains("\"eth_getTransactionReceipt\"") {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "gasUsed": "0x5208",
                "status": "0x1",
                "contractAddress": null,
                "logs": []
            }
        })
    } else if request.contains("\"debug_traceTransaction\"") {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "returnValue": "",
                "structLogs": [
                    {
                        "pc": 0,
                        "op": "CALL",
                        "gas": 90,
                        "gasCost": 700,
                        "depth": 0,
                        "stack": ["0x0", call_target, "0x0"]
                    },
                    {"pc": 1, "op": "STOP", "gas": 0, "gasCost": 0, "depth": 0}
                ]
            }
        })
    } else {
        json!({"jsonrpc": "2.0", "id": 1, "error": {"message": "unknown method"}})
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

fn event_log(address: &str, data_suffix: &str) -> serde_json::Value {
    json!({
        "address": address,
        "topics": ["0x3cf8b50771c17d723f2cb711ca7dadde485b222e13c84ba0730a14093fad6d5c"],
        "data": format!("0x{}{}", "0".repeat(62), data_suffix),
    })
}

fn decoded_balance_updated_log() -> serde_json::Value {
    json!({
        "address": "0x2",
        "topics": [
            balance_updated_topic(),
            format!("0x{}f39fd6e51aad88f6f4ce6ab8827279cfffb92266", "0".repeat(24))
        ],
        "data": format!("0x{:064x}", 99),
    })
}

fn write_balance_updated_abi() -> (PathBuf, String) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("soldb-cli-abi-{unique}"));
    fs::create_dir_all(&dir).expect("create abi dir");
    fs::write(dir.join("TestContract.abi"), BALANCE_UPDATED_ABI).expect("write abi");
    let spec = format!("0x2:TestContract:{}", dir.display());
    (dir, spec)
}

fn balance_updated_topic() -> String {
    let event = parse_event_abis(BALANCE_UPDATED_ABI)
        .expect("parse abi")
        .remove(0);
    event_topic(&event)
}

fn read_http_request(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        let read = stream.read(&mut buffer).expect("read request");
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);

        if let Some(header_end) = find_header_end(&data) {
            let headers = String::from_utf8_lossy(&data[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let body_len = data.len().saturating_sub(header_end + 4);
            if body_len >= content_length {
                break;
            }
        }
    }
    String::from_utf8(data).expect("utf8 request")
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}
