use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::thread;

use serde_json::json;

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
    assert!(stdout.contains("Use --raw flag to see detailed instruction trace"));
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
fn simulate_without_raw_data_reports_unported_abi_encoding() {
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "simulate",
            "0x2",
            "increment(uint256)",
            "4",
            "--from",
            "0x1",
        ])
        .output()
        .expect("run soldb");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("supports --raw-data only"));
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
                "contractAddress": null
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
