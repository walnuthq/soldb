//! Mock JSON-RPC servers and fixtures shared by the crate's test modules.
//!
//! Each server answers on a loopback port for a fixed number of requests, so tests never
//! need a real node and never leak a listener past the test that started it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use serde_json::json;
use soldb_core::{TraceArtifacts, TraceCapabilities, TransactionTrace};

pub(crate) fn start_trace_server(request_count: usize) -> String {
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

pub(crate) fn respond_to_rpc_request(mut stream: TcpStream) {
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
                "gas": 21000,
                "returnValue": "",
                "structLogs": [
                    {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 0, "stack": []},
                    {"pc": 2, "op": "MSTORE", "gas": 97, "gasCost": 3, "depth": 0, "memory": ["aa", "bb"]},
                    {"pc": 3, "op": "STOP", "gas": 94, "gasCost": 0, "depth": 0}
                ]
            }
        })
    } else if request.contains("\"debug_traceCall\"") {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "gas": 42000,
                "returnValue": "2a",
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

pub(crate) fn sample_transaction_trace(output: &str) -> TransactionTrace {
    TransactionTrace {
        tx_hash: Some("0xabc".to_owned()),
        from_addr: "0x1".to_owned(),
        to_addr: Some("0x2".to_owned()),
        value: "0x0".to_owned(),
        input_data: "0x".to_owned(),
        gas_used: 21_000,
        output: output.to_owned(),
        success: true,
        error: None,
        debug_trace_available: true,
        contract_address: None,
        backend: Some(output.to_owned()),
        capabilities: TraceCapabilities::default(),
        artifacts: TraceArtifacts::default(),
        steps: Vec::new(),
    }
}

pub(crate) fn read_http_request(stream: &mut TcpStream) -> String {
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

pub(crate) fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

pub(crate) fn event_log(address: &str, data_suffix: &str) -> serde_json::Value {
    json!({
        "address": address,
        "topics": ["0x3cf8b50771c17d723f2cb711ca7dadde485b222e13c84ba0730a14093fad6d5c"],
        "data": format!("0x{}{}", "0".repeat(62), data_suffix),
    })
}
