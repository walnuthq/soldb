//! Smoke tests for the exported bindings, run under Node.js by `wasm-pack test --node`.
//!
//! The behavior behind each export is covered natively in `pipeline`; these prove that
//! the `wasm-bindgen` surface links, that the handle survives across calls, that values
//! round-trip through the JavaScript ABI, and that the package links no REVM.
#![cfg(target_arch = "wasm32")]

use serde_json::{json, Value};
use soldb_wasm::{replay_available, version, Trace};
use wasm_bindgen_test::wasm_bindgen_test;

const SOURCE: &str =
    "contract Counter {\n    function increment() public {\n        count += 1;\n    }\n}\n";

fn canned_trace() -> Trace {
    let debug_trace = json!({
        "gas": 21000,
        "returnValue": "",
        "structLogs": [
            {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 1, "stack": []},
            {"pc": 2, "op": "MSTORE", "gas": 97, "gasCost": 3, "depth": 1, "stack": ["0x80", "0x40"]},
            {"pc": 3, "op": "STOP", "gas": 94, "gasCost": 0, "depth": 1}
        ]
    })
    .to_string();
    let transaction = json!({"hash": "0xabc", "from": "0x1", "to": "0x2"}).to_string();
    let receipt = json!({"gasUsed": "0x5208", "status": "0x1"}).to_string();
    Trace::from_transaction(&debug_trace, &transaction, &receipt).expect("trace")
}

fn artifacts() -> Value {
    let statement = SOURCE.find("count += 1").expect("offset");
    json!({
        "name": "Counter",
        "metadata": {"compilation": {"sources": [{"id": 0, "path": "Counter.sol", "contents": SOURCE}]}},
        "program": {
            "instructions": [
                {
                    "offset": 2,
                    "operation": {"mnemonic": "MSTORE"},
                    "context": {
                        "code": {"source": {"id": 0}, "range": {"offset": statement, "length": 10}},
                        "variables": [
                            {"name": "count", "type": "uint256", "location": {"type": "stack", "offset": 1}}
                        ]
                    }
                }
            ]
        },
        "abi": [{"type": "function", "name": "increment", "inputs": [], "outputs": []}]
    })
}

fn parse(json: &str) -> Value {
    serde_json::from_str(json).expect("JSON")
}

#[wasm_bindgen_test]
fn reports_the_workspace_version() {
    assert_eq!(version(), env!("CARGO_PKG_VERSION"));
}

#[cfg(not(feature = "replay"))]
#[wasm_bindgen_test]
fn the_lean_package_links_without_the_replay_backend() {
    // The lean package's size rests on this: REVM is only reachable through the
    // `replay` feature, which `make wasm-lean` leaves off.
    assert!(!soldb_rpc::replay_backend_available());
    assert!(!replay_available());
}

#[cfg(feature = "replay")]
#[wasm_bindgen_test]
fn the_replay_package_reports_the_backend() {
    assert!(soldb_rpc::replay_backend_available());
    assert!(replay_available());
}

#[cfg(feature = "replay")]
#[wasm_bindgen_test]
fn replays_a_transaction_from_host_supplied_state() {
    use soldb_wasm::Replay;

    const SENDER: &str = "0x1111111111111111111111111111111111111111";
    const COUNTER: &str = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
    // PUSH1 0 BLOCKHASH POP  PUSH1 0 SLOAD PUSH1 1 ADD PUSH1 0 SSTORE  STOP.
    const COUNTER_CODE: &str = "0x6000405060005460010160005500";

    let transaction = json!({
        "hash": "0xaaa", "from": SENDER, "to": COUNTER, "value": "0x0", "input": "0x",
        "gas": "0x186a0", "gasPrice": "0x1", "nonce": "0x0", "blockNumber": "0x1",
        "transactionIndex": "0x0", "type": "0x0", "chainId": "0x7a69"
    });
    let block = json!({
        "hash": format!("0x{}", "11".repeat(32)), "timestamp": "0x64",
        "gasLimit": "0x1c9c380", "baseFeePerGas": "0x0",
        "mixHash": format!("0x{}", "33".repeat(32)), "transactions": [transaction]
    });
    let receipt = json!({"gasUsed": "0x5208", "status": "0x1"});
    // What the host's node would answer, keyed the way requests arrive.
    let world = json!({
        "accounts": {
            SENDER: {"balance": "0xde0b6b3a7640000", "nonce": "0x0", "code": "0x"},
            COUNTER: {"balance": "0x0", "nonce": "0x1", "code": COUNTER_CODE}
        },
        "storage": {COUNTER: {"0x0": "0x29"}},
        "blockHashes": {"0": format!("0x{}", "22".repeat(32))}
    });

    let mut replay = Replay::prepare(
        &transaction.to_string(),
        &receipt.to_string(),
        &block.to_string(),
        "0x7a69",
    )
    .expect("prepared");

    // The host loop: answer whatever the module asks for until it completes.
    let mut status = parse(&replay.status().expect("status"));
    let mut runs = 0;
    while status["status"] != "complete" {
        assert_eq!(status["status"], "needsState");
        assert_eq!(status["block"], "0x0");
        let mut batch = json!({"accounts": {}, "storage": {}, "blockHashes": {}});
        for request in status["requests"].as_array().expect("requests") {
            let kind = request["kind"].as_str().expect("kind");
            match kind {
                "account" => {
                    let address = request["address"].as_str().expect("address");
                    batch["accounts"][address] = world["accounts"]
                        .get(address)
                        .cloned()
                        .unwrap_or(json!({"balance": "0x0", "nonce": "0x0", "code": "0x"}));
                }
                "storage" => {
                    let address = request["address"].as_str().expect("address");
                    let slot = request["slot"].as_str().expect("slot");
                    if batch["storage"].get(address).is_none() {
                        batch["storage"][address] = json!({});
                    }
                    batch["storage"][address][slot] = world["storage"][address]
                        .get(slot)
                        .cloned()
                        .unwrap_or(json!("0x0"));
                }
                "blockHash" => {
                    let number = request["number"].to_string();
                    batch["blockHashes"][&number] = world["blockHashes"][&number].clone();
                }
                other => panic!("unexpected request kind {other}"),
            }
        }
        replay.provide_state(&batch.to_string()).expect("provide");
        status = parse(&replay.run().expect("run"));
        runs += 1;
        assert!(runs < 10, "did not converge");
    }
    assert_eq!(runs, 2);
    assert!(replay.is_complete());

    let trace = replay.finish().expect("trace");
    assert_eq!(trace.step_count(), 10);
    let summary = parse(&trace.summary().expect("summary"));
    assert_eq!(summary["backend"], "replay");
    assert_eq!(summary["success"], true);
    let sstore = parse(&trace.step(8).expect("step").expect("in range"));
    assert_eq!(sstore["op"], "SSTORE");
    assert_eq!(sstore["snapshot"]["storage"]["0x0"], "0x2a");
}

#[cfg(feature = "replay")]
#[wasm_bindgen_test]
fn replay_surfaces_errors_as_exceptions() {
    use soldb_wasm::Replay;
    assert!(Replay::prepare("{", "{}", "{}", "0x1").is_err());
    // Participants must be real addresses: seeding rejects a malformed sender.
    assert!(Replay::prepare(
        &json!({"hash": "0xaaa", "from": "0x1", "to": "0x2", "blockNumber": "0x1"}).to_string(),
        &json!({"gasUsed": "0x0"}).to_string(),
        &json!({"timestamp": "0x0", "gasLimit": "0x0", "transactions": [{"hash": "0xaaa", "from": "0x1", "to": "0x2", "blockNumber": "0x1"}]}).to_string(),
        "0x1",
    )
    .is_err());

    let sender = format!("0x{}", "11".repeat(20));
    let recipient = format!("0x{}", "22".repeat(20));
    let transaction =
        json!({"hash": "0xaaa", "from": sender, "to": recipient, "blockNumber": "0x1"});
    let block = json!({"timestamp": "0x0", "gasLimit": "0x0", "transactions": [transaction]});
    let mut replay = Replay::prepare(
        &transaction.to_string(),
        &json!({"gasUsed": "0x0"}).to_string(),
        &block.to_string(),
        "0x1",
    )
    .expect("prepared");
    assert!(!replay.is_complete());
    assert!(replay.provide_state("not a batch").is_err());
    assert!(replay.finish().is_err());
}

#[wasm_bindgen_test]
fn steps_through_a_trace_held_in_memory() {
    let trace = canned_trace();

    assert_eq!(trace.step_count(), 3);
    assert!(!trace.has_ethdebug());
    let step = parse(&trace.step(1).expect("step").expect("in range"));
    assert_eq!(step["pc"], 2);
    assert_eq!(step["op"], "MSTORE");
    assert_eq!(step["snapshot"]["stack"], json!(["0x80", "0x40"]));
    assert_eq!(step["source"], Value::Null);
    assert_eq!(trace.step(3).expect("step"), None);
}

#[wasm_bindgen_test]
fn attaches_debug_info_and_keeps_the_trace() {
    let mut trace = canned_trace();
    trace
        .attach_ethdebug(&artifacts().to_string())
        .expect("attach");

    assert!(trace.has_ethdebug());
    assert_eq!(trace.step_count(), 3);
    let step = parse(&trace.step(1).expect("step").expect("in range"));
    assert_eq!(step["source"]["path"], "Counter.sol");
    assert_eq!(step["source"]["line"], 3);
    assert_eq!(step["function"]["name"], "increment");
    assert_eq!(step["variables"][0]["name"], "count");
    assert_eq!(step["variables"][0]["value"]["display"], "64");

    let summary = parse(&trace.summary().expect("summary"));
    assert_eq!(summary["txHash"], "0xabc");
    assert_eq!(summary["stepCount"], 3);
    assert_eq!(summary["debugInfo"]["contract"], "Counter");
    assert_eq!(summary["debugInfo"]["pcsWithVariables"], 1);
}

#[wasm_bindgen_test]
fn renders_the_web_documents() {
    let trace = canned_trace();

    let document = parse(&trace.to_web_json(None).expect("web JSON"));
    assert_eq!(document["status"], "success");
    assert_eq!(document["steps"].as_array().map(Vec::len), Some(3));
    assert_eq!(document["contracts"], json!({}));

    let contracts = json!({"0xAbC": artifacts()}).to_string();
    let document = parse(
        &trace
            .to_web_json(Some(contracts.clone()))
            .expect("web JSON"),
    );
    let contract = &document["contracts"]["0xabc"];
    assert_eq!(contract["debugAvailable"], true);
    assert_eq!(contract["sources"]["0"], SOURCE);
    assert_eq!(contract["abi"][0]["name"], "increment");

    let document = parse(
        &trace
            .to_simulation_web_json("increment", Some(contracts))
            .expect("web JSON"),
    );
    assert_eq!(document["function_name"], "increment");
    assert_eq!(document["contracts"]["0xabc"]["debugAvailable"], true);
}

#[wasm_bindgen_test]
fn round_trips_trace_json_and_builds_simulations() {
    let trace = canned_trace();
    let reloaded = Trace::from_json(&trace.to_json().expect("json")).expect("reloaded");
    assert_eq!(reloaded.step_count(), trace.step_count());
    assert_eq!(
        reloaded.to_json().expect("json"),
        trace.to_json().expect("json")
    );

    let debug_trace = json!({"gas": 7, "returnValue": "2a", "structLogs": []}).to_string();
    let simulation =
        Trace::from_simulation("0x1", "0x2", "0x1234", "1ether", &debug_trace).expect("simulation");
    let summary = parse(&simulation.summary().expect("summary"));
    assert_eq!(summary["txHash"], Value::Null);
    assert_eq!(summary["value"], "0xde0b6b3a7640000");
    assert_eq!(summary["output"], "0x2a");
    assert_eq!(summary["gasUsed"], 7);
}

#[wasm_bindgen_test]
fn surfaces_errors_as_exceptions() {
    assert!(Trace::from_transaction("{", "{}", "{}").is_err());
    assert!(Trace::from_simulation("0x1", "0x2", "0x", "0x0", "nope").is_err());
    assert!(Trace::from_json("not a trace").is_err());
    let mut trace = canned_trace();
    assert!(trace.attach_ethdebug("not artifacts").is_err());
    assert!(trace.to_web_json(Some("[1]".to_owned())).is_err());
}
