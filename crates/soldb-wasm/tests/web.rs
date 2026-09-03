//! Smoke tests for the exported bindings, run under Node.js by `wasm-pack test --node`.
//!
//! The behavior behind each export is covered natively in `pipeline`; these only prove
//! that the `wasm-bindgen` surface links and round-trips through the JavaScript ABI.
#![cfg(target_arch = "wasm32")]

use serde_json::{json, Value};
use soldb_wasm::{build_transaction_trace, trace_to_web_json, version, DebugSession};
use wasm_bindgen_test::wasm_bindgen_test;

fn canned_trace() -> String {
    let debug_trace = json!({
        "gas": 21000,
        "returnValue": "",
        "structLogs": [
            {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 1, "stack": []},
            {"pc": 2, "op": "STOP", "gas": 97, "gasCost": 0, "depth": 1}
        ]
    })
    .to_string();
    let transaction = json!({"hash": "0xabc", "from": "0x1", "to": "0x2"}).to_string();
    let receipt = json!({"gasUsed": "0x5208", "status": "0x1"}).to_string();
    build_transaction_trace(&debug_trace, &transaction, &receipt).expect("trace")
}

#[wasm_bindgen_test]
fn reports_the_workspace_version() {
    assert_eq!(version(), env!("CARGO_PKG_VERSION"));
}

#[wasm_bindgen_test]
fn builds_a_trace_and_renders_the_web_document() {
    let document: Value =
        serde_json::from_str(&trace_to_web_json(&canned_trace(), None).expect("web JSON"))
            .expect("document");

    assert_eq!(document["status"], "success");
    assert_eq!(document["steps"].as_array().map(Vec::len), Some(2));
}

#[wasm_bindgen_test]
fn steps_through_a_session() {
    let session = DebugSession::new(&canned_trace()).expect("session");

    assert_eq!(session.step_count(), 2);
    let step: Value =
        serde_json::from_str(&session.step(1).expect("step").expect("in range")).expect("step");
    assert_eq!(step["pc"], 2);
    assert_eq!(step["op"], "STOP");
    assert_eq!(session.step(2).expect("step"), None);
}

#[wasm_bindgen_test]
fn surfaces_errors_as_exceptions() {
    assert!(build_transaction_trace("{", "{}", "{}").is_err());
    assert!(DebugSession::new("not a trace").is_err());
}
