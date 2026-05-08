use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;
use soldb_ethdebug::{encode_function_call, event_topic, parse_event_abis};

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
fn help_and_version_are_served_by_rust_cli() {
    let help = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .arg("--help")
        .output()
        .expect("run soldb help");
    assert!(help.status.success());
    let stdout = String::from_utf8(help.stdout).expect("utf8 help");
    assert!(stdout.contains("SolDB - Ethereum transaction analysis tool"));
    assert!(stdout.contains("trace"));
    assert!(stdout.contains("simulate"));
    assert!(stdout.contains("list-events"));

    let version = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .arg("--version")
        .output()
        .expect("run soldb version");
    assert!(version.status.success());
    let stdout = String::from_utf8(version.stdout).expect("utf8 version");
    assert!(stdout.contains("soldb 0.1.0"));
}

#[test]
fn missing_command_reports_clap_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .output()
        .expect("run soldb without command");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("Usage:"));
    assert!(stderr.contains("<COMMAND>"));
}

#[test]
fn bridge_invalid_host_reports_start_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "bridge",
            "--host",
            "999.999.999.999",
            "--port",
            "8765",
            "--json",
        ])
        .output()
        .expect("run soldb");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(stderr.contains("Error starting bridge server:"));
}

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
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("trace json");
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["traceCall"]["callId"], 0);
    assert_eq!(value["steps"][0]["traceCallIndex"], 0);
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
fn trace_interactive_accepts_repl_commands() {
    let rpc_url = start_rpc_server(3);
    let output = run_with_stdin(
        Command::new(env!("CARGO_BIN_EXE_soldb")).args([
            "trace",
            "0xabc",
            "--rpc",
            &rpc_url,
            "--interactive",
        ]),
        "nexti\nbreak 3\ncontinue\nq\n",
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Transaction trace debugger"));
    assert!(stdout.contains("Loaded trace with 4 steps"));
    assert!(stdout.contains("Step 1/3 | PC 2 | MSTORE | gas 97"));
    assert!(stdout.contains("Breakpoint set at PC 3"));
    assert!(stdout.contains("Breakpoint hit at step 2, PC 3"));
    assert!(stdout.contains("Exiting debugger."));
}

#[test]
fn simulate_json_labels_raw_data_without_metadata() {
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
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("simulate json");
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["traceCall"]["callId"], 0);
    assert_eq!(value["traceCall"]["functionName"], "raw_data");
    assert_eq!(value["steps"][0]["traceCallIndex"], 0);
    assert!(stdout.contains("\"status\": \"success\""));
    assert!(stdout.contains("\"type\": \"ENTRY\""));
    assert!(stdout.contains("\"callId\": 0"));
    assert!(stdout.contains("\"function_name\": \"raw_data\""));
    assert!(stdout.contains("\"isVerified\": false"));
}

#[test]
fn simulate_interactive_accepts_repl_commands() {
    let rpc_url = start_rpc_server(1);
    let output = run_with_stdin(
        Command::new(env!("CARGO_BIN_EXE_soldb")).args([
            "simulate",
            "0x2",
            "--from",
            "0x1",
            "--rpc",
            &rpc_url,
            "--raw-data",
            "0x7cf5dab00000000000000000000000000000000000000000000000000000000000000004",
            "--interactive",
        ]),
        "nexti\nmode asm\nq\n",
    );

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Simulation debugger"));
    assert!(stdout.contains("Loaded trace with 3 steps"));
    assert!(stdout.contains("Step 1/2 | PC 1 | CALLDATASIZE | gas 97"));
    assert!(stdout.contains("Mode: asm"));
    assert!(stdout.contains("Exiting debugger."));
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
fn simulate_json_encodes_dynamic_array_abi_call() {
    let rpc_url = start_rpc_server(1);
    let expected_input =
        encode_function_call("set(uint256[])", &["[1,2,3]".to_owned()]).expect("calldata");
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "simulate",
            "0x2",
            "set(uint256[])",
            "[1,2,3]",
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
    assert!(stdout.contains(&format!("\"input\": \"{expected_input}\"")));
    assert!(stdout.contains("\"function_name\": \"set(uint256[])\""));
}

#[test]
#[cfg(unix)]
fn compile_verify_version_json_uses_rust_compiler_path() {
    let temp = temp_dir("compile-version");
    let solc = fake_solc(&temp);
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "compile",
            "--verify-version",
            "--solc-path",
            &solc.to_string_lossy(),
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
    assert!(stdout.contains("\"supported\": true"));
    assert!(stdout.contains("\"version\": \"0.8.31\""));
}

#[test]
#[cfg(unix)]
fn compile_solidity_contract_writes_ethdebug_outputs() {
    let temp = temp_dir("compile-contract");
    let solc = fake_solc(&temp);
    let contract = temp.join("Counter.sol");
    fs::write(&contract, "contract Counter {}").expect("write contract");
    let out = temp.join("out");
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "compile",
            &contract.to_string_lossy(),
            "--solc-path",
            &solc.to_string_lossy(),
            "--output-dir",
            &out.to_string_lossy(),
        ])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("ETHDebug compilation successful"));
    assert!(out.join("Counter.abi").exists());
    assert!(out.join("Counter.bin").exists());
    assert!(out.join("Counter_ethdebug.json").exists());
}

#[test]
#[cfg(unix)]
fn simulate_auto_deploys_solidity_file_before_trace_call() {
    let temp = temp_dir("simulate-auto-deploy");
    let solc = fake_solc(&temp);
    let contract = temp.join("Counter.sol");
    fs::write(
        &contract,
        "contract Counter { function set(uint256 n) public {} }",
    )
    .expect("write contract");
    let out = temp.join("out");
    let rpc_url = start_auto_deploy_rpc_server();

    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "simulate",
            "--from",
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            &contract.to_string_lossy(),
            "set(uint256)",
            "7",
            "--rpc-url",
            &rpc_url,
            "--solc-path",
            &solc.to_string_lossy(),
            "--output-dir",
            &out.to_string_lossy(),
        ])
        .output()
        .expect("run soldb");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Deployed Counter at 0x5fbdb2315678afecb367f032d93f642f64180aa3"));
    assert!(stdout.contains("Contract: Counter"));
    assert!(stdout.contains("Function Call Trace:"));
    assert!(out.join("deployment.json").exists());
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
    assert!(!stdout.contains("#1 increment"));
    assert!(!stdout.contains("increment2 [internal]"));
    assert!(!stdout.contains("increment3 [internal]"));
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
    assert!(stdout.contains("arg0: 4"));
    assert!(!stdout.contains("increment2 [internal]"));
    assert!(!stdout.contains("increment3 [internal]"));
}

#[test]
fn simulate_summary_prints_raw_word_for_unsupported_abi_arg() {
    let rpc_url = start_rpc_server(1);
    let (_abi_dir, ethdebug_spec) = write_function_abi(
        "TestContract",
        r#"[{"type":"function","name":"set","inputs":[{"name":"value","type":"string"}]}]"#,
    );
    let calldata = encode_function_call("set(string)", &["hi".to_owned()]).expect("calldata");
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "simulate",
            "0x2",
            "--from",
            "0x1",
            "--rpc",
            &rpc_url,
            "--ethdebug-dir",
            &ethdebug_spec,
            "--raw-data",
            &calldata,
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
    assert!(stdout.contains("#1 set"));
    assert!(stdout
        .contains("value raw: 0x0000000000000000000000000000000000000000000000000000000000000020"));
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
fn simulate_json_encodes_dynamic_abi_call() {
    let rpc_url = start_rpc_server(1);
    let expected_input = encode_function_call("set(string)", &["hi".to_owned()]).expect("calldata");
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "simulate",
            "0x2",
            "set(string)",
            "hi",
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
    assert!(stdout.contains(&format!("\"input\": \"{expected_input}\"")));
    assert!(stdout.contains("\"function_name\": \"set(string)\""));
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
fn list_events_decodes_abi_from_deployment_json_path() {
    let abi_dir = write_balance_updated_deployment_dir();
    let rpc_url = start_decoded_event_rpc_server();
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "list-events",
            "0xabc",
            "--rpc",
            &rpc_url,
            "--ethdebug-dir",
            &abi_dir.to_string_lossy(),
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
    assert!(stdout.contains("newBalance: 99 (uint256)"));
}

#[test]
fn list_events_decodes_abi_from_contract_mapping_file() {
    let (abi_dir, mapping_file) = write_balance_updated_contract_mapping();
    let rpc_url = start_decoded_event_rpc_server();
    let output = Command::new(env!("CARGO_BIN_EXE_soldb"))
        .args([
            "list-events",
            "0xabc",
            "--rpc",
            &rpc_url,
            "--contracts",
            &mapping_file.to_string_lossy(),
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
    assert!(stdout.contains("\"contract_name\": \"TestContract\""));
    assert!(stdout.contains("\"signature\": \"BalanceUpdated(address,uint256)\""));
    assert!(stdout.contains("\"value\": 99"));
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

fn run_with_stdin(command: &mut Command, input: &str) -> std::process::Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn soldb");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait for soldb")
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

#[cfg(unix)]
fn start_auto_deploy_rpc_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind rpc server");
    let address = listener.local_addr().expect("local addr");
    thread::spawn(move || {
        for _ in 0..4 {
            let (stream, _) = listener.accept().expect("accept rpc request");
            respond_to_auto_deploy_rpc_request(stream);
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

#[cfg(unix)]
fn respond_to_auto_deploy_rpc_request(mut stream: TcpStream) {
    let request = read_http_request(&mut stream);
    let response = if request.contains("\"eth_accounts\"") {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": ["0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"]
        })
    } else if request.contains("\"eth_sendTransaction\"") {
        assert!(request.contains("6001600055"));
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": "0x85368076afa1f63460e6f98fe3f2a85d121c4b9c0086ed37fc20022ebea4964c"
        })
    } else if request.contains("\"eth_getTransactionReceipt\"") {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "gasUsed": "0x5208",
                "status": "0x1",
                "contractAddress": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                "logs": []
            }
        })
    } else if request.contains("\"debug_traceCall\"") {
        let expected_input =
            encode_function_call("set(uint256)", &["7".to_owned()]).expect("calldata");
        assert!(request.contains("0x5fbdb2315678afecb367f032d93f642f64180aa3"));
        assert!(request.contains(&expected_input));
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "gas": 42000,
                "returnValue": "",
                "failed": false,
                "structLogs": [
                    {"pc": 0, "op": "PUSH1", "gas": 100, "gasCost": 3, "depth": 0, "stack": []},
                    {"pc": 1, "op": "STOP", "gas": 97, "gasCost": 0, "depth": 0}
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

fn write_function_abi(contract_name: &str, abi: &str) -> (PathBuf, String) {
    let dir = temp_dir("function-abi");
    fs::write(dir.join(format!("{contract_name}.abi")), abi).expect("write abi");
    let spec = format!("0x2:{contract_name}:{}", dir.display());
    (dir, spec)
}

fn write_balance_updated_deployment_dir() -> PathBuf {
    let dir = temp_dir("deployment-abi");
    fs::write(dir.join("TestContract.abi"), BALANCE_UPDATED_ABI).expect("write abi");
    fs::write(
        dir.join("deployment.json"),
        json!({
            "address": "0x2",
            "contract": "TestContract",
            "ethdebug": {"enabled": true}
        })
        .to_string(),
    )
    .expect("write deployment");
    dir
}

fn write_balance_updated_contract_mapping() -> (PathBuf, PathBuf) {
    let dir = temp_dir("contracts-mapping");
    let debug_dir = dir.join("debug");
    fs::create_dir_all(&debug_dir).expect("create debug dir");
    fs::write(debug_dir.join("TestContract.abi"), BALANCE_UPDATED_ABI).expect("write abi");
    let mapping_file = dir.join("contracts.json");
    fs::write(
        &mapping_file,
        json!({
            "contracts": [
                {
                    "address": "0x2",
                    "name": "TestContract",
                    "debug_dir": "debug"
                }
            ]
        })
        .to_string(),
    )
    .expect("write mapping");
    (dir, mapping_file)
}

fn balance_updated_topic() -> String {
    let event = parse_event_abis(BALANCE_UPDATED_ABI)
        .expect("parse abi")
        .remove(0);
    event_topic(&event)
}

#[cfg(unix)]
fn fake_solc(root: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let path = root.join("solc");
    let script = r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "solc, the solidity compiler"
  echo "Version: 0.8.31+commit.test"
  exit 0
fi
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then
    out="$arg"
  fi
  prev="$arg"
done
mkdir -p "$out"
cat > "$out/ethdebug.json" <<'EOF'
{"version":1}
EOF
cat > "$out/Counter.abi" <<'EOF'
[{"type":"function","name":"set","inputs":[{"name":"n","type":"uint256"}]}]
EOF
cat > "$out/Counter.bin" <<'EOF'
6001600055
EOF
cat > "$out/Counter_ethdebug.json" <<'EOF'
{"contract":"Counter"}
EOF
cat > "$out/Counter_ethdebug-runtime.json" <<'EOF'
{"contract":"Counter"}
EOF
"#;
    fs::write(&path, script).expect("write fake solc");
    let mut permissions = fs::metadata(&path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).expect("chmod");
    path
}

fn temp_dir(label: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("soldb-cli-{label}-{unique}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
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
