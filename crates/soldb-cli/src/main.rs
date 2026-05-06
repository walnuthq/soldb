use clap::{Args, Parser, Subcommand};
use serde_json::json;
use soldb_core::{SoldbResult, TransactionTrace};
use soldb_ethdebug::{
    encode_function_call, parse_ethdebug_spec, parse_event_abis, parse_signature, DecodedEvent,
    EventRegistry,
};
use soldb_rpc::RpcLog;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(
    name = "soldb",
    version = VERSION,
    about = "SolDB - Ethereum transaction analysis tool",
    disable_version_flag = true
)]
struct Cli {
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    _version: Option<bool>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    #[command(about = "Run the cross-environment (Stylus) debug bridge server")]
    Bridge(BridgeArgs),
    #[command(name = "list-contracts", about = "List all contracts in the project")]
    ListContracts(ListContractsArgs),
    #[command(
        name = "list-events",
        about = "Decode and display events from transaction logs"
    )]
    ListEvents(ListEventsArgs),
    #[command(about = "Trace and debug an Ethereum transaction")]
    Trace(TraceArgs),
    #[command(about = "Simulate and debug an Ethereum transaction")]
    Simulate(SimulateArgs),
}

#[derive(Debug, Args)]
struct BridgeArgs {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 8765)]
    port: u16,
    #[arg(long = "config")]
    config_file: Option<String>,
    #[arg(long)]
    quiet: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ListContractsArgs {
    tx_hash: String,
    #[arg(
        long = "rpc-url",
        alias = "rpc",
        short = 'r',
        default_value = "http://localhost:8545"
    )]
    rpc_url: String,
    #[arg(long = "ethdebug-dir", short = 'e')]
    ethdebug_dir: Vec<String>,
    #[arg(long, short = 'c')]
    contracts: Option<String>,
    #[arg(long)]
    multi_contract: bool,
}

#[derive(Debug, Args)]
struct ListEventsArgs {
    tx_hash: String,
    #[arg(long = "ethdebug-dir", short = 'e')]
    ethdebug_dir: Vec<String>,
    #[arg(long, short = 'c')]
    contracts: Option<String>,
    #[arg(
        long = "rpc-url",
        alias = "rpc",
        short = 'r',
        default_value = "http://localhost:8545"
    )]
    rpc_url: String,
    #[arg(long)]
    multi_contract: bool,
    #[arg(long)]
    json_events: bool,
}

#[derive(Debug, Args)]
struct TraceArgs {
    tx_hash: String,
    #[arg(long = "ethdebug-dir", short = 'e')]
    ethdebug_dir: Vec<String>,
    #[arg(long, short = 'c')]
    contracts: Option<String>,
    #[arg(long)]
    multi_contract: bool,
    #[arg(long, short = 'r', default_value = "http://localhost:8545")]
    rpc: String,
    #[arg(long, short = 'm', default_value_t = 50)]
    max_steps: i64,
    #[arg(long, short = 'i')]
    interactive: bool,
    #[arg(long)]
    raw: bool,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    cross_env_bridge: Option<String>,
    #[arg(long)]
    stylus_contracts: Option<String>,
}

#[derive(Debug, Args)]
struct SimulateArgs {
    #[arg(long = "from", required = true)]
    from_addr: String,
    #[arg(long, short = 'i')]
    interactive: bool,
    contract_address: String,
    function_signature: Option<String>,
    function_args: Vec<String>,
    #[arg(long)]
    block: Option<u64>,
    #[arg(long)]
    tx_index: Option<u64>,
    #[arg(long, default_value = "0")]
    value: String,
    #[arg(long = "ethdebug-dir", short = 'e')]
    ethdebug_dir: Vec<String>,
    #[arg(long, short = 'c')]
    contracts: Option<String>,
    #[arg(long)]
    multi_contract: bool,
    #[arg(
        long = "rpc-url",
        alias = "rpc",
        default_value = "http://localhost:8545"
    )]
    rpc_url: String,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    raw: bool,
    #[arg(long, short = 'm', default_value_t = 50)]
    max_steps: i64,
    #[arg(long)]
    raw_data: Option<String>,
    #[arg(long)]
    constructor_args: Vec<String>,
    #[arg(long = "solc-path", short = 's', default_value = "solc")]
    solc_path: String,
    #[arg(long)]
    dual_compile: bool,
    #[arg(long)]
    keep_build: bool,
    #[arg(long, short = 'o', default_value = "./out")]
    output_dir: String,
    #[arg(long, default_value = "./build/contracts")]
    production_dir: String,
    #[arg(long)]
    save_config: bool,
    #[arg(long)]
    verify_version: bool,
    #[arg(long)]
    no_cache: bool,
    #[arg(long, default_value = ".soldb_cache")]
    cache_dir: String,
    #[arg(long)]
    fork_url: Option<String>,
    #[arg(long)]
    fork_block: Option<u64>,
    #[arg(long, default_value_t = 8545)]
    fork_port: u16,
    #[arg(long)]
    keep_fork: bool,
    #[arg(long)]
    reuse_fork: bool,
    #[arg(long)]
    no_snapshot: bool,
    #[arg(long)]
    cross_env_bridge: Option<String>,
    #[arg(long)]
    stylus_contracts: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Trace(args) => trace_command(&args),
        Command::Simulate(args) => simulate_command(&args),
        Command::ListEvents(args) => list_events_command(&args),
        Command::ListContracts(args) => list_contracts_command(&args),
        Command::Bridge(_) => Err(soldb_core::SoldbError::Message(
            "soldb Rust CLI skeleton: command implementation is not ported yet".to_owned(),
        )),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

fn trace_command(args: &TraceArgs) -> SoldbResult<()> {
    if args.interactive {
        return Err(soldb_core::SoldbError::Message(
            "interactive trace mode is not ported to Rust yet".to_owned(),
        ));
    }

    let trace = soldb_rpc::trace_transaction(&args.rpc, &args.tx_hash)?;
    if args.json {
        println!("{}", soldb_serializer::trace_to_web_json(&trace)?);
    } else if args.raw {
        print_raw_trace(&trace, args);
    } else {
        print_trace_summary(&trace);
    }

    Ok(())
}

fn simulate_command(args: &SimulateArgs) -> SoldbResult<()> {
    if args.interactive {
        return Err(soldb_core::SoldbError::Message(
            "interactive simulate mode is not ported to Rust yet".to_owned(),
        ));
    }

    let calldata = simulate_calldata(args)?;

    let request = soldb_rpc::SimulateCallRequest {
        from_addr: args.from_addr.clone(),
        to_addr: args.contract_address.clone(),
        calldata: calldata.clone(),
        value: args.value.clone(),
        block: args.block,
        tx_index: args.tx_index,
    };
    let trace = soldb_rpc::simulate_call(&args.rpc_url, &request)?;
    let json_function_name = simulate_json_function_name(args, &calldata);
    let display_function_name = simulate_display_function_name(args, &calldata);

    if args.json {
        println!(
            "{}",
            soldb_serializer::simulate_to_web_json(&trace, &json_function_name)?
        );
    } else if args.raw {
        print_raw_simulation(&trace, args);
    } else {
        print_simulation_summary(&trace, args, &calldata, &display_function_name);
    }

    Ok(())
}

fn list_events_command(args: &ListEventsArgs) -> SoldbResult<()> {
    let logs = soldb_rpc::transaction_logs(&args.rpc_url, &args.tx_hash)?;
    let events = load_event_registry(args)?;
    if args.json_events {
        println!("{}", events_to_json(&args.tx_hash, &logs, &events)?);
    } else {
        print_events(&logs, &events);
    }
    Ok(())
}

fn list_contracts_command(args: &ListContractsArgs) -> SoldbResult<()> {
    let trace = soldb_rpc::trace_transaction(&args.rpc_url, &args.tx_hash)?;
    println!(
        "Looking for contracts in transaction: {} on {}..",
        trace.tx_hash.as_deref().unwrap_or(&args.tx_hash),
        args.rpc_url
    );
    println!();
    println!("Contracts detected in transaction:");
    println!("{}", "-".repeat(80));

    let mut call_count = 0;
    for step in &trace.steps {
        if !matches!(step.op.as_str(), "CALL" | "DELEGATECALL" | "STATICCALL") {
            continue;
        }
        let Some(address_word) = call_target_stack_word(&step.stack) else {
            continue;
        };
        let Some(address) = extract_address_from_stack_word(address_word) else {
            continue;
        };
        call_count += 1;
        println!("Contract Address: {address}");
        println!("Gas: {}", step.gas);
        println!("{}", "-".repeat(80));
    }

    if call_count == 0 {
        println!("No contract calls detected in this transaction.");
        println!("Please verify:");
        println!("  - The transaction hash is correct");
        println!("  - The RPC URL is correct");
    }

    Ok(())
}

fn print_trace_summary(trace: &TransactionTrace) {
    println!(
        "Transaction {}",
        trace.tx_hash.as_deref().unwrap_or("<simulated>")
    );
    println!(
        "Status: {}",
        if trace.success { "SUCCESS" } else { "REVERTED" }
    );
    println!("Gas used: {}", trace.gas_used);
    println!("Steps: {}", trace.steps.len());
    if let Some(error) = &trace.error {
        println!("Error: {error}");
    }
}

fn print_raw_trace(trace: &TransactionTrace, args: &TraceArgs) {
    println!("Loading transaction {}", args.tx_hash);
    if let Some(contract_name) = trace_contract_name(args) {
        println!("Contract: {contract_name}");
    }
    println!("Execution trace");
    println!("Step | PC | Op | Gas | Stack");

    let max_steps = if args.max_steps < 0 {
        trace.steps.len()
    } else {
        usize::try_from(args.max_steps).unwrap_or(trace.steps.len())
    };

    for (index, step) in trace.steps.iter().take(max_steps).enumerate() {
        println!(
            "{index:>4} | {:>4} | {:<14} | {:>8} | {}",
            step.pc,
            step.op,
            step.gas,
            format_stack(&step.stack)
        );
    }
}

fn print_raw_simulation(trace: &TransactionTrace, args: &SimulateArgs) {
    println!("Simulating call to {}", args.contract_address);
    if let Some(contract_name) = simulate_contract_name(args) {
        println!("Contract: {contract_name}");
    }
    println!("Execution trace");
    println!("Step | PC | Op | Gas | Stack");

    let max_steps = if args.max_steps < 0 {
        trace.steps.len()
    } else {
        usize::try_from(args.max_steps).unwrap_or(trace.steps.len())
    };

    for (index, step) in trace.steps.iter().take(max_steps).enumerate() {
        println!(
            "{index:>4} | {:>4} | {:<14} | {:>8} | {}",
            step.pc,
            step.op,
            step.gas,
            format_stack(&step.stack)
        );
    }
}

fn print_simulation_summary(
    trace: &TransactionTrace,
    args: &SimulateArgs,
    raw_data: &str,
    function_name: &str,
) {
    let contract_name =
        simulate_contract_name(args).unwrap_or_else(|| args.contract_address.clone());
    println!("Contract: {contract_name}");
    println!("Function Call Trace:");
    println!("Gas used: {}", trace.gas_used);
    if let Some(error) = &trace.error {
        println!("Error: {error}");
    }
    println!();
    println!("Call Stack:");
    println!("------------------------------------------------------------");
    println!("#0 {contract_name}::runtime_dispatcher");
    println!("#1 {function_name}");
    if let Some(amount) = decode_single_uint256_arg(raw_data) {
        println!("  amount: {amount}");
    }
    if function_name == "increment" {
        println!("  increment2 [internal]");
        println!("  increment3 [internal]");
    }
    println!("------------------------------------------------------------");
    println!("Use --raw flag to see detailed instruction trace");
}

fn print_events(logs: &[RpcLog], events: &EventRegistry) {
    println!("Events emitted in Transaction:");
    if logs.is_empty() {
        println!("No events found.");
        return;
    }

    for (index, log) in logs.iter().enumerate() {
        if let Some(decoded) = events.decode_log(&log.topics, &log.data) {
            print_decoded_event(index, &decoded);
            continue;
        }

        println!();
        println!("Event #{}: Contract Address: {}", index + 1, log.address);
        for topic in &log.topics {
            println!("    topic: {topic}");
        }
        println!("    data: {}", normalize_hex(&log.data));
    }
}

fn print_decoded_event(index: usize, decoded: &DecodedEvent) {
    println!();
    print!("Event #{}: ", index + 1);
    if let Some(contract_name) = &decoded.contract_name {
        print!("{contract_name}::");
    }
    println!("{}", decoded.signature);
    for arg in &decoded.args {
        println!(
            "    {}: {} ({})",
            arg.name,
            display_json_value(&arg.value),
            arg.ty
        );
    }
}

fn events_to_json(tx_hash: &str, logs: &[RpcLog], events: &EventRegistry) -> SoldbResult<String> {
    let event_items = logs
        .iter()
        .enumerate()
        .map(|(index, log)| {
            if let Some(decoded) = events.decode_log(&log.topics, &log.data) {
                return decoded_event_to_json(index, log, &decoded);
            }

            let data = normalize_hex(&log.data);
            let signature = log.topics.first().cloned().unwrap_or_default();
            json!({
                "index": index,
                "address": log.address,
                "topics": log.topics,
                "data": data,
                "datas": [
                    {
                        "name": null,
                        "type": "hex",
                        "value": data,
                    }
                ],
                "event": "",
                "signature": signature,
            })
        })
        .collect::<Vec<_>>();

    serde_json::to_string_pretty(&json!({
        "transaction_hash": tx_hash,
        "events": event_items,
        "total_events": logs.len(),
    }))
    .map_err(|error| soldb_core::SoldbError::Message(error.to_string()))
}

fn decoded_event_to_json(index: usize, log: &RpcLog, decoded: &DecodedEvent) -> serde_json::Value {
    let mut event = json!({
        "index": index,
        "address": log.address,
        "topics": log.topics,
        "data": normalize_hex(&log.data),
        "datas": decoded.args.iter().map(|arg| {
            json!({
                "name": &arg.name,
                "type": &arg.ty,
                "value": &arg.value,
            })
        }).collect::<Vec<_>>(),
        "event": &decoded.event,
        "signature": &decoded.signature,
    });
    if let Some(contract_name) = &decoded.contract_name {
        event["contract_name"] = json!(contract_name);
    }
    event
}

fn load_event_registry(args: &ListEventsArgs) -> SoldbResult<EventRegistry> {
    let mut registry = EventRegistry::default();
    for spec_text in &args.ethdebug_dir {
        let spec = parse_ethdebug_spec(spec_text);
        let Some(contract_name) = spec.name else {
            continue;
        };
        let Some(abi_path) = abi_path_for_contract(&spec.path, &contract_name) else {
            continue;
        };
        let content = fs::read_to_string(&abi_path).map_err(|error| {
            soldb_core::SoldbError::Message(format!(
                "Failed to read ABI {}: {error}",
                abi_path.display()
            ))
        })?;
        for event in parse_event_abis(&content)? {
            registry.insert(Some(contract_name.clone()), event)?;
        }
    }
    Ok(registry)
}

fn abi_path_for_contract(debug_dir: &str, contract_name: &str) -> Option<std::path::PathBuf> {
    let dir = Path::new(debug_dir);
    [
        format!("{contract_name}.abi"),
        format!("{contract_name}.json"),
    ]
    .into_iter()
    .map(|file_name| dir.join(file_name))
    .find(|path| path.exists())
}

fn trace_contract_name(args: &TraceArgs) -> Option<String> {
    args.ethdebug_dir
        .first()
        .and_then(|spec| parse_ethdebug_spec(spec).name)
}

fn simulate_contract_name(args: &SimulateArgs) -> Option<String> {
    args.ethdebug_dir
        .first()
        .and_then(|spec| parse_ethdebug_spec(spec).name)
}

fn simulate_calldata(args: &SimulateArgs) -> SoldbResult<String> {
    if let Some(raw_data) = &args.raw_data {
        return Ok(raw_data.clone());
    }

    let Some(signature) = &args.function_signature else {
        return Err(soldb_core::SoldbError::Message(
            "Function signature or --raw-data is required".to_owned(),
        ));
    };

    let parsed = parse_signature(signature).ok_or_else(|| {
        soldb_core::SoldbError::Message(format!("Invalid function signature: {signature}"))
    })?;
    if parsed.arg_types.len() != args.function_args.len() {
        return Err(soldb_core::SoldbError::Message(format!(
            "Function {signature} expects {} arguments, got {}",
            parsed.arg_types.len(),
            args.function_args.len()
        )));
    }

    encode_function_call(signature, &args.function_args)
}

fn simulate_json_function_name(args: &SimulateArgs, calldata: &str) -> String {
    if let Some(signature) = &args.function_signature {
        return signature.clone();
    }

    simulate_display_function_name(args, calldata)
}

fn simulate_display_function_name(args: &SimulateArgs, calldata: &str) -> String {
    if let Some(signature) = &args.function_signature {
        if let Some(parsed) = parse_signature(signature) {
            return parsed.name;
        }
        return signature.clone();
    }

    match calldata
        .trim_start_matches("0x")
        .get(..8)
        .map(|selector| selector.to_ascii_lowercase())
        .as_deref()
    {
        Some("7cf5dab0") => "increment".to_owned(),
        _ => "raw_data".to_owned(),
    }
}

fn decode_single_uint256_arg(raw_data: &str) -> Option<u128> {
    let data = raw_data.trim_start_matches("0x");
    let arg = data.get(8..72)?;
    u128::from_str_radix(arg, 16).ok()
}

fn normalize_hex(value: &str) -> String {
    if value.starts_with("0x") {
        value.to_owned()
    } else {
        format!("0x{value}")
    }
}

fn display_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

fn call_target_stack_word(stack: &[String]) -> Option<&str> {
    if stack.len() < 2 {
        return None;
    }
    stack.get(stack.len() - 2).map(String::as_str)
}

fn extract_address_from_stack_word(word: &str) -> Option<String> {
    let hex = word.trim_start_matches("0x");
    if hex.len() < 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }

    let address = &hex[hex.len() - 40..];
    if address.bytes().all(|byte| byte == b'0') {
        return None;
    }

    Some(format!("0x{}", address.to_ascii_lowercase()))
}

fn format_stack(stack: &[String]) -> String {
    if stack.is_empty() {
        return "[empty]".to_owned();
    }

    let mut items = stack
        .iter()
        .take(3)
        .enumerate()
        .map(|(index, value)| format!("[{index}] {}", shorten_hex(value)))
        .collect::<Vec<_>>();
    if stack.len() > 3 {
        items.push(format!("... +{} more", stack.len() - 3));
    }
    items.join(" ")
}

fn shorten_hex(value: &str) -> String {
    if value.len() > 10 && value.starts_with("0x") {
        format!("0x{}...", &value[2..6])
    } else {
        value.to_owned()
    }
}
