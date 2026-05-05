use clap::{Args, Parser, Subcommand};
use soldb_core::{SoldbResult, TransactionTrace};
use soldb_ethdebug::parse_ethdebug_spec;
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
    #[arg(long = "rpc-url", short = 'r', default_value = "http://localhost:8545")]
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
    #[arg(long = "rpc-url", short = 'r', default_value = "http://localhost:8545")]
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
    #[arg(long = "rpc-url", default_value = "http://localhost:8545")]
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
        Command::Bridge(_)
        | Command::ListContracts(_)
        | Command::ListEvents(_)
        | Command::Simulate(_) => Err(soldb_core::SoldbError::Message(
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

fn trace_contract_name(args: &TraceArgs) -> Option<String> {
    args.ethdebug_dir
        .first()
        .and_then(|spec| parse_ethdebug_spec(spec).name)
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
