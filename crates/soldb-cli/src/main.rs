use clap::{Args, Parser, Subcommand};

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

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Bridge(_)
        | Command::ListContracts(_)
        | Command::ListEvents(_)
        | Command::Trace(_)
        | Command::Simulate(_) => {
            eprintln!("soldb Rust CLI skeleton: command implementation is not ported yet");
            std::process::exit(2);
        }
    }
}
