//! The `soldb` command-line interface.
//!
//! This binary owns argument parsing, command dispatch, and every piece of
//! human-readable formatting in the project: the library crates return data and this
//! layer decides how it looks. That split is what lets the DAP server and the JSON
//! output reuse the same logic without inheriting terminal behavior.
//!
//! Output conventions worth preserving when editing this file:
//!
//! - Colors go through the `paint` helpers, which honor `NO_COLOR`, `CLICOLOR_FORCE`,
//!   and whether the stream being written to is a terminal — stdout for the result,
//!   stderr for warnings, decided separately so a redirected log never collects escape
//!   codes and a warning on a terminal keeps its color when the result is piped away.
//!   Emitting escapes directly breaks the lit tests.
//! - `--json` and `--json-events` print only their JSON document, so the output stays
//!   pipeable into `jq`. Progress lines must stay gated on those flags.
//! - A command that has already rendered a failure returns
//!   [`soldb_core::SoldbError::AlreadyReported`] so the exit path does not print it
//!   twice. Failures exit with code 2.

mod profile;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::json;
use soldb_core::{ExecutionLog, SoldbResult, TransactionTrace, Word as StackWord};
use soldb_debugger::{
    CachedChain, ChainRead, ChainStorage, ContractDebugInfo, SourceFunction, SourceParam,
    StorageWords,
};
use soldb_ethdebug::{
    encode_function_call, ethdebug_resources_from_metadata, find_ethdebug_metadata,
    function_selector, load_debug_program_with_sources, parse_ethdebug_spec, parse_event_abis,
    parse_signature, DecodedEvent, EventRegistry, SourceMapEnvironment,
};
use soldb_repl::{
    BreakpointKind, DebuggerCommand, DebuggerInfoCommand, DebuggerState, DisplayMode, StepOutcome,
};
use soldb_rpc::{RpcLog, TraceBackend};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt::Display;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Mutex, OnceLock};

use profile::ProfileArgs;

const VERSION: &str = env!("CARGO_PKG_VERSION");
static COLORS_ENABLED: OnceLock<bool> = OnceLock::new();

fn colors_enabled() -> bool {
    *COLORS_ENABLED.get_or_init(|| colors_enabled_on(io::stdout().is_terminal()))
}

/// Whether to color what goes to stderr, which is warnings and the final error.
///
/// Decided separately from stdout: piping a trace into a file should not take the color
/// off a warning still being read on the terminal, and redirecting the warnings into a
/// log should not fill it with escape codes.
fn stderr_colors_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| colors_enabled_on(io::stderr().is_terminal()))
}

fn colors_enabled_on(is_terminal: bool) -> bool {
    if let Some(force) = env::var_os("CLICOLOR_FORCE") {
        return force.to_string_lossy() != "0";
    }
    if env::var_os("NO_COLOR").is_some() {
        return false;
    }
    is_terminal && env::var("TERM").map_or(true, |term| term != "dumb")
}

/// Writes a failure to stderr: the first line as the error, and a following `note:` line
/// styled like the notes `report_once` writes, so the two read the same way.
fn report_error(message: &str) {
    let mut lines = message.split('\n');
    if let Some(first) = lines.next() {
        eprintln!("{} {first}", paint_stderr("error:", "91"));
    }
    for line in lines {
        match line.strip_prefix("note:") {
            Some(rest) => eprintln!("{}{rest}", paint_stderr("note:", "2")),
            None => eprintln!("{line}"),
        }
    }
}

fn paint(value: impl Display, code: &str) -> String {
    paint_when(colors_enabled(), value, code)
}

/// The same, for text written to stderr.
fn paint_stderr(value: impl Display, code: &str) -> String {
    paint_when(stderr_colors_enabled(), value, code)
}

fn paint_when(enabled: bool, value: impl Display, code: &str) -> String {
    let text = value.to_string();
    if enabled {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text
    }
}

fn bold(value: impl Display) -> String {
    paint(value, "1")
}

fn dim(value: impl Display) -> String {
    paint(value, "2")
}

fn info(value: impl Display) -> String {
    paint(value, "96")
}

fn success(value: impl Display) -> String {
    paint(value, "92")
}

fn warning(value: impl Display) -> String {
    paint(value, "93")
}

fn error_color(value: impl Display) -> String {
    paint(value, "91")
}

fn opcode_color(value: impl Display) -> String {
    paint(value, "94")
}

fn address_color(value: impl Display) -> String {
    paint(value, "95")
}

fn number_color(value: impl Display) -> String {
    paint(value, "93")
}

fn function_color(value: impl Display) -> String {
    paint(value, "95")
}

fn separator(width: usize) -> String {
    dim("-".repeat(width))
}

#[derive(Debug, Parser)]
#[command(
    name = "soldb",
    version = VERSION,
    about = "SolDB - Ethereum transaction analysis tool",
    disable_version_flag = true
)]
struct Cli {
    #[arg(
        short = 'v',
        long = "version",
        action = clap::ArgAction::Version,
        help = "Print version"
    )]
    _version: Option<bool>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    #[command(about = "Run the cross-environment (Stylus) debug bridge server")]
    Bridge(BridgeArgs),
    #[command(about = "Compile Solidity contracts with ETHDebug artifacts")]
    Compile(CompileArgs),
    #[command(about = "Inspect compiler debug metadata")]
    Info(InfoArgs),
    #[command(name = "list-contracts", about = "List all contracts in the project")]
    ListContracts(ListContractsArgs),
    #[command(
        name = "list-events",
        about = "Decode and display events from transaction logs"
    )]
    ListEvents(ListEventsArgs),
    #[command(about = "Trace and debug an Ethereum transaction")]
    Trace(TraceArgs),
    #[command(
        about = "Replay a transaction or call from a file written by --save-replay, with no node"
    )]
    Replay(ReplayArgs),
    #[command(about = "Run bytecode on a local chain that exists only for this run, with no node")]
    Run(RunArgs),
    #[command(about = "Profile gas by contract, function, and source line")]
    Profile(ProfileArgs),
    #[command(about = "Simulate and debug an Ethereum transaction")]
    Simulate(SimulateArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TraceBackendArg {
    Auto,
    DebugRpc,
    Replay,
}

impl From<TraceBackendArg> for TraceBackend {
    fn from(value: TraceBackendArg) -> Self {
        match value {
            TraceBackendArg::Auto => Self::Auto,
            TraceBackendArg::DebugRpc => Self::DebugRpc,
            TraceBackendArg::Replay => Self::Replay,
        }
    }
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
struct CompileArgs {
    contract_file: Option<String>,
    #[arg(
        long = "solc",
        alias = "solc-path",
        short = 's',
        default_value = "solc"
    )]
    solc_path: String,
    #[arg(long = "output-dir", short = 'o', default_value = "./out")]
    output_dir: String,
    #[arg(long)]
    dual_compile: bool,
    /// The directory relative imports resolve against. Found from the project the
    /// contract is in when not given.
    #[arg(long)]
    base_path: Option<String>,
    /// Where non-relative imports are looked up, such as a `lib` directory. Repeatable.
    #[arg(long = "include-path")]
    include_paths: Vec<String>,
    /// An import remapping, as `prefix=target`. Repeatable, and added to the ones the
    /// project declares.
    #[arg(long = "remapping")]
    remappings: Vec<String>,
    /// Ignore the project's own layout and remappings.
    #[arg(long)]
    no_project: bool,
    #[arg(long, default_value = "./build/contracts")]
    production_dir: String,
    #[arg(long)]
    verify_version: bool,
    #[arg(long)]
    save_config: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct InfoArgs {
    #[command(subcommand)]
    command: InfoCommand,
}

#[derive(Debug, Subcommand)]
enum InfoCommand {
    #[command(about = "Print ETHDebug resources metadata")]
    Resources(InfoResourcesArgs),
}

#[derive(Debug, Args)]
struct InfoResourcesArgs {
    #[arg(long = "ethdebug-dir", short = 'e')]
    ethdebug_dir: Vec<String>,
    /// Where the sources named by the debug artifacts are, when they are not next to
    /// them: the directory the contract was compiled in. Repeatable.
    #[arg(long = "source-path")]
    source_path: Vec<String>,
    #[arg(long, short = 'c')]
    contracts: Option<String>,
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
    /// Where the sources named by the debug artifacts are, when they are not next to
    /// them: the directory the contract was compiled in. Repeatable.
    #[arg(long = "source-path")]
    source_path: Vec<String>,
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
    /// Where the sources named by the debug artifacts are, when they are not next to
    /// them: the directory the contract was compiled in. Repeatable.
    #[arg(long = "source-path")]
    source_path: Vec<String>,
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
    /// Record everything the replay backend reads into FILE, so `soldb replay FILE`
    /// reproduces this trace with no node. Implies `--backend replay`.
    #[arg(long, value_name = "FILE")]
    save_replay: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = TraceBackendArg::Auto)]
    backend: TraceBackendArg,
    #[arg(long = "ethdebug-dir", short = 'e')]
    ethdebug_dir: Vec<String>,
    /// Where the sources named by the debug artifacts are, when they are not next to
    /// them: the directory the contract was compiled in. Repeatable.
    #[arg(long = "source-path")]
    source_path: Vec<String>,
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

/// What presenting a traced transaction needs, whichever command produced the trace.
///
/// `trace` and `replay` share every output path; they differ in where the trace comes
/// from, so the presentation helpers take this view rather than either command's
/// arguments.
#[derive(Debug, Clone)]
struct TraceView {
    tx_hash: String,
    /// The node the transaction was traced through, or `None` for a trace read from a
    /// replay file, which has no chain to ask.
    rpc_url: Option<String>,
    ethdebug_dir: Vec<String>,
    /// Where the sources named by the artifacts are, when they are not next to them.
    source_path: Vec<String>,
    contracts: Option<String>,
    max_steps: i64,
}

impl TraceView {
    fn for_trace(args: &TraceArgs) -> Self {
        Self {
            tx_hash: args.tx_hash.clone(),
            rpc_url: Some(args.rpc.clone()),
            ethdebug_dir: args.ethdebug_dir.clone(),
            source_path: args.source_path.clone(),
            contracts: args.contracts.clone(),
            max_steps: args.max_steps,
        }
    }

    fn for_replay(args: &ReplayArgs, tx_hash: &str) -> Self {
        Self {
            tx_hash: tx_hash.to_owned(),
            rpc_url: None,
            ethdebug_dir: args.ethdebug_dir.clone(),
            source_path: args.source_path.clone(),
            contracts: args.contracts.clone(),
            max_steps: args.max_steps,
        }
    }

    /// The chain the traced transaction started from, for reading slots it never touched.
    fn chain_storage(&self) -> Option<ChainReader> {
        NodeStorage::before_transaction(self.rpc_url.as_deref()?, &self.tx_hash)
    }
}

impl SimulationView {
    /// The chain the call ran on top of, for reading slots it never touched.
    fn chain_storage(&self) -> Option<ChainReader> {
        NodeStorage::at_block(self.rpc_url.as_deref()?, self.chain_block?)
    }
}

/// What presenting a simulated call needs, whichever command produced it.
///
/// `simulate` and `run` share every output path: source mapping, the interactive
/// debugger, the JSON document, the raw view. They differ in how the trace is obtained,
/// so the presentation helpers take this view rather than either command's arguments.
#[derive(Debug, Clone)]
struct SimulationView {
    /// The node the call ran against, or `None` for a chain that exists only for the run.
    rpc_url: Option<String>,
    /// The replay file the call came from, when it did not run against a node or a
    /// local chain.
    replayed_from: Option<PathBuf>,
    contract_address: String,
    function_signature: Option<String>,
    function_args: Vec<String>,
    raw_data: Option<String>,
    ethdebug_dir: Vec<String>,
    /// Where the sources named by the artifacts are, when they are not next to them.
    source_path: Vec<String>,
    contracts: Option<String>,
    interactive: bool,
    json: bool,
    raw: bool,
    max_steps: i64,
    /// The block the call ran on top of, when it ran on a node and the block is fixed:
    /// its end state is exactly what the call started from. `None` when the call ran at a
    /// position inside a block, where neither that block nor its parent is that state.
    chain_block: Option<Option<u64>>,
}

impl SimulationView {
    fn for_simulate(args: &SimulateArgs, contract_address: &str) -> Self {
        Self {
            rpc_url: Some(args.rpc_url.clone()),
            replayed_from: None,
            // A call placed inside a block runs after the transactions before it, so
            // neither that block's end state nor its parent's is what it started from.
            chain_block: args
                .tx_index
                .is_none_or(|index| index == 0)
                .then_some(args.block),
            contract_address: contract_address.to_owned(),
            function_signature: args.function_signature.clone(),
            function_args: args.function_args.clone(),
            raw_data: args.raw_data.clone(),
            ethdebug_dir: args.ethdebug_dir.clone(),
            source_path: args.source_path.clone(),
            contracts: args.contracts.clone(),
            interactive: args.interactive,
            json: args.json,
            raw: args.raw,
            max_steps: args.max_steps,
        }
    }

    fn for_run(args: &RunArgs, contract_address: &str) -> Self {
        Self {
            rpc_url: None,
            replayed_from: None,
            chain_block: None,
            contract_address: contract_address.to_owned(),
            function_signature: args.function_signature.clone(),
            function_args: args.function_args.clone(),
            // A run with neither a signature nor data calls the contract with empty
            // calldata, which is what plain bytecode without a dispatcher expects.
            raw_data: args
                .raw_data
                .clone()
                .or_else(|| args.function_signature.is_none().then(|| "0x".to_owned())),
            ethdebug_dir: args.ethdebug_dir.clone(),
            source_path: args.source_path.clone(),
            contracts: args.contracts.clone(),
            interactive: args.interactive,
            json: args.json,
            raw: args.raw,
            max_steps: args.max_steps,
        }
    }

    /// A call replayed from a recording: the request carries the calldata, and the
    /// presentation flags come from `replay`.
    fn for_replay(
        args: &ReplayArgs,
        request: &soldb_rpc::SimulateCallRequest,
        file: &Path,
    ) -> Self {
        Self {
            rpc_url: None,
            replayed_from: Some(file.to_path_buf()),
            chain_block: None,
            contract_address: request.to_addr.clone(),
            function_signature: None,
            function_args: Vec::new(),
            raw_data: Some(request.calldata.clone()),
            ethdebug_dir: args.ethdebug_dir.clone(),
            source_path: args.source_path.clone(),
            contracts: args.contracts.clone(),
            interactive: args.interactive,
            json: args.json,
            raw: args.raw,
            max_steps: args.max_steps,
        }
    }
}

/// Arguments of `soldb replay`: a file written by `--save-replay`, and how to show it.
#[derive(Debug, Args)]
struct ReplayArgs {
    /// A replay file written by `trace --save-replay` or `simulate --save-replay`.
    file: PathBuf,
    #[arg(long = "ethdebug-dir", short = 'e')]
    ethdebug_dir: Vec<String>,
    /// Where the sources named by the debug artifacts are, when they are not next to
    /// them: the directory the contract was compiled in. Repeatable.
    #[arg(long = "source-path")]
    source_path: Vec<String>,
    #[arg(long, short = 'c')]
    contracts: Option<String>,
    #[arg(long)]
    multi_contract: bool,
    #[arg(long, short = 'm', default_value_t = 50)]
    max_steps: i64,
    #[arg(long, short = 'i')]
    interactive: bool,
    #[arg(long)]
    raw: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Bytecode to run: a file such as `out/Counter.bin`, or a hex string. Creation code
    /// unless `--runtime`; it is deployed locally first, so the constructor's state is
    /// what the call sees.
    bytecode: String,
    function_signature: Option<String>,
    function_args: Vec<String>,
    /// The caller. Defaults to the first Anvil account, so a deployment lands at the
    /// address Anvil would give it.
    #[arg(
        long = "from",
        default_value = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    )]
    from_addr: String,
    /// The bytecode is runtime code: install it at `--address` instead of deploying.
    #[arg(long)]
    runtime: bool,
    /// Trace the constructor and stop.
    #[arg(long)]
    deploy: bool,
    /// Where `--runtime` code lives; defaults to the first Anvil deployment address. A
    /// deployment lands at the CREATE address of `--from` at nonce zero instead.
    #[arg(long, requires = "runtime")]
    address: Option<String>,
    /// Value sent with the call, or with the deployment under `--deploy`.
    #[arg(long, default_value = "0")]
    value: String,
    /// Value sent to the constructor when creation code is deployed before the call.
    #[arg(long, default_value = "0")]
    constructor_value: String,
    #[arg(long)]
    raw_data: Option<String>,
    /// Constructor arguments, encoded against the ABI found through `--ethdebug-dir`.
    #[arg(long)]
    constructor_args: Vec<String>,
    /// A storage slot to set on the contract before the run, as `slot=value`.
    #[arg(long = "storage")]
    storage: Vec<String>,
    /// The caller's balance.
    #[arg(long, default_value = "10000ether")]
    balance: String,
    #[arg(long, default_value_t = 31_337)]
    chain_id: u64,
    #[arg(long, default_value_t = 1)]
    block_number: u64,
    #[arg(long, default_value_t = 0)]
    timestamp: u64,
    #[arg(long, default_value_t = 30_000_000)]
    gas_limit: u64,
    #[arg(long = "ethdebug-dir", short = 'e')]
    ethdebug_dir: Vec<String>,
    /// Where the sources named by the debug artifacts are, when they are not next to
    /// them: the directory the contract was compiled in. Repeatable.
    #[arg(long = "source-path")]
    source_path: Vec<String>,
    #[arg(long, short = 'c')]
    contracts: Option<String>,
    #[arg(long)]
    multi_contract: bool,
    #[arg(long, short = 'i')]
    interactive: bool,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    raw: bool,
    #[arg(long, short = 'm', default_value_t = 50)]
    max_steps: i64,
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
    /// Where the call runs: `debug_traceCall` on the node, or a local `replay` over the
    /// node's state, which works on a node that cannot trace.
    #[arg(long, value_enum, default_value_t = TraceBackendArg::DebugRpc)]
    backend: TraceBackendArg,
    /// Record everything the replay backend reads into FILE, so `soldb replay FILE`
    /// reproduces this simulation with no node. Implies `--backend replay`.
    #[arg(long, value_name = "FILE")]
    save_replay: Option<PathBuf>,
    #[arg(long, default_value = "0")]
    value: String,
    #[arg(long = "ethdebug-dir", short = 'e')]
    ethdebug_dir: Vec<String>,
    /// Where the sources named by the debug artifacts are, when they are not next to
    /// them: the directory the contract was compiled in. Repeatable.
    #[arg(long = "source-path")]
    source_path: Vec<String>,
    #[arg(long, short = 'c')]
    contracts: Option<String>,
    #[arg(long)]
    multi_contract: bool,
    #[arg(
        long = "rpc-url",
        alias = "rpc",
        short = 'r',
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
        Command::Replay(args) => replay_command(&args),
        Command::Profile(args) => profile::command(&args),
        Command::Simulate(args) => simulate_command(&args),
        Command::Run(args) => run_command(&args),
        Command::ListEvents(args) => list_events_command(&args),
        Command::ListContracts(args) => list_contracts_command(&args),
        Command::Bridge(args) => bridge_command(&args),
        Command::Compile(args) => compile_command(&args),
        Command::Info(args) => info_command(&args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        // `AlreadyReported` means the command has already rendered the failure, so printing
        // here would duplicate it.
        Err(soldb_core::SoldbError::AlreadyReported) => ExitCode::from(2),
        Err(error) => {
            report_error(&error.to_string());
            ExitCode::from(2)
        }
    }
}

fn info_command(args: &InfoArgs) -> SoldbResult<()> {
    match &args.command {
        InfoCommand::Resources(resources) => info_resources_command(resources),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InfoResourcesJson {
    contracts: Vec<InfoResourcesContractJson>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InfoResourcesContractJson {
    address: Option<String>,
    name: String,
    debug_dir: String,
    resources: serde_json::Value,
}

fn info_resources_command(args: &InfoResourcesArgs) -> SoldbResult<()> {
    let specs = resolve_contract_specs(
        &args.ethdebug_dir,
        args.contracts.as_deref(),
        &args.source_path,
    )?;
    if specs.is_empty() {
        return Err(soldb_core::SoldbError::Message(
            "No ETHDebug contract specs provided".to_owned(),
        ));
    }

    let contracts = specs
        .iter()
        .map(|spec| {
            Ok(InfoResourcesContractJson {
                address: spec.address.clone(),
                name: spec.name.clone(),
                debug_dir: spec.debug_dir.display().to_string(),
                resources: ethdebug_resources_for_spec(spec)?,
            })
        })
        .collect::<SoldbResult<Vec<_>>>()?;

    if args.json {
        print_json(&InfoResourcesJson { contracts })?;
    } else {
        print_info_resources(&contracts);
    }
    Ok(())
}

fn print_info_resources(contracts: &[InfoResourcesContractJson]) {
    for contract in contracts {
        println!("Contract: {}", contract.name);
        if let Some(address) = &contract.address {
            println!("Address: {address}");
        }
        println!("Debug directory: {}", contract.debug_dir);
        if let Some(compiler) = contract
            .resources
            .get("compilation")
            .and_then(|compilation| compilation.get("compiler"))
        {
            let name = compiler
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<unknown>");
            let version = compiler
                .get("version")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<unknown>");
            println!("Compiler: {name} {version}");
        }
        let source_count = contract
            .resources
            .get("compilation")
            .and_then(|compilation| compilation.get("sources"))
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        println!("Sources: {source_count}");
        println!();
    }
}

/// How the compile command resolves imports: what the user passed, over what the
/// contract's own project declares.
fn compile_project_layout(args: &CompileArgs) -> soldb_compiler::ProjectLayout {
    let mut project = match (&args.contract_file, args.no_project) {
        (Some(file), false) => soldb_compiler::ProjectLayout::detect(Path::new(file)),
        _ => soldb_compiler::ProjectLayout::default(),
    };
    if let Some(base_path) = &args.base_path {
        project.base_path = Some(PathBuf::from(base_path));
    }
    project
        .include_paths
        .extend(args.include_paths.iter().map(PathBuf::from));
    project.remappings.extend(args.remappings.iter().cloned());
    project
}

fn compile_command(args: &CompileArgs) -> SoldbResult<()> {
    let mut config = soldb_compiler::CompilerConfig::with_paths(
        args.solc_path.clone(),
        &args.output_dir,
        &args.production_dir,
    );
    config.project = compile_project_layout(args);

    if args.verify_version {
        let info = config.verify_solc_version();
        if args.json {
            print_json(&info)?;
        } else if info.supported {
            println!(
                "Solidity {} supports ETHDebug",
                info.version.as_deref().unwrap_or("<unknown>")
            );
        } else {
            println!(
                "{}",
                info.error
                    .as_deref()
                    .unwrap_or("Solidity compiler does not support ETHDebug")
            );
        }
        if !info.supported {
            return Err(soldb_core::SoldbError::Message(
                info.error
                    .unwrap_or_else(|| "Unsupported solc version".to_owned()),
            ));
        }
        return Ok(());
    }

    if args.save_config {
        config.save_to_soldb_config("soldb.config.yaml")?;
        if !args.json {
            println!("Configuration saved to soldb.config.yaml");
        }
    }

    let contract_file = args
        .contract_file
        .as_deref()
        .ok_or_else(|| soldb_core::SoldbError::Message("Contract file is required".to_owned()))?;
    if !Path::new(contract_file).exists() {
        return Err(soldb_core::SoldbError::Message(format!(
            "Contract file '{contract_file}' not found"
        )));
    }

    if !args.json && !config.project.is_empty() {
        // Say what the imports resolve against: a wrong root is the difference between a
        // contract that compiles and one that does not, and it should not be a mystery.
        if let Some(base_path) = &config.project.base_path {
            println!("{} {}", info("Project root:"), base_path.display());
        }
        if !config.project.remappings.is_empty() {
            println!(
                "{} {}",
                info("Remappings:"),
                config.project.remappings.join(", ")
            );
        }
    }

    if args.dual_compile {
        let result = soldb_compiler::dual_compile(contract_file, &config);
        if args.json {
            print_json(&result)?;
        } else {
            match &result.production {
                Ok(production) => {
                    println!(
                        "Production build created in {}",
                        production.output_dir.display()
                    )
                }
                Err(error) => println!("Production build failed: {error}"),
            }
            match &result.debug {
                Ok(debug) => print_compile_result(debug),
                Err(error) => {
                    println!("ETHDebug build failed: {error}");
                    return Err(soldb_core::SoldbError::Message(error.clone()));
                }
            }
        }
        return Ok(());
    }

    let result = config.compile_with_ethdebug(contract_file, None)?;
    if args.json {
        print_json(&result)?;
    } else {
        print_compile_result(&result);
    }
    Ok(())
}

fn print_compile_result(result: &soldb_compiler::CompilationResult) {
    println!("ETHDebug compilation successful");
    println!("Output directory: {}", result.output_dir.display());
    if result.files.ethdebug.is_some() {
        println!("  - ethdebug.json");
    }
    for (contract_name, files) in &result.files.contracts {
        println!("Contract: {contract_name}");
        if let Some(path) = &files.bytecode {
            println!("  - {}", path.display());
        }
        if let Some(path) = &files.abi {
            println!("  - {}", path.display());
        }
        if let Some(path) = &files.ethdebug {
            println!("  - {}", path.display());
        }
        if let Some(path) = &files.ethdebug_runtime {
            println!("  - {}", path.display());
        }
    }
    if !result.stderr.trim().is_empty() {
        println!("Compiler warnings:");
        println!("{}", result.stderr.trim());
    }
}

fn bridge_command(args: &BridgeArgs) -> SoldbResult<()> {
    let verbose = !args.quiet;
    if verbose {
        println!("Cross-Environment Debug Bridge");
        println!("URL: http://{}:{}", args.host, args.port);
        println!(
            "Starting SolDB Cross-Environment Bridge on {}:{}...",
            args.host, args.port
        );
    }

    soldb_bridge::run_bridge_server(&args.host, args.port, verbose, args.config_file.as_deref())
        .map_err(|error| {
            soldb_core::SoldbError::Message(format!("Error starting bridge server: {error}"))
        })
}

fn trace_command(args: &TraceArgs) -> SoldbResult<()> {
    let traced = match &args.save_replay {
        Some(file) => {
            if matches!(args.backend, TraceBackendArg::DebugRpc) {
                return Err(soldb_core::SoldbError::Message(
                    "`--save-replay` records the replay backend; drop `--backend debug-rpc`"
                        .to_owned(),
                ));
            }
            soldb_rpc::record_replay(&args.rpc, &args.tx_hash).and_then(|(trace, bundle)| {
                write_replay_bundle(file, &bundle)?;
                if !args.json {
                    println!(
                        "{} {} to {}",
                        info("Saved"),
                        bundle.describe(),
                        file.display()
                    );
                }
                Ok(trace)
            })
        }
        None => soldb_rpc::trace_transaction_with_resolved_backend(
            &args.rpc,
            &args.tx_hash,
            args.backend.into(),
        )
        .map(|resolved| resolved.trace),
    };
    let trace = match traced {
        Ok(trace) => trace,
        Err(error) if args.json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "error": true,
                    "type": "TransactionError",
                    "message": error.to_string(),
                }))
                .map_err(|error| soldb_core::SoldbError::Message(error.to_string()))?
            );
            return Err(soldb_core::SoldbError::AlreadyReported);
        }
        Err(error) => return Err(error),
    };
    present_trace(
        &TraceView::for_trace(args),
        trace,
        args.interactive,
        args.json,
        args.raw,
    )
}

/// Shows a traced transaction the way the user asked: interactively, as the web
/// document, as raw steps, or as the summary. Shared by `trace` and `replay`.
fn present_trace(
    view: &TraceView,
    trace: TransactionTrace,
    interactive: bool,
    json: bool,
    raw: bool,
) -> SoldbResult<()> {
    if interactive {
        let source_indexes = interactive_trace_source_indexes(view, &trace);
        run_interactive_debugger(
            trace,
            "Transaction trace debugger",
            source_indexes,
            view.chain_storage(),
        )?;
    } else if json {
        println!(
            "{}",
            soldb_serializer::trace_to_web_json_with_contracts(
                &trace,
                trace_web_contracts(view, &trace)
            )?
        );
    } else if raw {
        print_raw_trace(&trace, view);
    } else {
        print_trace_summary(&trace, view);
    }

    Ok(())
}

/// Replays a recording with no node and shows it as `trace` or `simulate` would have.
fn replay_command(args: &ReplayArgs) -> SoldbResult<()> {
    let bundle = read_replay_bundle(&args.file)?;
    if !args.json {
        println!(
            "{} {} from {}; no node involved",
            info("Replaying"),
            bundle.describe(),
            args.file.display()
        );
    }
    let trace = bundle.replay()?;
    match &bundle.target {
        soldb_rpc::ReplayBundleTarget::Transaction { transaction, .. } => present_trace(
            &TraceView::for_replay(args, &transaction.hash),
            trace,
            args.interactive,
            args.json,
            args.raw,
        ),
        soldb_rpc::ReplayBundleTarget::Call { request, .. } => {
            let view = SimulationView::for_replay(args, request, &args.file);
            present_simulation(&view, trace, None, &request.calldata)
        }
    }
}

fn write_replay_bundle(path: &Path, bundle: &soldb_rpc::ReplayBundle) -> SoldbResult<()> {
    let json = serde_json::to_string_pretty(bundle)
        .map_err(|error| soldb_core::SoldbError::Message(error.to_string()))?;
    fs::write(path, json).map_err(|error| {
        soldb_core::SoldbError::Message(format!(
            "could not write the replay file `{}`: {error}",
            path.display()
        ))
    })
}

fn read_replay_bundle(path: &Path) -> SoldbResult<soldb_rpc::ReplayBundle> {
    let content = fs::read_to_string(path).map_err(|error| {
        soldb_core::SoldbError::Message(format!(
            "could not read the replay file `{}`: {error}",
            path.display()
        ))
    })?;
    serde_json::from_str(&content).map_err(|error| {
        soldb_core::SoldbError::Message(format!(
            "`{}` is not a replay file written by `--save-replay`: {error}",
            path.display()
        ))
    })
}

fn simulate_command(args: &SimulateArgs) -> SoldbResult<()> {
    let auto_deploy = maybe_auto_deploy(args)?;
    let contract_address = auto_deploy.as_ref().map_or_else(
        || args.contract_address.clone(),
        |deploy| deploy.contract_address.clone(),
    );
    let contract_name = auto_deploy
        .as_ref()
        .map(|deploy| deploy.contract_name.clone());
    let view = SimulationView::for_simulate(args, &contract_address);
    let calldata = match simulate_calldata(&view) {
        Ok(calldata) => calldata,
        Err(error) if args.json => {
            print_json_command_error("SimulationError", &error.to_string(), None)?;
            return Err(soldb_core::SoldbError::AlreadyReported);
        }
        Err(error) => return Err(error),
    };
    if let Err(message) = validate_simulate_value(&args.value) {
        if args.json {
            print_json_command_error("InvalidValue", &message, Some(&args.value))?;
            return Err(soldb_core::SoldbError::AlreadyReported);
        }
        return Err(soldb_core::SoldbError::Message(message));
    }

    let request = soldb_rpc::SimulateCallRequest {
        from_addr: args.from_addr.clone(),
        to_addr: contract_address.clone(),
        calldata: calldata.clone(),
        value: args.value.clone(),
        block: args.block,
        tx_index: args.tx_index,
    };
    let trace = match &args.save_replay {
        // Recording means replaying, whatever backend the flag names: a call has no
        // mined result, so replay is the only backend that can be recorded.
        Some(file) => {
            let (trace, bundle) = soldb_rpc::record_simulation_replay(&args.rpc_url, &request)?;
            write_replay_bundle(file, &bundle)?;
            if !args.json {
                println!(
                    "{} {} to {}",
                    info("Saved"),
                    bundle.describe(),
                    file.display()
                );
            }
            trace
        }
        None => {
            soldb_rpc::simulate_call_with_backend(&args.rpc_url, &request, args.backend.into())?
        }
    };
    present_simulation(&view, trace, contract_name.as_deref(), &calldata)
}

/// Shows a simulated call the way the user asked: interactively, as the web document, as
/// raw steps, or as the summary. Shared by `simulate` and `run`.
fn present_simulation(
    view: &SimulationView,
    trace: TransactionTrace,
    contract_name: Option<&str>,
    calldata: &str,
) -> SoldbResult<()> {
    let contract_address = view.contract_address.as_str();
    let json_function_name = simulate_json_function_name(view, calldata);
    let display_function_name = simulate_display_function_name(view, calldata);

    if view.interactive {
        print_simulation_interactive_prelude(
            view,
            contract_address,
            contract_name,
            calldata,
            &display_function_name,
        );
        let source_indexes = interactive_simulation_source_indexes(view, contract_address);
        run_interactive_debugger(
            trace,
            "Simulation debugger",
            source_indexes,
            view.chain_storage(),
        )?;
    } else if view.json {
        println!(
            "{}",
            soldb_serializer::simulate_to_web_json_with_contracts(
                &trace,
                &json_function_name,
                simulate_web_contracts(view, &trace, contract_address)
            )?
        );
    } else if view.raw {
        print_raw_simulation(&trace, view, contract_address);
    } else {
        print_simulation_summary(
            &trace,
            view,
            contract_address,
            contract_name,
            calldata,
            &display_function_name,
        );
    }

    Ok(())
}

/// Runs bytecode on a chain that exists only for this run.
///
/// Creation code is deployed first, from the caller at nonce zero, and the call runs in
/// the same synthetic block right after it, so whatever the constructor stored is what
/// the call sees. `--runtime` installs the bytes as they are instead, and `--deploy`
/// traces the constructor and stops. Everything after execution is `simulate`'s: the same
/// ETHDebug mapping, REPL, JSON document, and raw view.
fn run_command(args: &RunArgs) -> SoldbResult<()> {
    let bytecode = load_bytecode(&args.bytecode)?;
    let mut chain = soldb_rpc::LocalChain::new()
        .with_chain_id(args.chain_id)
        .with_block_number(args.block_number)
        .with_timestamp(args.timestamp)
        .with_gas_limit(args.gas_limit)
        .with_account(&args.from_addr, &args.balance, 0, "0x")?;

    let (contract_address, prefix) = if args.runtime {
        let address = args
            .address
            .clone()
            .unwrap_or_else(|| "0x5FbDB2315678afecB367f032d93F642f64180aa3".to_owned());
        chain = chain.with_account(&address, "0", 1, &bytecode)?;
        (normalize_contract_address_key(&address), Vec::new())
    } else {
        let created = soldb_rpc::LocalChain::created_address(&args.from_addr, 0)?;
        let init_code = format!("{bytecode}{}", run_constructor_args(args)?);
        // Under `--deploy` the constructor is the whole run, so `--value` is its value.
        let deployment_value = if args.deploy {
            &args.value
        } else {
            &args.constructor_value
        };
        let deployment = chain.deployment(&args.from_addr, &init_code, deployment_value, 0)?;
        (created, vec![deployment])
    };
    for entry in &args.storage {
        let Some((slot, value)) = entry.split_once('=') else {
            return Err(soldb_core::SoldbError::Message(format!(
                "invalid `--storage` entry `{entry}`; expected `<slot>=<value>`"
            )));
        };
        chain = chain.with_storage(&contract_address, slot.trim(), value.trim())?;
    }

    // Before saying the contract is there: a constructor that reverted leaves no code,
    // and the call would run against an empty account. The constructor runs again as the
    // call's prefix, which for a local run costs less than reporting a deployment that
    // did not happen.
    if !args.runtime && !args.deploy {
        if let Some(deployment) = prefix.first() {
            let deployed = chain.deploy(deployment)?;
            if !deployed.success {
                let reason = deployed
                    .error
                    .clone()
                    .or_else(|| {
                        deployed
                            .artifacts
                            .revert_data
                            .as_deref()
                            .and_then(soldb_rpc::decode_revert_reason)
                    })
                    .unwrap_or_else(|| "the constructor reverted".to_owned());
                return Err(soldb_core::SoldbError::Message(format!(
                    "the contract was not deployed: {reason}\nnote: pass the constructor's arguments with `--constructor-args`, one per argument"
                )));
            }
        }
    }

    let view = SimulationView::for_run(args, &contract_address);
    let contract_name = simulate_contract_name(&view);
    if !args.json {
        let what = if args.runtime {
            "Installed runtime code at"
        } else if args.deploy {
            "Deploying locally to"
        } else {
            "Deployed locally at"
        };
        println!("{} {}", info(what), address_color(&contract_address));
    }

    if args.deploy {
        let deployment = prefix.first().ok_or_else(|| {
            soldb_core::SoldbError::Message(
                "`--deploy` traces creation code; drop `--runtime` or pass creation bytecode"
                    .to_owned(),
            )
        })?;
        let trace = chain.deploy(deployment)?;
        let calldata = deployment.input_data.clone();
        return present_simulation(&view, trace, contract_name.as_deref(), &calldata);
    }

    let calldata = simulate_calldata(&view)?;
    let request = soldb_rpc::SimulateCallRequest {
        from_addr: args.from_addr.clone(),
        to_addr: contract_address.clone(),
        calldata: calldata.clone(),
        value: args.value.clone(),
        block: None,
        tx_index: None,
    };
    let trace = chain.call(&prefix, &request)?;
    if trace.steps.is_empty() {
        // The code is there — the deployment was checked — so the call reached nothing:
        // an address with no code, or runtime bytes that are not a contract.
        return Err(soldb_core::SoldbError::Message(format!(
            "the call executed no instructions; there is no code at `{contract_address}`\nnote: pass creation code, or `--runtime` with the deployed code"
        )));
    }
    present_simulation(&view, trace, contract_name.as_deref(), &calldata)
}

/// Reads bytecode from a file when `source` names one, otherwise treats it as hex.
fn load_bytecode(source: &str) -> SoldbResult<String> {
    let path = Path::new(source);
    let text = if path.is_file() {
        fs::read_to_string(path).map_err(|error| {
            soldb_core::SoldbError::Message(format!("failed to read `{}`: {error}", path.display()))
        })?
    } else {
        source.to_owned()
    };
    let hex = text.trim().trim_start_matches("0x");
    if hex.is_empty() {
        return Err(soldb_core::SoldbError::Message(format!(
            "`{source}` holds no bytecode"
        )));
    }
    if hex.len() % 2 != 0 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(soldb_core::SoldbError::Message(format!(
            "`{source}` is not hex bytecode; pass a `.bin` file or a hex string"
        )));
    }
    Ok(hex.to_ascii_lowercase())
}

/// ABI-encodes `--constructor-args` against the constructor found through
/// `--ethdebug-dir`, or reports that no ABI was found to encode them with.
fn run_constructor_args(args: &RunArgs) -> SoldbResult<String> {
    if args.constructor_args.is_empty() {
        return Ok(String::new());
    }
    let abi = resolve_contract_specs_reporting(&args.ethdebug_dir, args.contracts.as_deref(), &args.source_path)
        .iter()
        .find_map(abi_value_for_spec)
        .and_then(|abi| abi.as_array().cloned())
        .ok_or_else(|| {
            soldb_core::SoldbError::Message(
                "`--constructor-args` need the contract ABI; pass `--ethdebug-dir <address>:<name>:<dir>` with a `<name>.abi` in it"
                    .to_owned(),
            )
        })?;
    let encoded = soldb_compiler::encode_constructor_args(&abi, &args.constructor_args)?;
    Ok(encoded.trim_start_matches("0x").to_owned())
}

fn maybe_auto_deploy(args: &SimulateArgs) -> SoldbResult<Option<soldb_compiler::AutoDeployResult>> {
    let path = Path::new(&args.contract_address);
    if path.extension().and_then(|extension| extension.to_str()) != Some("sol") || !path.exists() {
        return Ok(None);
    }

    let mut config = soldb_compiler::AutoDeployConfig::new(path, args.rpc_url.clone());
    config.compiler = soldb_compiler::CompilerConfig::with_paths(
        args.solc_path.clone(),
        &args.output_dir,
        &args.production_dir,
    );
    config.dual_compile = args.dual_compile;
    config.verify_version = args.verify_version;
    config.save_config = args.save_config;
    config.constructor_args = args.constructor_args.clone();

    let result = soldb_compiler::auto_deploy(&config)?;
    println!(
        "Deployed {} at {}",
        result.contract_name, result.contract_address
    );
    println!("Deployment transaction: {}", result.transaction_hash);
    Ok(Some(result))
}

fn print_simulation_interactive_prelude(
    args: &SimulationView,
    contract_address: &str,
    auto_contract_name: Option<&str>,
    calldata: &str,
    function_name: &str,
) {
    let contract_name = auto_contract_name
        .map(str::to_owned)
        .or_else(|| simulate_contract_name(args))
        .unwrap_or_else(|| contract_address.to_owned());
    println!("{} {}", info("Contract:"), function_color(&contract_name));
    println!(
        "{} {}",
        info("Simulating"),
        function_color(format_simulated_call(args, function_name))
    );
    if let Some(source_file) = simulation_source_file(args, &contract_name) {
        println!("{}", dim(source_file));
    }
    println!("{} {}", dim("=> contract"), function_color(&contract_name));
    if !args.function_args.is_empty() {
        println!("{}", info("Parameters:"));
        let params = resolve_contract_specs_reporting(
            &args.ethdebug_dir,
            args.contracts.as_deref(),
            &args.source_path,
        )
        .into_iter()
        .find_map(|spec| call_descriptor_for_calldata(&spec, calldata))
        .map(|descriptor| descriptor.params)
        .unwrap_or_else(|| {
            args.function_args
                .iter()
                .enumerate()
                .map(|(index, value)| DecodedCallParam {
                    name: format!("arg{index}"),
                    ty: None,
                    value: value.clone(),
                    raw: false,
                })
                .collect()
        });
        for param in params {
            println!(
                "{} {}",
                info(format!("{}:", param.name)),
                number_color(param.value)
            );
        }
    }
}

fn interactive_trace_source_indexes(
    args: &TraceView,
    trace: &TransactionTrace,
) -> Vec<TraceSourceIndex> {
    let contract_address = trace.to_addr.as_ref().or(trace.contract_address.as_ref());
    source_indexes_for_specs(
        resolve_contract_specs_reporting(
            &args.ethdebug_dir,
            args.contracts.as_deref(),
            &args.source_path,
        ),
        contract_address.map(String::as_str),
    )
}

fn interactive_simulation_source_indexes(
    args: &SimulationView,
    contract_address: &str,
) -> Vec<TraceSourceIndex> {
    source_indexes_for_specs(
        resolve_contract_specs_reporting(
            &args.ethdebug_dir,
            args.contracts.as_deref(),
            &args.source_path,
        ),
        Some(contract_address),
    )
}

/// Loads every contract's debug info, the one deployed at `contract_address` first so it
/// is the default wherever a single contract is needed.
fn source_indexes_for_specs(
    specs: Vec<ResolvedContractSpec>,
    contract_address: Option<&str>,
) -> Vec<TraceSourceIndex> {
    let mut indexes = specs
        .iter()
        .filter_map(load_source_index)
        .collect::<Vec<_>>();
    if let Some(contract_address) = contract_address {
        if let Some(position) = indexes.iter().position(|index| {
            index
                .spec
                .address
                .as_deref()
                .is_some_and(|address| address.eq_ignore_ascii_case(contract_address))
        }) {
            let target = indexes.remove(position);
            indexes.insert(0, target);
        }
    }
    indexes
}

/// The chain a debugging session reads storage slots from, for slots the transaction
/// never touched.
///
/// The block is fixed when the session starts, so every answer is the state at one point
/// in history. The caching and the labelling are [`soldb_debugger::CachedChain`]'s; what
/// is here is which block to ask about and the reading itself.
struct NodeStorage;

impl NodeStorage {
    /// The state the traced transaction started from: the end of its parent block.
    ///
    /// A transaction that is not the first in its block ran after its neighbours, so a
    /// slot one of them wrote reads here as it was before the block. That is why the
    /// value is labelled with the block it came from rather than presented as the
    /// transaction's own starting state.
    fn before_transaction(rpc_url: &str, tx_hash: &str) -> Option<ChainReader> {
        let (block, _index) = match soldb_rpc::transaction_block(rpc_url, tx_hash) {
            Ok(found) => found,
            Err(error) => {
                report_once(
                    format!("chain-storage-block:{rpc_url}"),
                    &format!("could not find the block of the traced transaction: {error}"),
                    "state variables this transaction never touched stay unknown",
                );
                return None;
            }
        };
        let number = u64::from_str_radix(block.trim_start_matches("0x"), 16).ok()?;
        let parent = number.checked_sub(1)?;
        Some(Self::reader(
            rpc_url,
            format!("0x{parent:x}"),
            format!("the chain at block {parent}, before this transaction's block"),
        ))
    }

    /// The state a call was simulated on: the end of the block it ran on top of.
    fn at_block(rpc_url: &str, block: Option<u64>) -> Option<ChainReader> {
        let number = match block {
            Some(number) => number,
            None => match soldb_rpc::latest_block(rpc_url) {
                Ok(latest) => u64::from_str_radix(latest.trim_start_matches("0x"), 16).ok()?,
                Err(error) => {
                    report_once(
                        format!("chain-storage-latest:{rpc_url}"),
                        &format!("could not resolve the latest block: {error}"),
                        "state variables this call never touched stay unknown",
                    );
                    return None;
                }
            },
        };
        Some(Self::reader(
            rpc_url,
            format!("0x{number:x}"),
            format!("the chain at block {number}"),
        ))
    }

    fn reader(rpc_url: &str, block: String, label: String) -> ChainReader {
        let rpc_url = rpc_url.to_owned();
        let read: ChainRead = Box::new(move |address: &str, slot: &[u8; 32]| {
            match soldb_rpc::storage_at(&rpc_url, address, &soldb_ethdebug::word_hex(slot), &block)
            {
                Ok(value) => soldb_ethdebug::parse_word(&value).ok(),
                Err(error) => {
                    report_once(
                        format!("chain-storage-read:{rpc_url}"),
                        &format!("could not read storage from the node: {error}"),
                        "state variables the transaction never touched stay unknown",
                    );
                    None
                }
            }
        });
        CachedChain::new(label, read)
    }
}

/// What a session reads untouched slots through.
type ChainReader = CachedChain<ChainRead>;

fn run_interactive_debugger(
    trace: TransactionTrace,
    title: &str,
    source_indexes: Vec<TraceSourceIndex>,
    chain: Option<ChainReader>,
) -> SoldbResult<()> {
    let contract_address = trace.to_addr.clone().or(trace.contract_address.clone());
    let mut state = DebuggerState::new();
    state.load_trace(trace);
    state.attach_debug_info(
        source_indexes
            .iter()
            .map(|index| index.debug.clone())
            .collect(),
    );

    println!("{}", bold(info("Starting interactive debugger...")));
    if let Some(address) = contract_address {
        println!("{} {}", info("Contract found:"), address_color(address));
    }
    println!(
        "Transaction loaded. {} steps.",
        number_color(state.step_count())
    );
    println!(
        "Loaded trace with {} steps",
        number_color(state.step_count())
    );
    println!("{}", bold(info(title)));
    print_current_debugger_step(&state);

    let stdin = io::stdin();
    let mut line = String::new();
    loop {
        print!("soldb> ");
        io::stdout()
            .flush()
            .map_err(|error| soldb_core::SoldbError::Message(error.to_string()))?;

        line.clear();
        let bytes_read = stdin
            .read_line(&mut line)
            .map_err(|error| soldb_core::SoldbError::Message(error.to_string()))?;
        if bytes_read == 0 {
            println!();
            break;
        }

        let command = DebuggerCommand::parse(&line);
        let report_note = |state: &DebuggerState| {
            if let Some(note) = state.take_note() {
                println!("{} {note}", warning("Note:"));
            }
        };
        match command {
            DebuggerCommand::Empty => {}
            DebuggerCommand::Quit => {
                println!("{}", info("Exiting debugger."));
                break;
            }
            DebuggerCommand::Help(topic) => print_debugger_help(topic.as_deref()),
            DebuggerCommand::Mode(None) => {
                println!("{} {}", info("Mode:"), bold(state.display_mode.as_str()));
            }
            DebuggerCommand::Info(DebuggerInfoCommand::Resources { json }) => {
                if let Err(error) = print_debugger_resources(source_indexes.first(), json) {
                    println!("{} {}", warning("Could not print resources:"), error);
                }
            }
            DebuggerCommand::Info(DebuggerInfoCommand::Breakpoints) => {
                print_debugger_breakpoints(&state);
            }
            DebuggerCommand::Info(DebuggerInfoCommand::Storage) => print_debugger_storage(&state),
            DebuggerCommand::Vars => {
                print_debugger_variables(&state, &source_indexes, chain.as_ref(), None);
            }
            DebuggerCommand::Print(name) => {
                let name = name.trim();
                if name.is_empty() {
                    println!("{} print <variable>", warning("Usage:"));
                } else {
                    print_debugger_variables(&state, &source_indexes, chain.as_ref(), Some(name));
                }
            }
            DebuggerCommand::Backtrace => print_debugger_backtrace(&state),
            DebuggerCommand::List => print_debugger_listing(&state),
            DebuggerCommand::Memory { offset, length } => {
                print_debugger_memory(&state, offset, length);
            }
            DebuggerCommand::Calldata => print_debugger_calldata(&state),
            DebuggerCommand::Stack => print_debugger_stack(&state),
            DebuggerCommand::Unknown(command) => {
                println!("{} {}", warning("Unknown command:"), command);
            }
            command => {
                if let Some(outcome) = state.apply_command(command) {
                    print_step_outcome(&state, &outcome);
                }
                report_note(&state);
            }
        }
    }

    Ok(())
}

fn print_debugger_resources(
    source_index: Option<&TraceSourceIndex>,
    json_output: bool,
) -> SoldbResult<()> {
    let Some(source_index) = source_index else {
        println!("{}", warning("ETHDebug resources are not loaded."));
        return Ok(());
    };

    let contract = InfoResourcesContractJson {
        address: source_index.spec.address.clone(),
        name: source_index.spec.name.clone(),
        debug_dir: source_index.spec.debug_dir.display().to_string(),
        resources: source_index.resources.clone(),
    };

    if json_output {
        print_json(&InfoResourcesJson {
            contracts: vec![contract],
        })
    } else {
        print_info_resources(&[contract]);
        Ok(())
    }
}

fn print_current_debugger_step(state: &DebuggerState) {
    let Some(step) = state.current_step_data() else {
        println!("{}", warning("No trace loaded."));
        return;
    };
    let max_step = state.step_count().saturating_sub(1);
    println!(
        "Step {}/{} | PC {} | {} | gas {}",
        number_color(state.current_step),
        number_color(max_step),
        number_color(step.pc),
        opcode_color(&step.op),
        success(step.gas)
    );
    println!(
        "Step {}/{}",
        number_color(state.current_step),
        number_color(max_step)
    );
    println!(
        "PC: {} | {} | Gas: {} |",
        number_color(step.pc),
        opcode_color(&step.op),
        success(step.gas)
    );
    println!(
        "[ Step {} | Gas: {} | PC: {} | {} ]",
        number_color(state.current_step),
        success(step.gas),
        number_color(step.pc),
        opcode_color(&step.op)
    );
    match state.display_mode {
        DisplayMode::Source => print_debugger_location(state),
        DisplayMode::Assembly => {
            let stack = step.snapshot_ref().stack;
            if !stack.is_empty() {
                println!("{} {}", info("Stack:"), format_stack(stack));
            }
        }
    }
}

/// Where the current step is in the source: file, line, function, and the line's text.
/// Says so when a mapped trace has no source for this step, and stays quiet when no
/// source is loaded at all.
fn print_debugger_location(state: &DebuggerState) {
    let Some(location) = state.location() else {
        if state.has_source() {
            let address = state
                .step_map()
                .and_then(|map| map.executing_address(state.current_step))
                .map(|address| format!(" in {}", address_color(address)))
                .unwrap_or_default();
            println!("{}", dim(format!("no source for this step{address}")));
        }
        return;
    };
    let function = location
        .function_name
        .as_deref()
        .map(|name| format!(" in {}", function_color(name)))
        .unwrap_or_default();
    let generated = if location.generated {
        dim("  (compiler-generated code for this line)")
    } else {
        String::new()
    };
    println!(
        "{}:{}{}{}",
        info(&location.path),
        number_color(location.line),
        function,
        generated
    );
    let text = state
        .step_map()
        .and_then(|map| map.contracts().get(location.key.contract))
        .and_then(|contract| contract.line_text(location.key.source_id, location.line));
    if let Some(text) = text {
        println!("{} {}", dim(format!("{:>5} |", location.line)), text);
    }
}

fn print_step_outcome(state: &DebuggerState, outcome: &StepOutcome) {
    match outcome {
        StepOutcome::NoTrace => println!("{}", warning("No trace loaded.")),
        StepOutcome::Moved { .. } => print_current_debugger_step(state),
        StepOutcome::BreakpointHit {
            step,
            pc,
            breakpoint,
        } => {
            let detail = if matches!(breakpoint.kind, BreakpointKind::Pc(_)) {
                format!("PC {}", number_color(pc))
            } else {
                format!("{}, PC {}", breakpoint.label(), number_color(pc))
            };
            println!(
                "{} step {}, {detail}",
                success(format!("Breakpoint #{} hit at", breakpoint.id)),
                number_color(step)
            );
            print_current_debugger_step(state);
        }
        StepOutcome::AtEnd { step } => {
            println!("{} {}", info("End of trace at step"), number_color(step));
            print_current_debugger_step(state);
        }
        StepOutcome::AtStart { step } => {
            println!("{} {}", info("Start of trace at step"), number_color(step));
            print_current_debugger_step(state);
        }
        StepOutcome::InvalidStep {
            requested,
            max_step,
        } => match max_step {
            Some(max_step) => println!(
                "{} {}; max step is {}",
                warning("Invalid step"),
                number_color(requested),
                number_color(max_step)
            ),
            None => println!(
                "{} {}; trace is empty",
                warning("Invalid step"),
                number_color(requested)
            ),
        },
        StepOutcome::ModeChanged(mode) => println!("{} {}", info("Mode:"), bold(mode.as_str())),
        StepOutcome::BreakpointSet(breakpoint) => {
            println!(
                "{} {}",
                success(format!("Breakpoint #{} set at", breakpoint.id)),
                breakpoint.label()
            );
        }
        StepOutcome::BreakpointCleared(breakpoint) => {
            println!(
                "{} {}",
                info(format!("Breakpoint #{} cleared at", breakpoint.id)),
                breakpoint.label()
            );
        }
        StepOutcome::BreakpointMissing(label) => {
            println!("{} {}", warning("No breakpoint set at"), label);
        }
        StepOutcome::BreakpointError(message) => {
            println!("{} {}", warning("Could not set breakpoint:"), message);
        }
    }
}

fn print_debugger_breakpoints(state: &DebuggerState) {
    let breakpoints = state.breakpoints();
    if breakpoints.is_empty() {
        println!("{}", dim("No breakpoints set."));
        return;
    }
    for breakpoint in breakpoints {
        println!("#{} {}", number_color(breakpoint.id), breakpoint.label());
    }
}

/// The call structure at the current step, innermost frame first: the function or, for a
/// frame without source, the contract or address executing, where it is, and the step
/// and program counter it sits at.
fn print_debugger_backtrace(state: &DebuggerState) {
    let frames = state.frames();
    if frames.is_empty() {
        println!("{}", warning("No trace loaded."));
        return;
    }
    if frames.iter().any(|frame| !frame.arguments.is_empty()) {
        // These values are read off the stack, not reported by the compiler. The order was
        // proved from this trace, but say so: it is an inference about the whole contract
        // drawn from the frames the trace happened to contain.
        report_once(
            "frame-arguments".to_owned(),
            "frame arguments are read off the stack, not from compiler-reported variable locations",
            "the calling convention was proved from this trace's calldata; ETHDebug variable locations will replace this once the compiler emits them",
        );
    }
    for (index, frame) in frames.iter().enumerate() {
        let name = frame
            .function_name
            .clone()
            .or_else(|| frame.contract_name.clone())
            .or_else(|| frame.address.clone())
            .unwrap_or_else(|| "<unknown>".to_owned());
        let mut line = format!("#{index:<2} {}", function_color(&name));
        if !frame.arguments.is_empty() {
            let arguments = frame
                .arguments
                .iter()
                .map(|argument| format!("{} = {}", argument.name, argument.value.display))
                .collect::<Vec<_>>()
                .join(", ");
            line.push_str(&format!("({arguments})"));
        }
        if let Some(location) = &frame.location {
            line.push_str(&format!(" at {}:{}", location.path, location.line));
        }
        if frame.external && frame.function_name.is_some() {
            if let Some(address) = &frame.address {
                line.push_str(&format!(" ({})", address_color(address)));
            }
        }
        line.push_str(&dim(format!("  step {}, PC {}", frame.step, frame.pc)));
        println!("{line}");
    }
}

/// Five lines of source on each side of the current step's line, the current one marked.
fn print_debugger_listing(state: &DebuggerState) {
    let Some(listing) = state.source_listing(5) else {
        if state.has_source() {
            println!("{}", warning("No source for this step."));
        } else {
            println!(
                "{} no ETHDebug metadata is loaded; start the session with `--ethdebug-dir <address>:<contract>:<dir>`",
                warning("Cannot list source:")
            );
        }
        return;
    };
    println!(
        "{}:{}",
        info(&listing.path),
        number_color(listing.current_line)
    );
    for (line, text) in &listing.lines {
        if *line == listing.current_line {
            println!("{} {}", bold(format!("=> {line:>5} |")), bold(text));
        } else {
            println!("{} {}", dim(format!("   {line:>5} |")), text);
        }
    }
}

/// Memory at the current step in 32-byte words, the whole of it or one range.
fn print_debugger_memory(state: &DebuggerState, offset: Option<u64>, length: Option<u64>) {
    let Some(step) = state.current_step_data() else {
        println!("{}", warning("No trace loaded."));
        return;
    };
    let Some(memory) = step.snapshot_ref().memory else {
        let captured = state.trace().is_some_and(|trace| trace.capabilities.memory);
        if captured {
            println!("{}", dim("Memory is empty at this step."));
        } else {
            println!("{}", warning("Memory was not captured by this backend."));
        }
        return;
    };
    let hex = memory.trim_start_matches("0x");
    if hex.is_empty() {
        println!("{}", dim("Memory is empty at this step."));
        return;
    }
    if !hex.is_ascii() {
        // Not hex at all; show it as the backend sent it rather than slicing into it.
        println!("{} {}", info("Memory:"), hex);
        return;
    }
    let total = hex.len() / 2;
    let start = usize::try_from(offset.unwrap_or(0)).unwrap_or(usize::MAX);
    if start >= total {
        println!(
            "{} memory is {} bytes; offset {} is past the end",
            warning("Nothing to show:"),
            number_color(total),
            number_color(start)
        );
        return;
    }
    let end = length
        .and_then(|length| usize::try_from(length).ok())
        .and_then(|length| start.checked_add(length))
        .map_or(total, |end| end.min(total));
    let range = if start > 0 || end < total {
        format!(", showing bytes {start}..{end}")
    } else {
        String::new()
    };
    println!("{} {} bytes{}", info("Memory:"), number_color(total), range);
    let bytes = hex.as_bytes();
    let mut word_start = start;
    while word_start < end {
        let word_end = word_start.saturating_add(32).min(end);
        let word = std::str::from_utf8(&bytes[word_start * 2..word_end * 2]).unwrap_or("");
        println!("{} {word}", dim(format!("0x{word_start:04x}:")));
        word_start = word_end;
    }
}

/// Every slot whose value is known at the current step: what the transaction has read or
/// written so far in this frame's storage, not only what the current opcode touched.
fn print_debugger_storage(state: &DebuggerState) {
    if state.current_step_data().is_none() {
        println!("{}", warning("No trace loaded."));
        return;
    }
    let captured = state
        .trace()
        .is_some_and(|trace| trace.capabilities.storage);
    if !captured {
        println!(
            "{}",
            warning("Storage was not captured by this backend; the debug-rpc node returned no per-step storage.")
        );
        return;
    }
    let known = state
        .storage_words()
        .map(|words| words.known())
        .unwrap_or_default();
    if known.is_empty() {
        println!("{}", dim("Storage: no slots read or written yet."));
        return;
    }
    match state.storage_address() {
        Some(address) => println!("{} {}", info("Storage:"), dim(format!("of {address}"))),
        None => println!("{}", info("Storage:")),
    }
    // The slots this step itself changed, so a stop at an `SSTORE` shows what moved.
    let changed = state
        .current_step_data()
        .map(|step| step.snapshot_ref().storage_diff.clone())
        .unwrap_or_default();
    for (slot, value) in known {
        let slot = soldb_debugger::short_hex(&slot);
        let change = changed
            .iter()
            .find(|(candidate, _)| normalize_storage_slot(candidate) == slot)
            .map(|(_, change)| {
                dim(format!(
                    "  (was {})",
                    change.before.as_deref().unwrap_or("0x0")
                ))
            })
            .unwrap_or_default();
        println!(
            "  {} = {}{}",
            slot,
            soldb_debugger::short_hex(&value),
            change
        );
    }
}

/// A recorded slot as `print_debugger_storage` prints it: `0x`-prefixed, no leading
/// zeros.
fn normalize_storage_slot(slot: &str) -> String {
    let digits = slot.trim_start_matches("0x").trim_start_matches('0');
    if digits.is_empty() {
        "0x0".to_owned()
    } else {
        format!("0x{}", digits.to_ascii_lowercase())
    }
}

fn print_debugger_calldata(state: &DebuggerState) {
    if state.trace().is_none() {
        println!("{}", warning("No trace loaded."));
        return;
    }
    match state.calldata() {
        Some(calldata) => {
            let bytes = calldata.trim_start_matches("0x").len() / 2;
            println!("{} {} bytes", info("Calldata:"), number_color(bytes));
            println!("{calldata}");
        }
        None => println!(
            "{}",
            warning("Calldata for this frame was not recorded by the backend; only the root frame's is known.")
        ),
    }
}

fn print_debugger_stack(state: &DebuggerState) {
    let Some(step) = state.current_step_data() else {
        println!("{}", warning("No trace loaded."));
        return;
    };
    let stack = step.snapshot_ref().stack;
    if stack.is_empty() {
        println!("{}", dim("Stack: empty"));
    } else {
        println!("{} {}", info("Stack:"), format_stack(stack));
    }
}

/// Prints the source variables ETHDebug reports as live at the current program counter.
///
/// With `filter` set, only the variable of that name is printed. This is the terminal
/// counterpart of the DAP `variables` request; both go through
/// `soldb_debugger::variables_for_step` so the two frontends decode identically. The
/// variables come from the contract whose code the step executes, when that is known.
fn print_debugger_variables(
    state: &DebuggerState,
    source_indexes: &[TraceSourceIndex],
    chain: Option<&ChainReader>,
    filter: Option<&str>,
) {
    let executing = state
        .step_map()
        .and_then(|map| map.executing_address(state.current_step));
    let index = executing
        .and_then(|address| {
            source_indexes.iter().find(|index| {
                index
                    .spec
                    .address
                    .as_deref()
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(address))
            })
        })
        .or_else(|| source_indexes.first());
    let Some(index) = index else {
        println!(
            "{} no ETHDebug metadata is loaded; start the session with `--ethdebug-dir <address>:<contract>:<dir>`",
            warning("Cannot read variables:")
        );
        return;
    };
    let Some(trace) = state.trace() else {
        println!("{} no trace is loaded", warning("Cannot read variables:"));
        return;
    };
    let Some(step) = state.current_step_data() else {
        println!(
            "{} step {} is outside the loaded trace",
            warning("Cannot read variables:"),
            state.current_step
        );
        return;
    };

    let variables = soldb_debugger::variables_for_step(trace, &index.debug.info, step);
    let words = state.storage_words_with_chain(chain.map(|chain| chain as &dyn ChainStorage));
    let layout = state
        .storage_layout()
        .or(index.debug.storage_layout.as_ref());

    let print_value = |ty: &str, name: &str, value: &soldb_debugger::DebugValue, place: String| {
        let shown = match value.status {
            soldb_debugger::DebugValueStatus::Unavailable => warning(&value.display),
            _ => success(&value.display),
        };
        println!("{} {} = {} {}", info(ty), bold(name), shown, dim(place));
    };
    let print_variable = |variable: &soldb_debugger::DebugVariable| {
        print_value(
            &variable.ty,
            &variable.name,
            &variable.value,
            format!("[{}+{}]", variable.location.kind, variable.location.offset),
        );
    };
    let chain_label = words.as_ref().and_then(StorageWords::chain_label);
    let print_state = |variable: &soldb_debugger::StateVariable| {
        let mut place = if variable.offset == 0 {
            format!("[slot {}", variable.slot)
        } else {
            format!("[slot {} + {}", variable.slot, variable.offset)
        };
        // A value the transaction never touched came from the chain; say so, because it
        // is the state before the transaction, not a step of it.
        if variable.source == soldb_debugger::StateSource::Chain {
            place.push_str(&format!(", from {}", chain_label.unwrap_or("the chain")));
        }
        place.push(']');
        print_value(&variable.ty, &variable.name, &variable.value, place);
    };

    if let Some(name) = filter {
        if let Some(variable) = variables.iter().find(|variable| variable.name == name) {
            print_variable(variable);
            return;
        }
        let (Some(layout), Some(words)) = (layout, words) else {
            println!(
                "{} `{name}` is not in scope at PC {}; state variables need a storage layout, compile with `--storage-layout`",
                warning("No such variable:"),
                number_color(step.pc)
            );
            return;
        };
        match soldb_debugger::state_value(layout, &words, name) {
            Ok(variable) => print_state(&variable),
            Err(error) => {
                println!(
                    "{} `{name}` is not in scope at PC {}; {error}",
                    warning("No such variable:"),
                    number_color(step.pc)
                );
                if !index.debug.info.has_variable_locations() {
                    println!(
                        "{} this artifact carries no ETHDebug variable locations, so a local of that name cannot be looked up; the compiler that produced it does not emit them yet",
                        dim("note:")
                    );
                }
            }
        }
        return;
    }

    if variables.is_empty() {
        if index.debug.info.has_variable_locations() {
            println!(
                "{} no variables in scope at PC {}",
                dim("Variables:"),
                number_color(step.pc)
            );
        } else {
            // The difference matters: the compiler described no variables at all, which is
            // not the same as none being live here.
            println!(
                "{} this artifact carries no ETHDebug variable locations, so locals cannot be shown; the compiler that produced it does not emit them yet",
                dim("Variables:")
            );
        }
    }
    for variable in &variables {
        print_variable(variable);
    }
    match (layout, words) {
        // A contract can have a layout and no state variables at all, which is worth
        // saying: an empty `State:` heading reads like something failed.
        (Some(layout), _) if layout.variables.is_empty() => println!(
            "{}",
            dim("State: this contract declares no state variables")
        ),
        (Some(layout), Some(words)) => {
            println!("{}", dim("State:"));
            for variable in soldb_debugger::state_variables(layout, &words) {
                print_state(&variable);
            }
        }
        _ => println!(
            "{}",
            dim("State: no storage layout loaded; compile with `--storage-layout` to read state variables")
        ),
    }
}

fn print_debugger_help(topic: Option<&str>) {
    match topic {
        Some("mode") => println!("mode source|asm - switch display mode"),
        Some("info") => {
            println!("info resources [--json] - print loaded ETHDebug resources");
            println!("info breakpoints - list breakpoints with their numbers");
            println!("info storage - print the contract's storage at the current step");
        }
        Some("vars" | "locals" | "print") => {
            println!("vars - print the variables live at the current PC, the frame's arguments at entry, and every state variable");
            println!("print <variable> - print one variable by name");
            println!("print <state>[<key>] | <state>[<i>] | <state>.<member> - read a mapping entry, an array element, or a struct member from storage");
        }
        Some("break" | "b" | "clear" | "delete") => {
            println!("break <pc> - stop at a program counter");
            println!(
                "break <file>:<line> | break line <line> - stop when a source line is entered"
            );
            println!(
                "break <function> | break <Contract>.<function> - stop when a function is entered"
            );
            println!("break storage <slot> - stop at an SSTORE to a slot");
            println!("break revert - stop at a REVERT or a failing step");
            println!("break call [<address>] - stop at a call, to one address or to any");
            println!("break op <OPCODE> - stop at every execution of an opcode");
            println!("break <target> if <condition> - stop there only when the condition holds,");
            println!("    over state variables, the frame's arguments, and pc/gas/depth/op/step,");
            println!("    compared with == != < <= > >= and joined with && or ||");
            println!("clear <target> - remove the breakpoint set with that target");
            println!("delete <n> - remove breakpoint number n");
        }
        Some("next" | "step" | "finish" | "continue" | "reverse") => {
            println!("next (n) - run to the next source line, stepping over calls");
            println!("step (s) - run to the next source line, entering calls");
            println!("nexti (ni) - execute one EVM instruction");
            println!("finish (fin) - run until the current frame returns");
            println!("continue (c) - run to the next breakpoint or the end");
            println!("Each has a reverse form: reverse-next (rn), reverse-step (rs), reverse-nexti (back),");
            println!("reverse-finish (rfin), reverse-continue (rc). Without debug info next and step move one instruction.");
        }
        Some("backtrace" | "bt" | "list" | "memory" | "stack" | "storage" | "calldata") => {
            println!("backtrace (bt) - the call frames at the current step, innermost first");
            println!("list (l) - the source around the current step");
            println!("stack - the EVM stack at the current step");
            println!("memory [offset [length]] - memory at the current step, in 32-byte words");
            println!("storage - the contract's storage at the current step");
            println!("calldata - the calldata of the current frame");
        }
        Some(topic) => println!("No help for {topic}"),
        None => {
            println!(
                "Stepping: next (n), step (s), nexti (ni), finish (fin), continue (c), goto <step>"
            );
            println!("Reverse:  reverse-next (rn), reverse-step (rs), reverse-nexti (back), reverse-finish (rfin), reverse-continue (rc)");
            println!("Break:    break <pc>|<file>:<line>|line <line>|<function>|storage <slot>|revert|call [<address>]|op <OPCODE>");
            println!("          break <target> if <condition>, e.g. break line 30 if counter > 4");
            println!("          clear <target>, delete <n>, info breakpoints");
            println!("Inspect:  backtrace (bt), list (l), vars, print <variable>|<state>[<key>], stack, memory [offset [length]], storage, calldata");
            println!("Other:    info resources [--json], mode source|asm, help <command>, quit");
        }
    }
}

fn list_events_command(args: &ListEventsArgs) -> SoldbResult<()> {
    let logs = match soldb_rpc::transaction_logs(&args.rpc_url, &args.tx_hash) {
        Ok(logs) => logs,
        Err(error) if args.json_events => {
            print_json_command_error("TransactionReceiptError", &error.to_string(), None)?;
            return Err(soldb_core::SoldbError::AlreadyReported);
        }
        Err(error) => return Err(error),
    };
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
        if !matches!(&*step.op, "CALL" | "DELEGATECALL" | "STATICCALL") {
            continue;
        }
        let Some(address_word) = call_target_stack_word(step.snapshot_ref().stack) else {
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

fn print_trace_summary(trace: &TransactionTrace, args: &TraceView) {
    let Some(spec) = trace_contract_spec(args) else {
        print_plain_trace_summary(trace);
        return;
    };
    let metadata = trace_debug_metadata(&spec);

    println!(
        "{} {}",
        info("Loading transaction"),
        address_color(trace.tx_hash.as_deref().unwrap_or("<simulated>"))
    );
    if metadata.is_legacy {
        println!("{} {}", info("Debug format:"), bold("srcmap-runtime"));
    }
    print_trace_backend_details(trace);
    println!("{} {}", info("Contract:"), function_color(&spec.name));
    if let Some(version) = metadata.compiler_version {
        if let Some(name) = metadata.compiler_name {
            println!(
                "{} {} {}",
                info("Compiler:"),
                bold(name),
                number_color(version)
            );
        } else {
            println!("{} {}", info("Compiler version:"), number_color(version));
        }
    }
    println!("{} {}", info("Gas used:"), success(trace.gas_used));
    let status = if trace.success {
        success("SUCCESS")
    } else {
        error_color("REVERTED")
    };
    println!("{} {}", info("Status:"), status);
    if let Some(error) = &trace.error {
        println!("{} {}", error_color("Error:"), error_color(error));
    }
    println!();
    println!("{}", bold(info("Call Stack:")));
    println!("{}", separator(60));
    println!(
        "{} {}",
        dim("#0"),
        function_color(format!("{}::runtime_dispatcher", spec.name))
    );
    print_call_frames(&build_trace_call_frames(trace, &spec, None));
    print_trace_event_lines(trace, &trace_event_registry(args));
    println!("{}", separator(60));
    println!(
        "{}",
        dim("Use --raw flag to see detailed instruction trace")
    );
}

fn print_plain_trace_summary(trace: &TransactionTrace) {
    println!(
        "{} {}",
        info("Transaction"),
        address_color(trace.tx_hash.as_deref().unwrap_or("<simulated>"))
    );
    print_trace_backend_details(trace);
    let status = if trace.success {
        success("SUCCESS")
    } else {
        error_color("REVERTED")
    };
    println!("{} {}", info("Status:"), status);
    println!("{} {}", info("Gas used:"), success(trace.gas_used));
    println!("{} {}", info("Steps:"), number_color(trace.steps.len()));
    if let Some(error) = &trace.error {
        println!("{} {}", error_color("Error:"), error_color(error));
    }
}

fn print_trace_backend_details(trace: &TransactionTrace) {
    for note in &trace.capabilities.notes {
        println!("{} {}", warning("Capability note:"), note);
    }

    if let Some(gas) = &trace.artifacts.gas {
        let mut gas_parts = Vec::new();
        if let Some(spent) = gas.spent {
            gas_parts.push(format!("spent={spent}"));
        }
        if let Some(refunded) = gas.refunded {
            gas_parts.push(format!("refunded={refunded}"));
        }
        if !gas_parts.is_empty() {
            println!(
                "{} {}",
                info("Gas details:"),
                number_color(gas_parts.join(", "))
            );
        }
    }
}

fn print_raw_trace(trace: &TransactionTrace, args: &TraceView) {
    println!(
        "{} {}",
        info("Loading transaction"),
        address_color(&args.tx_hash)
    );
    if let Some(contract_name) = trace_contract_name(args) {
        println!("{} {}", info("Contract:"), function_color(contract_name));
    }
    print_trace_backend_details(trace);
    println!("{}", bold(info("Execution trace")));
    println!(
        "{} | {} | {} | {} | {} | {}",
        bold("Step"),
        bold("PC"),
        bold("Op"),
        bold("Gas"),
        bold("Stack"),
        bold("State")
    );

    let max_steps = if args.max_steps < 0 {
        trace.steps.len()
    } else {
        usize::try_from(args.max_steps).unwrap_or(trace.steps.len())
    };

    for (index, step) in trace.steps.iter().take(max_steps).enumerate() {
        let snapshot = step.snapshot_ref();
        println!(
            "{} | {} | {} | {} | {} | {}",
            number_color(format!("{index:>4}")),
            number_color(format!("{:>4}", step.pc)),
            opcode_color(format!("{:<14}", step.op)),
            success(format!("{:>8}", step.gas)),
            format_stack(snapshot.stack),
            format_snapshot_state(snapshot)
        );
    }
}

fn print_raw_simulation(trace: &TransactionTrace, args: &SimulationView, contract_address: &str) {
    println!(
        "{} {}",
        info("Simulating call to"),
        address_color(contract_address)
    );
    if let Some(contract_name) = simulate_contract_name(args) {
        println!("{} {}", info("Contract:"), function_color(contract_name));
    }
    print_trace_backend_details(trace);
    println!("{}", bold(info("Execution trace")));
    println!(
        "{} | {} | {} | {} | {} | {}",
        bold("Step"),
        bold("PC"),
        bold("Op"),
        bold("Gas"),
        bold("Stack"),
        bold("State")
    );

    let max_steps = if args.max_steps < 0 {
        trace.steps.len()
    } else {
        usize::try_from(args.max_steps).unwrap_or(trace.steps.len())
    };

    for (index, step) in trace.steps.iter().take(max_steps).enumerate() {
        let snapshot = step.snapshot_ref();
        println!(
            "{} | {} | {} | {} | {} | {}",
            number_color(format!("{index:>4}")),
            number_color(format!("{:>4}", step.pc)),
            opcode_color(format!("{:<14}", step.op)),
            success(format!("{:>8}", step.gas)),
            format_stack(snapshot.stack),
            format_snapshot_state(snapshot)
        );
    }
}

fn print_simulation_summary(
    trace: &TransactionTrace,
    args: &SimulationView,
    contract_address: &str,
    auto_contract_name: Option<&str>,
    raw_data: &str,
    function_name: &str,
) {
    let contract_name = auto_contract_name
        .map(str::to_owned)
        .or_else(|| simulate_contract_name(args))
        .unwrap_or_else(|| contract_address.to_owned());
    let has_debug_info = !args.ethdebug_dir.is_empty() || args.contracts.is_some();
    // Where the call ran is worth a line whenever no node was involved; the node's URL
    // is only interesting when nothing else identifies the session.
    match (&args.rpc_url, &args.replayed_from) {
        (Some(rpc_url), _) if !has_debug_info => {
            println!("{} {}", info("Connecting to RPC:"), address_color(rpc_url));
        }
        (Some(_), _) => {}
        (None, Some(file)) => println!(
            "{} {}; no node involved",
            info("Replayed from"),
            file.display()
        ),
        (None, None) => println!("{}", info("Running on a local chain; no node involved")),
    }
    if !has_debug_info {
        if let Some(signature) = &args.function_signature {
            println!(
                "{} {}",
                warning("No ABI files found. Proceeding with function signature:"),
                function_color(signature)
            );
        }
    }
    println!("{} {}", info("Contract:"), function_color(&contract_name));
    print_trace_backend_details(trace);
    println!("{} {}", info("Gas used:"), success(trace.gas_used));
    let status = if trace.success {
        success("SUCCESS")
    } else {
        error_color("REVERTED")
    };
    println!("{} {}", info("Status:"), status);
    if let Some(error) = &trace.error {
        println!("{} {}", error_color("Error:"), error_color(error));
    }
    println!();
    println!("{}", bold(info("Call Stack:")));
    println!("{}", separator(60));
    println!(
        "{} {}",
        dim("#0"),
        function_color(format!("{contract_name}::runtime_dispatcher"))
    );
    let fallback = simulated_call_descriptor(args, raw_data, function_name);
    print_call_frames(&build_simulation_call_frames(
        trace, args, raw_data, fallback,
    ));
    print_trace_event_lines(trace, &simulate_event_registry(args));
    println!("{}", separator(60));
    println!(
        "{}",
        dim("Use --raw flag to see detailed instruction trace")
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallFrame {
    name: String,
    params: Vec<DecodedCallParam>,
    source_params: Vec<SourceParam>,
    source_path: Option<String>,
    source_line: Option<u64>,
    raw_stack: Vec<StackWord>,
    internal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CallDescriptor {
    name: String,
    params: Vec<DecodedCallParam>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedCallParam {
    name: String,
    ty: Option<String>,
    value: String,
    raw: bool,
}

/// One contract's debug info as the CLI loads it: the spec it came from, the ETHDebug
/// resources record for `info resources`, and the prepared [`ContractDebugInfo`] the
/// debugger steps with.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceSourceIndex {
    spec: ResolvedContractSpec,
    resources: serde_json::Value,
    debug: ContractDebugInfo,
}

impl TraceSourceIndex {
    fn load(spec: &ResolvedContractSpec) -> SoldbResult<Self> {
        Self::load_environment(spec, SourceMapEnvironment::Runtime)?.ok_or_else(|| {
            soldb_core::SoldbError::Message(format!(
                "no ETHDebug or legacy runtime source map found in `{}`",
                spec.debug_dir.display()
            ))
        })
    }

    fn load_environment(
        spec: &ResolvedContractSpec,
        environment: SourceMapEnvironment,
    ) -> SoldbResult<Option<Self>> {
        let Some(program) = load_debug_program_with_sources(
            &spec.debug_dir,
            &spec.name,
            environment,
            &spec.source_paths,
        )?
        else {
            return Ok(None);
        };
        if !program.missing_sources.is_empty() {
            // The artifact names sources that are not where it says: source lines,
            // functions, and frames come from that text, so say it plainly rather than
            // showing an opcode view that looks like a contract compiled without debug
            // info.
            report_once(
                format!("sources:{}", spec.debug_dir.display()),
                &format!(
                    "could not read {} for `{}`: {}",
                    if program.missing_sources.len() == 1 {
                        "the source".to_owned()
                    } else {
                        format!("{} sources", program.missing_sources.len())
                    },
                    spec.name,
                    program.missing_sources.join(", ")
                ),
                "source lines and functions are unavailable for them; the paths are relative to the directory the contract was compiled in, so run soldb from there or keep the sources next to the artifacts",
            );
        }
        let debug = ContractDebugInfo::new(
            spec.address.as_deref(),
            &spec.name,
            program.info,
            program.source_contents,
        )
        .with_storage_layout(program.storage_layout);
        Ok(Some(Self {
            spec: spec.clone(),
            resources: program.resources,
            debug,
        }))
    }

    fn function_at_pc(&self, pc: u64) -> Option<&SourceFunction> {
        self.debug.function_at_pc(pc)
    }

    fn descriptor_for_calldata(&self, calldata: &str) -> Option<CallDescriptor> {
        let selector = selector_from_calldata(calldata)?;
        self.debug.functions.iter().find_map(|function| {
            let signature = source_function_signature(function);
            let function_selector = selector_hex(function_selector(&signature).ok()?);
            (function_selector == selector)
                .then(|| descriptor_from_source_function(function, calldata))
        })
    }
}

fn print_call_frames(frames: &[CallFrame]) {
    for (index, frame) in frames.iter().enumerate() {
        let call = format_call_frame(frame);
        let location = format_call_frame_location(frame);
        if frame.internal {
            println!(
                "{} {} {}{}",
                dim(format!("#{}", index + 1)),
                function_color(call),
                dim("[internal]"),
                location
            );
        } else {
            println!(
                "{} {}{}",
                dim(format!("#{}", index + 1)),
                function_color(call),
                location
            );
        }
        if frame.internal
            && frame.params.is_empty()
            && !frame.source_params.is_empty()
            && !frame.raw_stack.is_empty()
        {
            println!(
                "  {} {}",
                info("raw entry stack:"),
                number_color(format_raw_stack(&frame.raw_stack))
            );
        }
    }
}

fn format_call_frame(frame: &CallFrame) -> String {
    if !frame.params.is_empty() {
        return format_decoded_call(&frame.name, &frame.params);
    }
    if !frame.source_params.is_empty() {
        return format_source_prototype(&frame.name, &frame.source_params);
    }
    frame.name.clone()
}

fn format_call_frame_location(frame: &CallFrame) -> String {
    match (&frame.source_path, frame.source_line) {
        (Some(path), Some(line)) => dim(format!(" at {path}:{line}")),
        _ => String::new(),
    }
}

fn print_trace_event_lines(trace: &TransactionTrace, events: &EventRegistry) {
    for log in &trace.artifacts.logs {
        println!(
            "  {} {}",
            dim("emit"),
            function_color(format_trace_event(log, events))
        );
    }
}

fn format_trace_event(log: &ExecutionLog, events: &EventRegistry) -> String {
    if let Some(decoded) = events.decode_log(&log.topics, &log.data) {
        return format_decoded_event_inline(&decoded);
    }
    let topic = log.topics.first().map_or("<anonymous>", String::as_str);
    format!("{topic}(data = {})", normalize_hex(&log.data))
}

fn format_decoded_event_inline(decoded: &DecodedEvent) -> String {
    let name = decoded.contract_name.as_ref().map_or_else(
        || decoded.event.clone(),
        |contract| format!("{contract}::{}", decoded.event),
    );
    format!(
        "{}({})",
        name,
        decoded
            .args
            .iter()
            .map(|arg| {
                if arg.name.is_empty() {
                    display_json_value(&arg.value)
                } else {
                    format!("{} = {}", arg.name, display_json_value(&arg.value))
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn build_trace_call_frames(
    trace: &TransactionTrace,
    spec: &ResolvedContractSpec,
    fallback: Option<CallDescriptor>,
) -> Vec<CallFrame> {
    let source_index = load_source_index(spec);
    let descriptor = source_index
        .as_ref()
        .and_then(|index| index.descriptor_for_calldata(&trace.input_data))
        .or_else(|| abi_descriptor_for_calldata(spec, &trace.input_data))
        .or(fallback);
    build_call_frames(trace, source_index.as_ref(), descriptor)
}

fn build_simulation_call_frames(
    trace: &TransactionTrace,
    args: &SimulationView,
    raw_data: &str,
    fallback: Option<CallDescriptor>,
) -> Vec<CallFrame> {
    let source_index = resolve_contract_specs_reporting(
        &args.ethdebug_dir,
        args.contracts.as_deref(),
        &args.source_path,
    )
    .into_iter()
    .find_map(|spec| load_source_index(&spec));
    let descriptor = source_index
        .as_ref()
        .and_then(|index| index.descriptor_for_calldata(raw_data))
        .or_else(|| {
            resolve_contract_specs_reporting(
                &args.ethdebug_dir,
                args.contracts.as_deref(),
                &args.source_path,
            )
            .into_iter()
            .find_map(|spec| abi_descriptor_for_calldata(&spec, raw_data))
        })
        .or(fallback);
    build_call_frames(trace, source_index.as_ref(), descriptor)
}

fn build_call_frames(
    trace: &TransactionTrace,
    source_index: Option<&TraceSourceIndex>,
    descriptor: Option<CallDescriptor>,
) -> Vec<CallFrame> {
    let mut frames = Vec::<CallFrame>::new();

    if let Some(index) = source_index {
        for step in &trace.steps {
            let Some(function) = index.function_at_pc(step.pc) else {
                continue;
            };
            if frames.iter().any(|frame| frame.name == function.name) {
                continue;
            }
            frames.push(CallFrame {
                name: function.name.clone(),
                params: Vec::new(),
                source_params: function.params.clone(),
                source_path: index
                    .debug
                    .source_path(function.source_id)
                    .map(str::to_owned),
                source_line: Some(function.declaration_line),
                raw_stack: step.snapshot_ref().stack.to_vec(),
                internal: false,
            });
        }
    }

    if let Some(descriptor) = descriptor {
        if let Some(frame) = frames
            .iter_mut()
            .find(|frame| frame.name == descriptor.name)
        {
            frame.params = descriptor.params;
        } else {
            frames.insert(
                0,
                CallFrame {
                    name: descriptor.name,
                    params: descriptor.params,
                    source_params: Vec::new(),
                    source_path: None,
                    source_line: None,
                    raw_stack: Vec::new(),
                    internal: false,
                },
            );
        }
    }

    for (index, frame) in frames.iter_mut().enumerate() {
        frame.internal = index > 0;
    }

    frames
}

fn call_descriptor_for_calldata(
    spec: &ResolvedContractSpec,
    calldata: &str,
) -> Option<CallDescriptor> {
    load_source_index(spec)
        .and_then(|index| index.descriptor_for_calldata(calldata))
        .or_else(|| abi_descriptor_for_calldata(spec, calldata))
}

fn simulated_call_descriptor(
    args: &SimulationView,
    raw_data: &str,
    function_name: &str,
) -> Option<CallDescriptor> {
    if let Some(signature) = &args.function_signature {
        let parsed = parse_signature(signature)?;
        let has_debug_info = !args.ethdebug_dir.is_empty() || args.contracts.is_some();
        let params = parsed
            .arg_types
            .iter()
            .enumerate()
            .filter_map(|(index, _)| {
                args.function_args.get(index).map(|value| DecodedCallParam {
                    name: format!("arg{index}"),
                    ty: parsed.arg_types.get(index).cloned(),
                    value: value.clone(),
                    raw: false,
                })
            })
            .collect();
        return Some(CallDescriptor {
            name: if has_debug_info {
                parsed.name
            } else {
                signature.clone()
            },
            params,
        });
    }

    if function_name != "raw_data" {
        return Some(CallDescriptor {
            name: function_name.to_owned(),
            params: Vec::new(),
        });
    }

    resolve_contract_specs_reporting(
        &args.ethdebug_dir,
        args.contracts.as_deref(),
        &args.source_path,
    )
    .into_iter()
    .find_map(|spec| call_descriptor_for_calldata(&spec, raw_data))
}

#[derive(Debug, serde::Deserialize)]
struct FunctionAbiEntry {
    #[serde(rename = "type")]
    item_type: String,
    name: Option<String>,
    #[serde(default)]
    inputs: Vec<FunctionAbiInput>,
}

#[derive(Debug, serde::Deserialize)]
struct FunctionAbiInput {
    #[serde(default)]
    name: String,
    #[serde(rename = "type")]
    ty: String,
}

fn abi_descriptor_for_calldata(
    spec: &ResolvedContractSpec,
    calldata: &str,
) -> Option<CallDescriptor> {
    let selector = selector_from_calldata(calldata)?;
    let entries = abi_entries_for_spec(spec)?;
    entries
        .into_iter()
        .filter(|entry| entry.item_type == "function")
        .find_map(|entry| {
            let name = entry.name?;
            let signature = format!(
                "{}({})",
                name,
                entry
                    .inputs
                    .iter()
                    .map(|input| input.ty.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let function_selector = selector_hex(function_selector(&signature).ok()?);
            if function_selector != selector {
                return None;
            }
            let params = entry
                .inputs
                .iter()
                .enumerate()
                .filter_map(|(index, input)| {
                    let name = if input.name.is_empty() {
                        format!("arg{index}")
                    } else {
                        input.name.clone()
                    };
                    decode_calldata_word(calldata, index, &input.ty).map(|word| DecodedCallParam {
                        name,
                        ty: Some(input.ty.clone()),
                        value: word.value,
                        raw: word.raw,
                    })
                })
                .collect();
            Some(CallDescriptor { name, params })
        })
}

fn abi_entries_for_spec(spec: &ResolvedContractSpec) -> Option<Vec<FunctionAbiEntry>> {
    serde_json::from_value(abi_value_for_spec(spec)?).ok()
}

fn abi_value_for_spec(spec: &ResolvedContractSpec) -> Option<serde_json::Value> {
    if let Some(abi_path) = abi_path_for_contract(&spec.debug_dir, &spec.name) {
        let content = fs::read_to_string(abi_path).ok()?;
        let value = serde_json::from_str::<serde_json::Value>(&content).ok()?;
        if value.is_array() {
            return Some(value);
        }
        return value.get("abi").filter(|abi| abi.is_array()).cloned();
    }

    let combined = read_json_file(&spec.debug_dir.join("combined.json")).ok()?;
    let contracts = combined.get("contracts")?.as_object()?;
    contracts
        .iter()
        .find(|(key, _)| {
            key.rsplit_once(':')
                .map_or(*key == &spec.name, |(_, name)| name == spec.name)
        })
        .and_then(|(_, contract)| contract.get("abi").filter(|abi| abi.is_array()).cloned())
}

fn descriptor_from_source_function(function: &SourceFunction, calldata: &str) -> CallDescriptor {
    let params = function
        .params
        .iter()
        .enumerate()
        .filter_map(|(index, param)| {
            decode_calldata_word(calldata, index, &param.ty).map(|word| DecodedCallParam {
                name: param.name.clone(),
                ty: Some(param.ty.clone()),
                value: word.value,
                raw: word.raw,
            })
        })
        .collect();
    CallDescriptor {
        name: function.name.clone(),
        params,
    }
}

fn source_function_signature(function: &SourceFunction) -> String {
    format!(
        "{}({})",
        function.name,
        function
            .params
            .iter()
            .map(|param| param.ty.as_str())
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn selector_from_calldata(calldata: &str) -> Option<String> {
    let data = calldata.trim_start_matches("0x");
    let selector = data.get(..8)?;
    selector
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit())
        .then(|| selector.to_ascii_lowercase())
}

fn selector_hex(selector: [u8; 4]) -> String {
    selector
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedWord {
    value: String,
    raw: bool,
}

fn decode_calldata_word(calldata: &str, index: usize, ty: &str) -> Option<DecodedWord> {
    let data = calldata.trim_start_matches("0x");
    let start = 8 + index * 64;
    let word = data.get(start..start + 64)?;
    decode_static_word(word, ty).map_or_else(
        || {
            Some(DecodedWord {
                value: format!("0x{}", word.to_ascii_lowercase()),
                raw: true,
            })
        },
        |value| Some(DecodedWord { value, raw: false }),
    )
}

fn decode_static_word(word: &str, ty: &str) -> Option<String> {
    let ty = ty.trim();
    if ty.starts_with("uint") {
        return Some(format_uint_word(word));
    }
    if ty == "address" {
        return Some(format!("0x{}", &word[word.len().saturating_sub(40)..]).to_ascii_lowercase());
    }
    if ty == "bool" {
        return Some((word.trim_start_matches('0') == "1").to_string());
    }
    if ty == "bytes32" {
        return Some(format!("0x{}", word.to_ascii_lowercase()));
    }
    None
}

fn format_uint_word(word: &str) -> String {
    let trimmed = word.trim_start_matches('0');
    if trimmed.is_empty() {
        return "0".to_owned();
    }
    if trimmed.len() <= 32 {
        return u128::from_str_radix(trimmed, 16)
            .map(|value| value.to_string())
            .unwrap_or_else(|_| format!("0x{}", trimmed.to_ascii_lowercase()));
    }
    format!("0x{}", trimmed.to_ascii_lowercase())
}

fn format_source_prototype(name: &str, params: &[SourceParam]) -> String {
    format!(
        "{}({})",
        name,
        params
            .iter()
            .map(|param| {
                if param.name.is_empty() {
                    param.ty.clone()
                } else {
                    format!("{} {}", param.ty, param.name)
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn format_decoded_call(name: &str, params: &[DecodedCallParam]) -> String {
    format!(
        "{}({})",
        name,
        params
            .iter()
            .map(format_decoded_call_param)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn format_decoded_call_param(param: &DecodedCallParam) -> String {
    let value_label = if param.raw { "raw = " } else { "= " };
    match (param.ty.as_deref(), param.name.is_empty()) {
        (Some(ty), false) => format!("{ty} {} {value_label}{}", param.name, param.value),
        (Some(ty), true) => format!("{ty} {value_label}{}", param.value),
        (None, false) => format!("{} {value_label}{}", param.name, param.value),
        (None, true) => param.value.clone(),
    }
}

fn format_raw_stack(stack: &[StackWord]) -> String {
    if stack.is_empty() {
        return "[empty]".to_owned();
    }
    stack
        .iter()
        .enumerate()
        .map(|(index, value)| format!("[{index}] {}", normalize_stack_word(value)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn print_events(logs: &[RpcLog], events: &EventRegistry) {
    println!("{}", bold(info("Events emitted in Transaction:")));
    if logs.is_empty() {
        println!("{}", warning("No events emitted"));
        return;
    }

    for (index, log) in logs.iter().enumerate() {
        if let Some(decoded) = events.decode_log(&log.topics, &log.data) {
            print_decoded_event(index, &decoded);
            continue;
        }

        println!();
        println!(
            "{} {}: {} {}",
            info("Event"),
            number_color(format!("#{}", index + 1)),
            info("Contract Address:"),
            address_color(&log.address)
        );
        for topic in &log.topics {
            println!("    {} {}", info("topic:"), number_color(topic));
        }
        println!(
            "    {} {}",
            info("data:"),
            number_color(normalize_hex(&log.data))
        );
    }
}

fn print_decoded_event(index: usize, decoded: &DecodedEvent) {
    println!();
    print!(
        "{} {}: ",
        info("Event"),
        number_color(format!("#{}", index + 1))
    );
    if let Some(contract_name) = &decoded.contract_name {
        print!("{}::", function_color(contract_name));
    }
    println!("{}", function_color(&decoded.signature));
    for arg in &decoded.args {
        println!(
            "    {} {} {}",
            info(format!("{}:", arg.name)),
            number_color(display_json_value(&arg.value)),
            dim(format!("({})", arg.ty))
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
            EventJson {
                index,
                address: log.address.clone(),
                topics: log.topics.clone(),
                data: data.clone(),
                datas: raw_event_data_items(&data),
                event: String::new(),
                signature,
                contract_name: None,
            }
        })
        .collect::<Vec<_>>();

    #[derive(serde::Serialize)]
    struct EventsJson {
        transaction_hash: String,
        events: Vec<EventJson>,
        total_events: usize,
    }

    serde_json::to_string_pretty(&EventsJson {
        transaction_hash: tx_hash.to_owned(),
        events: event_items,
        total_events: logs.len(),
    })
    .map_err(|error| soldb_core::SoldbError::Message(error.to_string()))
}

fn decoded_event_to_json(index: usize, log: &RpcLog, decoded: &DecodedEvent) -> EventJson {
    let data = normalize_hex(&log.data);
    let datas = decoded
        .args
        .iter()
        .map(|arg| event_data_json(Some(&arg.name), &arg.ty, arg.value.clone()))
        .collect::<Vec<_>>();
    EventJson {
        index,
        address: log.address.clone(),
        topics: log.topics.clone(),
        data,
        datas,
        event: decoded.event.clone(),
        signature: decoded.signature.clone(),
        contract_name: decoded.contract_name.clone(),
    }
}

#[derive(serde::Serialize)]
struct EventJson {
    index: usize,
    address: String,
    topics: Vec<String>,
    data: String,
    datas: Vec<EventDataJson>,
    event: String,
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    contract_name: Option<String>,
}

#[derive(serde::Serialize)]
struct EventDataJson {
    name: Option<String>,
    #[serde(rename = "type")]
    ty: String,
    value: serde_json::Value,
}

fn raw_event_data_items(data: &str) -> Vec<EventDataJson> {
    let hex = data.trim_start_matches("0x");
    if hex.is_empty() {
        return vec![event_data_json(None, "hex", json!("0x"))];
    }
    hex.as_bytes()
        .chunks(64)
        .map(|chunk| {
            let value = std::str::from_utf8(chunk).unwrap_or_default();
            event_data_json(None, "hex", json!(format!("0x{value}")))
        })
        .collect()
}

fn event_data_json(name: Option<&str>, ty: &str, value: serde_json::Value) -> EventDataJson {
    EventDataJson {
        name: name.map(str::to_owned),
        ty: ty.to_owned(),
        value,
    }
}

fn load_event_registry(args: &ListEventsArgs) -> SoldbResult<EventRegistry> {
    if !should_decode_events(args) {
        return Ok(EventRegistry::default());
    }
    event_registry_for_specs(resolve_contract_specs(
        &args.ethdebug_dir,
        args.contracts.as_deref(),
        &args.source_path,
    )?)
}

fn trace_event_registry(args: &TraceView) -> EventRegistry {
    event_registry_reporting(resolve_contract_specs_reporting(
        &args.ethdebug_dir,
        args.contracts.as_deref(),
        &args.source_path,
    ))
}

fn simulate_event_registry(args: &SimulationView) -> EventRegistry {
    event_registry_reporting(resolve_contract_specs_reporting(
        &args.ethdebug_dir,
        args.contracts.as_deref(),
        &args.source_path,
    ))
}

/// Builds the event registry, reporting a failure instead of decoding nothing in silence.
fn event_registry_reporting(specs: Vec<ResolvedContractSpec>) -> EventRegistry {
    match event_registry_for_specs(specs) {
        Ok(registry) => registry,
        Err(error) => {
            report_once(
                format!("events:{error}"),
                &format!("could not load event ABIs: {error}"),
                "logs are shown without decoded names or arguments",
            );
            EventRegistry::default()
        }
    }
}

fn event_registry_for_specs(specs: Vec<ResolvedContractSpec>) -> SoldbResult<EventRegistry> {
    let mut registry = EventRegistry::default();
    for spec in specs {
        let Some(abi_path) = abi_path_for_contract(&spec.debug_dir, &spec.name) else {
            continue;
        };
        let content = fs::read_to_string(&abi_path).map_err(|error| {
            soldb_core::SoldbError::Message(format!(
                "Failed to read ABI {}: {error}",
                abi_path.display()
            ))
        })?;
        for event in parse_event_abis(&content)? {
            registry.insert(Some(spec.name.clone()), event)?;
        }
    }
    Ok(registry)
}

fn should_decode_events(args: &ListEventsArgs) -> bool {
    args.multi_contract
        || args.contracts.is_some()
        || args.ethdebug_dir.len() > 1
        || args
            .ethdebug_dir
            .iter()
            .any(|spec| parse_ethdebug_spec(spec).name.is_none())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedContractSpec {
    address: Option<String>,
    name: String,
    debug_dir: PathBuf,
    /// Where to look for the sources the artifacts name, from `--source-path`.
    source_paths: Vec<PathBuf>,
}

/// Loads ETHDebug metadata for a contract spec, reporting a failure instead of hiding it.
///
/// The user asked for ETHDebug by naming a directory on the command line. Silently
/// dropping to a raw opcode view when that directory cannot be read is the worst failure
/// mode for a debugger whose whole premise is compiler-generated debug info: the symptom
/// (no source lines) looks identical to a contract that was simply compiled without it.
///
/// Reports go to stderr so `--json` output stays pipeable, and each spec is reported only
/// once because a single run resolves the same spec from several places.
fn load_source_index(spec: &ResolvedContractSpec) -> Option<TraceSourceIndex> {
    match TraceSourceIndex::load(spec) {
        Ok(index) => Some(index),
        Err(error) => {
            report_once(
                format!("ethdebug:{}:{}", spec.name, spec.debug_dir.display()),
                &format!(
                    "could not load debug metadata for `{}` from `{}`: {error}",
                    spec.name,
                    spec.debug_dir.display()
                ),
                "source lines, variables, and decoded parameters are unavailable for it",
            );
            None
        }
    }
}

/// Resolves contract specs, reporting a bad spec instead of continuing with none.
///
/// Every caller degrades to "no debug info" on failure, so without this a typo in
/// `--ethdebug-dir` is indistinguishable from not passing it at all.
fn resolve_contract_specs_reporting(
    ethdebug_dirs: &[String],
    contracts_file: Option<&str>,
    source_paths: &[String],
) -> Vec<ResolvedContractSpec> {
    match resolve_contract_specs(ethdebug_dirs, contracts_file, source_paths) {
        Ok(specs) => specs,
        Err(error) => {
            report_once(
                format!("specs:{error}"),
                &format!("could not resolve the requested contracts: {error}"),
                "continuing without source-level information for this run",
            );
            Vec::new()
        }
    }
}

/// Writes a warning and a follow-up note to stderr, at most once per `key`.
fn report_once(key: String, message: &str, note: &str) {
    static REPORTED: OnceLock<Mutex<BTreeSet<String>>> = OnceLock::new();

    let mut reported = match REPORTED.get_or_init(|| Mutex::new(BTreeSet::new())).lock() {
        Ok(reported) => reported,
        // A poisoned lock only means another thread panicked while reporting. Losing
        // deduplication is better than losing the diagnostic.
        Err(poisoned) => poisoned.into_inner(),
    };
    if !reported.insert(key) {
        return;
    }
    eprintln!("{} {message}", paint_stderr("warning:", "93"));
    eprintln!("{} {note}", paint_stderr("note:", "2"));
}

fn resolve_contract_specs(
    ethdebug_dirs: &[String],
    contracts_file: Option<&str>,
    source_paths: &[String],
) -> SoldbResult<Vec<ResolvedContractSpec>> {
    let mut specs = Vec::new();
    if let Some(contracts_file) = contracts_file {
        specs.extend(load_contract_mapping_file(Path::new(contracts_file))?);
    }

    for spec_text in ethdebug_dirs {
        specs.extend(resolve_ethdebug_spec(spec_text)?);
    }
    // Where to look for sources is a property of this invocation, not of one contract, so
    // every spec gets what the user passed.
    let source_paths = source_paths.iter().map(PathBuf::from).collect::<Vec<_>>();
    for spec in &mut specs {
        spec.source_paths = source_paths.clone();
    }
    Ok(specs)
}

fn resolve_ethdebug_spec(spec_text: &str) -> SoldbResult<Vec<ResolvedContractSpec>> {
    let spec = parse_ethdebug_spec(spec_text);
    if let Some(name) = spec.name {
        return Ok(vec![ResolvedContractSpec {
            address: spec.address,
            name,
            debug_dir: PathBuf::from(spec.path),
            source_paths: Vec::new(),
        }]);
    }

    let path = PathBuf::from(&spec.path);
    let mut loaded = if path.is_file() {
        load_contract_mapping_or_deployment(&path)?
    } else if path.join("deployment.json").exists() {
        load_deployment_file(&path.join("deployment.json"))?
    } else {
        infer_contract_specs_from_dir(&path)?
    };

    if let Some(address) = spec.address {
        loaded.retain(|candidate| {
            candidate
                .address
                .as_deref()
                .is_some_and(|candidate_address| candidate_address.eq_ignore_ascii_case(&address))
        });
        if loaded.is_empty() {
            return Ok(vec![ResolvedContractSpec {
                address: Some(address),
                name: infer_contract_name_from_dir(&path).unwrap_or_else(|| "Unknown".to_owned()),
                debug_dir: path,
                source_paths: Vec::new(),
            }]);
        }
    }

    // Resolving nothing is a failure, not an empty result. The user named this on the
    // command line; returning zero contracts silently is indistinguishable from having
    // passed no `--ethdebug-dir` at all, and it is how a mistyped spec turns into a
    // confusing "no debug info" trace.
    if loaded.is_empty() {
        return Err(soldb_core::SoldbError::Message(format!(
            "no contracts found for `{spec_text}`; expected `<address>:<contract>:<dir>`, \
             a directory of ETHDebug artifacts, or a contract mapping file"
        )));
    }

    Ok(loaded)
}

fn load_contract_mapping_or_deployment(path: &Path) -> SoldbResult<Vec<ResolvedContractSpec>> {
    let value = read_json_file(path)?;
    if value
        .get("contracts")
        .and_then(serde_json::Value::as_array)
        .is_some()
    {
        return parse_contract_mapping_array(path, &value);
    }
    parse_deployment_value(path, &value)
}

fn load_contract_mapping_file(path: &Path) -> SoldbResult<Vec<ResolvedContractSpec>> {
    let value = read_json_file(path)?;
    if value
        .get("contracts")
        .and_then(serde_json::Value::as_array)
        .is_some()
    {
        return parse_contract_mapping_array(path, &value);
    }
    parse_deployment_value(path, &value)
}

fn load_deployment_file(path: &Path) -> SoldbResult<Vec<ResolvedContractSpec>> {
    let value = read_json_file(path)?;
    parse_deployment_value(path, &value)
}

fn parse_contract_mapping_array(
    path: &Path,
    value: &serde_json::Value,
) -> SoldbResult<Vec<ResolvedContractSpec>> {
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let contracts = value
        .get("contracts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            soldb_core::SoldbError::Message(format!(
                "Contracts mapping {} must contain a contracts array",
                path.display()
            ))
        })?;

    Ok(contracts
        .iter()
        .filter_map(|contract| {
            let address = contract.get("address")?.as_str()?.to_owned();
            let name = contract
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Unknown")
                .to_owned();
            let debug_dir = contract
                .get("debug_dir")
                .and_then(serde_json::Value::as_str)
                .map(PathBuf::from)?;
            let debug_dir = if debug_dir.is_absolute() {
                debug_dir
            } else {
                base_dir.join(debug_dir)
            };
            Some(ResolvedContractSpec {
                address: Some(address),
                name,
                debug_dir,
                source_paths: Vec::new(),
            })
        })
        .collect())
}

fn parse_deployment_value(
    path: &Path,
    value: &serde_json::Value,
) -> SoldbResult<Vec<ResolvedContractSpec>> {
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    if let (Some(address), Some(contract)) = (
        value.get("address").and_then(serde_json::Value::as_str),
        value.get("contract").and_then(serde_json::Value::as_str),
    ) {
        return Ok(vec![ResolvedContractSpec {
            address: Some(address.to_owned()),
            name: contract.to_owned(),
            debug_dir: base_dir.to_path_buf(),
            source_paths: Vec::new(),
        }]);
    }

    let Some(contracts) = value
        .get("contracts")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(Vec::new());
    };
    Ok(contracts
        .iter()
        .filter_map(|(name, contract)| {
            let address = contract.get("address")?.as_str()?.to_owned();
            Some(ResolvedContractSpec {
                address: Some(address),
                name: name.clone(),
                debug_dir: find_debug_dir_for_contract(base_dir, name),
                source_paths: Vec::new(),
            })
        })
        .collect())
}

fn find_debug_dir_for_contract(base_dir: &Path, contract_name: &str) -> PathBuf {
    let candidates = [
        base_dir.join(format!("debug_{}", contract_name.to_ascii_lowercase())),
        base_dir.join("debug").join(contract_name),
        base_dir.join(contract_name).join("debug"),
        base_dir.to_path_buf(),
    ];
    candidates
        .into_iter()
        .find(|candidate| {
            find_ethdebug_metadata(candidate).is_some() || candidate.join("combined.json").exists()
        })
        .unwrap_or_else(|| base_dir.to_path_buf())
}

fn infer_contract_specs_from_dir(path: &Path) -> SoldbResult<Vec<ResolvedContractSpec>> {
    let Some(name) = infer_contract_name_from_dir(path) else {
        return Ok(Vec::new());
    };
    Ok(vec![ResolvedContractSpec {
        address: None,
        name,
        debug_dir: path.to_path_buf(),
        source_paths: Vec::new(),
    }])
}

fn infer_contract_name_from_dir(path: &Path) -> Option<String> {
    let entries = fs::read_dir(path).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("abi") {
            return path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_owned);
        }
    }

    let combined = read_json_file(&path.join("combined.json")).ok()?;
    let contracts = combined.get("contracts")?.as_object()?;
    if contracts.len() != 1 {
        return None;
    }
    let contract = contracts.keys().next()?;
    Some(
        contract
            .rsplit_once(':')
            .map_or(contract.as_str(), |(_, name)| name)
            .to_owned(),
    )
}

fn read_json_file(path: &Path) -> SoldbResult<serde_json::Value> {
    let content = fs::read_to_string(path).map_err(|error| {
        soldb_core::SoldbError::Message(format!("Failed to read {}: {error}", path.display()))
    })?;
    serde_json::from_str(&content).map_err(|error| {
        soldb_core::SoldbError::Message(format!("Invalid JSON {}: {error}", path.display()))
    })
}

fn ethdebug_resources_for_spec(spec: &ResolvedContractSpec) -> SoldbResult<serde_json::Value> {
    if let Some(path) = find_ethdebug_metadata(&spec.debug_dir) {
        let metadata = read_json_file(&path)?;
        return ethdebug_resources_from_metadata(&path, &metadata);
    }

    TraceSourceIndex::load(spec).map(|index| index.resources)
}

fn abi_path_for_contract(debug_dir: &Path, contract_name: &str) -> Option<std::path::PathBuf> {
    let dir = debug_dir;
    [
        format!("{contract_name}.abi"),
        format!("{contract_name}.json"),
    ]
    .into_iter()
    .map(|file_name| dir.join(file_name))
    .find(|path| path.exists())
}

fn trace_web_contracts(
    args: &TraceView,
    trace: &TransactionTrace,
) -> BTreeMap<String, soldb_serializer::WebContractMetadata> {
    let specs = resolve_contract_specs_reporting(
        &args.ethdebug_dir,
        args.contracts.as_deref(),
        &args.source_path,
    );
    web_contracts_for_specs(specs, trace, None)
}

fn simulate_web_contracts(
    args: &SimulationView,
    trace: &TransactionTrace,
    contract_address: &str,
) -> BTreeMap<String, soldb_serializer::WebContractMetadata> {
    let specs = resolve_contract_specs_reporting(
        &args.ethdebug_dir,
        args.contracts.as_deref(),
        &args.source_path,
    );
    web_contracts_for_specs(specs, trace, Some(contract_address))
}

fn web_contracts_for_specs(
    specs: Vec<ResolvedContractSpec>,
    trace: &TransactionTrace,
    fallback_address: Option<&str>,
) -> BTreeMap<String, soldb_serializer::WebContractMetadata> {
    let single_spec = specs.len() == 1;
    specs
        .into_iter()
        .filter_map(|spec| {
            let address = spec
                .address
                .clone()
                .or_else(|| {
                    single_spec
                        .then(|| fallback_address.map(str::to_owned))
                        .flatten()
                })
                .or_else(|| {
                    single_spec
                        .then(|| {
                            trace
                                .to_addr
                                .clone()
                                .or_else(|| trace.contract_address.clone())
                        })
                        .flatten()
                })?;
            let metadata = web_contract_metadata_for_spec(&spec)?;
            let metadata = with_final_state(metadata, &spec, trace, &address);
            Some((normalize_contract_address_key(&address), metadata))
        })
        .collect()
}

/// Adds the contract's storage layout and its state at the end of the transaction.
///
/// A client reading the document gets what the REPL shows: each variable's slot, its
/// value, and whether that value came from the recording, from a chain, or from neither.
fn with_final_state(
    metadata: soldb_serializer::WebContractMetadata,
    spec: &ResolvedContractSpec,
    trace: &TransactionTrace,
    address: &str,
) -> soldb_serializer::WebContractMetadata {
    let Some(index) = load_source_index(spec) else {
        return metadata;
    };
    let Some(layout) = index.debug.storage_layout.as_ref() else {
        return metadata;
    };
    let Some(last) = trace.steps.len().checked_sub(1) else {
        return metadata;
    };
    let map = soldb_debugger::StepMap::new(trace, vec![index.debug.clone()]);
    let tape = soldb_debugger::StorageTape::new(trace, &map);
    // The account this contract's storage belongs to, rather than whichever frame the
    // last step happened to be in.
    let context = (0..trace.steps.len()).find(|step| {
        map.storage_address(*step)
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(address))
    });
    let Some(context) = context.and_then(|step| map.storage_context_index(step)) else {
        return metadata;
    };
    let words = tape.at(last, Some(context));
    let variables = soldb_debugger::state_variables(layout, &words)
        .into_iter()
        .map(|variable| soldb_serializer::WebStateVariable {
            name: variable.name,
            ty: variable.ty,
            slot: variable.slot,
            offset: variable.offset,
            value: variable.value.display,
            source: match (variable.value.status, variable.source) {
                (soldb_debugger::DebugValueStatus::Unavailable, _) => "unknown",
                (_, soldb_debugger::StateSource::Chain) => "chain",
                (_, soldb_debugger::StateSource::Trace) => "trace",
            }
            .to_owned(),
        })
        .collect();
    metadata.with_state(layout.source.clone(), variables)
}

fn web_contract_metadata_for_spec(
    spec: &ResolvedContractSpec,
) -> Option<soldb_serializer::WebContractMetadata> {
    let abi = abi_value_for_spec(spec);
    let Some(index) = load_source_index(spec) else {
        let metadata = soldb_serializer::WebContractMetadata {
            abi,
            ..Default::default()
        };
        return (!metadata.is_empty()).then_some(metadata);
    };

    // The loader already read every source it could find next to the artifacts; the
    // projection falls back to the path for anything still missing.
    let metadata = soldb_serializer::WebContractMetadata::from_ethdebug(
        &index.debug.info,
        &index.debug.source_contents,
        abi,
    );
    (!metadata.is_empty()).then_some(metadata)
}

fn normalize_contract_address_key(address: &str) -> String {
    address.to_ascii_lowercase()
}

fn trace_contract_name(args: &TraceView) -> Option<String> {
    trace_contract_spec(args).map(|spec| spec.name)
}

fn trace_contract_spec(args: &TraceView) -> Option<ResolvedContractSpec> {
    resolve_contract_specs_reporting(
        &args.ethdebug_dir,
        args.contracts.as_deref(),
        &args.source_path,
    )
    .into_iter()
    .next()
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct TraceDebugMetadata {
    is_legacy: bool,
    compiler_name: Option<String>,
    compiler_version: Option<String>,
}

fn trace_debug_metadata(spec: &ResolvedContractSpec) -> TraceDebugMetadata {
    let combined_json = spec.debug_dir.join("combined.json");
    if find_ethdebug_metadata(&spec.debug_dir).is_none() && combined_json.exists() {
        let version = read_json_file(&combined_json)
            .ok()
            .and_then(|value| {
                value
                    .get("version")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .map(|version| {
                version
                    .split_once('+')
                    .map_or(version.as_str(), |(core, _)| core)
                    .to_owned()
            });
        return TraceDebugMetadata {
            is_legacy: true,
            compiler_name: None,
            compiler_version: version,
        };
    }

    let compiler = find_ethdebug_metadata(&spec.debug_dir)
        .and_then(|ethdebug_json| read_json_file(&ethdebug_json).ok())
        .and_then(|value| {
            value
                .get("compilation")
                .and_then(|compilation| compilation.get("compiler"))
                .cloned()
        });
    let compiler_name = compiler
        .as_ref()
        .and_then(|compiler| compiler.get("name"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let compiler_version = compiler
        .as_ref()
        .and_then(|compiler| compiler.get("version"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .map(|version| {
            version
                .split_once('+')
                .map_or(version.as_str(), |(core, _)| core)
                .to_owned()
        });
    TraceDebugMetadata {
        is_legacy: false,
        compiler_name,
        compiler_version,
    }
}

fn simulate_contract_name(args: &SimulationView) -> Option<String> {
    resolve_contract_specs_reporting(
        &args.ethdebug_dir,
        args.contracts.as_deref(),
        &args.source_path,
    )
    .into_iter()
    .next()
    .map(|spec| spec.name)
}

fn simulate_calldata(args: &SimulationView) -> SoldbResult<String> {
    if let Some(raw_data) = &args.raw_data {
        if args.function_signature.is_some() || !args.function_args.is_empty() {
            return Err(soldb_core::SoldbError::Message(
                "Error: When using --raw-data, do not provide function_signature or function_args."
                    .to_owned(),
            ));
        }
        return Ok(raw_data.clone());
    }

    let Some(signature) = &args.function_signature else {
        return Err(soldb_core::SoldbError::Message(
            "Error: function_signature is required if --raw-data is not provided".to_owned(),
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

fn validate_simulate_value(value: &str) -> Result<(), String> {
    let value = value.trim();
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        (!hex.is_empty() && hex.chars().all(|ch| ch.is_ascii_hexdigit())).then_some(())
    } else if let Some(ether) = strip_ether_value(value) {
        validate_ether_value(ether)
    } else {
        (!value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit())).then_some(())
    };
    parsed.ok_or_else(|| format!("Invalid value for --value: {value}"))
}

fn strip_ether_value(value: &str) -> Option<&str> {
    value
        .get(..value.len().checked_sub("ether".len())?)
        .filter(|_| value.to_ascii_lowercase().ends_with("ether"))
        .map(str::trim)
}

fn validate_ether_value(value: &str) -> Option<()> {
    let (whole, fractional) = value.split_once('.').unwrap_or((value, ""));
    let valid_whole = whole.is_empty() || whole.chars().all(|ch| ch.is_ascii_digit());
    let valid_fractional =
        fractional.is_empty() || fractional.chars().all(|ch| ch.is_ascii_digit());
    (valid_whole
        && valid_fractional
        && !(whole.is_empty() && fractional.is_empty())
        && fractional.len() <= 18)
        .then_some(())
}

fn print_json_command_error(
    error_type: &str,
    message: &str,
    provided_value: Option<&str>,
) -> SoldbResult<()> {
    #[derive(serde::Serialize)]
    struct CommandErrorJson<'a> {
        error: bool,
        #[serde(rename = "type")]
        error_type: &'a str,
        message: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        provided_value: Option<&'a str>,
    }

    print_json(&CommandErrorJson {
        error: true,
        error_type,
        message,
        provided_value,
    })
}

fn format_simulated_call(args: &SimulationView, function_name: &str) -> String {
    if args.function_args.is_empty() {
        return args
            .function_signature
            .as_ref()
            .cloned()
            .unwrap_or_else(|| function_name.to_owned());
    }
    format!("{}({})", function_name, args.function_args.join(", "))
}

fn simulation_source_file(args: &SimulationView, contract_name: &str) -> Option<String> {
    resolve_contract_specs_reporting(
        &args.ethdebug_dir,
        args.contracts.as_deref(),
        &args.source_path,
    )
    .into_iter()
    .find(|spec| spec.name == contract_name)
    .and_then(|spec| {
        let ethdebug = find_ethdebug_metadata(&spec.debug_dir)?;
        read_json_file(&ethdebug).ok().and_then(|value| {
            value
                .get("compilation")
                .and_then(|compilation| compilation.get("sources"))
                .and_then(serde_json::Value::as_array)
                .and_then(|sources| sources.first())
                .and_then(|source| source.get("path"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
    })
}

fn simulate_json_function_name(args: &SimulationView, calldata: &str) -> String {
    if let Some(signature) = &args.function_signature {
        return signature.clone();
    }

    simulate_display_function_name(args, calldata)
}

fn simulate_display_function_name(args: &SimulationView, calldata: &str) -> String {
    if let Some(signature) = &args.function_signature {
        if let Some(parsed) = parse_signature(signature) {
            return parsed.name;
        }
        return signature.clone();
    }

    resolve_contract_specs_reporting(
        &args.ethdebug_dir,
        args.contracts.as_deref(),
        &args.source_path,
    )
    .into_iter()
    .find_map(|spec| call_descriptor_for_calldata(&spec, calldata))
    .map_or_else(|| "raw_data".to_owned(), |descriptor| descriptor.name)
}

fn normalize_hex(value: &str) -> String {
    if value.starts_with("0x") {
        value.to_owned()
    } else {
        format!("0x{value}")
    }
}

fn normalize_stack_word(value: &str) -> String {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if hex.is_empty() {
        return "0x0000000000000000000000000000000000000000000000000000000000000000".to_owned();
    }
    if hex.len() >= 64 {
        return format!("0x{hex}");
    }
    format!("0x{:0>64}", hex)
}

fn display_json_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

fn print_json<T: serde::Serialize>(value: &T) -> SoldbResult<()> {
    let output = serde_json::to_string_pretty(value)
        .map_err(|error| soldb_core::SoldbError::Message(error.to_string()))?;
    println!("{output}");
    Ok(())
}

fn call_target_stack_word(stack: &[StackWord]) -> Option<&str> {
    if stack.len() < 2 {
        return None;
    }
    stack.get(stack.len() - 2).map(|word| &**word)
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

fn format_stack(stack: &[StackWord]) -> String {
    if stack.is_empty() {
        return dim("[empty]");
    }

    let mut items = stack
        .iter()
        .take(3)
        .enumerate()
        .map(|(index, value)| {
            format!(
                "{} {}",
                dim(format!("[{index}]")),
                number_color(shorten_hex(value))
            )
        })
        .collect::<Vec<_>>();
    if stack.len() > 3 {
        items.push(dim(format!("... +{} more", stack.len() - 3)));
    }
    items.join(" ")
}

fn format_snapshot_state(snapshot: soldb_core::StepSnapshotRef<'_>) -> String {
    let mut items = Vec::new();
    if let Some(memory) = snapshot.memory {
        if !memory.is_empty() {
            items.push(format!("mem={}b", memory.len() / 2));
        }
    }
    if !snapshot.storage.is_empty() {
        items.push(format!("storage={}", snapshot.storage.len()));
    }
    if !snapshot.storage_diff.is_empty() {
        items.push(format!("diff={}", snapshot.storage_diff.len()));
    }
    if items.is_empty() {
        dim("[none]")
    } else {
        number_color(items.join(", "))
    }
}

fn shorten_hex(value: &str) -> String {
    // Stack and memory words come straight from the node, so they are not guaranteed to be
    // ASCII hex. Take characters rather than byte offsets: `&value[2..6]` panics when byte
    // 6 lands inside a multi-byte character.
    let Some(digits) = value.strip_prefix("0x") else {
        return value.to_owned();
    };
    if value.len() <= 10 {
        return value.to_owned();
    }
    let head = digits.chars().take(4).collect::<String>();
    format!("0x{head}...")
}

#[cfg(test)]
mod tests {

    #[test]
    fn paints_only_when_the_stream_is_a_terminal() {
        // `CLICOLOR_FORCE` and `NO_COLOR` are read from the environment, which the tests
        // share; the decision itself is what this pins.
        assert_eq!(super::paint_when(false, "warning:", "93"), "warning:");
        assert_eq!(
            super::paint_when(true, "warning:", "93"),
            "\u{1b}[93mwarning:\u{1b}[0m"
        );
    }
    use super::*;
    use serde_json::Value;
    use soldb_ethdebug::{EthdebugInfo, Instruction};
    use soldb_repl::{BreakpointTarget, SourceBreakpointTarget};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("soldb-cli-main-{label}-{unique}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn trace_step(pc: u64, stack: &[&str]) -> soldb_core::TraceStep {
        soldb_core::TraceStep {
            pc,
            op: "JUMPDEST".into(),
            gas: 100,
            gas_cost: 1,
            depth: 0,
            stack: stack.iter().map(|value| StackWord::from(*value)).collect(),
            memory: None,
            storage: None,
            error: None,
            snapshot: Default::default(),
        }
    }

    fn transaction_trace(
        input_data: String,
        steps: Vec<soldb_core::TraceStep>,
    ) -> TransactionTrace {
        TransactionTrace {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0x0".to_owned(),
            input_data,
            gas_used: 100,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: Some("debug-rpc".to_owned()),
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps,
        }
    }

    fn simulate_args() -> SimulateArgs {
        SimulateArgs {
            backend: TraceBackendArg::DebugRpc,
            save_replay: None,
            from_addr: "0x1".to_owned(),
            interactive: false,
            contract_address: "0x2".to_owned(),
            function_signature: None,
            function_args: Vec::new(),
            block: None,
            tx_index: None,
            value: "0".to_owned(),
            ethdebug_dir: Vec::new(),
            source_path: Vec::new(),
            contracts: None,
            multi_contract: false,
            rpc_url: "http://localhost:8545".to_owned(),
            json: false,
            raw: false,
            max_steps: 50,
            raw_data: None,
            constructor_args: Vec::new(),
            solc_path: "solc".to_owned(),
            dual_compile: false,
            keep_build: false,
            output_dir: "./out".to_owned(),
            production_dir: "./build/contracts".to_owned(),
            save_config: false,
            verify_version: false,
            no_cache: false,
            cache_dir: ".soldb_cache".to_owned(),
            fork_url: None,
            fork_block: None,
            fork_port: 8545,
            keep_fork: false,
            reuse_fork: false,
            no_snapshot: false,
            cross_env_bridge: None,
            stylus_contracts: None,
        }
    }

    fn list_events_args() -> ListEventsArgs {
        ListEventsArgs {
            tx_hash: "0xabc".to_owned(),
            ethdebug_dir: Vec::new(),
            source_path: Vec::new(),
            contracts: None,
            rpc_url: "http://localhost:8545".to_owned(),
            multi_contract: false,
            json_events: false,
        }
    }

    fn instruction_at(pc: u64, offset: u64, length: u64) -> Instruction {
        Instruction {
            offset: pc,
            operation: serde_json::json!({"mnemonic": "JUMPDEST"}),
            context: Some(serde_json::json!({
                "code": {"source": {"id": 0}, "range": {"offset": offset, "length": length}}
            })),
        }
    }

    #[test]
    fn source_breakpoints_prefer_the_span_generated_for_the_line() {
        // Three source lines; the statement for line 2 starts at byte 10.
        let source = "contract C {\n  uint x = 1;\n}\n";
        let line_two_offset = source.find("uint").expect("line two statement") as u64;

        let info = EthdebugInfo {
            compilation: serde_json::Value::Null,
            contract_name: "C".to_owned(),
            environment: "runtime".to_owned(),
            instructions: vec![
                // The dispatcher preamble solc attributes to the whole contract. Its span
                // intersects every line, so it used to win every source breakpoint.
                instruction_at(2, 0, source.len() as u64),
                instruction_at(4, 0, source.len() as u64),
                // The instruction actually generated for line 2.
                instruction_at(64, line_two_offset, 11),
            ],
            sources: BTreeMap::from([(0, "C.sol".to_owned())]),
            variable_locations: BTreeMap::new(),
        };
        let debug =
            ContractDebugInfo::new(None, "C", info, BTreeMap::from([(0, source.to_owned())]));

        let mut trace = TransactionTrace {
            tx_hash: None,
            from_addr: "0x1".to_owned(),
            to_addr: None,
            value: "0x0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 0,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: None,
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps: Vec::new(),
        };
        for pc in [2, 4, 64] {
            trace.steps.push(soldb_core::TraceStep {
                pc,
                op: "JUMPDEST".into(),
                gas: 0,
                gas_cost: 0,
                depth: 0,
                stack: Vec::new(),
                memory: None,
                storage: None,
                error: None,
                snapshot: Default::default(),
            });
        }

        let mut state = DebuggerState::new();
        state.load_trace(trace);
        state.attach_debug_info(vec![debug]);
        let outcome =
            state.set_breakpoint_target(&BreakpointTarget::SourceLine(SourceBreakpointTarget {
                file: Some("C.sol".to_owned()),
                line: 2,
            }));
        let StepOutcome::BreakpointSet(breakpoint) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(breakpoint.label(), "C.sol:2");
        // The dispatcher steps belong to line 1; only the instruction generated for line 2
        // enters the line.
        assert!(matches!(
            state.continue_execution(),
            StepOutcome::BreakpointHit {
                step: 2,
                pc: 64,
                ..
            }
        ));
    }

    #[test]
    fn shortening_hex_handles_non_ascii_values() {
        // Trace values are whatever the node sent us. Slicing bytes 2..6 panicked when a
        // multi-byte character straddled byte 6.
        assert_eq!(
            shorten_hex("0x\u{20ac}\u{20ac}\u{20ac}\u{20ac}\u{20ac}"),
            "0x\u{20ac}\u{20ac}\u{20ac}\u{20ac}..."
        );
        assert_eq!(shorten_hex("0x1234"), "0x1234");
        assert_eq!(shorten_hex("not hex at all"), "not hex at all");
        assert_eq!(
            shorten_hex("0x00000000000000000000000000000000000000000000000000000000000000ff"),
            "0x0000..."
        );
    }

    #[test]
    fn builds_call_frames_from_ethdebug_source_metadata() {
        let dir = temp_dir("ethdebug-frames");
        let source = r#"
contract Counter {
    function set(uint256 amount) public {
        helper(amount, amount + 1);
    }

    function helper(uint256 amount, uint256 amount2) internal {
    }
}
"#;
        fs::write(dir.join("Counter.sol"), source).expect("write source");
        fs::write(
            dir.join("ethdebug.json"),
            json!({
                "compilation": {
                    "compiler": {"name": "solc", "version": "0.8.31+commit.test"},
                    "sources": [{"id": 0, "path": "Counter.sol"}]
                }
            })
            .to_string(),
        )
        .expect("write metadata");

        let set_offset = source.find("function set").expect("set offset");
        let helper_offset = source.find("function helper").expect("helper offset");
        fs::write(
            dir.join("Counter_ethdebug-runtime.json"),
            json!({
                "contract": {"name": "Counter"},
                "environment": "runtime",
                "instructions": [
                    {
                        "offset": 10,
                        "operation": {"mnemonic": "JUMPDEST"},
                        "context": {
                            "code": {
                                "source": {"id": 0},
                                "range": {"offset": set_offset, "length": 12}
                            }
                        }
                    },
                    {
                        "offset": 20,
                        "operation": {"mnemonic": "JUMPDEST"},
                        "context": {
                            "code": {
                                "source": {"id": 0},
                                "range": {"offset": helper_offset, "length": 18}
                            }
                        }
                    }
                ]
            })
            .to_string(),
        )
        .expect("write runtime");

        let spec = ResolvedContractSpec {
            address: Some("0x2".to_owned()),
            name: "Counter".to_owned(),
            debug_dir: dir,
            source_paths: Vec::new(),
        };
        let calldata = encode_function_call("set(uint256)", &["4".to_owned()]).expect("calldata");
        let trace = transaction_trace(
            calldata,
            vec![
                trace_step(10, &["0x01", "0x02"]),
                trace_step(20, &["0xaa", "0xbb", "0x04"]),
            ],
        );

        let frames = build_trace_call_frames(&trace, &spec, None);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].name, "set");
        assert_eq!(frames[0].params[0].name, "amount");
        assert_eq!(frames[0].params[0].value, "4");
        assert_eq!(frames[0].source_path.as_deref(), Some("Counter.sol"));
        assert_eq!(frames[0].source_line, Some(3));
        assert!(!frames[0].internal);
        assert_eq!(frames[1].name, "helper");
        assert_eq!(frames[1].source_path.as_deref(), Some("Counter.sol"));
        assert_eq!(frames[1].source_line, Some(7));
        assert!(frames[1].internal);
        assert!(frames[1].params.is_empty());
        assert_eq!(
            format_source_prototype(&frames[1].name, &frames[1].source_params),
            "helper(uint256 amount, uint256 amount2)"
        );
        assert_eq!(
            format_raw_stack(&frames[1].raw_stack),
            "[0] 0x00000000000000000000000000000000000000000000000000000000000000aa [1] 0x00000000000000000000000000000000000000000000000000000000000000bb [2] 0x0000000000000000000000000000000000000000000000000000000000000004"
        );
    }

    #[test]
    fn loads_legacy_source_maps_for_source_debugging() {
        let dir = temp_dir("legacy-source-debugging");
        let source = "contract Counter {\n    function set(uint256 value) external {}\n}\n";
        let set_offset = source.find("function set").expect("set offset");
        fs::write(dir.join("Counter.sol"), source).expect("write source");
        fs::write(
            dir.join("combined.json"),
            json!({
                "version": "0.8.36+commit.test",
                "sourceList": ["Counter.sol"],
                "contracts": {
                    "Counter.sol:Counter": {
                        "bin-runtime": "60015b",
                        "srcmap-runtime": format!(
                            "0:{}:0:-:0;{set_offset}:12:0",
                            source.len()
                        )
                    }
                }
            })
            .to_string(),
        )
        .expect("write combined JSON");
        let spec = ResolvedContractSpec {
            address: Some("0x2".to_owned()),
            name: "Counter".to_owned(),
            debug_dir: dir,
            source_paths: Vec::new(),
        };

        let index = TraceSourceIndex::load(&spec).expect("load legacy source map");
        assert_eq!(
            index.debug.info.source_info(2),
            Some(("Counter.sol", set_offset as u64, 12))
        );
        // Legacy maps attribute steps to functions like ETHDebug does.
        assert_eq!(
            index
                .function_at_pc(2)
                .map(|function| function.name.as_str()),
            Some("set")
        );

        let trace = transaction_trace(
            "0x".to_owned(),
            vec![trace_step(0, &[]), trace_step(2, &[])],
        );
        let mut state = DebuggerState::new();
        state.load_trace(trace);
        state.attach_debug_info(vec![index.debug.clone()]);
        let outcome =
            state.set_breakpoint_target(&BreakpointTarget::SourceLine(SourceBreakpointTarget {
                file: Some("Counter.sol".to_owned()),
                line: 2,
            }));
        assert!(
            matches!(&outcome, StepOutcome::BreakpointSet(breakpoint) if breakpoint.label() == "Counter.sol:2"),
            "{outcome:?}"
        );

        let web = web_contract_metadata_for_spec(&spec).expect("web metadata");
        let expected_mapping = format!("{set_offset}:12:0");
        assert_eq!(
            web.pc_to_source_mappings.get(&2).map(String::as_str),
            Some(expected_mapping.as_str())
        );
        assert_eq!(web.sources.get(&0).map(String::as_str), Some(source));

        fs::write(
            spec.debug_dir.join("ethdebug.json"),
            json!({
                "compilation": {
                    "sources": [{"id": 0, "path": "Counter.sol"}]
                }
            })
            .to_string(),
        )
        .expect("write ETHDebug metadata");
        fs::write(
            spec.debug_dir.join("Counter_ethdebug-runtime.json"),
            json!({
                "instructions": [{
                    "offset": 7,
                    "operation": {"mnemonic": "STOP"},
                    "context": {
                        "code": {
                            "source": {"id": 0},
                            "range": {"offset": 0, "length": 1}
                        }
                    }
                }]
            })
            .to_string(),
        )
        .expect("write ETHDebug program");

        let preferred = TraceSourceIndex::load(&spec).expect("prefer ETHDebug");
        assert!(preferred.debug.info.instruction_at_pc(7).is_some());
        assert!(preferred.debug.info.instruction_at_pc(2).is_none());
    }

    #[test]
    fn builds_web_contract_metadata_from_ethdebug_artifacts() {
        let dir = temp_dir("web-contract-metadata");
        let source = "contract Counter { function set(uint256 amount) public {} }";
        fs::write(dir.join("Counter.sol"), source).expect("write source");
        fs::write(
            dir.join("ethdebug.json"),
            json!({
                "compilation": {
                    "compiler": {"name": "solc", "version": "0.8.31+commit.test"},
                    "sources": [{"id": 0, "path": "Counter.sol"}]
                }
            })
            .to_string(),
        )
        .expect("write metadata");
        fs::write(
            dir.join("Counter_ethdebug-runtime.json"),
            json!({
                "contract": {"name": "Counter"},
                "environment": "runtime",
                "instructions": [
                    {
                        "offset": 10,
                        "operation": {"mnemonic": "JUMPDEST"},
                        "context": {
                            "code": {
                                "source": {"id": 0},
                                "range": {"offset": 4, "length": 8}
                            }
                        }
                    }
                ]
            })
            .to_string(),
        )
        .expect("write runtime");
        fs::write(
            dir.join("Counter.abi"),
            r#"[{"type":"function","name":"set","inputs":[{"name":"amount","type":"uint256"}]}]"#,
        )
        .expect("write abi");

        let spec = ResolvedContractSpec {
            address: None,
            name: "Counter".to_owned(),
            debug_dir: dir,
            source_paths: Vec::new(),
        };
        let trace = transaction_trace("0x".to_owned(), Vec::new());
        let contracts = web_contracts_for_specs(vec![spec], &trace, None);
        let metadata = contracts.get("0x2").expect("contract metadata");
        assert_eq!(
            metadata.pc_to_source_mappings.get(&10).map(String::as_str),
            Some("4:8:0")
        );
        assert_eq!(metadata.sources.get(&0).map(String::as_str), Some(source));
        assert_eq!(
            metadata.source_paths.get(&0).map(String::as_str),
            Some("Counter.sol")
        );
        assert!(metadata.debug_available);
        assert_eq!(metadata.abi.as_ref().expect("abi")[0]["name"], "set");
    }

    #[test]
    fn decodes_abi_descriptors_from_abi_and_combined_json() {
        let abi_dir = temp_dir("abi");
        fs::write(
            abi_dir.join("Token.abi"),
            r#"[{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}]}]"#,
        )
        .expect("write abi");
        let spec = ResolvedContractSpec {
            address: Some("0x2".to_owned()),
            name: "Token".to_owned(),
            debug_dir: abi_dir,
            source_paths: Vec::new(),
        };
        let calldata = encode_function_call(
            "transfer(address,uint256)",
            &[
                "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_owned(),
                "99".to_owned(),
            ],
        )
        .expect("calldata");
        let descriptor = abi_descriptor_for_calldata(&spec, &calldata).expect("descriptor");
        assert_eq!(descriptor.name, "transfer");
        assert_eq!(
            descriptor.params[0].value,
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
        assert_eq!(descriptor.params[1].value, "99");

        let combined_dir = temp_dir("combined");
        fs::write(
            combined_dir.join("combined.json"),
            json!({
                "version": "0.8.16+commit.test",
                "contracts": {
                    "Legacy.sol:Legacy": {
                        "abi": [
                            {
                                "type": "function",
                                "name": "set",
                                "inputs": [{"name": "value", "type": "string"}]
                            }
                        ]
                    }
                }
            })
            .to_string(),
        )
        .expect("write combined");
        let legacy = ResolvedContractSpec {
            address: None,
            name: "Legacy".to_owned(),
            debug_dir: combined_dir,
            source_paths: Vec::new(),
        };
        let raw = encode_function_call("set(string)", &["hi".to_owned()]).expect("calldata");
        let descriptor = abi_descriptor_for_calldata(&legacy, &raw).expect("combined descriptor");
        assert_eq!(descriptor.name, "set");
        assert_eq!(descriptor.params[0].name, "value");
        assert!(descriptor.params[0].raw);
        assert_eq!(
            descriptor.params[0].value,
            "0x0000000000000000000000000000000000000000000000000000000000000020"
        );
    }

    #[test]
    fn resolves_contract_specs_from_supported_file_shapes() {
        let dir = temp_dir("contracts");
        let debug_dir = dir.join("debug");
        fs::create_dir_all(&debug_dir).expect("create debug dir");
        fs::write(debug_dir.join("Token.abi"), "[]").expect("write abi");

        let mapping = dir.join("contracts.json");
        fs::write(
            &mapping,
            json!({
                "contracts": [
                    {"address": "0xabc", "name": "Token", "debug_dir": "debug"}
                ]
            })
            .to_string(),
        )
        .expect("write mapping");
        let specs = load_contract_mapping_file(&mapping).expect("mapping");
        assert_eq!(specs[0].address.as_deref(), Some("0xabc"));
        assert_eq!(specs[0].debug_dir, debug_dir);

        let deployment = dir.join("deployment.json");
        fs::write(
            &deployment,
            json!({"address": "0xdef", "contract": "Token"}).to_string(),
        )
        .expect("write deployment");
        let specs = load_deployment_file(&deployment).expect("deployment");
        assert_eq!(specs[0].name, "Token");
        assert_eq!(find_debug_dir_for_contract(&dir, "Token"), dir);
        assert_eq!(infer_contract_name_from_dir(&dir), None);
        assert_eq!(
            infer_contract_name_from_dir(&debug_dir).as_deref(),
            Some("Token")
        );

        let specs = resolve_ethdebug_spec(&format!("0xabc:{}", mapping.display()))
            .expect("resolve with address");
        assert_eq!(specs[0].name, "Token");

        let fallback =
            resolve_ethdebug_spec(&format!("0xmissing:{}", debug_dir.display())).expect("fallback");
        assert_eq!(fallback[0].name, "Token");
        assert_eq!(
            abi_path_for_contract(&debug_dir, "Token").expect("abi path"),
            debug_dir.join("Token.abi")
        );
    }

    #[test]
    fn event_json_covers_raw_and_decoded_paths() {
        let event = parse_event_abis(
            r#"[{"type":"event","name":"Updated","inputs":[{"name":"value","type":"uint256","indexed":false}]}]"#,
        )
        .expect("event abi")
        .remove(0);
        let topic = soldb_ethdebug::event_topic(&event);
        let mut registry = EventRegistry::default();
        registry
            .insert(Some("Counter".to_owned()), event)
            .expect("insert event");
        let logs = vec![
            RpcLog {
                address: "0x2".to_owned(),
                topics: vec![topic],
                data: format!("0x{:064x}", 42),
            },
            RpcLog {
                address: "0x3".to_owned(),
                topics: vec!["0x1234".to_owned()],
                data: "04".to_owned(),
            },
        ];

        let output = events_to_json("0xabc", &logs, &registry).expect("events json");
        assert!(output.contains("\"event\": \"Updated\""));
        assert!(output.contains("\"value\": 42"));
        assert!(output.contains("\"data\": \"0x04\""));
        let raw_items = raw_event_data_items("0x");
        assert_eq!(raw_items.len(), 1);
        assert_eq!(
            serde_json::to_value(&raw_items[0]).expect("raw item")["value"],
            "0x"
        );

        let mut args = list_events_args();
        assert!(!should_decode_events(&args));
        args.multi_contract = true;
        assert!(should_decode_events(&args));
    }

    #[test]
    fn simulate_and_format_helpers_cover_error_paths() {
        let mut args = simulate_args();
        let view_of =
            |args: &SimulateArgs| SimulationView::for_simulate(args, &args.contract_address);
        assert!(maybe_auto_deploy(&args).expect("auto deploy").is_none());
        assert!(simulate_calldata(&view_of(&args)).is_err());

        args.function_signature = Some("increment(uint256)".to_owned());
        args.function_args = vec!["4".to_owned()];
        let calldata = simulate_calldata(&view_of(&args)).expect("encoded calldata");
        assert!(calldata.starts_with("0x7cf5dab0"));
        assert_eq!(
            simulate_json_function_name(&view_of(&args), &calldata),
            "increment(uint256)"
        );
        assert_eq!(
            simulate_display_function_name(&view_of(&args), &calldata),
            "increment"
        );
        let descriptor =
            simulated_call_descriptor(&view_of(&args), &calldata, "increment").expect("descriptor");
        assert_eq!(descriptor.name, "increment(uint256)");
        assert_eq!(descriptor.params[0].value, "4");
        assert_eq!(
            format_simulated_call(&view_of(&args), "increment"),
            "increment(4)"
        );

        args.raw_data = Some("0x1234".to_owned());
        assert!(simulate_calldata(&view_of(&args)).is_err());
        args.function_signature = None;
        args.function_args.clear();
        assert_eq!(
            simulate_calldata(&view_of(&args)).expect("raw calldata"),
            "0x1234"
        );

        assert!(validate_simulate_value("0x2a").is_ok());
        assert!(validate_simulate_value("42").is_ok());
        assert!(validate_simulate_value("1ether").is_ok());
        assert!(validate_simulate_value("0.1ether").is_ok());
        assert!(validate_simulate_value(".5ether").is_ok());
        assert!(validate_simulate_value("nope").is_err());
        assert!(validate_simulate_value("0.0000000000000000001ether").is_err());
        assert_eq!(normalize_hex("abcd"), "0xabcd");
        assert_eq!(normalize_hex("0xabcd"), "0xabcd");
        assert_eq!(display_json_value(&json!("hello")), "hello");
        assert_eq!(display_json_value(&json!({"a": 1})), "{\"a\":1}");
        assert_eq!(shorten_hex("0x1234567890"), "0x1234...");
        assert_eq!(shorten_hex("0x1234"), "0x1234");
        assert_eq!(format_stack(&[]), "[empty]");
        assert!(
            format_stack(&["0x01".into(), "0x02".into(), "0x03".into(), "0x04".into()])
                .contains("... +1 more")
        );
        assert_eq!(
            call_target_stack_word(&["0x1".into(), "0x2".into()]),
            Some("0x1")
        );
        assert_eq!(call_target_stack_word(&["0x1".into()]), None);
        assert_eq!(
            extract_address_from_stack_word(
                "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266"
            )
            .as_deref(),
            Some("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
        );
        assert!(extract_address_from_stack_word("0x0").is_none());
        assert!(extract_address_from_stack_word(&format!("0x{}", "0".repeat(64))).is_none());
    }

    #[test]
    fn metadata_and_summary_helpers_cover_legacy_and_plain_paths() {
        let dir = temp_dir("metadata");
        fs::write(
            dir.join("combined.json"),
            json!({"version": "0.8.16+commit.test", "contracts": {}}).to_string(),
        )
        .expect("write combined");
        let spec = ResolvedContractSpec {
            address: None,
            name: "Legacy".to_owned(),
            debug_dir: dir.clone(),
            source_paths: Vec::new(),
        };
        let metadata = trace_debug_metadata(&spec);
        assert!(metadata.is_legacy);
        assert_eq!(metadata.compiler_version.as_deref(), Some("0.8.16"));

        fs::remove_file(dir.join("combined.json")).expect("remove combined");
        fs::write(
            dir.join("ethdebug.json"),
            json!({
                "compilation": {
                    "compiler": {"version": "0.8.31+commit.test"},
                    "sources": [{"id": 0, "path": "Missing.sol"}]
                }
            })
            .to_string(),
        )
        .expect("write ethdebug");
        let metadata = trace_debug_metadata(&spec);
        assert!(!metadata.is_legacy);
        assert_eq!(metadata.compiler_version.as_deref(), Some("0.8.31"));

        let trace_args = TraceView {
            tx_hash: "0xabc".to_owned(),
            rpc_url: None,
            ethdebug_dir: vec![format!("0x2:Legacy:{}", dir.display())],
            source_path: Vec::new(),
            contracts: None,
            max_steps: 1,
        };
        let trace = transaction_trace("0x".to_owned(), vec![trace_step(0, &[])]);
        print_plain_trace_summary(&trace);
        print_raw_trace(&trace, &trace_args);
        assert_eq!(trace_contract_name(&trace_args).as_deref(), Some("Legacy"));
    }

    #[test]
    fn decoded_word_helpers_keep_raw_fallbacks() {
        let raw = "0xabcdef120000000000000000000000000000000000000000000000000000000000000020";
        let word = decode_calldata_word(raw, 0, "string").expect("raw word");
        assert!(word.raw);
        assert_eq!(
            word.value,
            "0x0000000000000000000000000000000000000000000000000000000000000020"
        );
        assert_eq!(
            decode_static_word(
                "0000000000000000000000000000000000000000000000000000000000000001",
                "bool"
            )
            .as_deref(),
            Some("true")
        );
        assert_eq!(
            decode_static_word(
                "000000000000000000000000000000000000000000000000000000000000002a",
                "uint256"
            )
            .as_deref(),
            Some("42")
        );
        assert_eq!(
            decode_static_word(
                "000000000000000000000000000000000000000000000000000000000000002a",
                "bytes32"
            )
            .as_deref(),
            Some("0x000000000000000000000000000000000000000000000000000000000000002a")
        );
        assert!(selector_from_calldata("0xxyz").is_none());
        assert_eq!(selector_hex([0xab, 0xcd, 0xef, 0x12]), "abcdef12");
        assert_eq!(
            format_uint_word(&"f".repeat(64)),
            format!("0x{}", "f".repeat(64))
        );
    }

    #[test]
    fn json_printing_reports_serialization_errors() {
        let value: Value = serde_json::from_str(r#"{"ok":true}"#).expect("json");
        print_json(&value).expect("print json");
        assert!(read_json_file(Path::new("/definitely/missing/file.json")).is_err());
    }
}
