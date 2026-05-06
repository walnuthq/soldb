use clap::{Args, Parser, Subcommand};
use serde_json::json;
use soldb_core::{SoldbResult, TransactionTrace};
use soldb_ethdebug::{
    encode_function_call, function_selector, parse_ethdebug_spec, parse_event_abis,
    parse_signature, parse_variable_locations, DecodedEvent, EthdebugInfo, EventRegistry,
    Instruction,
};
use soldb_repl::{DebuggerCommand, DebuggerState, StepOutcome};
use soldb_rpc::RpcLog;
use std::collections::BTreeMap;
use std::env;
use std::fmt::Display;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;

const VERSION: &str = env!("CARGO_PKG_VERSION");
static COLORS_ENABLED: OnceLock<bool> = OnceLock::new();

fn colors_enabled() -> bool {
    *COLORS_ENABLED.get_or_init(|| {
        if let Some(force) = env::var_os("CLICOLOR_FORCE") {
            return force.to_string_lossy() != "0";
        }
        if env::var_os("NO_COLOR").is_some() {
            return false;
        }
        io::stdout().is_terminal() && env::var("TERM").map_or(true, |term| term != "dumb")
    })
}

fn paint(value: impl Display, code: &str) -> String {
    let text = value.to_string();
    if colors_enabled() {
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
    #[command(about = "Compile Solidity contracts with ETHDebug artifacts")]
    Compile(CompileArgs),
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
        Command::Bridge(args) => bridge_command(&args),
        Command::Compile(args) => compile_command(&args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if !error.to_string().is_empty() {
                eprintln!("{error}");
            }
            ExitCode::from(2)
        }
    }
}

fn compile_command(args: &CompileArgs) -> SoldbResult<()> {
    let config = soldb_compiler::CompilerConfig::with_paths(
        args.solc_path.clone(),
        &args.output_dir,
        &args.production_dir,
    );

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
    let trace = match soldb_rpc::trace_transaction(&args.rpc, &args.tx_hash) {
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
            return Err(soldb_core::SoldbError::Message(String::new()));
        }
        Err(error) => return Err(error),
    };
    if args.interactive {
        run_interactive_debugger(trace, "Transaction trace debugger")?;
    } else if args.json {
        println!("{}", soldb_serializer::trace_to_web_json(&trace)?);
    } else if args.raw {
        print_raw_trace(&trace, args);
    } else {
        print_trace_summary(&trace, args);
    }

    Ok(())
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
    let calldata = match simulate_calldata(args) {
        Ok(calldata) => calldata,
        Err(error) if args.json => {
            print_json_command_error("SimulationError", &error.to_string(), None)?;
            return Err(soldb_core::SoldbError::Message(String::new()));
        }
        Err(error) => return Err(error),
    };
    if let Err(message) = validate_simulate_value(&args.value) {
        if args.json {
            print_json_command_error("InvalidValue", &message, Some(&args.value))?;
            return Err(soldb_core::SoldbError::Message(String::new()));
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
    let trace = soldb_rpc::simulate_call(&args.rpc_url, &request)?;
    let json_function_name = simulate_json_function_name(args, &calldata);
    let display_function_name = simulate_display_function_name(args, &calldata);

    if args.interactive {
        print_simulation_interactive_prelude(
            args,
            &contract_address,
            contract_name.as_deref(),
            &calldata,
            &display_function_name,
        );
        run_interactive_debugger(trace, "Simulation debugger")?;
    } else if args.json {
        println!(
            "{}",
            soldb_serializer::simulate_to_web_json(&trace, &json_function_name)?
        );
    } else if args.raw {
        print_raw_simulation(&trace, args, &contract_address);
    } else {
        print_simulation_summary(
            &trace,
            args,
            &contract_address,
            contract_name.as_deref(),
            &calldata,
            &display_function_name,
        );
    }

    Ok(())
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
    args: &SimulateArgs,
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
        let params = resolve_contract_specs(&args.ethdebug_dir, args.contracts.as_deref())
            .ok()
            .and_then(|specs| {
                specs
                    .into_iter()
                    .find_map(|spec| call_descriptor_for_calldata(&spec, calldata))
            })
            .map(|descriptor| descriptor.params)
            .unwrap_or_else(|| {
                args.function_args
                    .iter()
                    .enumerate()
                    .map(|(index, value)| DecodedCallParam {
                        name: format!("arg{index}"),
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

fn run_interactive_debugger(trace: TransactionTrace, title: &str) -> SoldbResult<()> {
    let contract_address = trace.to_addr.clone().or(trace.contract_address.clone());
    let mut state = DebuggerState::new();
    state.load_trace(trace);

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
            DebuggerCommand::Unknown(command) => {
                println!("{} {}", warning("Unknown command:"), command);
            }
            command => {
                if let Some(outcome) = state.apply_command(command) {
                    print_step_outcome(&state, &outcome);
                }
            }
        }
    }

    Ok(())
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
    if !step.stack.is_empty() {
        println!("{} {}", info("Stack:"), format_stack(&step.stack));
    }
}

fn print_step_outcome(state: &DebuggerState, outcome: &StepOutcome) {
    match outcome {
        StepOutcome::NoTrace => println!("{}", warning("No trace loaded.")),
        StepOutcome::Moved { .. } => print_current_debugger_step(state),
        StepOutcome::BreakpointHit { step, pc } => {
            println!(
                "{} step {}, PC {}",
                success("Breakpoint hit at"),
                number_color(step),
                number_color(pc)
            );
            print_current_debugger_step(state);
        }
        StepOutcome::AtEnd { step } => {
            println!("{} {}", info("End of trace at step"), number_color(step));
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
        StepOutcome::BreakpointSet(pc) => {
            println!("{} PC {}", success("Breakpoint set at"), number_color(pc));
        }
        StepOutcome::BreakpointCleared(pc) => {
            println!("{} PC {}", info("Breakpoint cleared at"), number_color(pc));
        }
        StepOutcome::BreakpointMissing(pc) => {
            println!(
                "{} PC {}",
                warning("No breakpoint set at"),
                number_color(pc)
            );
        }
    }
}

fn print_debugger_help(topic: Option<&str>) {
    match topic {
        Some("mode") => println!("mode source|asm - switch display mode"),
        Some(topic) => println!("No help for {topic}"),
        None => {
            println!("Commands: next, nexti, step, continue, goto <step>");
            println!("          break <pc>, clear <pc>, mode source|asm, help, quit");
        }
    }
}

fn list_events_command(args: &ListEventsArgs) -> SoldbResult<()> {
    let logs = match soldb_rpc::transaction_logs(&args.rpc_url, &args.tx_hash) {
        Ok(logs) => logs,
        Err(error) if args.json_events => {
            print_json_command_error("TransactionReceiptError", &error.to_string(), None)?;
            return Err(soldb_core::SoldbError::Message(String::new()));
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

fn print_trace_summary(trace: &TransactionTrace, args: &TraceArgs) {
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
    println!("{} {}", info("Contract:"), function_color(&spec.name));
    if let Some(compiler) = metadata.compiler_version {
        println!("{} solc {}", info("Compiler:"), number_color(compiler));
    }
    println!("{}", bold(info("Function Call Trace:")));
    println!("{} {}", info("Gas used:"), success(trace.gas_used));
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

fn print_raw_trace(trace: &TransactionTrace, args: &TraceArgs) {
    println!(
        "{} {}",
        info("Loading transaction"),
        address_color(&args.tx_hash)
    );
    if let Some(contract_name) = trace_contract_name(args) {
        println!("{} {}", info("Contract:"), function_color(contract_name));
    }
    println!("{}", bold(info("Execution trace")));
    println!(
        "{} | {} | {} | {} | {}",
        bold("Step"),
        bold("PC"),
        bold("Op"),
        bold("Gas"),
        bold("Stack")
    );

    let max_steps = if args.max_steps < 0 {
        trace.steps.len()
    } else {
        usize::try_from(args.max_steps).unwrap_or(trace.steps.len())
    };

    for (index, step) in trace.steps.iter().take(max_steps).enumerate() {
        println!(
            "{} | {} | {} | {} | {}",
            number_color(format!("{index:>4}")),
            number_color(format!("{:>4}", step.pc)),
            opcode_color(format!("{:<14}", step.op)),
            success(format!("{:>8}", step.gas)),
            format_stack(&step.stack)
        );
    }
}

fn print_raw_simulation(trace: &TransactionTrace, args: &SimulateArgs, contract_address: &str) {
    println!(
        "{} {}",
        info("Simulating call to"),
        address_color(contract_address)
    );
    if let Some(contract_name) = simulate_contract_name(args) {
        println!("{} {}", info("Contract:"), function_color(contract_name));
    }
    println!("{}", bold(info("Execution trace")));
    println!(
        "{} | {} | {} | {} | {}",
        bold("Step"),
        bold("PC"),
        bold("Op"),
        bold("Gas"),
        bold("Stack")
    );

    let max_steps = if args.max_steps < 0 {
        trace.steps.len()
    } else {
        usize::try_from(args.max_steps).unwrap_or(trace.steps.len())
    };

    for (index, step) in trace.steps.iter().take(max_steps).enumerate() {
        println!(
            "{} | {} | {} | {} | {}",
            number_color(format!("{index:>4}")),
            number_color(format!("{:>4}", step.pc)),
            opcode_color(format!("{:<14}", step.op)),
            success(format!("{:>8}", step.gas)),
            format_stack(&step.stack)
        );
    }
}

fn print_simulation_summary(
    trace: &TransactionTrace,
    args: &SimulateArgs,
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
    if !has_debug_info {
        println!(
            "{} {}",
            info("Connecting to RPC:"),
            address_color(&args.rpc_url)
        );
        if let Some(signature) = &args.function_signature {
            println!(
                "{} {}",
                warning("No ABI files found. Proceeding with function signature:"),
                function_color(signature)
            );
        }
    }
    println!("{} {}", info("Contract:"), function_color(&contract_name));
    println!("{}", bold(info("Function Call Trace:")));
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
    raw_stack: Vec<String>,
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
    value: String,
    raw: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceFunction {
    source_id: u64,
    name: String,
    params: Vec<SourceParam>,
    declaration_start: u64,
    body_end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceParam {
    name: String,
    ty: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceSourceIndex {
    info: EthdebugInfo,
    functions: Vec<SourceFunction>,
}

impl TraceSourceIndex {
    fn load(spec: &ResolvedContractSpec) -> SoldbResult<Self> {
        let metadata_path = spec.debug_dir.join("ethdebug.json");
        let runtime_path = find_runtime_ethdebug(&spec.debug_dir, &spec.name).ok_or_else(|| {
            soldb_core::SoldbError::Message(format!(
                "No ETHDebug runtime file found in {}",
                spec.debug_dir.display()
            ))
        })?;

        let metadata = read_json_file(&metadata_path)?;
        let runtime = read_json_file(&runtime_path)?;
        let instructions = runtime
            .get("instructions")
            .cloned()
            .map(serde_json::from_value::<Vec<Instruction>>)
            .transpose()
            .map_err(|error| {
                soldb_core::SoldbError::Message(format!(
                    "Invalid instructions in {}: {error}",
                    runtime_path.display()
                ))
            })?
            .unwrap_or_default();
        let compilation = metadata
            .get("compilation")
            .cloned()
            .unwrap_or_else(|| metadata.clone());
        let sources = parse_compilation_sources(&compilation);
        let variable_locations = parse_variable_locations(&runtime)?;
        let info = EthdebugInfo {
            compilation,
            contract_name: spec.name.clone(),
            environment: "runtime".to_owned(),
            instructions,
            sources,
            variable_locations,
        };

        let mut functions = Vec::new();
        for (source_id, source_path) in &info.sources {
            if let Some(source) = read_debug_source(&spec.debug_dir, source_path) {
                functions.extend(parse_source_functions(*source_id, &source));
            }
        }

        Ok(Self { info, functions })
    }

    fn function_at_pc(&self, pc: u64) -> Option<&SourceFunction> {
        let location = self.info.instruction_at_pc(pc)?.source_location()?;
        self.functions
            .iter()
            .filter(|function| {
                function.source_id == location.source_id
                    && function.declaration_start <= location.offset
                    && location.offset <= function.body_end
            })
            .min_by_key(|function| function.body_end - function.declaration_start)
    }

    fn descriptor_for_calldata(&self, calldata: &str) -> Option<CallDescriptor> {
        let selector = selector_from_calldata(calldata)?;
        self.functions.iter().find_map(|function| {
            let signature = source_function_signature(function);
            let function_selector = selector_hex(function_selector(&signature).ok()?);
            (function_selector == selector)
                .then(|| descriptor_from_source_function(function, calldata))
        })
    }
}

fn print_call_frames(frames: &[CallFrame]) {
    for (index, frame) in frames.iter().enumerate() {
        if frame.internal {
            println!(
                "{} {} {}",
                dim(format!("#{}", index + 1)),
                function_color(&frame.name),
                dim("[internal]")
            );
        } else {
            println!(
                "{} {}",
                dim(format!("#{}", index + 1)),
                function_color(&frame.name)
            );
        }
        for param in &frame.params {
            let label = if param.raw {
                format!("{} raw:", param.name)
            } else {
                format!("{}:", param.name)
            };
            println!("  {} {}", info(label), number_color(&param.value));
        }
        if frame.internal && !frame.source_params.is_empty() && frame.params.is_empty() {
            let signature = frame
                .source_params
                .iter()
                .map(|param| format!("{}:{}", param.name, param.ty))
                .collect::<Vec<_>>()
                .join(", ");
            println!("  {} {}", info("args:"), dim(signature));
            if !frame.raw_stack.is_empty() {
                println!(
                    "  {} {}",
                    info("raw stack:"),
                    number_color(format_raw_stack(&frame.raw_stack))
                );
            }
        }
    }
}

fn build_trace_call_frames(
    trace: &TransactionTrace,
    spec: &ResolvedContractSpec,
    fallback: Option<CallDescriptor>,
) -> Vec<CallFrame> {
    let source_index = TraceSourceIndex::load(spec).ok();
    let descriptor = source_index
        .as_ref()
        .and_then(|index| index.descriptor_for_calldata(&trace.input_data))
        .or_else(|| abi_descriptor_for_calldata(spec, &trace.input_data))
        .or(fallback);
    build_call_frames(trace, source_index.as_ref(), descriptor)
}

fn build_simulation_call_frames(
    trace: &TransactionTrace,
    args: &SimulateArgs,
    raw_data: &str,
    fallback: Option<CallDescriptor>,
) -> Vec<CallFrame> {
    let source_index = resolve_contract_specs(&args.ethdebug_dir, args.contracts.as_deref())
        .ok()
        .and_then(|specs| {
            specs
                .into_iter()
                .find_map(|spec| TraceSourceIndex::load(&spec).ok())
        });
    let descriptor = source_index
        .as_ref()
        .and_then(|index| index.descriptor_for_calldata(raw_data))
        .or_else(|| {
            resolve_contract_specs(&args.ethdebug_dir, args.contracts.as_deref())
                .ok()
                .and_then(|specs| {
                    specs
                        .into_iter()
                        .find_map(|spec| abi_descriptor_for_calldata(&spec, raw_data))
                })
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
                raw_stack: step.stack.clone(),
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
    TraceSourceIndex::load(spec)
        .ok()
        .and_then(|index| index.descriptor_for_calldata(calldata))
        .or_else(|| abi_descriptor_for_calldata(spec, calldata))
}

fn simulated_call_descriptor(
    args: &SimulateArgs,
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

    resolve_contract_specs(&args.ethdebug_dir, args.contracts.as_deref())
        .ok()
        .and_then(|specs| {
            specs
                .into_iter()
                .find_map(|spec| call_descriptor_for_calldata(&spec, raw_data))
        })
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
                        value: word.value,
                        raw: word.raw,
                    })
                })
                .collect();
            Some(CallDescriptor { name, params })
        })
}

fn abi_entries_for_spec(spec: &ResolvedContractSpec) -> Option<Vec<FunctionAbiEntry>> {
    if let Some(abi_path) = abi_path_for_contract(&spec.debug_dir, &spec.name) {
        let content = fs::read_to_string(abi_path).ok()?;
        return serde_json::from_str::<Vec<FunctionAbiEntry>>(&content).ok();
    }

    let combined = read_json_file(&spec.debug_dir.join("combined.json")).ok()?;
    let contracts = combined.get("contracts")?.as_object()?;
    contracts
        .iter()
        .find(|(key, _)| {
            key.rsplit_once(':')
                .map_or(*key == &spec.name, |(_, name)| name == spec.name)
        })
        .and_then(|(_, contract)| contract.get("abi").cloned())
        .and_then(|abi| serde_json::from_value::<Vec<FunctionAbiEntry>>(abi).ok())
}

fn descriptor_from_source_function(function: &SourceFunction, calldata: &str) -> CallDescriptor {
    let params = function
        .params
        .iter()
        .enumerate()
        .filter_map(|(index, param)| {
            decode_calldata_word(calldata, index, &param.ty).map(|word| DecodedCallParam {
                name: param.name.clone(),
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

fn format_raw_stack(stack: &[String]) -> String {
    if stack.is_empty() {
        return "[empty]".to_owned();
    }
    stack
        .iter()
        .enumerate()
        .map(|(index, value)| format!("[{index}] {}", normalize_hex(value)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn find_runtime_ethdebug(root: &Path, contract_name: &str) -> Option<PathBuf> {
    let named = root.join(format!("{contract_name}_ethdebug-runtime.json"));
    if named.exists() {
        return Some(named);
    }

    fs::read_dir(root)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with("_ethdebug-runtime.json"))
        })
}

fn parse_compilation_sources(compilation: &serde_json::Value) -> BTreeMap<u64, String> {
    compilation
        .get("sources")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|source| {
            Some((
                source.get("id")?.as_u64()?,
                source.get("path")?.as_str()?.to_owned(),
            ))
        })
        .collect()
}

fn read_debug_source(root: &Path, source_path: &str) -> Option<String> {
    let source = Path::new(source_path);
    let mut candidates = Vec::new();
    if source.is_absolute() {
        candidates.push(source.to_path_buf());
    } else {
        candidates.push(root.join(source));
        if let Some(parent) = root.parent() {
            candidates.push(parent.join(source));
        }
        candidates.push(source.to_path_buf());
    }

    candidates
        .into_iter()
        .find_map(|candidate| fs::read_to_string(candidate).ok())
}

fn parse_source_functions(source_id: u64, source: &str) -> Vec<SourceFunction> {
    let mut functions = Vec::new();
    let mut cursor = 0;
    while let Some(keyword_start) = find_solidity_keyword(source, "function", cursor) {
        let mut index = keyword_start + "function".len();
        index = skip_ascii_whitespace(source, index);
        let Some((name, name_end)) = parse_identifier(source, index) else {
            cursor = index;
            continue;
        };
        index = skip_ascii_whitespace(source, name_end);
        let Some(params_start) = source.as_bytes().get(index).filter(|byte| **byte == b'(') else {
            cursor = index;
            continue;
        };
        let _ = params_start;
        let Some(params_end) = find_matching_delimiter(source, index, b'(', b')') else {
            cursor = index + 1;
            continue;
        };
        let params = parse_source_params(&source[index + 1..params_end]);
        let Some(body_start) = find_next_byte(source, params_end + 1, b'{') else {
            cursor = params_end + 1;
            continue;
        };
        let Some(body_end) = find_matching_delimiter(source, body_start, b'{', b'}') else {
            cursor = body_start + 1;
            continue;
        };

        functions.push(SourceFunction {
            source_id,
            name: name.to_owned(),
            params,
            declaration_start: keyword_start as u64,
            body_end: body_end as u64,
        });
        cursor = body_end + 1;
    }
    functions
}

fn parse_source_params(params: &str) -> Vec<SourceParam> {
    split_top_level_commas(params)
        .into_iter()
        .enumerate()
        .filter_map(|(index, param)| {
            let param = param.trim();
            if param.is_empty() {
                return None;
            }
            let mut tokens = param.split_whitespace().collect::<Vec<_>>();
            let name = tokens
                .last()
                .copied()
                .filter(|token| is_identifier(token))
                .map_or_else(|| format!("arg{index}"), str::to_owned);
            if tokens.last().copied() == Some(name.as_str()) && tokens.len() > 1 {
                tokens.pop();
            }
            let ty = tokens
                .into_iter()
                .filter(|token| !matches!(*token, "memory" | "calldata" | "storage" | "payable"))
                .collect::<Vec<_>>()
                .join(" ");
            (!ty.is_empty()).then_some(SourceParam { name, ty })
        })
        .collect()
}

fn split_top_level_commas(input: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0_i32;
    for (index, byte) in input.bytes().enumerate() {
        match byte {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(&input[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&input[start..]);
    parts
}

fn find_solidity_keyword(source: &str, keyword: &str, start: usize) -> Option<usize> {
    let mut cursor = start;
    while let Some(relative) = source[cursor..].find(keyword) {
        let absolute = cursor + relative;
        let before = absolute
            .checked_sub(1)
            .and_then(|index| source.as_bytes().get(index))
            .copied();
        let after = source.as_bytes().get(absolute + keyword.len()).copied();
        if before.is_none_or(|byte| !is_identifier_byte(byte))
            && after.is_none_or(|byte| !is_identifier_byte(byte))
        {
            return Some(absolute);
        }
        cursor = absolute + keyword.len();
    }
    None
}

fn parse_identifier(source: &str, start: usize) -> Option<(&str, usize)> {
    let bytes = source.as_bytes();
    let first = *bytes.get(start)?;
    if !is_identifier_start_byte(first) {
        return None;
    }
    let mut end = start + 1;
    while bytes.get(end).is_some_and(|byte| is_identifier_byte(*byte)) {
        end += 1;
    }
    Some((&source[start..end], end))
}

fn is_identifier(input: &str) -> bool {
    let mut bytes = input.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    is_identifier_start_byte(first) && bytes.all(is_identifier_byte)
}

fn is_identifier_start_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_identifier_byte(byte: u8) -> bool {
    is_identifier_start_byte(byte) || byte.is_ascii_digit()
}

fn skip_ascii_whitespace(source: &str, mut index: usize) -> usize {
    while source
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn find_next_byte(source: &str, start: usize, needle: u8) -> Option<usize> {
    source
        .as_bytes()
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, byte)| (*byte == needle).then_some(index))
}

fn find_matching_delimiter(source: &str, open_index: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0_i32;
    for (index, byte) in source.bytes().enumerate().skip(open_index) {
        if byte == open {
            depth += 1;
        } else if byte == close {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
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
    let mut registry = EventRegistry::default();
    if !should_decode_events(args) {
        return Ok(registry);
    }
    for spec in resolve_contract_specs(&args.ethdebug_dir, args.contracts.as_deref())? {
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
}

fn resolve_contract_specs(
    ethdebug_dirs: &[String],
    contracts_file: Option<&str>,
) -> SoldbResult<Vec<ResolvedContractSpec>> {
    let mut specs = Vec::new();
    if let Some(contracts_file) = contracts_file {
        specs.extend(load_contract_mapping_file(Path::new(contracts_file))?);
    }

    for spec_text in ethdebug_dirs {
        specs.extend(resolve_ethdebug_spec(spec_text)?);
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
            }]);
        }
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
        .find(|candidate| candidate.join("ethdebug.json").exists())
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
    None
}

fn read_json_file(path: &Path) -> SoldbResult<serde_json::Value> {
    let content = fs::read_to_string(path).map_err(|error| {
        soldb_core::SoldbError::Message(format!("Failed to read {}: {error}", path.display()))
    })?;
    serde_json::from_str(&content).map_err(|error| {
        soldb_core::SoldbError::Message(format!("Invalid JSON {}: {error}", path.display()))
    })
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

fn trace_contract_name(args: &TraceArgs) -> Option<String> {
    resolve_contract_specs(&args.ethdebug_dir, args.contracts.as_deref())
        .ok()
        .and_then(|specs| specs.into_iter().next().map(|spec| spec.name))
}

fn trace_contract_spec(args: &TraceArgs) -> Option<ResolvedContractSpec> {
    resolve_contract_specs(&args.ethdebug_dir, args.contracts.as_deref())
        .ok()
        .and_then(|specs| specs.into_iter().next())
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct TraceDebugMetadata {
    is_legacy: bool,
    compiler_version: Option<String>,
}

fn trace_debug_metadata(spec: &ResolvedContractSpec) -> TraceDebugMetadata {
    let combined_json = spec.debug_dir.join("combined.json");
    if combined_json.exists() {
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
            compiler_version: version,
        };
    }

    let ethdebug_json = spec.debug_dir.join("ethdebug.json");
    let compiler_version = read_json_file(&ethdebug_json)
        .ok()
        .and_then(|value| {
            value
                .get("compilation")
                .and_then(|compilation| compilation.get("compiler"))
                .and_then(|compiler| compiler.get("version"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .map(|version| {
            version
                .split_once('+')
                .map_or(version.as_str(), |(core, _)| core)
                .to_owned()
        });
    TraceDebugMetadata {
        is_legacy: false,
        compiler_version,
    }
}

fn simulate_contract_name(args: &SimulateArgs) -> Option<String> {
    resolve_contract_specs(&args.ethdebug_dir, args.contracts.as_deref())
        .ok()
        .and_then(|specs| specs.into_iter().next().map(|spec| spec.name))
}

fn simulate_calldata(args: &SimulateArgs) -> SoldbResult<String> {
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
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map(|_| ())
    } else {
        value.parse::<u64>().map(|_| ())
    };
    parsed.map_err(|_| format!("Invalid value for --value: {value}"))
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

fn format_simulated_call(args: &SimulateArgs, function_name: &str) -> String {
    if args.function_args.is_empty() {
        return args
            .function_signature
            .as_ref()
            .cloned()
            .unwrap_or_else(|| function_name.to_owned());
    }
    format!("{}({})", function_name, args.function_args.join(", "))
}

fn simulation_source_file(args: &SimulateArgs, contract_name: &str) -> Option<String> {
    resolve_contract_specs(&args.ethdebug_dir, args.contracts.as_deref())
        .ok()?
        .into_iter()
        .find(|spec| spec.name == contract_name)
        .and_then(|spec| {
            let ethdebug = spec.debug_dir.join("ethdebug.json");
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

    resolve_contract_specs(&args.ethdebug_dir, args.contracts.as_deref())
        .ok()
        .and_then(|specs| {
            specs
                .into_iter()
                .find_map(|spec| call_descriptor_for_calldata(&spec, calldata))
        })
        .map_or_else(|| "raw_data".to_owned(), |descriptor| descriptor.name)
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

fn print_json<T: serde::Serialize>(value: &T) -> SoldbResult<()> {
    let output = serde_json::to_string_pretty(value)
        .map_err(|error| soldb_core::SoldbError::Message(error.to_string()))?;
    println!("{output}");
    Ok(())
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

fn shorten_hex(value: &str) -> String {
    if value.len() > 10 && value.starts_with("0x") {
        format!("0x{}...", &value[2..6])
    } else {
        value.to_owned()
    }
}
