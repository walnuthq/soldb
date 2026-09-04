//! Gas-profile command loading and presentation.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use clap::Args;
use soldb_core::{SoldbError, SoldbResult, TransactionTrace};
use soldb_ethdebug::SourceMapEnvironment;
use soldb_profiler::{profile_transaction, ProfileProgram, ProfileReport, ProgramEnvironment};

use crate::{
    bold, dim, error_color, function_color, info, number_color, opcode_color, print_json,
    print_json_command_error, resolve_contract_specs, separator, success, TraceBackendArg,
    TraceSourceIndex,
};

#[derive(Debug, Args)]
pub(crate) struct ProfileArgs {
    #[arg(required_unless_present = "trace_file", conflicts_with = "trace_file")]
    tx_hash: Option<String>,
    #[arg(
        long,
        value_name = "PATH",
        required_unless_present = "tx_hash",
        conflicts_with = "tx_hash"
    )]
    trace_file: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = TraceBackendArg::Replay)]
    backend: TraceBackendArg,
    #[arg(long = "ethdebug-dir", short = 'e')]
    ethdebug_dir: Vec<String>,
    #[arg(long, short = 'c')]
    contracts: Option<String>,
    #[arg(long, short = 'r', default_value = "http://localhost:8545")]
    rpc: String,
    #[arg(long, default_value_t = 20)]
    top: usize,
    #[arg(long)]
    json: bool,
    #[arg(long, value_name = "PATH")]
    folded: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    flamegraph: Option<PathBuf>,
}

pub(crate) fn command(args: &ProfileArgs) -> SoldbResult<()> {
    match command_inner(args) {
        Err(error) if args.json => {
            print_json_command_error("ProfileError", &error.to_string(), None)?;
            Err(SoldbError::AlreadyReported)
        }
        result => result,
    }
}

fn command_inner(args: &ProfileArgs) -> SoldbResult<()> {
    let trace = load_trace(args)?;
    let programs = load_programs(args, &trace)?;
    let report = profile_transaction(&trace, &programs)?;

    if let Some(path) = &args.folded {
        write_folded(&report, path)?;
    }
    if let Some(path) = &args.flamegraph {
        write_flamegraph(&report, path)?;
    }

    if args.json {
        print_json(&report)?;
    } else {
        print_report(&report, args.top);
        if let Some(path) = &args.folded {
            println!("{} {}", info("Folded stacks:"), path.display());
        }
        if let Some(path) = &args.flamegraph {
            println!("{} {}", info("Flame graph:"), path.display());
        }
    }
    Ok(())
}

fn load_trace(args: &ProfileArgs) -> SoldbResult<TransactionTrace> {
    if let Some(path) = &args.trace_file {
        let input = fs::read_to_string(path).map_err(|error| {
            SoldbError::Message(format!(
                "failed to read trace file `{}`: {error}",
                path.display()
            ))
        })?;
        return serde_json::from_str(&input).map_err(|error| {
            SoldbError::Message(format!(
                "invalid transaction trace in `{}`: {error}",
                path.display()
            ))
        });
    }

    let tx_hash = args.tx_hash.as_deref().ok_or_else(|| {
        SoldbError::Message("profile requires a transaction hash or `--trace-file`".to_owned())
    })?;
    soldb_rpc::trace_transaction_with_resolved_backend(&args.rpc, tx_hash, args.backend.into())
        .map(|resolved| resolved.trace)
}

fn load_programs(args: &ProfileArgs, trace: &TransactionTrace) -> SoldbResult<Vec<ProfileProgram>> {
    let specs = resolve_contract_specs(&args.ethdebug_dir, args.contracts.as_deref())?;
    let single_spec = specs.len() == 1;
    let mut programs = Vec::new();

    for spec in specs {
        if !single_spec && spec.address.is_none() {
            return Err(SoldbError::Message(format!(
                "multi-contract profile requires an address for `{}`; use \
                 `<address>:<contract>:<dir>` or a contract mapping file",
                spec.name
            )));
        }
        let mut loaded = false;
        if let Some(index) =
            TraceSourceIndex::load_environment(&spec, SourceMapEnvironment::Runtime)?
        {
            let address = spec
                .address
                .clone()
                .or_else(|| single_spec.then(|| trace.to_addr.clone()).flatten());
            programs.push(ProfileProgram::new(
                address,
                index.debug.info,
                index.debug.source_contents,
            )?);
            loaded = true;
        }
        if let Some(index) =
            TraceSourceIndex::load_environment(&spec, SourceMapEnvironment::Creation)?
        {
            let address = spec.address.clone().or_else(|| {
                single_spec
                    .then(|| trace.contract_address.clone())
                    .flatten()
            });
            programs.push(ProfileProgram::new(
                address,
                index.debug.info,
                index.debug.source_contents,
            )?);
            loaded = true;
        }
        if !loaded {
            return Err(SoldbError::Message(format!(
                "no ETHDebug or legacy source-map program for `{}` found in `{}`",
                spec.name,
                spec.debug_dir.display()
            )));
        }
    }

    Ok(programs)
}

fn write_folded(report: &ProfileReport, path: &Path) -> SoldbResult<()> {
    fs::write(path, report.folded_text()).map_err(|error| {
        SoldbError::Message(format!(
            "failed to write folded stacks to `{}`: {error}",
            path.display()
        ))
    })
}

fn write_flamegraph(report: &ProfileReport, path: &Path) -> SoldbResult<()> {
    let folded = report.folded_text();
    if folded.is_empty() {
        return Err(SoldbError::Message(
            "cannot render a flame graph without nonzero gas samples".to_owned(),
        ));
    }

    let output = fs::File::create(path).map_err(|error| {
        SoldbError::Message(format!(
            "failed to create flame graph `{}`: {error}",
            path.display()
        ))
    })?;
    let mut options = inferno::flamegraph::Options::default();
    options.title = "EVM gas profile".to_owned();
    options.count_name = "gas".to_owned();
    options.name_type = "stack".to_owned();
    options.deterministic = true;
    inferno::flamegraph::from_reader(&mut options, Cursor::new(folded), output).map_err(|error| {
        SoldbError::Message(format!(
            "failed to render flame graph `{}`: {error}",
            path.display()
        ))
    })
}

fn print_report(report: &ProfileReport, top: usize) {
    println!("{}", bold(info("EVM Gas Profile")));
    if let Some(hash) = &report.transaction.hash {
        println!("{} {hash}", info("Transaction:"));
    }
    if let Some(backend) = &report.transaction.backend {
        println!("{} {backend}", info("Backend:"));
    }
    println!("{} {}", info("Status:"), profile_status(report));
    println!(
        "{} {}",
        info("Transaction gas used:"),
        number_color(report.transaction.gas_used)
    );
    println!(
        "{} {} across {} steps",
        info("Traced instruction gas:"),
        number_color(report.totals.step_gas),
        number_color(report.transaction.steps)
    );
    println!(
        "{} {} ({})",
        info("Program-attributed gas:"),
        number_color(report.totals.program_gas),
        percent(report.totals.program_gas, report.totals.step_gas)
    );
    println!(
        "{} {} ({})",
        info("Source-attributed gas:"),
        number_color(report.totals.source_gas),
        percent(report.totals.source_gas, report.totals.step_gas)
    );
    println!(
        "{} {} ({})",
        info("Known program without source:"),
        number_color(report.totals.sourceless_gas),
        percent(report.totals.sourceless_gas, report.totals.step_gas)
    );
    println!(
        "{} {} ({})",
        info("Unmapped execution gas:"),
        number_color(report.totals.unmapped_gas),
        percent(report.totals.unmapped_gas, report.totals.step_gas)
    );

    print_contracts(report, top);
    print_functions(report, top);
    print_source_lines(report, top);
    print_opcodes(report, top);
    print_hotspots(report, top);
}

fn profile_status(report: &ProfileReport) -> String {
    if report.transaction.success {
        success("SUCCESS")
    } else {
        error_color("REVERTED")
    }
}

fn print_contracts(report: &ProfileReport, top: usize) {
    println!();
    println!("{}", bold("Contracts"));
    println!("{}", separator(72));
    for row in report.contracts.iter().take(top) {
        let environment = match row.environment {
            ProgramEnvironment::Create => "create",
            ProgramEnvironment::Call => "call",
        };
        println!(
            "{:>12} {:>7} {:>8}  {} ({environment})",
            number_color(row.gas),
            percent(row.gas, report.totals.step_gas),
            number_color(row.hits),
            function_color(&row.contract)
        );
    }
    if report.contracts.is_empty() {
        println!("{}", dim("No execution steps matched a debug program"));
    }
}

fn print_functions(report: &ProfileReport, top: usize) {
    println!();
    println!("{}", bold("Functions"));
    println!("{}", separator(72));
    for row in report.functions.iter().take(top) {
        let location = match (&row.source, row.line) {
            (Some(source), Some(line)) => format!(" {source}:{line}"),
            _ => String::new(),
        };
        println!(
            "{:>12} {:>7} {:>8}  {}::{}{}",
            number_color(row.gas),
            percent(row.gas, report.totals.step_gas),
            number_color(row.hits),
            function_color(&row.contract),
            function_color(&row.function),
            dim(location)
        );
    }
    if report.functions.is_empty() {
        println!("{}", dim("No function-level samples"));
    }
}

fn print_source_lines(report: &ProfileReport, top: usize) {
    println!();
    println!("{}", bold("Hot source lines"));
    println!("{}", separator(72));
    for row in report.source_lines.iter().take(top) {
        let text = row
            .text
            .as_deref()
            .map(|text| truncate_text(text, 56))
            .unwrap_or_default();
        println!(
            "{:>12} {:>7} {:>8}  {}:{}  {}",
            number_color(row.gas),
            percent(row.gas, report.totals.step_gas),
            number_color(row.hits),
            row.source,
            row.line,
            dim(text)
        );
    }
    if report.source_lines.is_empty() {
        println!("{}", dim("No source-line samples"));
    }
}

fn print_opcodes(report: &ProfileReport, top: usize) {
    println!();
    println!("{}", bold("Opcodes"));
    println!("{}", separator(72));
    for row in report.opcodes.iter().take(top) {
        println!(
            "{:>12} {:>7} {:>8}  {}",
            number_color(row.gas),
            percent(row.gas, report.totals.step_gas),
            number_color(row.hits),
            opcode_color(&row.opcode)
        );
    }
}

fn print_hotspots(report: &ProfileReport, top: usize) {
    println!();
    println!("{}", bold("Hot instructions"));
    println!("{}", separator(72));
    for row in report.hotspots.iter().take(top) {
        let location = row.source.as_ref().map_or_else(
            || "[no source]".to_owned(),
            |source| {
                source.line.map_or_else(
                    || format!("{}@{}", source.path, source.offset),
                    |line| format!("{}:{line}", source.path),
                )
            },
        );
        println!(
            "{:>12} {:>7} {:>8}  {} PC {} {}",
            number_color(row.gas),
            percent(row.gas, report.totals.step_gas),
            number_color(row.hits),
            opcode_color(&row.opcode),
            number_color(row.pc),
            dim(location)
        );
    }
    if report.hotspots.is_empty() {
        println!("{}", dim("No instructions matched a debug program"));
    }
}

fn percent(value: u64, total: u64) -> String {
    if total == 0 {
        return "0.00%".to_owned();
    }
    format!("{:.2}%", value as f64 * 100.0 / total as f64)
}

fn truncate_text(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let prefix = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;
    use soldb_core::{TraceStep, TransactionTrace};

    use super::{load_programs, percent, truncate_text, ProfileArgs};
    use crate::TraceBackendArg;

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("soldb-profile-{label}-{unique}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn formats_percentages_and_unicode_text() {
        assert_eq!(percent(1, 4), "25.00%");
        assert_eq!(percent(0, 0), "0.00%");
        assert_eq!(truncate_text("aébc", 2), "aé…");
        assert_eq!(truncate_text("short", 8), "short");
    }

    #[test]
    fn profiles_programs_loaded_from_legacy_source_maps() {
        let dir = temp_dir("legacy-source-map");
        let source = "contract Counter {}\n";
        fs::write(dir.join("Counter.sol"), source).expect("write source");
        fs::write(
            dir.join("combined.json"),
            json!({
                "sourceList": ["Counter.sol"],
                "contracts": {
                    "Counter.sol:Counter": {
                        "bin-runtime": "00",
                        "srcmap-runtime": format!("0:{}:0", source.len())
                    }
                }
            })
            .to_string(),
        )
        .expect("write combined JSON");
        let args = ProfileArgs {
            tx_hash: None,
            trace_file: None,
            backend: TraceBackendArg::Replay,
            ethdebug_dir: vec![format!("0x2:Counter:{}", dir.display())],
            contracts: None,
            rpc: String::new(),
            top: 20,
            json: false,
            folded: None,
            flamegraph: None,
        };
        let trace = TransactionTrace {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0x0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 3,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: Some("replay".to_owned()),
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps: vec![TraceStep {
                pc: 0,
                op: "STOP".to_owned(),
                gas: 3,
                gas_cost: 3,
                depth: 0,
                stack: Vec::new(),
                memory: None,
                storage: None,
                error: None,
                snapshot: Default::default(),
            }],
        };

        let programs = load_programs(&args, &trace).expect("load legacy profile program");
        let report = soldb_profiler::profile_transaction(&trace, &programs).expect("profile");

        assert_eq!(programs.len(), 1);
        assert_eq!(report.totals.source_gas, 3);
        assert_eq!(report.source_lines[0].source, "Counter.sol");
        assert_eq!(report.source_lines[0].line, 1);
    }
}
