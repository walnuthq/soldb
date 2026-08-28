//! Gas-profile command loading and presentation.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use clap::Args;
use soldb_core::{SoldbError, SoldbResult, TransactionTrace};
use soldb_profiler::{profile_transaction, ProfileProgram, ProfileReport, ProgramEnvironment};

use crate::{
    bold, dim, error_color, find_creation_ethdebug, find_runtime_ethdebug, function_color, info,
    number_color, opcode_color, print_json, print_json_command_error, resolve_contract_specs,
    separator, success, TraceBackendArg, TraceSourceIndex,
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
        if let Some(path) = find_runtime_ethdebug(&spec.debug_dir, &spec.name) {
            let index = TraceSourceIndex::load_program(&spec, &path, "call")?;
            let address = spec
                .address
                .clone()
                .or_else(|| single_spec.then(|| trace.to_addr.clone()).flatten());
            programs.push(ProfileProgram::new(
                address,
                index.info,
                index.source_contents,
            )?);
            loaded = true;
        }
        if let Some(path) = find_creation_ethdebug(&spec.debug_dir, &spec.name) {
            let index = TraceSourceIndex::load_program(&spec, &path, "create")?;
            let address = spec.address.clone().or_else(|| {
                single_spec
                    .then(|| trace.contract_address.clone())
                    .flatten()
            });
            programs.push(ProfileProgram::new(
                address,
                index.info,
                index.source_contents,
            )?);
            loaded = true;
        }
        if !loaded {
            return Err(SoldbError::Message(format!(
                "no ETHDebug program for `{}` found in `{}`",
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
        println!("{}", dim("No execution steps matched an ETHDebug program"));
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
        println!("{}", dim("No instructions matched an ETHDebug program"));
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
    use super::{percent, truncate_text};

    #[test]
    fn formats_percentages_and_unicode_text() {
        assert_eq!(percent(1, 4), "25.00%");
        assert_eq!(percent(0, 0), "0.00%");
        assert_eq!(truncate_text("aébc", 2), "aé…");
        assert_eq!(truncate_text("short", 8), "short");
    }
}
