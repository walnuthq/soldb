//! Source-level debug-info differential command.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use soldb_core::{SoldbError, SoldbResult, TransactionTrace};
use soldb_debugger::{
    capture_debug_trace, compare_debug_traces, ContractDebugInfo, DebugDiffMode, DebugDiffReport,
    DebugDifference, DebugTraceEvent,
};
use soldb_ethdebug::SourceMapEnvironment;

use crate::{
    bold, dim, error_color, function_color, info, number_color, print_json,
    print_json_command_error, resolve_contract_specs, success, TraceBackendArg, TraceSourceIndex,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DebugDiffModeArg {
    Steps,
    Spans,
    Coverage,
}

impl From<DebugDiffModeArg> for DebugDiffMode {
    fn from(value: DebugDiffModeArg) -> Self {
        match value {
            DebugDiffModeArg::Steps => Self::Steps,
            DebugDiffModeArg::Spans => Self::Spans,
            DebugDiffModeArg::Coverage => Self::Coverage,
        }
    }
}

#[derive(Debug, Args)]
pub(crate) struct DebugDiffArgs {
    /// A serialized reference `TransactionTrace`.
    #[arg(
        long,
        value_name = "PATH",
        required_unless_present = "reference_tx",
        conflicts_with = "reference_tx"
    )]
    reference_trace_file: Option<PathBuf>,
    /// Reference transaction hash to trace through `--rpc`.
    #[arg(
        long,
        value_name = "HASH",
        required_unless_present = "reference_trace_file",
        conflicts_with = "reference_trace_file"
    )]
    reference_tx: Option<String>,
    /// A serialized candidate `TransactionTrace`.
    #[arg(
        long,
        value_name = "PATH",
        required_unless_present = "candidate_tx",
        conflicts_with = "candidate_tx"
    )]
    candidate_trace_file: Option<PathBuf>,
    /// Candidate transaction hash to trace through `--rpc`.
    #[arg(
        long,
        value_name = "HASH",
        required_unless_present = "candidate_trace_file",
        conflicts_with = "candidate_trace_file"
    )]
    candidate_tx: Option<String>,
    /// Trace backend used for transaction hashes.
    #[arg(long, value_enum, default_value_t = TraceBackendArg::Replay)]
    backend: TraceBackendArg,
    /// RPC endpoint used for transaction hashes.
    #[arg(long, default_value = "http://localhost:8545")]
    rpc: String,
    /// Reference artifact as `<address>:<contract>:<dir>`. Repeatable.
    #[arg(long = "reference-ethdebug-dir", value_name = "SPEC")]
    reference_ethdebug_dir: Vec<String>,
    /// Root for sources named by reference artifacts. Repeatable.
    #[arg(long = "reference-source-path", value_name = "PATH")]
    reference_source_path: Vec<String>,
    /// Reference multi-contract mapping file.
    #[arg(long = "reference-contracts", value_name = "PATH")]
    reference_contracts: Option<String>,
    /// Candidate artifact as `<address>:<contract>:<dir>`. Repeatable.
    #[arg(long = "candidate-ethdebug-dir", value_name = "SPEC")]
    candidate_ethdebug_dir: Vec<String>,
    /// Root for sources named by candidate artifacts. Repeatable.
    #[arg(long = "candidate-source-path", value_name = "PATH")]
    candidate_source_path: Vec<String>,
    /// Candidate multi-contract mapping file.
    #[arg(long = "candidate-contracts", value_name = "PATH")]
    candidate_contracts: Option<String>,
    /// Compare ordered steps, exact spans, or reached source coverage.
    #[arg(long, value_enum, default_value_t = DebugDiffModeArg::Steps)]
    mode: DebugDiffModeArg,
    /// Maximum number of differences included in the report.
    #[arg(long, default_value_t = 8)]
    max_differences: usize,
    /// Emit one machine-readable report.
    #[arg(long)]
    json: bool,
}

pub(crate) fn command(args: &DebugDiffArgs) -> SoldbResult<()> {
    match command_inner(args) {
        Err(SoldbError::AlreadyReported) => Err(SoldbError::AlreadyReported),
        Err(error) if args.json => {
            print_json_command_error("DebugDiffError", &error.to_string(), None)?;
            Err(SoldbError::AlreadyReported)
        }
        result => result,
    }
}

fn command_inner(args: &DebugDiffArgs) -> SoldbResult<()> {
    let reference_trace = load_trace(
        "reference",
        args.reference_trace_file.as_deref(),
        args.reference_tx.as_deref(),
        &args.rpc,
        args.backend,
    )?;
    let candidate_trace = load_trace(
        "candidate",
        args.candidate_trace_file.as_deref(),
        args.candidate_tx.as_deref(),
        &args.rpc,
        args.backend,
    )?;
    let reference_contracts = load_contracts(
        "reference",
        &reference_trace,
        &args.reference_ethdebug_dir,
        args.reference_contracts.as_deref(),
        &args.reference_source_path,
    )?;
    let candidate_contracts = load_contracts(
        "candidate",
        &candidate_trace,
        &args.candidate_ethdebug_dir,
        args.candidate_contracts.as_deref(),
        &args.candidate_source_path,
    )?;
    let reference = capture_debug_trace(&reference_trace, reference_contracts);
    let candidate = capture_debug_trace(&candidate_trace, candidate_contracts);
    let report = compare_debug_traces(
        &reference,
        &candidate,
        args.mode.into(),
        args.max_differences,
    );

    if args.json {
        print_json(&report)?;
    } else {
        print_report(&report);
    }
    if report.equivalent {
        Ok(())
    } else {
        Err(SoldbError::AlreadyReported)
    }
}

fn load_trace(
    side: &str,
    path: Option<&Path>,
    tx_hash: Option<&str>,
    rpc: &str,
    backend: TraceBackendArg,
) -> SoldbResult<TransactionTrace> {
    if let Some(path) = path {
        let input = fs::read_to_string(path).map_err(|error| {
            SoldbError::Message(format!(
                "failed to read {side} trace file `{}`: {error}",
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

    let Some(tx_hash) = tx_hash else {
        return Err(SoldbError::Message(format!(
            "debug diff requires a {side} transaction or trace file"
        )));
    };
    soldb_rpc::trace_transaction_with_resolved_backend(rpc, tx_hash, backend.into())
        .map(|resolved| resolved.trace)
}

fn load_contracts(
    side: &str,
    trace: &TransactionTrace,
    ethdebug_dirs: &[String],
    contracts_file: Option<&str>,
    source_paths: &[String],
) -> SoldbResult<Vec<ContractDebugInfo>> {
    let specs = resolve_contract_specs(ethdebug_dirs, contracts_file, source_paths)?;
    if specs.is_empty() {
        return Err(SoldbError::Message(format!(
            "no {side} debug artifacts provided; use `--{side}-ethdebug-dir` or \
             `--{side}-contracts`"
        )));
    }
    let environment = if trace.to_addr.is_some() {
        SourceMapEnvironment::Runtime
    } else {
        SourceMapEnvironment::Creation
    };

    specs
        .iter()
        .map(|spec| {
            TraceSourceIndex::load_environment(spec, environment)?
                .map(|index| index.debug)
                .ok_or_else(|| {
                    SoldbError::Message(format!(
                        "no {side} {} debug program for `{}` found in `{}`",
                        environment_name(environment),
                        spec.name,
                        spec.debug_dir.display()
                    ))
                })
        })
        .collect()
}

fn environment_name(environment: SourceMapEnvironment) -> &'static str {
    match environment {
        SourceMapEnvironment::Creation => "creation",
        SourceMapEnvironment::Runtime => "runtime",
    }
}

fn print_report(report: &DebugDiffReport) {
    println!("{}", bold(info("Debug Info Differential")));
    println!("{} {:?}", info("Mode:"), report.mode);
    print_summary("Reference", &report.reference);
    print_summary("Candidate", &report.candidate);
    if !report.execution_equivalent {
        println!("{}", error_color("Execution differs:"));
        for difference in &report.execution_differences {
            println!("  - {difference}");
        }
    }
    for diagnostic in &report.diagnostics {
        println!("{} {diagnostic}", error_color("Unavailable:"));
    }
    if report.equivalent {
        println!("{} {}", info("Result:"), success("MATCH"));
        return;
    }

    println!("{} {}", info("Result:"), error_color("DIFFERENT"));
    println!(
        "{} {}",
        info("Source differences:"),
        number_color(report.difference_count)
    );
    for difference in &report.differences {
        print_difference(difference);
    }
    if report.differences_truncated {
        println!("{}", dim("additional differences omitted"));
    }
}

fn print_summary(label: &str, summary: &soldb_debugger::DebugTraceSummary) {
    println!(
        "{} {} source steps; {}/{} instructions mapped; {} frame entries",
        info(format!("{label}:")),
        number_color(summary.source_steps),
        number_color(summary.mapped_instructions),
        number_color(summary.instructions),
        number_color(summary.frame_entries)
    );
}

fn print_difference(difference: &DebugDifference) {
    println!(
        "{} {}",
        error_color(format!("{:?}", difference.kind)),
        dim(format!("at source step {}", difference.index))
    );
    if let Some(event) = &difference.reference {
        println!("  {} {}", info("reference:"), format_event(event));
    }
    if let Some(event) = &difference.candidate {
        println!("  {} {}", info("candidate:"), format_event(event));
    }
}

fn format_event(event: &DebugTraceEvent) -> String {
    let function = event.function.as_deref().unwrap_or("<contract>");
    format!(
        "{}:{}:{} in {}::{} at depth {} (instruction {}, pc {})",
        event.source,
        event.line,
        event.column,
        event.contract,
        function_color(function),
        event.frame_depth,
        event.instruction,
        event.pc
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::load_trace;
    use crate::TraceBackendArg;

    #[test]
    fn invalid_trace_file_names_the_side() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("soldb-debug-diff-{unique}.json"));
        fs::write(&path, "not json").expect("write trace");

        let error = load_trace("candidate", Some(&path), None, "", TraceBackendArg::Replay)
            .expect_err("invalid trace");

        assert!(error.to_string().contains("invalid transaction trace"));
    }
}
