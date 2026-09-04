//! The Debug Adapter Protocol server.
//!
//! [`DapServer`] holds one debug session and maps DAP requests onto it: launching from a
//! trace file, an inline trace, or a transaction hash plus RPC URL; setting line and
//! function breakpoints; reporting stack frames, scopes, and variables; and stepping by
//! source line or by instruction, forward and backward.
//!
//! Stepping, breakpoints, and frames go through `soldb-repl` and `soldb-debugger`, the
//! same state machine and source map the terminal debugger uses, so an editor stops at
//! the same steps and reports the same values as the terminal.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use soldb_core::{SoldbError, SoldbResult, TransactionTrace};
use soldb_debugger::ContractDebugInfo;
use soldb_ethdebug::{load_debug_program, SourceMapEnvironment};
use soldb_repl::{BreakpointTarget, DebuggerState, SourceBreakpointTarget, StepOutcome};
use soldb_rpc::trace_transaction;

use crate::{
    decode_dap_frame, encode_dap_frame, initialize_body, stack_trace_body, threads_body,
    DapFrameError, DapMessage, DapServerConfig, Source, StackFrame,
};

const LOCALS_REF: u64 = 1000;
const STACK_REF: u64 = 1001;
const STEP_REF: u64 = 1002;
const MEMORY_REF: u64 = 1003;
const STORAGE_REF: u64 = 1004;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DapServer {
    seq: u64,
    config: DapServerConfig,
    thread_id: u64,
    debugger: DebuggerState,
    source: Option<LoadedSource>,
    /// Line breakpoints by source file, as the editor last sent them. They are applied
    /// once a trace and its debug info are loaded, and re-applied after each launch.
    pending_breakpoints: BTreeMap<String, Vec<u64>>,
    pending_function_breakpoints: Vec<String>,
    /// The breakpoints each `setBreakpoints` source last produced, so the next request
    /// for that source replaces them, as the protocol requires.
    line_breakpoint_ids: BTreeMap<String, Vec<u32>>,
    function_breakpoint_ids: Vec<u32>,
    terminated: bool,
}

/// The contract's debug info and the directory it came from, which the paths reported to
/// the editor are built against.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LoadedSource {
    root: PathBuf,
    contract: ContractDebugInfo,
}

impl Default for DapServer {
    fn default() -> Self {
        Self {
            seq: 1,
            config: DapServerConfig::default(),
            thread_id: 1,
            debugger: DebuggerState::new(),
            source: None,
            pending_breakpoints: BTreeMap::new(),
            pending_function_breakpoints: Vec::new(),
            line_breakpoint_ids: BTreeMap::new(),
            function_breakpoint_ids: Vec::new(),
            terminated: false,
        }
    }
}

impl DapServer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_terminated(&self) -> bool {
        self.terminated
    }

    pub fn handle_message(&mut self, message: &DapMessage) -> Vec<DapMessage> {
        if message.message_type != "request" {
            return Vec::new();
        }

        match message.command.as_deref().unwrap_or_default() {
            "initialize" => self.initialize(message),
            "launch" | "attach" => self.launch(message),
            "configurationDone" => vec![self.response(message, true, Some(json!({})), None)],
            "setBreakpoints" => vec![self.set_breakpoints(message)],
            "setFunctionBreakpoints" => vec![self.set_function_breakpoints(message)],
            "threads" => vec![self.response(
                message,
                true,
                Some(threads_body(self.thread_id, "SolDB trace")),
                None,
            )],
            "stackTrace" => vec![self.stack_trace(message)],
            "scopes" => vec![self.scopes(message)],
            "variables" => vec![self.variables(message)],
            "evaluate" => vec![self.evaluate(message)],
            "continue" => self.continue_execution(message),
            "next" => self.step_over(message),
            "stepIn" => self.step_in(message),
            "stepOut" => self.step_out(message),
            "stepBack" => self.step_back(message),
            "reverseContinue" => self.reverse_continue(message),
            "pause" => {
                let response = self.response(message, true, Some(json!({})), None);
                let event = self.event(
                    "stopped",
                    Some(json!({"reason": "pause", "threadId": self.thread_id})),
                );
                vec![response, event]
            }
            "disconnect" | "terminate" => {
                self.terminated = true;
                let response = self.response(message, true, Some(json!({})), None);
                let event = self.event("terminated", Some(json!({})));
                vec![response, event]
            }
            command => vec![self.response(
                message,
                false,
                None,
                Some(format!("Unsupported DAP command: {command}")),
            )],
        }
    }

    fn initialize(&mut self, request: &DapMessage) -> Vec<DapMessage> {
        let response = self.response(
            request,
            true,
            Some(initialize_body(&self.config.adapter_id)),
            None,
        );
        let initialized = self.event("initialized", None);
        vec![response, initialized]
    }

    fn launch(&mut self, request: &DapMessage) -> Vec<DapMessage> {
        match self.load_launch_arguments(request.arguments.as_ref()) {
            Ok(summary) => {
                let mut messages = vec![self.response(request, true, Some(json!({})), None)];
                if let Some(summary) = summary {
                    messages.push(self.event(
                        "output",
                        Some(json!({"category": "stdout", "output": format!("{summary}\n")})),
                    ));
                    messages.push(self.event(
                        "stopped",
                        Some(json!({"reason": "entry", "threadId": self.thread_id})),
                    ));
                }
                messages
            }
            Err(error) => vec![self.response(request, false, None, Some(error.to_string()))],
        }
    }

    fn load_launch_arguments(&mut self, arguments: Option<&Value>) -> SoldbResult<Option<String>> {
        let args = arguments.cloned().unwrap_or_else(|| json!({}));
        if let Some(ethdebug_dir) = string_arg(&args, &["ethdebugDir", "ethdebugPath", "debugDir"])
        {
            let contract_name = string_arg(&args, &["contractName", "contract"]);
            self.source = Some(LoadedSource::load(
                Path::new(&ethdebug_dir),
                contract_name.as_deref().unwrap_or_default(),
            )?);
        }

        let trace = if let Some(trace_file) = string_arg(&args, &["traceFile", "tracePath"]) {
            let content = fs::read_to_string(&trace_file).map_err(|error| {
                SoldbError::Message(format!("Failed to read trace file {trace_file}: {error}"))
            })?;
            Some(
                serde_json::from_str::<TransactionTrace>(&content).map_err(|error| {
                    SoldbError::Message(format!("Invalid trace JSON {trace_file}: {error}"))
                })?,
            )
        } else if let Some(trace_value) = args.get("trace") {
            Some(
                serde_json::from_value::<TransactionTrace>(trace_value.clone()).map_err(
                    |error| SoldbError::Message(format!("Invalid launch trace object: {error}")),
                )?,
            )
        } else if let Some(tx_hash) =
            string_arg(&args, &["transactionHash", "txHash", "transaction"])
        {
            let rpc_url = string_arg(&args, &["rpcUrl", "rpcURL", "rpc"])
                .or_else(|| std::env::var("RPC_URL").ok())
                .unwrap_or_else(|| "http://127.0.0.1:8545".to_owned());
            Some(trace_transaction(&rpc_url, &tx_hash)?)
        } else {
            None
        };

        let Some(trace) = trace else {
            return Ok(None);
        };

        let step_count = trace.steps.len();
        let tx_hash = trace
            .tx_hash
            .clone()
            .unwrap_or_else(|| "simulation".to_owned());
        self.debugger.load_trace(trace);
        if let Some(source) = &self.source {
            self.debugger
                .attach_debug_info(vec![source.contract.clone()]);
        }
        self.register_pending_breakpoints();
        Ok(Some(format!(
            "Loaded {tx_hash} with {step_count} EVM steps"
        )))
    }

    /// Whether breakpoints can be resolved now: a trace with debug info is loaded.
    fn can_resolve_breakpoints(&self) -> bool {
        self.debugger.trace().is_some() && self.source.is_some()
    }

    fn set_breakpoints(&mut self, request: &DapMessage) -> DapMessage {
        let args = request
            .arguments
            .as_ref()
            .cloned()
            .unwrap_or_else(|| json!({}));
        let source_key = source_key(args.get("source")).unwrap_or_else(|| "unknown".to_owned());
        let lines = args
            .get("breakpoints")
            .and_then(Value::as_array)
            .map(|breakpoints| {
                breakpoints
                    .iter()
                    .filter_map(|breakpoint| breakpoint.get("line").and_then(Value::as_u64))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        self.pending_breakpoints
            .insert(source_key.clone(), lines.clone());
        let breakpoints = if self.can_resolve_breakpoints() {
            self.apply_line_breakpoints(&source_key, &lines)
        } else {
            // Nothing to resolve against yet; they are applied when the launch loads a
            // trace, and reported as set so the editor keeps them.
            lines
                .into_iter()
                .map(|line| json!({"verified": true, "line": line}))
                .collect()
        };
        self.response(
            request,
            true,
            Some(json!({"breakpoints": breakpoints})),
            None,
        )
    }

    fn set_function_breakpoints(&mut self, request: &DapMessage) -> DapMessage {
        let names = request
            .arguments
            .as_ref()
            .and_then(|args| args.get("breakpoints"))
            .and_then(Value::as_array)
            .map(|breakpoints| {
                breakpoints
                    .iter()
                    .filter_map(|breakpoint| breakpoint.get("name").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        self.pending_function_breakpoints = names.clone();
        let breakpoints = if self.can_resolve_breakpoints() {
            self.apply_function_breakpoints(&names)
        } else {
            names.iter().map(|_| json!({"verified": true})).collect()
        };
        self.response(
            request,
            true,
            Some(json!({"breakpoints": breakpoints})),
            None,
        )
    }

    /// Replaces the line breakpoints of one source with `lines`, reporting each as the
    /// protocol wants: verified when it resolved, otherwise with the reason.
    fn apply_line_breakpoints(&mut self, source_key: &str, lines: &[u64]) -> Vec<Value> {
        for id in self
            .line_breakpoint_ids
            .remove(source_key)
            .unwrap_or_default()
        {
            self.debugger.delete_breakpoint(id);
        }
        let mut ids = Vec::new();
        let breakpoints = lines
            .iter()
            .map(|line| {
                let target = BreakpointTarget::SourceLine(SourceBreakpointTarget {
                    file: Some(source_key.to_owned()),
                    line: *line,
                });
                match self.debugger.set_breakpoint_target(&target) {
                    StepOutcome::BreakpointSet(breakpoint) => {
                        ids.push(breakpoint.id);
                        json!({"verified": true, "line": line, "id": breakpoint.id})
                    }
                    StepOutcome::BreakpointError(message) => {
                        json!({"verified": false, "line": line, "message": message})
                    }
                    other => {
                        json!({"verified": false, "line": line, "message": format!("{other:?}")})
                    }
                }
            })
            .collect();
        self.line_breakpoint_ids.insert(source_key.to_owned(), ids);
        breakpoints
    }

    fn apply_function_breakpoints(&mut self, names: &[String]) -> Vec<Value> {
        for id in std::mem::take(&mut self.function_breakpoint_ids) {
            self.debugger.delete_breakpoint(id);
        }
        let mut ids = Vec::new();
        let breakpoints = names
            .iter()
            .map(|name| {
                match self
                    .debugger
                    .set_breakpoint_target(&BreakpointTarget::Function(name.clone()))
                {
                    StepOutcome::BreakpointSet(breakpoint) => {
                        ids.push(breakpoint.id);
                        json!({"verified": true, "id": breakpoint.id})
                    }
                    StepOutcome::BreakpointError(message) => {
                        json!({"verified": false, "message": message})
                    }
                    other => json!({"verified": false, "message": format!("{other:?}")}),
                }
            })
            .collect();
        self.function_breakpoint_ids = ids;
        breakpoints
    }

    fn register_pending_breakpoints(&mut self) {
        if !self.can_resolve_breakpoints() {
            return;
        }
        for (source, lines) in self.pending_breakpoints.clone() {
            self.apply_line_breakpoints(&source, &lines);
        }
        let names = self.pending_function_breakpoints.clone();
        self.apply_function_breakpoints(&names);
    }

    fn stack_trace(&mut self, request: &DapMessage) -> DapMessage {
        let frames = self.stack_frames();
        self.response(request, true, Some(stack_trace_body(frames)), None)
    }

    fn scopes(&mut self, request: &DapMessage) -> DapMessage {
        self.response(
            request,
            true,
            Some(json!({
                "scopes": [
                    {"name": "Locals", "variablesReference": LOCALS_REF, "expensive": false},
                    {"name": "Stack", "variablesReference": STACK_REF, "expensive": false},
                    {"name": "Memory", "variablesReference": MEMORY_REF, "expensive": false},
                    {"name": "Storage", "variablesReference": STORAGE_REF, "expensive": false},
                    {"name": "Step", "variablesReference": STEP_REF, "expensive": false}
                ]
            })),
            None,
        )
    }

    fn variables(&mut self, request: &DapMessage) -> DapMessage {
        let reference = request
            .arguments
            .as_ref()
            .and_then(|args| args.get("variablesReference"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let variables = match reference {
            LOCALS_REF => self.local_variables(),
            STACK_REF => self.stack_variables(),
            MEMORY_REF => self.memory_variables(),
            STORAGE_REF => self.storage_variables(),
            STEP_REF => self.step_variables(),
            _ => Vec::new(),
        };
        self.response(request, true, Some(json!({"variables": variables})), None)
    }

    fn evaluate(&mut self, request: &DapMessage) -> DapMessage {
        let expression = request
            .arguments
            .as_ref()
            .and_then(|args| args.get("expression"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let result = self.evaluate_expression(expression);
        self.response(
            request,
            true,
            Some(json!({"result": result, "variablesReference": 0})),
            None,
        )
    }

    fn continue_execution(&mut self, request: &DapMessage) -> Vec<DapMessage> {
        let outcome = self.debugger.continue_execution();
        let response = self.response(
            request,
            true,
            Some(json!({"allThreadsContinued": true})),
            None,
        );
        vec![response, self.stopped_event(outcome)]
    }

    /// `next`: the next source line in this frame, stepping over calls; one instruction
    /// with instruction granularity or without debug info.
    fn step_over(&mut self, request: &DapMessage) -> Vec<DapMessage> {
        let outcome = if instruction_granularity(request) {
            self.debugger.next_instruction()
        } else {
            self.debugger.next_source()
        };
        let response = self.response(request, true, Some(json!({})), None);
        vec![response, self.stopped_event(outcome)]
    }

    /// `stepIn`: the next source line anywhere, entering calls.
    fn step_in(&mut self, request: &DapMessage) -> Vec<DapMessage> {
        let outcome = if instruction_granularity(request) {
            self.debugger.next_instruction()
        } else {
            self.debugger.step_into()
        };
        let response = self.response(request, true, Some(json!({})), None);
        vec![response, self.stopped_event(outcome)]
    }

    /// The trace is a complete recording, so stepping back is exact: the previous source
    /// line, or the previous instruction, with the machine state it had.
    fn step_back(&mut self, request: &DapMessage) -> Vec<DapMessage> {
        let outcome = if instruction_granularity(request) {
            self.debugger.previous_instruction()
        } else {
            self.debugger.previous_source()
        };
        let response = self.response(request, true, Some(json!({})), None);
        vec![response, self.stopped_event(outcome)]
    }

    fn reverse_continue(&mut self, request: &DapMessage) -> Vec<DapMessage> {
        let outcome = self.debugger.reverse_continue();
        let response = self.response(request, true, Some(json!({})), None);
        vec![response, self.stopped_event(outcome)]
    }

    /// `stepOut`: run until the current frame, external or internal, has returned.
    fn step_out(&mut self, request: &DapMessage) -> Vec<DapMessage> {
        let outcome = self.debugger.finish();
        let response = self.response(request, true, Some(json!({})), None);
        vec![response, self.stopped_event(outcome)]
    }

    /// The call structure at the current step, innermost frame first. Each frame names
    /// its function when the source is known, otherwise the step it sits at.
    fn stack_frames(&self) -> Vec<StackFrame> {
        let Some(trace) = self.debugger.trace() else {
            return Vec::new();
        };
        self.debugger
            .frames()
            .into_iter()
            .enumerate()
            .map(|(index, frame)| {
                let step_name = trace.steps.get(frame.step).map_or_else(
                    || format!("step {}", frame.step),
                    |step| format!("step {}: {} @ pc {}", frame.step, step.op, step.pc),
                );
                let name = match (&frame.function_name, &frame.contract_name) {
                    (Some(function), _) => format!("{function} ({step_name})"),
                    (None, Some(contract)) => format!("{contract} ({step_name})"),
                    (None, None) => step_name,
                };
                let (source, line, column) = match &frame.location {
                    Some(location) => (
                        Some(Source {
                            name: normalize_source_key(&location.path),
                            path: self.display_source_path(&location.path),
                        }),
                        location.line,
                        location.column.max(1),
                    ),
                    None => (None, 1, 1),
                };
                StackFrame {
                    id: index as u64 + 1,
                    name,
                    source,
                    line,
                    column,
                }
            })
            .collect()
    }

    fn display_source_path(&self, source_path: &str) -> String {
        let path = Path::new(source_path);
        match &self.source {
            Some(source) if !path.is_absolute() => source.root.join(path).display().to_string(),
            _ => source_path.to_owned(),
        }
    }

    fn local_variables(&self) -> Vec<Value> {
        let Some(step) = self.debugger.current_step_data() else {
            return Vec::new();
        };
        let Some(source) = &self.source else {
            return Vec::new();
        };
        let Some(trace) = self.debugger.trace() else {
            return Vec::new();
        };

        soldb_debugger::variables_for_step(trace, &source.contract.info, step)
            .into_iter()
            .map(|variable| {
                json!({
                    "name": variable.name,
                    "value": variable.value.display,
                    "type": variable.ty,
                    "variablesReference": 0
                })
            })
            .collect()
    }

    fn stack_variables(&self) -> Vec<Value> {
        let Some(step) = self.debugger.current_step_data() else {
            return Vec::new();
        };
        step.snapshot_ref()
            .stack
            .iter()
            .enumerate()
            .map(|(index, value)| {
                json!({"name": format!("stack[{index}]"), "value": value, "variablesReference": 0})
            })
            .collect()
    }

    fn memory_variables(&self) -> Vec<Value> {
        let Some(step) = self.debugger.current_step_data() else {
            return Vec::new();
        };
        let Some(memory) = step.snapshot_ref().memory else {
            return Vec::new();
        };
        if memory.is_empty() {
            return Vec::new();
        }
        memory
            .as_bytes()
            .chunks(64)
            .enumerate()
            .map(|(index, chunk)| {
                json!({
                    "name": format!("memory[0x{:x}]", index * 32),
                    "value": std::str::from_utf8(chunk).unwrap_or_default(),
                    "variablesReference": 0
                })
            })
            .collect()
    }

    fn storage_variables(&self) -> Vec<Value> {
        let Some(step) = self.debugger.current_step_data() else {
            return Vec::new();
        };
        let snapshot = step.snapshot_ref();
        let mut variables = snapshot
            .storage
            .iter()
            .map(|(slot, value)| json!({"name": slot, "value": value, "variablesReference": 0}))
            .collect::<Vec<_>>();
        variables.extend(snapshot.storage_diff.iter().map(|(slot, change)| {
            json!({
                "name": format!("{slot} diff"),
                "value": format!(
                    "{} -> {}",
                    change.before.as_deref().unwrap_or("<unset>"),
                    change.after.as_deref().unwrap_or("<unset>")
                ),
                "variablesReference": 0
            })
        }));
        variables
    }

    fn step_variables(&self) -> Vec<Value> {
        let Some(step) = self.debugger.current_step_data() else {
            return Vec::new();
        };
        vec![
            json!({"name": "pc", "value": step.pc.to_string(), "variablesReference": 0}),
            json!({"name": "op", "value": step.op, "variablesReference": 0}),
            json!({"name": "gas", "value": step.gas.to_string(), "variablesReference": 0}),
            json!({"name": "gasCost", "value": step.gas_cost.to_string(), "variablesReference": 0}),
            json!({"name": "depth", "value": step.depth.to_string(), "variablesReference": 0}),
        ]
    }

    fn evaluate_expression(&self, expression: &str) -> String {
        let Some(step) = self.debugger.current_step_data() else {
            return "<no trace>".to_owned();
        };
        match expression.trim() {
            "pc" => step.pc.to_string(),
            "op" => step.op.clone(),
            "gas" => step.gas.to_string(),
            "gasCost" | "gas_cost" => step.gas_cost.to_string(),
            "depth" => step.depth.to_string(),
            expression if expression.starts_with("stack[") && expression.ends_with(']') => {
                let index = expression
                    .trim_start_matches("stack[")
                    .trim_end_matches(']')
                    .parse::<usize>()
                    .ok();
                index
                    .and_then(|index| step.snapshot_ref().stack.get(index).cloned())
                    .unwrap_or_else(|| "<unavailable>".to_owned())
            }
            expression if expression.starts_with("storage[") && expression.ends_with(']') => {
                let slot = expression
                    .trim_start_matches("storage[")
                    .trim_end_matches(']');
                step.snapshot_ref()
                    .storage
                    .get(slot)
                    .cloned()
                    .unwrap_or_else(|| "<unavailable>".to_owned())
            }
            _ => "<unsupported expression>".to_owned(),
        }
    }

    fn stopped_event(&mut self, outcome: StepOutcome) -> DapMessage {
        let reason = match outcome {
            StepOutcome::BreakpointHit { .. } => "breakpoint",
            StepOutcome::AtEnd { .. } => "end",
            StepOutcome::AtStart { .. } => "entry",
            StepOutcome::NoTrace => "pause",
            _ => "step",
        };
        self.event(
            "stopped",
            Some(json!({"reason": reason, "threadId": self.thread_id})),
        )
    }

    fn response(
        &mut self,
        request: &DapMessage,
        success: bool,
        body: Option<Value>,
        message: Option<String>,
    ) -> DapMessage {
        let seq = self.next_seq();
        DapMessage::response(seq, request, success, body, message)
    }

    fn event(&mut self, event: &str, body: Option<Value>) -> DapMessage {
        let seq = self.next_seq();
        DapMessage::event(seq, event, body)
    }

    fn next_seq(&mut self) -> u64 {
        let seq = self.seq;
        self.seq += 1;
        seq
    }
}

pub fn run_stdio_server<R: Read, W: Write>(mut reader: R, mut writer: W) -> SoldbResult<()> {
    let mut server = DapServer::new();
    let mut buffer = Vec::<u8>::new();
    let mut chunk = [0_u8; 8192];

    loop {
        let bytes_read = reader
            .read(&mut chunk)
            .map_err(|error| SoldbError::Message(format!("Failed to read DAP input: {error}")))?;
        if bytes_read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);

        loop {
            match decode_dap_frame(&buffer) {
                Ok((message, consumed)) => {
                    buffer.drain(..consumed);
                    for response in server.handle_message(&message) {
                        let frame = encode_dap_frame(&response).map_err(|error| {
                            SoldbError::Message(format!("Failed to encode DAP response: {error}"))
                        })?;
                        writer.write_all(&frame).map_err(|error| {
                            SoldbError::Message(format!("Failed to write DAP response: {error}"))
                        })?;
                    }
                    writer.flush().map_err(|error| {
                        SoldbError::Message(format!("Failed to flush DAP response: {error}"))
                    })?;
                    if server.is_terminated() {
                        return Ok(());
                    }
                }
                Err(DapFrameError::MissingHeaderEnd | DapFrameError::IncompleteBody { .. }) => {
                    break;
                }
                Err(error) => return Err(frame_error(error)),
            }
        }
    }

    Ok(())
}

fn instruction_granularity(request: &DapMessage) -> bool {
    request
        .arguments
        .as_ref()
        .and_then(|args| args.get("granularity"))
        .and_then(Value::as_str)
        == Some("instruction")
}

fn string_arg(args: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| args.get(*key).and_then(Value::as_str))
        .map(str::to_owned)
}

fn source_key(source: Option<&Value>) -> Option<String> {
    let source = source?;
    if let Some(path) = source.get("path").and_then(Value::as_str) {
        return Some(normalize_source_key(path));
    }
    if let Some(name) = source.get("name").and_then(Value::as_str) {
        return Some(normalize_source_key(name));
    }
    source.as_str().map(normalize_source_key)
}

fn normalize_source_key(input: &str) -> String {
    Path::new(input)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(input)
        .to_owned()
}

fn frame_error(error: DapFrameError) -> SoldbError {
    SoldbError::Message(format!("Invalid DAP frame: {error:?}"))
}

impl LoadedSource {
    /// Loads the contract's debug program from `root`: ETHDebug artifacts, or the legacy
    /// source map. An empty name loads the only program in the directory.
    fn load(root: &Path, contract_name: &str) -> SoldbResult<Self> {
        let program = load_debug_program(root, contract_name, SourceMapEnvironment::Runtime)?
            .ok_or_else(|| {
                SoldbError::Message(format!(
                    "no ETHDebug or legacy runtime source map found in `{}`",
                    root.display()
                ))
            })?;
        let name = program.info.contract_name.clone();
        Ok(Self {
            root: root.to_path_buf(),
            contract: ContractDebugInfo::new(None, &name, program.info, program.source_contents),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;
    use soldb_core::{TraceStep, TransactionTrace};

    use crate::{decode_dap_frame, encode_dap_frame, DapMessage};

    use super::{run_stdio_server, DapServer, MEMORY_REF, STACK_REF, STORAGE_REF};

    #[test]
    fn handles_initialize_and_threads() {
        let mut server = DapServer::new();
        let initialize = DapMessage::request(1, "initialize", Some(json!({})));
        let messages = server.handle_message(&initialize);

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].command.as_deref(), Some("initialize"));
        assert_eq!(messages[0].success, Some(true));
        assert_eq!(messages[1].event.as_deref(), Some("initialized"));

        let threads = DapMessage::request(2, "threads", None);
        let messages = server.handle_message(&threads);
        assert_eq!(
            messages[0].body.as_ref().expect("body")["threads"][0]["id"],
            1
        );
    }

    #[test]
    fn steps_back_and_reverse_continues_over_the_recording() {
        let temp = temp_dir("soldb-dap-reverse");
        std::fs::create_dir_all(&temp).expect("create temp");
        let trace_file = temp.join("trace.json");
        std::fs::write(
            &trace_file,
            serde_json::to_string(&sample_trace()).expect("trace json"),
        )
        .expect("write trace");

        let mut server = DapServer::new();
        let initialize = DapMessage::request(1, "initialize", Some(json!({})));
        let messages = server.handle_message(&initialize);
        assert_eq!(
            messages[0].body.as_ref().expect("capabilities")["supportsStepBack"],
            true
        );
        let launch = DapMessage::request(
            2,
            "launch",
            Some(json!({"traceFile": trace_file.display().to_string()})),
        );
        server.handle_message(&launch);
        let frame_name = |server: &mut DapServer, seq: u64| {
            let stack = server.handle_message(&DapMessage::request(seq, "stackTrace", None));
            stack[0].body.as_ref().expect("body")["stackFrames"][0]["name"]
                .as_str()
                .expect("frame name")
                .to_owned()
        };

        // One step forward, one back: the frame names show exactly where we are.
        server.handle_message(&DapMessage::request(3, "next", None));
        assert!(frame_name(&mut server, 4).starts_with("step 1:"));
        let messages = server.handle_message(&DapMessage::request(5, "stepBack", None));
        assert_eq!(messages[0].success, Some(true));
        assert_eq!(messages[1].event.as_deref(), Some("stopped"));
        assert_eq!(messages[1].body.as_ref().expect("body")["reason"], "step");
        assert!(frame_name(&mut server, 6).starts_with("step 0:"));

        // Reverse-continue runs back to the start when nothing earlier is a breakpoint.
        server.handle_message(&DapMessage::request(7, "next", None));
        let request = DapMessage::request(8, "reverseContinue", None);
        let messages = server.handle_message(&request);
        assert_eq!(messages[1].body.as_ref().expect("body")["reason"], "entry");
        assert!(frame_name(&mut server, 9).starts_with("step 0:"));

        // Stepping back at the start stays there and says so.
        let messages = server.handle_message(&DapMessage::request(10, "stepBack", None));
        assert_eq!(messages[1].body.as_ref().expect("body")["reason"], "entry");
        assert!(frame_name(&mut server, 11).starts_with("step 0:"));
    }

    #[test]
    fn launches_trace_file_and_exposes_stack_variables() {
        let temp = temp_dir("soldb-dap-trace");
        std::fs::create_dir_all(&temp).expect("create temp");
        let trace_file = temp.join("trace.json");
        std::fs::write(
            &trace_file,
            serde_json::to_string(&sample_trace()).expect("trace json"),
        )
        .expect("write trace");

        let mut server = DapServer::new();
        let launch = DapMessage::request(
            1,
            "launch",
            Some(json!({"traceFile": trace_file.display().to_string()})),
        );
        let messages = server.handle_message(&launch);
        assert_eq!(messages[0].success, Some(true));
        assert_eq!(messages[2].event.as_deref(), Some("stopped"));

        let stack_trace = DapMessage::request(2, "stackTrace", None);
        let messages = server.handle_message(&stack_trace);
        assert_eq!(
            messages[0].body.as_ref().expect("body")["stackFrames"][0]["name"],
            "step 0: PUSH1 @ pc 0"
        );

        let scopes = DapMessage::request(3, "scopes", None);
        let messages = server.handle_message(&scopes);
        let scope_names = messages[0].body.as_ref().expect("body")["scopes"]
            .as_array()
            .expect("scopes")
            .iter()
            .map(|scope| scope["name"].as_str().expect("scope name"))
            .collect::<Vec<_>>();
        assert!(scope_names.contains(&"Memory"));
        assert!(scope_names.contains(&"Storage"));

        let variables = DapMessage::request(
            4,
            "variables",
            Some(json!({"variablesReference": STACK_REF})),
        );
        let messages = server.handle_message(&variables);
        assert_eq!(
            messages[0].body.as_ref().expect("body")["variables"][0]["value"],
            "0x2a"
        );

        let memory = DapMessage::request(
            5,
            "variables",
            Some(json!({"variablesReference": MEMORY_REF})),
        );
        let messages = server.handle_message(&memory);
        assert_eq!(
            messages[0].body.as_ref().expect("body")["variables"][0]["value"],
            "aa"
        );

        let storage = DapMessage::request(
            6,
            "variables",
            Some(json!({"variablesReference": STORAGE_REF})),
        );
        let messages = server.handle_message(&storage);
        assert_eq!(
            messages[0].body.as_ref().expect("body")["variables"][0]["value"],
            "0x2a"
        );

        let evaluate =
            DapMessage::request(7, "evaluate", Some(json!({"expression": "storage[0x0]"})));
        let messages = server.handle_message(&evaluate);
        assert_eq!(messages[0].body.as_ref().expect("body")["result"], "0x2a");
    }

    #[test]
    fn maps_ethdebug_lines_to_stack_frames_and_breakpoints() {
        let temp = temp_dir("soldb-dap-ethdebug");
        std::fs::create_dir_all(&temp).expect("create temp");
        std::fs::write(
            temp.join("Counter.sol"),
            "contract Counter {\n  function set(uint256 x) public {\n    value = x;\n  }\n}\n",
        )
        .expect("write source");
        std::fs::write(
            temp.join("ethdebug.json"),
            r#"{"compilation":{"sources":[{"id":0,"path":"Counter.sol"}]}}"#,
        )
        .expect("write metadata");
        std::fs::write(
            temp.join("Counter_ethdebug-runtime.json"),
            r#"{"instructions":[{"offset":0,"operation":{"mnemonic":"PUSH1"},"context":{"code":{"source":{"id":0},"range":{"offset":59,"length":9}},"variables":[{"name":"x","type":"uint256","location":{"type":"stack","offset":0},"scope":{"start":0,"end":3}}]}},{"offset":3,"operation":{"mnemonic":"STOP"},"context":{"code":{"source":{"id":0},"range":{"offset":59,"length":9}}}}]}"#,
        )
        .expect("write runtime");
        let trace_file = temp.join("trace.json");
        std::fs::write(
            &trace_file,
            serde_json::to_string(&sample_trace()).expect("trace json"),
        )
        .expect("write trace");

        let mut server = DapServer::new();
        let set_breakpoints = DapMessage::request(
            1,
            "setBreakpoints",
            Some(json!({
                "source": {"path": temp.join("Counter.sol").display().to_string()},
                "breakpoints": [{"line": 3}]
            })),
        );
        assert_eq!(
            server.handle_message(&set_breakpoints)[0]
                .body
                .as_ref()
                .expect("body")["breakpoints"][0]["verified"],
            true
        );

        let launch = DapMessage::request(
            2,
            "launch",
            Some(json!({
                "traceFile": trace_file.display().to_string(),
                "ethdebugDir": temp.display().to_string(),
                "contractName": "Counter"
            })),
        );
        let messages = server.handle_message(&launch);
        assert_eq!(messages[0].success, Some(true));

        let stack_trace = DapMessage::request(3, "stackTrace", None);
        let messages = server.handle_message(&stack_trace);
        let frame = &messages[0].body.as_ref().expect("body")["stackFrames"][0];
        assert_eq!(frame["source"]["name"], "Counter.sol");
        assert_eq!(frame["line"], 3);
        assert!(
            frame["name"]
                .as_str()
                .expect("name")
                .starts_with("set (step 0:"),
            "{frame}"
        );

        // Function breakpoints resolve against the parsed source; an unknown name is
        // reported unverified with the reason.
        let function_breakpoints = DapMessage::request(
            30,
            "setFunctionBreakpoints",
            Some(json!({"breakpoints": [{"name": "set"}, {"name": "missing"}]})),
        );
        let body = server.handle_message(&function_breakpoints)[0]
            .body
            .clone()
            .expect("body");
        assert_eq!(body["breakpoints"][0]["verified"], true);
        assert_eq!(body["breakpoints"][1]["verified"], false);
        assert!(body["breakpoints"][1]["message"]
            .as_str()
            .expect("message")
            .contains("no function named"));
        // Re-sending the line breakpoints after launch resolves them for real: line 3 has
        // code, line 5 (the closing brace) belongs to the contract-wide span.
        let set_breakpoints = DapMessage::request(
            31,
            "setBreakpoints",
            Some(json!({
                "source": {"path": temp.join("Counter.sol").display().to_string()},
                "breakpoints": [{"line": 3}, {"line": 99}]
            })),
        );
        let body = server.handle_message(&set_breakpoints)[0]
            .body
            .clone()
            .expect("body");
        assert_eq!(body["breakpoints"][0]["verified"], true);
        assert_eq!(body["breakpoints"][1]["verified"], false);
        // Stepping by source line from step 0 reaches the end: both steps are line 3.
        let messages = server.handle_message(&DapMessage::request(32, "next", None));
        assert_eq!(messages[1].body.as_ref().expect("body")["reason"], "end");
        // Stepping back one instruction lands on step 0, where both the line and the
        // function breakpoint sit, so the stop is reported as a breakpoint.
        let messages = server.handle_message(&DapMessage::request(
            33,
            "stepBack",
            Some(json!({"granularity": "instruction"})),
        ));
        assert_eq!(
            messages[1].body.as_ref().expect("body")["reason"],
            "breakpoint"
        );

        let variables = DapMessage::request(
            4,
            "variables",
            Some(json!({"variablesReference": super::LOCALS_REF})),
        );
        let messages = server.handle_message(&variables);
        assert_eq!(
            messages[0].body.as_ref().expect("body")["variables"][0]["name"],
            "x"
        );
        assert_eq!(
            messages[0].body.as_ref().expect("body")["variables"][0]["value"],
            "42"
        );
    }

    #[test]
    fn maps_legacy_source_maps_to_stack_frames() {
        let temp = temp_dir("soldb-dap-source-map");
        std::fs::create_dir_all(&temp).expect("create temp");
        let source =
            "contract Counter {\n  function set(uint256 x) public {\n    value = x;\n  }\n}\n";
        let statement_offset = source.find("value = x").expect("statement offset");
        std::fs::write(temp.join("Counter.sol"), source).expect("write source");
        std::fs::write(
            temp.join("combined.json"),
            json!({
                "sourceList": ["Counter.sol"],
                "contracts": {
                    "Counter.sol:Counter": {
                        "bin-runtime": "60010000",
                        "srcmap-runtime": format!(
                            "{statement_offset}:9:0:-:0;{statement_offset}:9:0;\
                             {statement_offset}:9:0"
                        )
                    }
                }
            })
            .to_string(),
        )
        .expect("write combined JSON");
        let trace_file = temp.join("trace.json");
        std::fs::write(
            &trace_file,
            serde_json::to_string(&sample_trace()).expect("trace JSON"),
        )
        .expect("write trace");

        let mut server = DapServer::new();
        let launch = DapMessage::request(
            1,
            "launch",
            Some(json!({
                "traceFile": trace_file.display().to_string(),
                "ethdebugDir": temp.display().to_string(),
                "contractName": "Counter"
            })),
        );
        assert_eq!(server.handle_message(&launch)[0].success, Some(true));

        let stack_trace = DapMessage::request(2, "stackTrace", None);
        let messages = server.handle_message(&stack_trace);
        let frame = &messages[0].body.as_ref().expect("body")["stackFrames"][0];
        assert_eq!(frame["source"]["name"], "Counter.sol");
        assert_eq!(frame["line"], 3);
    }

    #[test]
    fn stdio_loop_decodes_multiple_requests() {
        let mut input = Vec::new();
        input.extend_from_slice(
            &encode_dap_frame(&DapMessage::request(1, "initialize", Some(json!({}))))
                .expect("initialize frame"),
        );
        input.extend_from_slice(
            &encode_dap_frame(&DapMessage::request(2, "threads", None)).expect("threads frame"),
        );
        input.extend_from_slice(
            &encode_dap_frame(&DapMessage::request(3, "disconnect", None))
                .expect("disconnect frame"),
        );

        let mut output = Vec::new();
        run_stdio_server(Cursor::new(input), &mut output).expect("stdio server");

        let (first, consumed) = decode_dap_frame(&output).expect("first response");
        let (second, _) = decode_dap_frame(&output[consumed..]).expect("second response");
        assert_eq!(first.command.as_deref(), Some("initialize"));
        assert_eq!(second.event.as_deref(), Some("initialized"));
    }

    fn sample_trace() -> TransactionTrace {
        TransactionTrace {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0x0".to_owned(),
            input_data: "0x".to_owned(),
            gas_used: 21_000,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: Some("debug-rpc".to_owned()),
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps: vec![
                TraceStep {
                    pc: 0,
                    op: "PUSH1".to_owned(),
                    gas: 100,
                    gas_cost: 1,
                    depth: 0,
                    stack: vec!["0x2a".to_owned()],
                    memory: Some("aa".to_owned()),
                    storage: Some(BTreeMap::from([("0x0".to_owned(), "0x2a".to_owned())])),
                    error: None,
                    snapshot: Default::default(),
                },
                TraceStep {
                    pc: 3,
                    op: "STOP".to_owned(),
                    gas: 99,
                    gas_cost: 0,
                    depth: 0,
                    stack: Vec::new(),
                    memory: None,
                    storage: None,
                    error: None,
                    snapshot: Default::default(),
                },
            ],
        }
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("{label}-{}-{nanos}", std::process::id()))
    }
}
