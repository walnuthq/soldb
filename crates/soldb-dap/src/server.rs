use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use soldb_core::{SoldbError, SoldbResult, TransactionTrace};
use soldb_ethdebug::{parse_variable_locations, EthdebugInfo, Instruction};
use soldb_repl::{DebuggerState, StepOutcome};
use soldb_rpc::trace_transaction;

use crate::{
    decode_dap_frame, encode_dap_frame, initialize_body, stack_trace_body, threads_body,
    DapFrameError, DapMessage, DapServerConfig, Source, StackFrame,
};

const LOCALS_REF: u64 = 1000;
const STACK_REF: u64 = 1001;
const STEP_REF: u64 = 1002;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DapServer {
    seq: u64,
    config: DapServerConfig,
    thread_id: u64,
    debugger: DebuggerState,
    source_index: Option<SourceIndex>,
    pending_breakpoints: BTreeMap<String, Vec<u64>>,
    terminated: bool,
}

impl Default for DapServer {
    fn default() -> Self {
        Self {
            seq: 1,
            config: DapServerConfig::default(),
            thread_id: 1,
            debugger: DebuggerState::new(),
            source_index: None,
            pending_breakpoints: BTreeMap::new(),
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
            "next" | "stepIn" => self.step_instruction(message),
            "stepOut" => self.step_out(message),
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
        let event = self.event("initialized", None);
        vec![response, event]
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
            self.source_index = Some(SourceIndex::load(Path::new(&ethdebug_dir), contract_name)?);
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
            self.register_pending_breakpoints();
            return Ok(None);
        };

        let step_count = trace.steps.len();
        let tx_hash = trace
            .tx_hash
            .clone()
            .unwrap_or_else(|| "simulation".to_owned());
        self.debugger.load_trace(trace);
        self.register_pending_breakpoints();
        Ok(Some(format!(
            "Loaded {tx_hash} with {step_count} EVM steps"
        )))
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
        self.register_source_breakpoints(&source_key, &lines);

        let breakpoints = lines
            .into_iter()
            .map(|line| json!({"verified": true, "line": line}))
            .collect::<Vec<_>>();
        self.response(
            request,
            true,
            Some(json!({"breakpoints": breakpoints})),
            None,
        )
    }

    fn stack_trace(&mut self, request: &DapMessage) -> DapMessage {
        let frames = self.current_stack_frame().into_iter().collect::<Vec<_>>();
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

    fn step_instruction(&mut self, request: &DapMessage) -> Vec<DapMessage> {
        let outcome = self.debugger.next_instruction();
        let response = self.response(request, true, Some(json!({})), None);
        vec![response, self.stopped_event(outcome)]
    }

    fn step_out(&mut self, request: &DapMessage) -> Vec<DapMessage> {
        let current_depth = self.debugger.current_step_data().map(|step| step.depth);
        let mut outcome = self.debugger.next_instruction();
        if let Some(depth) = current_depth {
            while self
                .debugger
                .current_step_data()
                .is_some_and(|step| step.depth >= depth)
                && self.debugger.current_step + 1 < self.debugger.step_count()
            {
                outcome = self.debugger.next_instruction();
            }
        }

        let response = self.response(request, true, Some(json!({})), None);
        vec![response, self.stopped_event(outcome)]
    }

    fn current_stack_frame(&self) -> Option<StackFrame> {
        let step = self.debugger.current_step_data()?;
        let source = self.source_position(step.pc).map(|position| Source {
            name: position.name.clone(),
            path: position.path.clone(),
        });
        let (line, column) = self
            .source_position(step.pc)
            .map_or((1, 1), |position| (position.line, position.column));

        Some(StackFrame {
            id: 1,
            name: format!(
                "step {}: {} @ pc {}",
                self.debugger.current_step, step.op, step.pc
            ),
            source,
            line,
            column,
        })
    }

    fn local_variables(&self) -> Vec<Value> {
        let Some(step) = self.debugger.current_step_data() else {
            return Vec::new();
        };
        let Some(index) = &self.source_index else {
            return Vec::new();
        };

        index
            .info
            .variables_at_pc(step.pc)
            .into_iter()
            .map(|variable| {
                let value = if variable.location_type == "stack" {
                    step.stack
                        .get(variable.offset as usize)
                        .cloned()
                        .unwrap_or_else(|| "<unavailable>".to_owned())
                } else {
                    format!("{}[{}]", variable.location_type, variable.offset)
                };
                json!({
                    "name": variable.name,
                    "value": value,
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
        step.stack
            .iter()
            .enumerate()
            .map(|(index, value)| {
                json!({"name": format!("stack[{index}]"), "value": value, "variablesReference": 0})
            })
            .collect()
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
                    .and_then(|index| step.stack.get(index))
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
            StepOutcome::NoTrace => "pause",
            _ => "step",
        };
        self.event(
            "stopped",
            Some(json!({"reason": reason, "threadId": self.thread_id})),
        )
    }

    fn source_position(&self, pc: u64) -> Option<&SourcePosition> {
        self.source_index.as_ref()?.positions.get(&pc)
    }

    fn register_pending_breakpoints(&mut self) {
        for (source, lines) in self.pending_breakpoints.clone() {
            self.register_source_breakpoints(&source, &lines);
        }
    }

    fn register_source_breakpoints(&mut self, source: &str, lines: &[u64]) {
        let Some(index) = &self.source_index else {
            return;
        };
        for line in lines {
            if let Some(pc) = index.first_pc_for_line(source, *line) {
                self.debugger.set_breakpoint(pc);
            }
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceIndex {
    info: EthdebugInfo,
    positions: BTreeMap<u64, SourcePosition>,
}

impl SourceIndex {
    fn load(root: &Path, contract_name: Option<String>) -> SoldbResult<Self> {
        let metadata = read_json(root.join("ethdebug.json"))?;
        let runtime_path = find_runtime_ethdebug(root, contract_name.as_deref())?;
        let runtime = read_json(&runtime_path)?;
        let instructions = runtime
            .get("instructions")
            .cloned()
            .map(serde_json::from_value::<Vec<Instruction>>)
            .transpose()
            .map_err(|error| {
                SoldbError::Message(format!(
                    "Invalid instructions in {}: {error}",
                    runtime_path.display()
                ))
            })?
            .unwrap_or_default();
        let compilation = metadata
            .get("compilation")
            .cloned()
            .unwrap_or_else(|| metadata.clone());
        let sources = parse_sources(&compilation);
        let variable_locations = parse_variable_locations(&runtime)?;
        let inferred_name = contract_name.unwrap_or_else(|| {
            runtime_path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix("_ethdebug-runtime.json"))
                .unwrap_or("Contract")
                .to_owned()
        });

        let info = EthdebugInfo {
            compilation,
            contract_name: inferred_name,
            environment: "runtime".to_owned(),
            instructions,
            sources,
            variable_locations,
        };
        let positions = build_positions(root, &info);
        Ok(Self { info, positions })
    }

    fn first_pc_for_line(&self, source: &str, line: u64) -> Option<u64> {
        let source = normalize_source_key(source);
        self.positions.iter().find_map(|(pc, position)| {
            (position.line == line && position.matches_source(&source)).then_some(*pc)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourcePosition {
    name: String,
    path: String,
    line: u64,
    column: u64,
}

impl SourcePosition {
    fn matches_source(&self, source: &str) -> bool {
        self.name == source || normalize_source_key(&self.path) == source
    }
}

fn read_json(path: impl AsRef<Path>) -> SoldbResult<Value> {
    let path = path.as_ref();
    let content = fs::read_to_string(path).map_err(|error| {
        SoldbError::Message(format!("Failed to read {}: {error}", path.display()))
    })?;
    serde_json::from_str(&content)
        .map_err(|error| SoldbError::Message(format!("Invalid JSON {}: {error}", path.display())))
}

fn find_runtime_ethdebug(root: &Path, contract_name: Option<&str>) -> SoldbResult<PathBuf> {
    if let Some(contract_name) = contract_name {
        let path = root.join(format!("{contract_name}_ethdebug-runtime.json"));
        if path.exists() {
            return Ok(path);
        }
    }

    let entries = fs::read_dir(root).map_err(|error| {
        SoldbError::Message(format!(
            "Failed to read debug dir {}: {error}",
            root.display()
        ))
    })?;
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with("_ethdebug-runtime.json"))
        })
        .ok_or_else(|| {
            SoldbError::Message(format!(
                "No *_ethdebug-runtime.json found in {}",
                root.display()
            ))
        })
}

fn parse_sources(compilation: &Value) -> BTreeMap<u64, String> {
    compilation
        .get("sources")
        .and_then(Value::as_array)
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

fn build_positions(root: &Path, info: &EthdebugInfo) -> BTreeMap<u64, SourcePosition> {
    let mut source_cache = BTreeMap::<String, String>::new();
    info.instructions
        .iter()
        .filter_map(|instruction| {
            let location = instruction.source_location()?;
            let source_path = info.sources.get(&location.source_id)?.clone();
            let content = source_cache
                .entry(source_path.clone())
                .or_insert_with(|| read_source(root, &source_path));
            let (line, column) = line_column(content, location.offset);
            let path = display_source_path(root, &source_path);
            Some((
                instruction.offset,
                SourcePosition {
                    name: normalize_source_key(&source_path),
                    path,
                    line,
                    column,
                },
            ))
        })
        .collect()
}

fn read_source(root: &Path, source_path: &str) -> String {
    let path = Path::new(source_path);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    fs::read_to_string(absolute).unwrap_or_default()
}

fn display_source_path(root: &Path, source_path: &str) -> String {
    let path = Path::new(source_path);
    if path.is_absolute() {
        source_path.to_owned()
    } else {
        root.join(path).display().to_string()
    }
}

fn line_column(content: &str, offset: u64) -> (u64, u64) {
    let mut line = 1;
    let mut column = 1;
    for byte in content
        .as_bytes()
        .iter()
        .take(usize::try_from(offset).unwrap_or(usize::MAX))
    {
        if *byte == b'\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;
    use soldb_core::{TraceStep, TransactionTrace};

    use crate::{decode_dap_frame, encode_dap_frame, DapMessage};

    use super::{run_stdio_server, DapServer, STACK_REF};

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

        let variables = DapMessage::request(
            3,
            "variables",
            Some(json!({"variablesReference": STACK_REF})),
        );
        let messages = server.handle_message(&variables);
        assert_eq!(
            messages[0].body.as_ref().expect("body")["variables"][0]["value"],
            "0x2a"
        );
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
            steps: vec![
                TraceStep {
                    pc: 0,
                    op: "PUSH1".to_owned(),
                    gas: 100,
                    gas_cost: 1,
                    depth: 0,
                    stack: vec!["0x2a".to_owned()],
                    memory: None,
                    storage: None,
                    error: None,
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
