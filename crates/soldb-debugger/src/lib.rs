use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use soldb_core::{StepSnapshot, TraceStep, TransactionTrace};
use soldb_ethdebug::{EthdebugInfo, VariableLocation};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugSession {
    pub trace: TransactionTrace,
    pub ethdebug: Option<EthdebugInfo>,
    #[serde(default)]
    pub source_contents: BTreeMap<u64, String>,
    #[serde(default)]
    pub functions: Vec<SourceFunction>,
}

impl DebugSession {
    #[must_use]
    pub fn new(trace: TransactionTrace) -> Self {
        Self {
            trace,
            ethdebug: None,
            source_contents: BTreeMap::new(),
            functions: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_ethdebug(
        trace: TransactionTrace,
        ethdebug: EthdebugInfo,
        source_contents: BTreeMap<u64, String>,
    ) -> Self {
        let functions = source_contents
            .iter()
            .flat_map(|(source_id, source)| parse_source_functions(*source_id, source))
            .collect();
        Self {
            trace,
            ethdebug: Some(ethdebug),
            source_contents,
            functions,
        }
    }

    #[must_use]
    pub fn step(&self, step_index: usize) -> Option<DebugStep> {
        let step = self.trace.steps.get(step_index)?;
        Some(DebugStep {
            index: step_index,
            pc: step.pc,
            op: step.op.clone(),
            gas: step.gas,
            gas_cost: step.gas_cost,
            depth: step.depth,
            source: self.source_span(step.pc),
            function: self.function_at_pc(step.pc).cloned(),
            snapshot: step.normalized_snapshot(),
            variables: self.variables_at_step(step),
        })
    }

    #[must_use]
    pub fn steps(&self) -> Vec<DebugStep> {
        (0..self.trace.steps.len())
            .filter_map(|step_index| self.step(step_index))
            .collect()
    }

    #[must_use]
    pub fn source_span(&self, pc: u64) -> Option<SourceSpan> {
        let ethdebug = self.ethdebug.as_ref()?;
        let instruction = ethdebug.instruction_at_pc(pc)?;
        let location = instruction.source_location()?;
        let path = ethdebug.sources.get(&location.source_id)?.clone();
        let position = self
            .source_contents
            .get(&location.source_id)
            .map(|source| line_column_for_offset(source, location.offset as usize));
        Some(SourceSpan {
            source_id: location.source_id,
            path,
            offset: location.offset,
            length: location.length,
            line: position.map_or(0, |position| position.line),
            column: position.map_or(0, |position| position.column),
        })
    }

    #[must_use]
    pub fn function_at_pc(&self, pc: u64) -> Option<&SourceFunction> {
        let location = self
            .ethdebug
            .as_ref()?
            .instruction_at_pc(pc)?
            .source_location()?;
        self.functions
            .iter()
            .filter(|function| {
                function.source_id == location.source_id
                    && function.declaration_start <= location.offset
                    && location.offset <= function.body_end
            })
            .min_by_key(|function| function.body_end - function.declaration_start)
    }

    #[must_use]
    pub fn variables_at_step(&self, step: &TraceStep) -> Vec<DebugVariable> {
        let Some(ethdebug) = &self.ethdebug else {
            return Vec::new();
        };
        variables_for_step(&self.trace, ethdebug, step)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugStep {
    pub index: usize,
    pub pc: u64,
    pub op: String,
    pub gas: u64,
    pub gas_cost: u64,
    pub depth: u64,
    pub source: Option<SourceSpan>,
    pub function: Option<SourceFunction>,
    pub snapshot: StepSnapshot,
    pub variables: Vec<DebugVariable>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub source_id: u64,
    pub path: String,
    pub offset: u64,
    pub length: u64,
    pub line: u64,
    pub column: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFunction {
    pub source_id: u64,
    pub name: String,
    pub params: Vec<SourceParam>,
    pub declaration_start: u64,
    pub body_end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceParam {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugVariable {
    pub name: String,
    pub ty: String,
    pub location: DebugLocation,
    pub value: DebugValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugLocation {
    pub kind: String,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugValue {
    pub display: String,
    pub raw: Option<String>,
    pub status: DebugValueStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugValueStatus {
    Decoded,
    Raw,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourcePosition {
    line: u64,
    column: u64,
}

#[must_use]
pub fn variables_for_step(
    trace: &TransactionTrace,
    ethdebug: &EthdebugInfo,
    step: &TraceStep,
) -> Vec<DebugVariable> {
    ethdebug
        .variables_at_pc(step.pc)
        .into_iter()
        .map(|variable| decode_variable(trace, step, variable))
        .collect()
}

fn decode_variable(
    trace: &TransactionTrace,
    step: &TraceStep,
    variable: &VariableLocation,
) -> DebugVariable {
    let raw = raw_value_for_location(trace, step, variable);
    let value = raw.map_or_else(
        || DebugValue {
            display: "<unavailable>".to_owned(),
            raw: None,
            status: DebugValueStatus::Unavailable,
        },
        |raw| decode_debug_value(&raw, &variable.ty),
    );
    DebugVariable {
        name: variable.name.clone(),
        ty: variable.ty.clone(),
        location: DebugLocation {
            kind: variable.location_type.clone(),
            offset: variable.offset,
        },
        value,
    }
}

fn raw_value_for_location(
    trace: &TransactionTrace,
    step: &TraceStep,
    variable: &VariableLocation,
) -> Option<String> {
    let snapshot = step.normalized_snapshot();
    match variable.location_type.as_str() {
        "stack" => snapshot
            .stack
            .get(variable.offset as usize)
            .map(|value| normalize_hex(value)),
        "memory" => word_from_hex_bytes(snapshot.memory.as_deref()?, variable.offset as usize),
        "calldata" => word_from_hex_bytes(&trace.input_data, variable.offset as usize),
        "storage" => storage_value(&snapshot.storage, variable.offset),
        _ => None,
    }
}

fn decode_debug_value(raw: &str, ty: &str) -> DebugValue {
    let ty = ty.trim();
    let normalized = normalize_hex(raw);
    let word = normalized.trim_start_matches("0x");
    let decoded = decode_static_word(word, ty);
    match decoded {
        Some(display) => DebugValue {
            display,
            raw: Some(normalized),
            status: DebugValueStatus::Decoded,
        },
        None => DebugValue {
            display: normalized.clone(),
            raw: Some(normalized),
            status: DebugValueStatus::Raw,
        },
    }
}

fn decode_static_word(word: &str, ty: &str) -> Option<String> {
    if !word.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    if ty.starts_with("uint") {
        return Some(format_uint_word(word));
    }
    if ty == "address" {
        let padded = left_pad_word(word);
        return Some(
            format!("0x{}", &padded[padded.len().saturating_sub(40)..]).to_ascii_lowercase(),
        );
    }
    if ty == "bool" {
        let trimmed = word.trim_start_matches('0');
        return match trimmed {
            "" | "0" => Some("false".to_owned()),
            "1" => Some("true".to_owned()),
            _ => None,
        };
    }
    if ty == "bytes32" {
        return Some(normalize_hex(word));
    }
    if let Some(size) = fixed_bytes_size(ty) {
        let padded = right_pad_word(word);
        return Some(format!("0x{}", &padded[..size * 2]).to_ascii_lowercase());
    }
    None
}

fn fixed_bytes_size(ty: &str) -> Option<usize> {
    let size = ty.strip_prefix("bytes")?.parse::<usize>().ok()?;
    (1..=32).contains(&size).then_some(size)
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

fn storage_value(storage: &BTreeMap<String, String>, slot: u64) -> Option<String> {
    storage
        .get(&format!("0x{slot:x}"))
        .or_else(|| storage.get(&format!("{slot:x}")))
        .or_else(|| storage.get(&format!("0x{slot:064x}")))
        .or_else(|| storage.get(&format!("{slot:064x}")))
        .map(|value| normalize_hex(value))
}

fn word_from_hex_bytes(input: &str, byte_offset: usize) -> Option<String> {
    let hex = input.trim_start_matches("0x");
    let start = byte_offset.checked_mul(2)?;
    let end = start.checked_add(64)?;
    let word = hex.get(start..end)?;
    word.bytes()
        .all(|byte| byte.is_ascii_hexdigit())
        .then(|| format!("0x{}", word.to_ascii_lowercase()))
}

fn normalize_hex(value: &str) -> String {
    let value = value.trim();
    let hex = value.strip_prefix("0x").unwrap_or(value);
    format!("0x{}", hex.to_ascii_lowercase())
}

fn left_pad_word(word: &str) -> String {
    let word = word.trim_start_matches("0x").to_ascii_lowercase();
    if word.len() >= 64 {
        return word;
    }
    format!("{:0>64}", word)
}

fn right_pad_word(word: &str) -> String {
    let word = word.trim_start_matches("0x").to_ascii_lowercase();
    if word.len() >= 64 {
        return word;
    }
    format!("{:0<64}", word)
}

fn line_column_for_offset(source: &str, offset: usize) -> SourcePosition {
    let mut line = 1;
    let mut column = 1;
    for byte in source.bytes().take(offset.min(source.len())) {
        if byte == b'\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    SourcePosition { line, column }
}

#[must_use]
pub fn parse_source_functions(source_id: u64, source: &str) -> Vec<SourceFunction> {
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
        if source.as_bytes().get(index) != Some(&b'(') {
            cursor = index;
            continue;
        }
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use soldb_core::{TraceStep, TransactionTrace};
    use soldb_ethdebug::{EthdebugInfo, Instruction, VariableLocation};

    use super::{parse_source_functions, DebugSession, DebugValueStatus};

    #[test]
    fn builds_source_steps_and_decodes_active_variables() {
        let source =
            "contract Counter {\n  function set(uint256 x) public {\n    value = x;\n  }\n}\n";
        let offset = source.find("value = x").expect("source offset") as u64;
        let trace = sample_trace();
        let mut sources = BTreeMap::new();
        sources.insert(0, "Counter.sol".to_owned());
        let mut source_contents = BTreeMap::new();
        source_contents.insert(0, source.to_owned());
        let mut variable_locations = BTreeMap::new();
        variable_locations.insert(
            0,
            vec![
                VariableLocation {
                    name: "x".to_owned(),
                    ty: "uint256".to_owned(),
                    location_type: "stack".to_owned(),
                    offset: 0,
                    pc_range: (0, 1),
                },
                VariableLocation {
                    name: "sender".to_owned(),
                    ty: "address".to_owned(),
                    location_type: "calldata".to_owned(),
                    offset: 4,
                    pc_range: (0, 1),
                },
            ],
        );
        let info = EthdebugInfo {
            compilation: json!({}),
            contract_name: "Counter".to_owned(),
            environment: "runtime".to_owned(),
            instructions: vec![Instruction {
                offset: 0,
                operation: json!({"mnemonic": "PUSH1"}),
                context: Some(json!({
                    "code": {
                        "source": {"id": 0},
                        "range": {"offset": offset, "length": 9}
                    }
                })),
            }],
            sources,
            variable_locations,
        };

        let session = DebugSession::with_ethdebug(trace, info, source_contents);
        let step = session.step(0).expect("debug step");
        assert_eq!(step.source.as_ref().expect("source").line, 3);
        assert_eq!(step.function.as_ref().expect("function").name, "set");
        assert_eq!(step.snapshot.stack, ["0x2a"]);
        assert_eq!(step.variables[0].name, "x");
        assert_eq!(step.variables[0].value.display, "42");
        assert_eq!(step.variables[0].value.status, DebugValueStatus::Decoded);
        assert_eq!(
            step.variables[1].value.display,
            "0x1111111111111111111111111111111111111111"
        );
    }

    #[test]
    fn keeps_raw_values_when_type_is_dynamic_or_location_is_unknown() {
        let trace = sample_trace();
        let mut variable_locations = BTreeMap::new();
        variable_locations.insert(
            0,
            vec![
                VariableLocation {
                    name: "name".to_owned(),
                    ty: "string".to_owned(),
                    location_type: "stack".to_owned(),
                    offset: 0,
                    pc_range: (0, 0),
                },
                VariableLocation {
                    name: "missing".to_owned(),
                    ty: "uint256".to_owned(),
                    location_type: "stack".to_owned(),
                    offset: 99,
                    pc_range: (0, 0),
                },
            ],
        );
        let info = EthdebugInfo {
            compilation: json!({}),
            contract_name: "Counter".to_owned(),
            environment: "runtime".to_owned(),
            instructions: Vec::new(),
            sources: BTreeMap::new(),
            variable_locations,
        };

        let session = DebugSession::with_ethdebug(trace, info, BTreeMap::new());
        let step = session.step(0).expect("debug step");
        assert_eq!(step.variables[0].value.status, DebugValueStatus::Raw);
        assert_eq!(step.variables[0].value.display, "0x2a");
        assert_eq!(
            step.variables[1].value.status,
            DebugValueStatus::Unavailable
        );
    }

    #[test]
    fn parses_source_functions_with_tuple_and_array_params() {
        let functions = parse_source_functions(
            7,
            "contract C { function submit(Person memory p, uint256[2] memory xs) public {} }",
        );
        assert_eq!(functions[0].source_id, 7);
        assert_eq!(functions[0].name, "submit");
        assert_eq!(functions[0].params[0].name, "p");
        assert_eq!(functions[0].params[0].ty, "Person");
        assert_eq!(functions[0].params[1].name, "xs");
        assert_eq!(functions[0].params[1].ty, "uint256[2]");
    }

    fn sample_trace() -> TransactionTrace {
        TransactionTrace {
            tx_hash: Some("0xabc".to_owned()),
            from_addr: "0x1".to_owned(),
            to_addr: Some("0x2".to_owned()),
            value: "0".to_owned(),
            input_data: format!(
                "0x12345678{}",
                "0000000000000000000000001111111111111111111111111111111111111111"
            ),
            gas_used: 1,
            output: "0x".to_owned(),
            success: true,
            error: None,
            debug_trace_available: true,
            contract_address: None,
            backend: Some("debug-rpc".to_owned()),
            capabilities: Default::default(),
            artifacts: Default::default(),
            steps: vec![TraceStep {
                pc: 0,
                op: "PUSH1".to_owned(),
                gas: 1,
                gas_cost: 0,
                depth: 0,
                stack: vec!["0x2a".to_owned()],
                memory: Some(format!("{}{}", "00".repeat(32), "2a".repeat(32))),
                storage: Some(BTreeMap::from([("0x0".to_owned(), "0x2a".to_owned())])),
                error: None,
                snapshot: Default::default(),
            }],
        }
    }
}
