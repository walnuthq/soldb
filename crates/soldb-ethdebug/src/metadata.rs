//! ETHDebug artifact model: instructions, source spans, and variable locations.
//!
//! An ETHDebug runtime artifact is a list of instructions, each carrying its program
//! counter and a `context` describing the source range it was generated from. Mapping a
//! program counter back to Solidity means finding its instruction and reading that span.
//!
//! Spans nest: a compiler attaches a whole-contract range to dispatcher and preamble
//! instructions, so a span containing a given line is not the same thing as a span
//! generated for it. Callers that resolve a source line to a program counter must rank
//! candidates accordingly rather than taking the first intersecting span.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use soldb_core::{SoldbError, SoldbResult};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceLocation {
    pub source_id: u64,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FunctionIdentity {
    pub identifier: Option<String>,
    pub declaration: Option<SourceLocation>,
    pub activation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FunctionExit {
    Return,
    Revert,
}

/// One instruction of a program and what the compiler says about it.
///
/// It reads and writes as an ETHDebug program lists it: its `offset`, an `operation`
/// naming the mnemonic, and a `context`. A legacy source map says the same few things
/// about every instruction, so one made from a source map holds them as plain values
/// (see [`Instruction::from_source_map`]) rather than as the JSON objects they stand
/// for, which cost a dozen allocations an instruction to build, read, and drop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "InstructionJson", into = "InstructionJson")]
pub struct Instruction {
    pub offset: u64,
    operation: Operation,
    context: Option<Context>,
}

/// An instruction as an ETHDebug program writes it.
#[derive(Serialize, Deserialize)]
struct InstructionJson {
    offset: u64,
    operation: Value,
    #[serde(default)]
    context: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Operation {
    /// An operation that says nothing but its mnemonic.
    Mnemonic(Cow<'static, str>),
    /// Any other operation, as the program wrote it.
    Json(Value),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Context {
    /// A context saying only what a legacy source map does.
    SourceMap(SourceMapContext),
    /// Any other context, as the program wrote it.
    Json(Value),
}

/// What a legacy source map says about one instruction, as the ETHDebug context
/// `{"modifierDepth": .., "code": .., "invoke" | "return": {}}` says it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceMapContext {
    /// The source range the instruction was generated from; generated code has none.
    pub code: Option<SourceLocation>,
    /// The jump the instruction makes.
    pub jump: SourceMapJump,
    /// How many modifiers deep the instruction runs.
    pub modifier_depth: i64,
}

/// The jump a legacy source map says an instruction makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SourceMapJump {
    /// An ordinary jump, or none: `-`.
    #[default]
    Regular,
    /// Into a function: `i`, the ETHDebug `invoke` context.
    Into,
    /// Out of a function: `o`, the ETHDebug `return` context.
    Out,
}

impl Instruction {
    /// An instruction at program counter `offset` that runs `mnemonic`, with its ETHDebug
    /// context, if any.
    #[must_use]
    pub fn new(offset: u64, mnemonic: &str, context: Option<Value>) -> Self {
        Self {
            offset,
            operation: Operation::Mnemonic(Cow::Owned(mnemonic.to_owned())),
            context: context.map(Context::from_json),
        }
    }

    /// An instruction at program counter `offset` that runs `mnemonic`, as a legacy
    /// source map describes it.
    #[must_use]
    pub fn from_source_map(
        offset: u64,
        mnemonic: impl Into<Cow<'static, str>>,
        context: SourceMapContext,
    ) -> Self {
        Self {
            offset,
            operation: Operation::Mnemonic(mnemonic.into()),
            context: Some(Context::SourceMap(context)),
        }
    }

    #[must_use]
    pub fn mnemonic(&self) -> Option<&str> {
        match &self.operation {
            Operation::Mnemonic(mnemonic) => Some(mnemonic),
            Operation::Json(operation) => operation.get("mnemonic").and_then(Value::as_str),
        }
    }

    #[must_use]
    pub fn arguments(&self) -> Vec<&str> {
        let Operation::Json(operation) = &self.operation else {
            return Vec::new();
        };
        operation
            .get("arguments")
            .and_then(Value::as_array)
            .map(|arguments| arguments.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn source_location(&self) -> Option<SourceLocation> {
        match &self.context {
            Some(Context::SourceMap(context)) => context.code.clone(),
            _ => {
                let mut locations = self.source_locations();
                (locations.len() == 1).then(|| locations.remove(0))
            }
        }
    }

    /// Returns every source alternative attached to this instruction.
    #[must_use]
    pub fn source_locations(&self) -> Vec<SourceLocation> {
        let mut locations = Vec::new();
        match &self.context {
            Some(Context::SourceMap(context)) => locations.extend(context.code.clone()),
            Some(Context::Json(context)) => collect_source_locations(context, &mut locations),
            None => {}
        }
        locations
    }

    /// Returns every possible function invocation attached to this instruction.
    #[must_use]
    pub fn function_invocations(&self) -> Vec<FunctionIdentity> {
        let mut functions = Vec::new();
        match &self.context {
            Some(Context::SourceMap(context)) if context.jump == SourceMapJump::Into => {
                functions.push(FunctionIdentity {
                    identifier: None,
                    declaration: None,
                    activation: None,
                });
            }
            Some(Context::Json(context)) => collect_function_invocations(context, &mut functions),
            _ => {}
        }
        functions
    }

    /// Returns the function exit attached to this instruction.
    #[must_use]
    pub fn function_exit(&self) -> Option<FunctionExit> {
        match self.context.as_ref()? {
            Context::SourceMap(context) => {
                (context.jump == SourceMapJump::Out).then_some(FunctionExit::Return)
            }
            Context::Json(context) => {
                if context.get("return").is_some() {
                    Some(FunctionExit::Return)
                } else if context.get("revert").is_some() {
                    Some(FunctionExit::Revert)
                } else {
                    None
                }
            }
        }
    }

    /// Legacy source-map modifier depth, when this instruction was adapted from one.
    #[must_use]
    pub fn modifier_depth(&self) -> Option<i64> {
        match self.context.as_ref()? {
            Context::SourceMap(context) => Some(context.modifier_depth),
            Context::Json(context) => context.get("modifierDepth")?.as_i64(),
        }
    }
}

impl From<InstructionJson> for Instruction {
    fn from(instruction: InstructionJson) -> Self {
        Self {
            offset: instruction.offset,
            operation: Operation::from_json(instruction.operation),
            context: instruction.context.map(Context::from_json),
        }
    }
}

impl From<Instruction> for InstructionJson {
    fn from(instruction: Instruction) -> Self {
        Self {
            offset: instruction.offset,
            operation: match instruction.operation {
                Operation::Mnemonic(mnemonic) => json!({"mnemonic": mnemonic}),
                Operation::Json(operation) => operation,
            },
            context: instruction.context.map(|context| match context {
                Context::SourceMap(context) => context.to_json(),
                Context::Json(context) => context,
            }),
        }
    }
}

impl Operation {
    /// Keeps an operation that names only its mnemonic as the mnemonic, so an
    /// instruction reads back equal to the one written.
    fn from_json(operation: Value) -> Self {
        if let Value::Object(fields) = &operation {
            if let (1, Some(Value::String(mnemonic))) = (fields.len(), fields.get("mnemonic")) {
                return Self::Mnemonic(Cow::Owned(mnemonic.clone()));
            }
        }
        Self::Json(operation)
    }
}

impl Context {
    /// Keeps a context that says only what a legacy source map does as values, so an
    /// instruction reads back equal to the one written.
    fn from_json(context: Value) -> Self {
        SourceMapContext::from_json(&context).map_or(Self::Json(context), Self::SourceMap)
    }
}

impl SourceMapContext {
    fn from_json(context: &Value) -> Option<Self> {
        let fields = context.as_object()?;
        let modifier_depth = fields.get("modifierDepth")?.as_i64()?;
        let mut code = None;
        let mut jump = SourceMapJump::Regular;
        for (key, value) in fields {
            match key.as_str() {
                "modifierDepth" => {}
                "code" => code = Some(source_range_of(value)?),
                "invoke" | "return" if empty_object(value) && jump == SourceMapJump::Regular => {
                    jump = if key == "invoke" {
                        SourceMapJump::Into
                    } else {
                        SourceMapJump::Out
                    };
                }
                _ => return None,
            }
        }
        Some(Self {
            code,
            jump,
            modifier_depth,
        })
    }

    fn to_json(&self) -> Value {
        let mut context = serde_json::Map::new();
        context.insert("modifierDepth".to_owned(), json!(self.modifier_depth));
        if let Some(code) = &self.code {
            context.insert(
                "code".to_owned(),
                source_range(code.source_id, code.offset, code.length),
            );
        }
        match self.jump {
            SourceMapJump::Regular => {}
            SourceMapJump::Into => {
                context.insert("invoke".to_owned(), json!({}));
            }
            SourceMapJump::Out => {
                context.insert("return".to_owned(), json!({}));
            }
        }
        Value::Object(context)
    }
}

/// The source location `value` holds, when it is exactly what [`source_range`] writes.
fn source_range_of(value: &Value) -> Option<SourceLocation> {
    let fields = value.as_object()?;
    let source = fields.get("source")?.as_object()?;
    let range = fields.get("range")?.as_object()?;
    if fields.len() != 2 || source.len() != 1 || range.len() != 2 {
        return None;
    }
    Some(SourceLocation {
        source_id: source.get("id")?.as_u64()?,
        offset: range.get("offset")?.as_u64()?,
        length: range.get("length")?.as_u64()?,
    })
}

fn empty_object(value: &Value) -> bool {
    value.as_object().is_some_and(serde_json::Map::is_empty)
}

fn collect_source_locations(context: &Value, locations: &mut Vec<SourceLocation>) {
    if let Some(location) = context.get("code").and_then(parse_source_location) {
        if !locations.contains(&location) {
            locations.push(location);
        }
    }
    if let Some(pick) = context.get("pick").and_then(Value::as_array) {
        for alternative in pick {
            collect_source_locations(alternative, locations);
        }
    }
}

fn collect_function_invocations(context: &Value, functions: &mut Vec<FunctionIdentity>) {
    if let Some(invoke) = context.get("invoke") {
        let function = FunctionIdentity {
            identifier: invoke
                .get("identifier")
                .and_then(Value::as_str)
                .map(str::to_owned),
            declaration: invoke.get("declaration").and_then(parse_source_location),
            activation: invoke
                .get("activation")
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
        if !functions.contains(&function) {
            functions.push(function);
        }
    }
    if let Some(pick) = context.get("pick").and_then(Value::as_array) {
        for alternative in pick {
            collect_function_invocations(alternative, functions);
        }
    }
}

/// The ETHDebug source range of `length` bytes at `offset` in source `source_id`, as an
/// instruction context carries it under `code`.
#[must_use]
pub fn source_range(source_id: u64, offset: u64, length: u64) -> Value {
    json!({"source": {"id": source_id}, "range": {"offset": offset, "length": length}})
}

fn parse_source_location(value: &Value) -> Option<SourceLocation> {
    let source_id = value.get("source")?.get("id")?.as_u64()?;
    let range = value.get("range")?;
    Some(SourceLocation {
        source_id,
        offset: range.get("offset")?.as_u64()?,
        length: range.get("length")?.as_u64()?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableLocation {
    pub name: String,
    pub ty: String,
    pub location_type: String,
    pub offset: u64,
    pub pc_range: (u64, u64),
}

impl VariableLocation {
    #[must_use]
    pub fn is_active_at_pc(&self, pc: u64) -> bool {
        self.pc_range.0 <= pc && pc <= self.pc_range.1
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthdebugInfo {
    pub compilation: Value,
    pub contract_name: String,
    pub environment: String,
    pub instructions: Vec<Instruction>,
    pub sources: BTreeMap<u64, String>,
    #[serde(default)]
    pub variable_locations: BTreeMap<u64, Vec<VariableLocation>>,
}

impl EthdebugInfo {
    /// Builds the debug info for one contract from already-parsed ETHDebug artifacts.
    ///
    /// `metadata` is the global resource file (`ethdebug.json` from older compilers,
    /// `ethdebug_resources.json` from modern ones) and `program` is the contract's
    /// program artifact (`<Contract>_ethdebug.json` for creation code,
    /// `<Contract>_ethdebug-runtime.json` for runtime code). Nothing is read from disk
    /// here, so the CLI, the DAP server, and any host that receives the artifacts as
    /// strings all build the same value through this one path.
    ///
    /// A program without an `instructions` array yields no instructions rather than an
    /// error; callers that need to know report it as a debug-info gap.
    pub fn from_artifacts(
        contract_name: &str,
        environment: &str,
        metadata: &Value,
        program: &Value,
    ) -> SoldbResult<Self> {
        let instructions = program
            .get("instructions")
            .cloned()
            .map(serde_json::from_value::<Vec<Instruction>>)
            .transpose()
            .map_err(|error| {
                SoldbError::Message(format!(
                    "invalid `instructions` in ETHDebug program artifact: {error}"
                ))
            })?
            .unwrap_or_default();
        let compilation = metadata
            .get("compilation")
            .cloned()
            .unwrap_or_else(|| metadata.clone());
        let sources = parse_compilation_sources(&compilation);
        let variable_locations = parse_variable_locations(program)?;
        Ok(Self {
            compilation,
            contract_name: contract_name.to_owned(),
            environment: environment.to_owned(),
            instructions,
            sources,
            variable_locations,
        })
    }

    #[must_use]
    pub fn instruction_at_pc(&self, pc: u64) -> Option<&Instruction> {
        self.instructions
            .iter()
            .find(|instruction| instruction.offset == pc)
    }

    #[must_use]
    pub fn source_info(&self, pc: u64) -> Option<(&str, u64, u64)> {
        let instruction = self.instruction_at_pc(pc)?;
        let source_location = instruction.source_location()?;
        let source_path = self.sources.get(&source_location.source_id)?;
        Some((source_path, source_location.offset, source_location.length))
    }

    /// Whether the artifact carries variable locations at all.
    ///
    /// No compiler release emits them yet, so this is usually false, and the difference
    /// matters to a user: nothing in scope at one program counter is not the same as a
    /// compiler that describes no variables anywhere.
    #[must_use]
    pub fn has_variable_locations(&self) -> bool {
        !self.variable_locations.is_empty()
    }

    pub fn variables_at_pc(&self, pc: u64) -> Vec<&VariableLocation> {
        if let Some(exact) = self.variable_locations.get(&pc) {
            return exact.iter().collect();
        }

        self.variable_locations
            .values()
            .flat_map(|variables| variables.iter())
            .filter(|variable| variable.is_active_at_pc(pc))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthdebugSpec {
    pub address: Option<String>,
    pub name: Option<String>,
    pub path: String,
}

pub fn parse_ethdebug_spec(input: &str) -> EthdebugSpec {
    if let Ok(spec) = parse_single_contract_spec(input) {
        return spec;
    }

    parse_multi_contract_spec(input).unwrap_or_else(|_| EthdebugSpec {
        address: None,
        name: None,
        path: input.to_owned(),
    })
}

pub fn parse_single_contract_spec(input: &str) -> SoldbResult<EthdebugSpec> {
    if !input.starts_with("0x") {
        return Err(SoldbError::Message(format!(
            "Must use format 'address:name:path' (got: {input})"
        )));
    }

    let parts = input.splitn(3, ':').collect::<Vec<_>>();
    if parts.len() != 3 || parts[1].is_empty() || parts[2].is_empty() {
        return Err(SoldbError::Message(format!(
            "Must use format 'address:name:path' (got: {input})"
        )));
    }

    Ok(EthdebugSpec {
        address: Some(parts[0].to_owned()),
        name: Some(parts[1].to_owned()),
        path: parts[2].to_owned(),
    })
}

pub fn parse_multi_contract_spec(input: &str) -> SoldbResult<EthdebugSpec> {
    if input.is_empty() {
        return Err(SoldbError::Message("Path cannot be empty".to_owned()));
    }

    if input.starts_with("0x") && input.contains(':') {
        let parts = input.splitn(2, ':').collect::<Vec<_>>();
        if parts.len() != 2 || parts[1].is_empty() {
            return Err(SoldbError::Message(format!(
                "Must use format 'address:path' (got: {input})"
            )));
        }

        return Ok(EthdebugSpec {
            address: Some(parts[0].to_owned()),
            name: None,
            path: parts[1].to_owned(),
        });
    }

    Ok(EthdebugSpec {
        address: None,
        name: None,
        path: input.to_owned(),
    })
}

/// Maps every source id listed in an ETHDebug `compilation` object to its path.
///
/// Entries without a numeric `id` or a string `path` are skipped rather than failing the
/// whole load, since one malformed source entry should not hide the mapping for the rest.
#[must_use]
pub fn parse_compilation_sources(compilation: &Value) -> BTreeMap<u64, String> {
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

/// Returns the contents of a source embedded in an ETHDebug `compilation` object.
///
/// Some artifacts inline each source under `contents` (older builds used `content`);
/// when they do, a frontend can show source without reading the file, which is the only
/// option for a host without a filesystem.
#[must_use]
pub fn read_compilation_source(compilation: &Value, source_id: u64) -> Option<String> {
    compilation
        .get("sources")
        .and_then(Value::as_array)?
        .iter()
        .find(|source| source.get("id").and_then(Value::as_u64) == Some(source_id))
        .and_then(|source| {
            source
                .get("contents")
                .or_else(|| source.get("content"))
                .and_then(Value::as_str)
        })
        .map(str::to_owned)
}

pub fn parse_variable_locations(
    contract_data: &Value,
) -> SoldbResult<BTreeMap<u64, Vec<VariableLocation>>> {
    let mut variable_locations = BTreeMap::<u64, Vec<VariableLocation>>::new();

    if let Some(instructions) = contract_data
        .get("instructions")
        .and_then(serde_json::Value::as_array)
    {
        for instruction in instructions {
            let pc = instruction
                .get("offset")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| SoldbError::Message("Instruction missing offset".to_owned()))?;

            let Some(variables) = instruction
                .get("context")
                .and_then(|context| context.get("variables"))
                .and_then(serde_json::Value::as_array)
            else {
                continue;
            };

            for variable in variables {
                variable_locations
                    .entry(pc)
                    .or_default()
                    .push(parse_context_variable(variable, pc));
            }
        }
    }

    if let Some(variables) = contract_data
        .get("variables")
        .and_then(serde_json::Value::as_array)
    {
        for variable in variables {
            let variable_location = parse_top_level_variable(variable);
            for pc in variable_location.pc_range.0..=variable_location.pc_range.1 {
                variable_locations
                    .entry(pc)
                    .or_default()
                    .push(variable_location.clone());
            }
        }
    }

    Ok(variable_locations)
}

fn parse_context_variable(variable: &Value, pc: u64) -> VariableLocation {
    let location = variable.get("location");
    let scope = variable.get("scope");

    VariableLocation {
        name: get_string(variable, "name", "unknown"),
        ty: get_string(variable, "type", "unknown"),
        location_type: location
            .and_then(|value| value.get("type"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("stack")
            .to_owned(),
        offset: location
            .and_then(|value| value.get("offset"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        pc_range: (
            scope
                .and_then(|value| value.get("start"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(pc),
            scope
                .and_then(|value| value.get("end"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(pc),
        ),
    }
}

fn parse_top_level_variable(variable: &Value) -> VariableLocation {
    VariableLocation {
        name: get_string(variable, "name", "unknown"),
        ty: get_string(variable, "type", "unknown"),
        location_type: get_string(variable, "location_type", "stack"),
        offset: variable
            .get("offset")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        pc_range: (
            variable
                .get("pc_start")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            variable
                .get("pc_end")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        ),
    }
}

fn get_string(value: &Value, key: &str, default: &str) -> String {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or(default)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        parse_compilation_sources, parse_ethdebug_spec, parse_multi_contract_spec,
        parse_single_contract_spec, parse_variable_locations, read_compilation_source,
        EthdebugInfo, FunctionExit, Instruction, SourceLocation, SourceMapContext, SourceMapJump,
    };
    use serde_json::json;

    #[test]
    fn reads_sources_embedded_in_the_compilation() {
        let compilation = json!({
            "sources": [
                {"id": 0, "path": "A.sol", "contents": "contract A {}"},
                {"id": 1, "path": "B.sol", "content": "contract B {}"},
                {"id": 2, "path": "C.sol"}
            ]
        });

        assert_eq!(
            read_compilation_source(&compilation, 0).as_deref(),
            Some("contract A {}")
        );
        assert_eq!(
            read_compilation_source(&compilation, 1).as_deref(),
            Some("contract B {}")
        );
        assert_eq!(read_compilation_source(&compilation, 2), None);
        assert_eq!(read_compilation_source(&compilation, 9), None);
        assert_eq!(read_compilation_source(&json!({}), 0), None);
    }

    #[test]
    fn builds_info_from_parsed_artifacts() {
        let metadata = json!({
            "compilation": {
                "sources": [
                    {"id": 0, "path": "Counter.sol"},
                    {"id": 1, "path": "lib/Math.sol"},
                    {"path": "missing-id.sol"},
                    {"id": 2}
                ]
            },
            "types": {},
            "pointers": {}
        });
        let program = json!({
            "instructions": [
                {
                    "offset": 0,
                    "operation": {"mnemonic": "PUSH1", "arguments": ["0x80"]},
                    "context": {
                        "code": {"source": {"id": 0}, "range": {"offset": 10, "length": 4}},
                        "variables": [
                            {"identifier": "x", "pointer": {"location": "stack", "slot": 0}}
                        ]
                    }
                },
                {"offset": 2, "operation": {"mnemonic": "STOP"}}
            ]
        });

        let info = EthdebugInfo::from_artifacts("Counter", "runtime", &metadata, &program)
            .expect("artifacts");

        assert_eq!(info.contract_name, "Counter");
        assert_eq!(info.environment, "runtime");
        assert_eq!(info.compilation, metadata["compilation"]);
        assert_eq!(
            info.sources,
            BTreeMap::from([
                (0, "Counter.sol".to_owned()),
                (1, "lib/Math.sol".to_owned())
            ])
        );
        assert_eq!(info.instructions.len(), 2);
        assert_eq!(info.source_info(0), Some(("Counter.sol", 10, 4)));
        assert_eq!(info.variables_at_pc(0).len(), 1);
        assert!(info.variables_at_pc(2).is_empty());
    }

    #[test]
    fn treats_legacy_metadata_without_compilation_wrapper_as_the_compilation() {
        let metadata = json!({"sources": [{"id": 3, "path": "Legacy.sol"}]});
        let program = json!({});

        let info = EthdebugInfo::from_artifacts("Legacy", "create", &metadata, &program)
            .expect("artifacts");

        assert_eq!(info.compilation, metadata);
        assert_eq!(info.sources, BTreeMap::from([(3, "Legacy.sol".to_owned())]));
        assert!(info.instructions.is_empty());
        assert!(info.variable_locations.is_empty());
    }

    #[test]
    fn rejects_malformed_instructions() {
        let metadata = json!({"compilation": {"sources": []}});
        let program = json!({"instructions": [{"operation": {"mnemonic": "STOP"}}]});

        let error = EthdebugInfo::from_artifacts("Broken", "runtime", &metadata, &program)
            .expect_err("missing offset must fail");

        assert!(
            error.to_string().contains("`instructions`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn parses_compilation_sources_skipping_incomplete_entries() {
        let compilation = json!({
            "sources": [
                {"id": 0, "path": "A.sol"},
                {"id": "1", "path": "B.sol"},
                {"id": 2, "path": 7},
                {"id": 3, "path": "D.sol"}
            ]
        });

        assert_eq!(
            parse_compilation_sources(&compilation),
            BTreeMap::from([(0, "A.sol".to_owned()), (3, "D.sol".to_owned())])
        );
        assert!(parse_compilation_sources(&json!({})).is_empty());
    }

    #[test]
    fn parses_single_and_multi_contract_specs() {
        let spec = parse_single_contract_spec("0xabc:Token:out").expect("single spec");
        assert_eq!(spec.address.as_deref(), Some("0xabc"));
        assert_eq!(spec.name.as_deref(), Some("Token"));
        assert_eq!(spec.path, "out");

        let multi = parse_multi_contract_spec("0xabc:out").expect("multi spec");
        assert_eq!(multi.address.as_deref(), Some("0xabc"));
        assert_eq!(multi.name, None);
        assert_eq!(multi.path, "out");

        let plain = parse_ethdebug_spec("out");
        assert_eq!(plain.address, None);
        assert_eq!(plain.path, "out");

        assert!(parse_single_contract_spec("out").is_err());
        assert!(parse_multi_contract_spec("").is_err());
    }

    #[test]
    fn extracts_instruction_source_locations() {
        let instruction: Instruction = serde_json::from_value(json!({
            "offset": 12,
            "operation": {"mnemonic": "PUSH1", "arguments": ["0x2a"]},
            "context": {
                "code": {
                    "source": {"id": 7},
                    "range": {"offset": 20, "length": 4}
                }
            }
        }))
        .expect("instruction");

        let source_location = instruction.source_location().expect("source location");
        assert_eq!(instruction.mnemonic(), Some("PUSH1"));
        assert_eq!(instruction.arguments(), ["0x2a"]);
        assert_eq!(source_location.source_id, 7);
        assert_eq!(source_location.offset, 20);
        assert_eq!(source_location.length, 4);
    }

    #[test]
    fn source_map_instructions_read_and_write_as_their_json() {
        let code = SourceLocation {
            source_id: 3,
            offset: 40,
            length: 9,
        };
        let typed = Instruction::from_source_map(
            7,
            "JUMP",
            SourceMapContext {
                code: Some(code.clone()),
                jump: SourceMapJump::Into,
                modifier_depth: 1,
            },
        );
        let json = json!({
            "offset": 7,
            "operation": {"mnemonic": "JUMP"},
            "context": {
                "modifierDepth": 1,
                "code": {"source": {"id": 3}, "range": {"offset": 40, "length": 9}},
                "invoke": {}
            }
        });
        assert_eq!(serde_json::to_value(&typed).expect("json"), json);
        let read: Instruction = serde_json::from_value(json.clone()).expect("instruction");
        assert_eq!(read, typed);
        let context = json.get("context").cloned();
        assert_eq!(Instruction::new(7, "JUMP", context), typed);

        assert_eq!(typed.mnemonic(), Some("JUMP"));
        assert!(typed.arguments().is_empty());
        assert_eq!(typed.source_location(), Some(code.clone()));
        assert_eq!(typed.source_locations(), [code]);
        assert_eq!(typed.function_invocations().len(), 1);
        assert_eq!(typed.function_exit(), None);
        assert_eq!(typed.modifier_depth(), Some(1));

        let generated = Instruction::from_source_map(
            8,
            "JUMP",
            SourceMapContext {
                code: None,
                jump: SourceMapJump::Out,
                modifier_depth: 0,
            },
        );
        assert_eq!(generated.source_location(), None);
        assert!(generated.function_invocations().is_empty());
        assert_eq!(generated.function_exit(), Some(FunctionExit::Return));
        assert_eq!(
            serde_json::to_value(&generated).expect("json")["context"],
            json!({"modifierDepth": 0, "return": {}})
        );
    }

    #[test]
    fn keeps_contexts_a_source_map_cannot_say_as_written() {
        for context in [
            // No modifier depth, or anything a source map does not say.
            json!({"code": {"source": {"id": 1}, "range": {"offset": 0, "length": 1}}}),
            json!({"modifierDepth": 0, "remark": "x"}),
            json!({"modifierDepth": 0, "invoke": {"identifier": "f"}}),
            json!({"modifierDepth": 0, "invoke": {}, "return": {}}),
            json!({"modifierDepth": 0, "code": {"source": {"id": 1, "path": "a.sol"},
                "range": {"offset": 0, "length": 1}}}),
        ] {
            let instruction = Instruction::new(0, "STOP", Some(context.clone()));
            let written = serde_json::to_value(&instruction).expect("json");
            assert_eq!(written["context"], context);
        }
        let push: Instruction = serde_json::from_value(json!({
            "offset": 0,
            "operation": {"mnemonic": "PUSH1", "arguments": ["0x01"]}
        }))
        .expect("instruction");
        assert_eq!(
            serde_json::to_value(&push).expect("json")["operation"],
            json!({"mnemonic": "PUSH1", "arguments": ["0x01"]})
        );
    }

    #[test]
    fn extracts_source_picks_and_function_events() {
        let invoke: Instruction = serde_json::from_value(json!({
            "offset": 12,
            "operation": {"mnemonic": "JUMPDEST"},
            "context": {
                "invoke": {
                    "identifier": "calculate",
                    "declaration": {
                        "source": {"id": 7},
                        "range": {"offset": 100, "length": 80}
                    },
                    "jump": true
                }
            }
        }))
        .expect("invoke instruction");
        let shared: Instruction = serde_json::from_value(json!({
            "offset": 13,
            "operation": {"mnemonic": "SSTORE"},
            "context": {
                "pick": [
                    {"code": {
                        "source": {"id": 7},
                        "range": {"offset": 20, "length": 4}
                    }},
                    {"code": {
                        "source": {"id": 7},
                        "range": {"offset": 140, "length": 4}
                    }}
                ]
            }
        }))
        .expect("shared instruction");
        let returned: Instruction = serde_json::from_value(json!({
            "offset": 14,
            "operation": {"mnemonic": "STOP"},
            "context": {"return": {}}
        }))
        .expect("return instruction");

        let function = invoke.function_invocations().remove(0);
        assert_eq!(function.identifier.as_deref(), Some("calculate"));
        assert_eq!(function.declaration.map(|range| range.offset), Some(100));
        assert_eq!(shared.source_location(), None);
        assert_eq!(
            shared
                .source_locations()
                .into_iter()
                .map(|location| location.offset)
                .collect::<Vec<_>>(),
            [20, 140]
        );
        assert_eq!(returned.function_exit(), Some(super::FunctionExit::Return));
    }

    #[test]
    fn reports_source_and_variable_info_at_pc() {
        let instruction: Instruction = serde_json::from_value(json!({
            "offset": 3,
            "operation": {"mnemonic": "SLOAD"},
            "context": {
                "code": {
                    "source": {"id": 0},
                    "range": {"offset": 9, "length": 5}
                }
            }
        }))
        .expect("instruction");

        let variable = super::VariableLocation {
            name: "stored".to_owned(),
            ty: "uint256".to_owned(),
            location_type: "storage".to_owned(),
            offset: 0,
            pc_range: (2, 5),
        };
        let mut sources = BTreeMap::new();
        sources.insert(0, "Counter.sol".to_owned());
        let mut variable_locations = BTreeMap::new();
        variable_locations.insert(2, vec![variable]);
        let info = EthdebugInfo {
            compilation: json!({}),
            contract_name: "Counter".to_owned(),
            environment: "runtime".to_owned(),
            instructions: vec![instruction],
            sources,
            variable_locations,
        };

        assert_eq!(info.source_info(3), Some(("Counter.sol", 9, 5)));
        assert_eq!(info.variables_at_pc(3)[0].name, "stored");
        assert!(info.variables_at_pc(9).is_empty());
    }

    #[test]
    fn parses_variable_locations_from_contract_data() {
        let variables = parse_variable_locations(&json!({
            "instructions": [
                {
                    "offset": 10,
                    "context": {
                        "variables": [
                            {
                                "name": "amount",
                                "type": "uint256",
                                "location": {"type": "stack", "offset": 1},
                                "scope": {"start": 10, "end": 12}
                            }
                        ]
                    }
                }
            ],
            "variables": [
                {
                    "name": "stored",
                    "type": "uint256",
                    "location_type": "storage",
                    "offset": 0,
                    "pc_start": 20,
                    "pc_end": 21
                }
            ]
        }))
        .expect("variables");

        assert_eq!(variables.get(&10).expect("pc 10")[0].name, "amount");
        assert_eq!(
            variables.get(&20).expect("pc 20")[0].location_type,
            "storage"
        );
        assert_eq!(variables.get(&21).expect("pc 21")[0].name, "stored");
    }
}
