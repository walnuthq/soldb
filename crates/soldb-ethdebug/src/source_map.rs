//! The legacy `srcmap` debug format.
//!
//! Solidity compilers can emit source mappings as a compact `s:l:f:j:m` string alongside
//! the bytecode, with fields inherited from the previous entry when omitted. This module
//! parses that format and builds the program-counter index for it, which requires walking
//! the bytecode so `PUSH` immediates are not mistaken for opcodes.
//!
//! This is a fallback path. ETHDebug is the primary source of debug information and
//! carries strictly more of it; prefer it whenever the compiler can produce it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use revm_bytecode::OpCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use soldb_core::{SoldbError, SoldbResult};

use crate::{EthdebugInfo, Instruction};

/// The bytecode environment described by a legacy source map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceMapEnvironment {
    Creation,
    Runtime,
}

impl SourceMapEnvironment {
    fn fields(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Creation => ("srcmap", "bin", "create"),
            Self::Runtime => ("srcmap-runtime", "bin-runtime", "call"),
        }
    }
}

/// A legacy source-map program adapted to the common debug-info model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMapProgram {
    pub info: EthdebugInfo,
    pub resources: Value,
    pub source_contents: BTreeMap<u64, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceMapEntry {
    pub offset: i64,
    pub length: i64,
    pub file_index: i64,
    pub jump_type: String,
    pub modifier_depth: i64,
}

impl SourceMapEntry {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.file_index >= 0 && self.offset >= 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceMapInfo {
    pub contract_name: String,
    pub sources: Vec<String>,
    pub bytecode: Vec<u8>,
    pub srcmap_entries: Vec<SourceMapEntry>,
    pub pc_to_instruction_index: BTreeMap<usize, usize>,
    pub compiler_version: Option<String>,
}

impl SourceMapInfo {
    #[must_use]
    pub fn source_entry_at_pc(&self, pc: usize) -> Option<&SourceMapEntry> {
        let instruction_index = self.pc_to_instruction_index.get(&pc)?;
        self.srcmap_entries.get(*instruction_index)
    }

    #[must_use]
    pub fn source_info(&self, pc: usize) -> Option<(&str, i64, i64)> {
        let entry = self.source_entry_at_pc(pc)?;
        if !entry.is_valid() {
            return None;
        }

        let source = self.sources.get(usize::try_from(entry.file_index).ok()?)?;
        Some((source, entry.offset, entry.length))
    }
}

pub fn build_pc_to_instruction_map(bytecode: &[u8]) -> BTreeMap<usize, usize> {
    let mut pc_to_index = BTreeMap::new();
    let mut pc = 0;
    let mut instruction_index = 0;

    while pc < bytecode.len() {
        pc_to_index.insert(pc, instruction_index);
        pc += 1 + push_data_size(bytecode[pc]).unwrap_or(0);
        instruction_index += 1;
    }

    pc_to_index
}

pub fn parse_srcmap(srcmap: &str) -> SoldbResult<Vec<SourceMapEntry>> {
    if srcmap.is_empty() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let mut previous = SourceMapEntry {
        offset: 0,
        length: 0,
        file_index: -1,
        jump_type: "-".to_owned(),
        modifier_depth: 0,
    };

    for part in srcmap.split(';') {
        if part.is_empty() {
            entries.push(previous.clone());
            continue;
        }

        let fields = part.split(':').collect::<Vec<_>>();
        let entry = SourceMapEntry {
            offset: parse_inherited_i64(fields.first().copied(), previous.offset, "offset")?,
            length: parse_inherited_i64(fields.get(1).copied(), previous.length, "length")?,
            file_index: parse_inherited_i64(
                fields.get(2).copied(),
                previous.file_index,
                "file index",
            )?,
            jump_type: parse_inherited_string(fields.get(3).copied(), &previous.jump_type),
            modifier_depth: parse_inherited_i64(
                fields.get(4).copied(),
                previous.modifier_depth,
                "modifier depth",
            )?,
        };

        previous = entry.clone();
        entries.push(entry);
    }

    Ok(entries)
}

/// Loads one program from `combined.json` when the requested source map exists.
///
/// `Ok(None)` means the directory has no legacy artifact, or the selected contract
/// does not contain that creation/runtime map. A present but malformed artifact is
/// always an error so callers cannot silently lose source attribution.
pub fn load_source_map_program(
    root: &Path,
    contract_name: &str,
    environment: SourceMapEnvironment,
) -> SoldbResult<Option<SourceMapProgram>> {
    let path = root.join("combined.json");
    if !path.exists() {
        return Ok(None);
    }

    let input = fs::read_to_string(&path).map_err(|error| {
        SoldbError::Message(format!("failed to read `{}`: {error}", path.display()))
    })?;
    let combined = serde_json::from_str::<Value>(&input).map_err(|error| {
        SoldbError::Message(format!("invalid JSON in `{}`: {error}", path.display()))
    })?;
    source_map_program_from_combined(root, &path, &combined, contract_name, environment)
}

fn source_map_program_from_combined(
    root: &Path,
    artifact_path: &Path,
    combined: &Value,
    contract_name: &str,
    environment: SourceMapEnvironment,
) -> SoldbResult<Option<SourceMapProgram>> {
    let contracts = combined
        .get("contracts")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            SoldbError::Message(format!(
                "legacy artifact `{}` does not contain a contracts object",
                artifact_path.display()
            ))
        })?;
    let Some((contract_key, contract)) = find_contract(contracts, contract_name)? else {
        return Ok(None);
    };
    let (source_map_field, bytecode_field, environment_name) = environment.fields();
    let Some(source_map) = contract.get(source_map_field).and_then(Value::as_str) else {
        return Ok(None);
    };
    let bytecode = contract
        .get(bytecode_field)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            SoldbError::Message(format!(
                "legacy artifact `{}` has `{source_map_field}` for `{contract_key}` but no \
                 `{bytecode_field}`; recompile with bytecode output enabled",
                artifact_path.display()
            ))
        })?;
    let bytecode = decode_bytecode(bytecode, artifact_path, contract_key, bytecode_field)?;
    let source_map = parse_srcmap(source_map)?;
    let source_list = combined
        .get("sourceList")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SoldbError::Message(format!(
                "legacy artifact `{}` does not contain a sourceList array",
                artifact_path.display()
            ))
        })?;

    let mut sources = BTreeMap::new();
    let mut source_contents = BTreeMap::new();
    let mut compilation_sources = Vec::with_capacity(source_list.len());
    for (source_id, source) in source_list.iter().enumerate() {
        let source_path = source.as_str().ok_or_else(|| {
            SoldbError::Message(format!(
                "legacy artifact `{}` has a non-string sourceList entry at index {source_id}",
                artifact_path.display()
            ))
        })?;
        let source_id = u64::try_from(source_id)
            .map_err(|_| SoldbError::Message("source index does not fit in `u64`".to_owned()))?;
        sources.insert(source_id, source_path.to_owned());

        let contents = read_source(root, source_path)?;
        if let Some(contents) = &contents {
            source_contents.insert(source_id, contents.clone());
        }
        let mut source = json!({
            "id": source_id,
            "path": source_path,
            "language": "Solidity",
        });
        if let Some(contents) = contents {
            source["contents"] = Value::String(contents);
        }
        compilation_sources.push(source);
    }

    let pc_to_instruction_index = build_pc_to_instruction_map(&bytecode);
    if source_map.len() > pc_to_instruction_index.len() {
        return Err(SoldbError::Message(format!(
            "legacy source map for `{contract_key}` has {} entries but `{bytecode_field}` has \
             only {} instructions",
            source_map.len(),
            pc_to_instruction_index.len()
        )));
    }

    let mut instructions = Vec::with_capacity(source_map.len());
    for (pc, instruction_index) in pc_to_instruction_index {
        let Some(entry) = source_map.get(instruction_index) else {
            break;
        };
        instructions.push(Instruction {
            offset: u64::try_from(pc).map_err(|_| {
                SoldbError::Message("program counter does not fit in `u64`".to_owned())
            })?,
            operation: opcode_operation(bytecode[pc]),
            context: source_context(
                entry,
                sources.len(),
                &source_contents,
                instruction_index,
                contract_key,
            )?,
        });
    }

    let compiler_version = combined
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let compilation = json!({
        "id": format!("legacy-{compiler_version}"),
        "compiler": {
            "name": "Solidity compiler",
            "version": compiler_version,
        },
        "sources": compilation_sources,
    });
    let resources = json!({
        "compilation": compilation,
        "types": {},
        "pointers": {},
    });
    let resolved_contract_name = contract_key
        .rsplit_once(':')
        .map_or(contract_key, |(_, name)| name);
    let info = EthdebugInfo {
        compilation,
        contract_name: resolved_contract_name.to_owned(),
        environment: environment_name.to_owned(),
        instructions,
        sources,
        variable_locations: BTreeMap::new(),
    };

    Ok(Some(SourceMapProgram {
        info,
        resources,
        source_contents,
    }))
}

fn find_contract<'a>(
    contracts: &'a serde_json::Map<String, Value>,
    contract_name: &str,
) -> SoldbResult<Option<(&'a str, &'a Value)>> {
    if contract_name.is_empty() {
        let mut contracts = contracts.iter();
        let Some((name, contract)) = contracts.next() else {
            return Ok(None);
        };
        if contracts.next().is_some() {
            return Err(SoldbError::Message(
                "legacy combined JSON contains multiple contracts; provide `contractName`"
                    .to_owned(),
            ));
        }
        return Ok(Some((name, contract)));
    }
    if let Some((name, contract)) = contracts.get_key_value(contract_name) {
        return Ok(Some((name, contract)));
    }

    let suffix = format!(":{contract_name}");
    let mut matches = contracts.iter().filter(|(name, _)| name.ends_with(&suffix));
    let Some((name, contract)) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(SoldbError::Message(format!(
            "contract name `{contract_name}` is ambiguous in legacy combined JSON"
        )));
    }
    Ok(Some((name, contract)))
}

fn decode_bytecode(
    bytecode: &str,
    artifact_path: &Path,
    contract_name: &str,
    bytecode_field: &str,
) -> SoldbResult<Vec<u8>> {
    let bytecode = bytecode.strip_prefix("0x").unwrap_or(bytecode);
    let (byte_pairs, remainder) = bytecode.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(SoldbError::Message(format!(
            "`{bytecode_field}` for `{contract_name}` in `{}` has an odd number of hex digits",
            artifact_path.display()
        )));
    }

    byte_pairs
        .iter()
        .map(|digits| {
            let high = decode_hex_digit(digits[0]);
            let low = decode_hex_digit(digits[1]);
            match (high, low) {
                (Some(high), Some(low)) => Ok(high << 4 | low),
                _ => Err(SoldbError::Message(format!(
                    "`{bytecode_field}` for `{contract_name}` in `{}` is not valid hex",
                    artifact_path.display()
                ))),
            }
        })
        .collect()
}

fn decode_hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

fn opcode_operation(opcode: u8) -> Value {
    let mnemonic = OpCode::new(opcode).map_or_else(
        || format!("UNKNOWN(0x{opcode:02x})"),
        |opcode| opcode.as_str().to_owned(),
    );
    json!({"mnemonic": mnemonic})
}

fn source_context(
    entry: &SourceMapEntry,
    source_count: usize,
    source_contents: &BTreeMap<u64, String>,
    instruction_index: usize,
    contract_name: &str,
) -> SoldbResult<Option<Value>> {
    if entry.file_index < 0 {
        return Ok(None);
    }
    if entry.offset < 0 || entry.length < 0 {
        return Err(SoldbError::Message(format!(
            "legacy source-map entry {instruction_index} for `{contract_name}` has a negative \
             source range"
        )));
    }
    let source_id = u64::try_from(entry.file_index).map_err(|_| {
        SoldbError::Message(format!(
            "legacy source-map entry {instruction_index} for `{contract_name}` has an invalid \
             source index"
        ))
    })?;
    if usize::try_from(source_id).map_or(true, |source_id| source_id >= source_count) {
        return Err(SoldbError::Message(format!(
            "legacy source-map entry {instruction_index} for `{contract_name}` references \
             missing source {source_id}"
        )));
    }
    let offset = u64::try_from(entry.offset).map_err(|_| {
        SoldbError::Message(format!(
            "legacy source-map entry {instruction_index} for `{contract_name}` has an invalid \
             offset"
        ))
    })?;
    let length = u64::try_from(entry.length).map_err(|_| {
        SoldbError::Message(format!(
            "legacy source-map entry {instruction_index} for `{contract_name}` has an invalid \
             length"
        ))
    })?;
    let end = offset.checked_add(length).ok_or_else(|| {
        SoldbError::Message(format!(
            "legacy source-map entry {instruction_index} for `{contract_name}` overflows its \
             source range"
        ))
    })?;
    if let Some(source) = source_contents.get(&source_id) {
        let source_len = u64::try_from(source.len())
            .map_err(|_| SoldbError::Message("source length does not fit in `u64`".to_owned()))?;
        if end > source_len {
            return Err(SoldbError::Message(format!(
                "legacy source-map entry {instruction_index} for `{contract_name}` ends at byte \
                 {end}, beyond source {source_id} length {source_len}"
            )));
        }
    }

    Ok(Some(json!({
        "code": {
            "source": {"id": source_id},
            "range": {
                "offset": offset,
                "length": length,
            },
        },
    })))
}

fn read_source(root: &Path, source_path: &str) -> SoldbResult<Option<String>> {
    let source_path = Path::new(source_path);
    let mut candidates = Vec::<PathBuf>::new();
    if source_path.is_absolute() {
        candidates.push(source_path.to_path_buf());
    } else {
        candidates.push(root.join(source_path));
        if let Some(parent) = root.parent() {
            candidates.push(parent.join(source_path));
        }
        candidates.push(source_path.to_path_buf());
    }

    for candidate in candidates {
        if candidate.exists() {
            return fs::read_to_string(&candidate).map(Some).map_err(|error| {
                SoldbError::Message(format!(
                    "failed to read source `{}`: {error}",
                    candidate.display()
                ))
            });
        }
    }
    Ok(None)
}

#[must_use]
pub fn is_legacy_compiler(version: &str) -> bool {
    if version.is_empty() {
        return true;
    }

    let version_core = version.split('+').next().unwrap_or(version);
    let parts = version_core.split('.').collect::<Vec<_>>();
    if parts.len() < 3 {
        return true;
    }

    let Ok(major) = parts[0].parse::<u64>() else {
        return true;
    };
    let Ok(minor) = parts[1].parse::<u64>() else {
        return true;
    };
    let Ok(patch) = parts[2].parse::<u64>() else {
        return true;
    };

    major == 0 && (minor < 8 || (minor == 8 && patch < 29))
}

fn push_data_size(opcode: u8) -> Option<usize> {
    if (0x60..=0x7f).contains(&opcode) {
        Some(usize::from(opcode - 0x5f))
    } else {
        None
    }
}

fn parse_inherited_i64(field: Option<&str>, previous: i64, label: &str) -> SoldbResult<i64> {
    let Some(field) = field else {
        return Ok(previous);
    };

    let trimmed = field.trim();
    if trimmed.is_empty() {
        return Ok(previous);
    }

    trimmed.parse::<i64>().map_err(|error| {
        SoldbError::Message(format!("Invalid source map {label} '{trimmed}': {error}"))
    })
}

fn parse_inherited_string(field: Option<&str>, previous: &str) -> String {
    field
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(previous)
        .to_owned()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use crate::Instruction;

    use super::{
        build_pc_to_instruction_map, is_legacy_compiler, load_source_map_program, parse_srcmap,
        SourceMapEnvironment, SourceMapInfo,
    };

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("soldb-source-map-{label}-{unique}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn maps_program_counters_around_push_data() {
        let bytecode = [0x60, 0xff, 0x61, 0x01, 0x02, 0x00];
        let pc_map = build_pc_to_instruction_map(&bytecode);

        assert_eq!(pc_map.get(&0), Some(&0));
        assert_eq!(pc_map.get(&2), Some(&1));
        assert_eq!(pc_map.get(&5), Some(&2));
        assert!(!pc_map.contains_key(&1));
        assert!(!pc_map.contains_key(&3));
    }

    #[test]
    fn parses_source_maps_with_inherited_fields() {
        let entries = parse_srcmap("0:10:0:-:0;:5::i:;20::1").expect("source map");

        assert_eq!(entries[0].offset, 0);
        assert_eq!(entries[1].offset, 0);
        assert_eq!(entries[1].length, 5);
        assert_eq!(entries[1].file_index, 0);
        assert_eq!(entries[1].jump_type, "i");
        assert_eq!(entries[2].offset, 20);
        assert_eq!(entries[2].length, 5);
        assert_eq!(entries[2].file_index, 1);
    }

    #[test]
    fn rejects_invalid_source_map_numbers() {
        let error = parse_srcmap("abc:10:0").expect_err("invalid number");
        assert!(error.to_string().contains("offset"));
    }

    #[test]
    fn reports_source_info_for_valid_pcs() {
        let bytecode = vec![0x60, 0xff, 0x00];
        let srcmap_entries = parse_srcmap("0:4:0;10:2:1").expect("source map");
        let info = SourceMapInfo {
            contract_name: "Counter".to_owned(),
            sources: vec!["A.sol".to_owned(), "B.sol".to_owned()],
            bytecode: bytecode.clone(),
            srcmap_entries,
            pc_to_instruction_index: build_pc_to_instruction_map(&bytecode),
            compiler_version: Some("0.8.16".to_owned()),
        };

        assert_eq!(info.source_info(0), Some(("A.sol", 0, 4)));
        assert_eq!(info.source_info(2), Some(("B.sol", 10, 2)));
        assert_eq!(info.source_info(1), None);
    }

    #[test]
    fn detects_legacy_compiler_versions() {
        assert!(is_legacy_compiler(""));
        assert!(is_legacy_compiler("0.8.16"));
        assert!(is_legacy_compiler("0.8.28+commit.deadbeef"));
        assert!(!is_legacy_compiler("0.8.29"));
        assert!(!is_legacy_compiler("0.9.0"));
    }

    #[test]
    fn loads_runtime_combined_json_as_debug_info() {
        let dir = temp_dir("runtime");
        let source = "contract Counter { function add() external {} }";
        fs::write(dir.join("Counter.sol"), source).expect("write source");
        fs::write(
            dir.join("combined.json"),
            json!({
                "version": "0.8.36+commit.test",
                "sourceList": ["Counter.sol"],
                "contracts": {
                    "Counter.sol:Counter": {
                        "bin-runtime": "600100",
                        "srcmap-runtime": "0:8:0:-:0;9:3:0"
                    }
                }
            })
            .to_string(),
        )
        .expect("write combined JSON");

        let program = load_source_map_program(&dir, "Counter", SourceMapEnvironment::Runtime)
            .expect("load source map")
            .expect("runtime program");

        assert_eq!(program.info.contract_name, "Counter");
        assert_eq!(program.info.environment, "call");
        assert_eq!(program.info.source_info(0), Some(("Counter.sol", 0, 8)));
        assert_eq!(program.info.source_info(2), Some(("Counter.sol", 9, 3)));
        assert_eq!(
            program
                .info
                .instruction_at_pc(0)
                .and_then(Instruction::mnemonic),
            Some("PUSH1")
        );
        assert_eq!(
            program
                .info
                .instruction_at_pc(2)
                .and_then(Instruction::mnemonic),
            Some("STOP")
        );
        assert_eq!(
            program.source_contents.get(&0).map(String::as_str),
            Some(source)
        );
        assert_eq!(
            program.resources["compilation"]["compiler"]["version"],
            "0.8.36+commit.test"
        );
    }

    #[test]
    fn loads_creation_map_and_infers_single_contract() {
        let dir = temp_dir("creation");
        fs::write(
            dir.join("combined.json"),
            json!({
                "sourceList": ["Missing.sol"],
                "contracts": {
                    "Missing.sol:Created": {
                        "bin": "00",
                        "srcmap": "0:1:0"
                    }
                }
            })
            .to_string(),
        )
        .expect("write combined JSON");

        let program = load_source_map_program(&dir, "", SourceMapEnvironment::Creation)
            .expect("load source map")
            .expect("creation program");

        assert_eq!(program.info.contract_name, "Created");
        assert_eq!(program.info.environment, "create");
        assert!(program.source_contents.is_empty());
    }

    #[test]
    fn requires_bytecode_for_program_counter_mapping() {
        let dir = temp_dir("missing-bytecode");
        fs::write(
            dir.join("combined.json"),
            json!({
                "sourceList": ["Counter.sol"],
                "contracts": {
                    "Counter.sol:Counter": {"srcmap-runtime": "0:1:0"}
                }
            })
            .to_string(),
        )
        .expect("write combined JSON");

        let error = load_source_map_program(&dir, "Counter", SourceMapEnvironment::Runtime)
            .expect_err("missing bytecode");
        assert!(error.to_string().contains("`bin-runtime`"));
        assert!(error.to_string().contains("bytecode output"));
    }
}
