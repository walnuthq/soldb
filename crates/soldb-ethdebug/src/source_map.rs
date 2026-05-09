use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use soldb_core::{SoldbError, SoldbResult};

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
    use super::{build_pc_to_instruction_map, is_legacy_compiler, parse_srcmap, SourceMapInfo};

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
}
