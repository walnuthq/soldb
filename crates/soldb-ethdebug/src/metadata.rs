use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use soldb_core::{SoldbError, SoldbResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    pub source_id: u64,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Instruction {
    pub offset: u64,
    pub operation: Value,
    #[serde(default)]
    pub context: Option<Value>,
}

impl Instruction {
    #[must_use]
    pub fn mnemonic(&self) -> Option<&str> {
        self.operation
            .get("mnemonic")
            .and_then(serde_json::Value::as_str)
    }

    #[must_use]
    pub fn arguments(&self) -> Vec<&str> {
        self.operation
            .get("arguments")
            .and_then(serde_json::Value::as_array)
            .map(|arguments| {
                arguments
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect()
            })
            .unwrap_or_default()
    }

    #[must_use]
    pub fn source_location(&self) -> Option<SourceLocation> {
        let code = self.context.as_ref()?.get("code")?;
        let source_id = code.get("source")?.get("id")?.as_u64()?;
        let range = code.get("range")?;
        Some(SourceLocation {
            source_id,
            offset: range.get("offset")?.as_u64()?,
            length: range.get("length")?.as_u64()?,
        })
    }
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

    #[must_use]
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
        parse_ethdebug_spec, parse_multi_contract_spec, parse_single_contract_spec,
        parse_variable_locations, EthdebugInfo, Instruction,
    };
    use serde_json::json;

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
