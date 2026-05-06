use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use soldb_core::{SoldbError, SoldbResult};

use crate::abi::keccak256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventParam {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub indexed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventAbi {
    pub name: String,
    #[serde(default)]
    pub inputs: Vec<EventParam>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodedEventArg {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecodedEvent {
    pub event: String,
    pub signature: String,
    pub contract_name: Option<String>,
    pub args: Vec<DecodedEventArg>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRegistryEntry {
    pub contract_name: Option<String>,
    pub topic: String,
    pub signature: String,
    pub event: EventAbi,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventRegistry {
    entries: BTreeMap<String, EventRegistryEntry>,
}

impl EventRegistry {
    pub fn insert(&mut self, contract_name: Option<String>, event: EventAbi) -> SoldbResult<()> {
        let signature = event_signature(&event);
        let topic = event_topic(&event);
        self.entries.insert(
            topic.clone(),
            EventRegistryEntry {
                contract_name,
                topic,
                signature,
                event,
            },
        );
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn decode_log(&self, topics: &[String], data: &str) -> Option<DecodedEvent> {
        let topic = topics.first()?.to_ascii_lowercase();
        let entry = self.entries.get(&topic)?;
        decode_event(entry, topics, data).ok()
    }
}

pub fn parse_event_abis(input: &str) -> SoldbResult<Vec<EventAbi>> {
    let value = serde_json::from_str::<Value>(input)
        .map_err(|error| SoldbError::Message(format!("Invalid ABI JSON: {error}")))?;
    let items = if let Some(items) = value.as_array() {
        items
    } else {
        value.get("abi").and_then(Value::as_array).ok_or_else(|| {
            SoldbError::Message("ABI JSON must be an array or contain an 'abi' array".to_owned())
        })?
    };

    let mut events = Vec::new();
    for item in items {
        if item.get("type").and_then(Value::as_str) != Some("event") {
            continue;
        }
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            continue;
        };
        let inputs = item
            .get("inputs")
            .and_then(Value::as_array)
            .map(|inputs| {
                inputs
                    .iter()
                    .filter_map(parse_event_param)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        events.push(EventAbi {
            name: name.to_owned(),
            inputs,
        });
    }

    Ok(events)
}

pub fn event_signature(event: &EventAbi) -> String {
    let input_types = event
        .inputs
        .iter()
        .map(|input| input.ty.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!("{}({input_types})", event.name)
}

pub fn event_topic(event: &EventAbi) -> String {
    let signature = event_signature(event);
    format!("0x{}", bytes_to_hex(&keccak256(signature.as_bytes())))
}

fn parse_event_param(value: &Value) -> Option<EventParam> {
    Some(EventParam {
        name: value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        ty: value.get("type")?.as_str()?.to_owned(),
        indexed: value
            .get("indexed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn decode_event(
    entry: &EventRegistryEntry,
    topics: &[String],
    data: &str,
) -> SoldbResult<DecodedEvent> {
    let data_words = split_data_words(data)?;
    let mut next_topic = 1;
    let mut next_data = 0;
    let mut args = Vec::with_capacity(entry.event.inputs.len());

    for input in &entry.event.inputs {
        let word = if input.indexed {
            let word = topics.get(next_topic).ok_or_else(|| {
                SoldbError::Message(format!("Missing indexed topic for {}", input.name))
            })?;
            next_topic += 1;
            word.as_str()
        } else {
            let word = data_words.get(next_data).ok_or_else(|| {
                SoldbError::Message(format!("Missing data word for {}", input.name))
            })?;
            next_data += 1;
            word.as_str()
        };
        args.push(DecodedEventArg {
            name: input.name.clone(),
            ty: input.ty.clone(),
            value: decode_static_word(&input.ty, word)?,
        });
    }

    Ok(DecodedEvent {
        event: entry.event.name.clone(),
        signature: entry.signature.clone(),
        contract_name: entry.contract_name.clone(),
        args,
    })
}

fn split_data_words(data: &str) -> SoldbResult<Vec<String>> {
    let data = data.trim_start_matches("0x");
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if !data.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SoldbError::Message("Event data is not hex".to_owned()));
    }

    Ok(data
        .as_bytes()
        .chunks(64)
        .filter(|chunk| chunk.len() == 64)
        .map(|chunk| String::from_utf8(chunk.to_vec()).expect("hex is utf8"))
        .collect())
}

fn decode_static_word(arg_type: &str, word: &str) -> SoldbResult<Value> {
    let word = normalize_word(word)?;
    if arg_type == "address" {
        return Ok(json!(format!("0x{}", &word[24..64])));
    }
    if arg_type == "bool" {
        return Ok(json!(u128::from_str_radix(&word, 16).unwrap_or(0) != 0));
    }
    if arg_type.starts_with("uint") {
        let value = u128::from_str_radix(&word, 16)
            .map_err(|error| SoldbError::Message(format!("Invalid uint event word: {error}")))?;
        if let Ok(value) = u64::try_from(value) {
            return Ok(json!(value));
        }
        return Ok(json!(value.to_string()));
    }
    if arg_type == "bytes32" {
        return Ok(json!(format!("0x{word}")));
    }

    Ok(json!(format!("0x{word}")))
}

fn normalize_word(word: &str) -> SoldbResult<String> {
    let word = word.trim_start_matches("0x");
    if word.len() > 64 || !word.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SoldbError::Message(format!(
            "Invalid ABI event word: {word}"
        )));
    }
    Ok(format!("{word:0>64}").to_ascii_lowercase())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::{event_signature, event_topic, parse_event_abis, EventRegistry};

    const BALANCE_UPDATED_ABI: &str = r#"[
        {
            "type": "event",
            "name": "BalanceUpdated",
            "inputs": [
                {"name": "user", "type": "address", "indexed": true},
                {"name": "newBalance", "type": "uint256", "indexed": false}
            ]
        },
        {"type": "function", "name": "ignored", "inputs": []}
    ]"#;

    #[test]
    fn parses_event_abis_from_array() {
        let events = parse_event_abis(BALANCE_UPDATED_ABI).expect("parse abi");

        assert_eq!(events.len(), 1);
        assert_eq!(
            event_signature(&events[0]),
            "BalanceUpdated(address,uint256)"
        );
        assert_eq!(event_topic(&events[0]).len(), 66);
    }

    #[test]
    fn decodes_static_event_arguments() {
        let event = parse_event_abis(BALANCE_UPDATED_ABI)
            .expect("parse abi")
            .remove(0);
        let topic = event_topic(&event);
        let mut registry = EventRegistry::default();
        registry
            .insert(Some("TestContract".to_owned()), event)
            .expect("insert event");

        let user = format!(
            "0x{}f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "0".repeat(24)
        );
        let data = format!("0x{:064x}", 99);
        let decoded = registry
            .decode_log(&[topic, user], &data)
            .expect("decode event");

        assert_eq!(decoded.contract_name.as_deref(), Some("TestContract"));
        assert_eq!(decoded.signature, "BalanceUpdated(address,uint256)");
        assert_eq!(
            decoded.args[0].value,
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
        assert_eq!(decoded.args[1].value, 99);
    }

    #[test]
    fn parses_event_abis_from_compiler_json_object() {
        let wrapped = format!(r#"{{"abi": {BALANCE_UPDATED_ABI}}}"#);
        let events = parse_event_abis(&wrapped).expect("parse wrapped abi");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].inputs[0].name, "user");
    }
}
