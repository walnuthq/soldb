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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<EventParam>,
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
        .map(canonical_event_type)
        .collect::<Vec<_>>()
        .join(",");
    format!("{}({input_types})", event.name)
}

pub fn event_topic(event: &EventAbi) -> String {
    let signature = event_signature(event);
    format!("0x{}", bytes_to_hex(&keccak256(signature.as_bytes())))
}

fn parse_event_param(value: &Value) -> Option<EventParam> {
    let components = value
        .get("components")
        .and_then(Value::as_array)
        .map(|components| {
            components
                .iter()
                .filter_map(parse_event_param)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

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
        components,
    })
}

fn decode_event(
    entry: &EventRegistryEntry,
    topics: &[String],
    data: &str,
) -> SoldbResult<DecodedEvent> {
    let data_bytes = parse_hex_data(data)?;
    let mut next_topic = 1;
    let mut next_data_offset = 0;
    let mut args = Vec::with_capacity(entry.event.inputs.len());

    for input in &entry.event.inputs {
        let value = if input.indexed {
            let topic = topics.get(next_topic).ok_or_else(|| {
                SoldbError::Message(format!("Missing indexed topic for {}", input.name))
            })?;
            next_topic += 1;
            decode_indexed_topic(input, topic)?
        } else {
            let head_words = event_param_head_words(input)?;
            let value = decode_param_at(input, &data_bytes, next_data_offset, 0)?;
            next_data_offset += head_words * 32;
            value
        };
        args.push(DecodedEventArg {
            name: input.name.clone(),
            ty: canonical_event_type(input),
            value,
        });
    }

    Ok(DecodedEvent {
        event: entry.event.name.clone(),
        signature: entry.signature.clone(),
        contract_name: entry.contract_name.clone(),
        args,
    })
}

fn canonical_event_type(input: &EventParam) -> String {
    if let Some(suffix) = input.ty.strip_prefix("tuple") {
        let components = input
            .components
            .iter()
            .map(canonical_event_type)
            .collect::<Vec<_>>()
            .join(",");
        return format!("({components}){suffix}");
    }
    input.ty.clone()
}

fn decode_indexed_topic(input: &EventParam, topic: &str) -> SoldbResult<Value> {
    if indexed_param_is_hashed(input) {
        let topic = normalize_word(topic)?;
        return Ok(json!(format!("0x{topic}")));
    }
    decode_static_word(&input.ty, topic)
}

fn indexed_param_is_hashed(input: &EventParam) -> bool {
    input.ty == "string"
        || input.ty == "bytes"
        || parse_array_type(&input.ty).is_some()
        || is_tuple_param(input)
}

fn decode_param_at(
    input: &EventParam,
    data: &[u8],
    head_offset: usize,
    base_offset: usize,
) -> SoldbResult<Value> {
    if event_param_is_dynamic(input)? {
        let relative_offset = read_usize_word(data, head_offset, &input.name)?;
        return decode_dynamic_param(input, data, base_offset + relative_offset);
    }
    decode_static_param(input, data, head_offset)
}

fn decode_dynamic_param(input: &EventParam, data: &[u8], offset: usize) -> SoldbResult<Value> {
    if input.ty == "string" {
        let bytes = read_dynamic_bytes(data, offset, &input.name)?;
        let value = String::from_utf8(bytes).map_err(|error| {
            SoldbError::Message(format!(
                "Invalid UTF-8 event string {}: {error}",
                input.name
            ))
        })?;
        return Ok(json!(value));
    }
    if input.ty == "bytes" {
        let bytes = read_dynamic_bytes(data, offset, &input.name)?;
        return Ok(json!(format!("0x{}", bytes_to_hex(&bytes))));
    }

    if let Some((base_type, fixed_len)) = parse_array_type(&input.ty) {
        let base = array_element_param(input, base_type);
        let (len, heads_offset, offsets_base) = if let Some(len) = fixed_len {
            (len, offset, offset)
        } else {
            let len = read_usize_word(data, offset, &input.name)?;
            (len, offset + 32, offset + 32)
        };
        return decode_array_items(&base, len, data, heads_offset, offsets_base);
    }

    if is_tuple_param(input) {
        return decode_tuple_components(&input.components, data, offset);
    }

    Err(SoldbError::Message(format!(
        "Dynamic event ABI type '{}' is not supported",
        input.ty
    )))
}

fn decode_static_param(input: &EventParam, data: &[u8], offset: usize) -> SoldbResult<Value> {
    if let Some((base_type, Some(len))) = parse_array_type(&input.ty) {
        let base = array_element_param(input, base_type);
        return decode_array_items(&base, len, data, offset, offset);
    }

    if is_tuple_param(input) {
        return decode_tuple_components(&input.components, data, offset);
    }

    let word = read_word_hex(data, offset)?;
    decode_static_word(&input.ty, &word)
}

fn decode_tuple_components(
    components: &[EventParam],
    data: &[u8],
    tuple_offset: usize,
) -> SoldbResult<Value> {
    let mut offset = tuple_offset;
    let mut values = Vec::with_capacity(components.len());
    for component in components {
        let head_words = event_param_head_words(component)?;
        values.push(decode_param_at(component, data, offset, tuple_offset)?);
        offset += head_words * 32;
    }
    Ok(Value::Array(values))
}

fn decode_array_items(
    base: &EventParam,
    len: usize,
    data: &[u8],
    heads_offset: usize,
    offsets_base: usize,
) -> SoldbResult<Value> {
    let mut offset = heads_offset;
    let mut values = Vec::with_capacity(len);
    let base_head_words = event_param_head_words(base)?;
    for _ in 0..len {
        values.push(decode_param_at(base, data, offset, offsets_base)?);
        offset += base_head_words * 32;
    }
    Ok(Value::Array(values))
}

fn event_param_head_words(input: &EventParam) -> SoldbResult<usize> {
    if event_param_is_dynamic(input)? {
        return Ok(1);
    }

    if let Some((base_type, Some(len))) = parse_array_type(&input.ty) {
        let base = array_element_param(input, base_type);
        return Ok(event_param_head_words(&base)? * len);
    }

    if is_tuple_param(input) {
        return input.components.iter().try_fold(0, |total, component| {
            Ok(total + event_param_head_words(component)?)
        });
    }

    Ok(1)
}

fn event_param_is_dynamic(input: &EventParam) -> SoldbResult<bool> {
    if input.ty == "string" || input.ty == "bytes" {
        return Ok(true);
    }

    if let Some((base_type, fixed_len)) = parse_array_type(&input.ty) {
        if fixed_len.is_none() {
            return Ok(true);
        }
        let base = array_element_param(input, base_type);
        return event_param_is_dynamic(&base);
    }

    if is_tuple_param(input) {
        return input
            .components
            .iter()
            .try_fold(false, |dynamic, component| {
                Ok(dynamic || event_param_is_dynamic(component)?)
            });
    }

    Ok(false)
}

fn array_element_param(input: &EventParam, base_type: &str) -> EventParam {
    EventParam {
        name: input.name.clone(),
        ty: base_type.to_owned(),
        indexed: false,
        components: input.components.clone(),
    }
}

fn parse_array_type(arg_type: &str) -> Option<(&str, Option<usize>)> {
    if !arg_type.ends_with(']') {
        return None;
    }
    let open = arg_type.rfind('[')?;
    let base_type = arg_type[..open].trim();
    if base_type.is_empty() {
        return None;
    }

    let length = &arg_type[open + 1..arg_type.len() - 1];
    if length.is_empty() {
        return Some((base_type, None));
    }
    Some((base_type, Some(length.parse::<usize>().ok()?)))
}

fn is_tuple_param(input: &EventParam) -> bool {
    input.ty == "tuple" || input.ty.starts_with("tuple[")
}

fn read_dynamic_bytes(data: &[u8], offset: usize, label: &str) -> SoldbResult<Vec<u8>> {
    let len = read_usize_word(data, offset, label)?;
    let start = offset + 32;
    let end = start + len;
    if end > data.len() {
        return Err(SoldbError::Message(format!(
            "Event dynamic bytes for {label} exceed data length"
        )));
    }
    Ok(data[start..end].to_vec())
}

fn read_usize_word(data: &[u8], offset: usize, label: &str) -> SoldbResult<usize> {
    let word = read_word(data, offset)?;
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(SoldbError::Message(format!(
            "Event offset or length for {label} does not fit usize"
        )));
    }
    let low = u64::from_be_bytes(word[24..32].try_into().expect("8-byte slice"));
    usize::try_from(low).map_err(|error| {
        SoldbError::Message(format!(
            "Event offset or length for {label} does not fit usize: {error}"
        ))
    })
}

fn read_word_hex(data: &[u8], offset: usize) -> SoldbResult<String> {
    Ok(bytes_to_hex(read_word(data, offset)?))
}

fn read_word(data: &[u8], offset: usize) -> SoldbResult<&[u8]> {
    let end = offset + 32;
    data.get(offset..end)
        .ok_or_else(|| SoldbError::Message("Event data is missing an ABI word".to_owned()))
}

fn parse_hex_data(data: &str) -> SoldbResult<Vec<u8>> {
    let data = data.trim_start_matches("0x");
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if !data.len().is_multiple_of(2) || !data.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SoldbError::Message("Event data is not hex".to_owned()));
    }

    data.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let pair = std::str::from_utf8(chunk)
                .map_err(|error| SoldbError::Message(format!("Invalid event data: {error}")))?;
            u8::from_str_radix(pair, 16)
                .map_err(|error| SoldbError::Message(format!("Invalid event data: {error}")))
        })
        .collect()
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
    use serde_json::json;

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

    const COMPLEX_EVENT_ABI: &str = r#"[
        {
            "type": "event",
            "name": "Complex",
            "inputs": [
                {"name": "sender", "type": "address", "indexed": true},
                {"name": "message", "type": "string", "indexed": false},
                {"name": "payload", "type": "bytes", "indexed": false},
                {"name": "values", "type": "uint256[]", "indexed": false},
                {"name": "labels", "type": "string[2]", "indexed": false},
                {
                    "name": "item",
                    "type": "tuple",
                    "indexed": false,
                    "components": [
                        {"name": "count", "type": "uint256"},
                        {"name": "note", "type": "string"}
                    ]
                },
                {
                    "name": "nested",
                    "type": "tuple",
                    "indexed": false,
                    "components": [
                        {"name": "count", "type": "uint256"},
                        {
                            "name": "inner",
                            "type": "tuple",
                            "components": [
                                {"name": "target", "type": "address"},
                                {"name": "label", "type": "string"}
                            ]
                        }
                    ]
                },
                {"name": "tag", "type": "string", "indexed": true}
            ]
        }
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
    fn decodes_dynamic_arrays_and_tuple_event_arguments() {
        let event = parse_event_abis(COMPLEX_EVENT_ABI)
            .expect("parse abi")
            .remove(0);
        assert_eq!(
            event_signature(&event),
            "Complex(address,string,bytes,uint256[],string[2],(uint256,string),(uint256,(address,string)),string)"
        );

        let topic = event_topic(&event);
        let mut registry = EventRegistry::default();
        registry.insert(None, event).expect("insert event");

        let sender = format!(
            "0x{}f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "0".repeat(24)
        );
        let indexed_tag_hash = format!("0x{}", "aa".repeat(32));
        let data = concat!(
            "0x",
            "00000000000000000000000000000000000000000000000000000000000000c0",
            "0000000000000000000000000000000000000000000000000000000000000100",
            "0000000000000000000000000000000000000000000000000000000000000140",
            "00000000000000000000000000000000000000000000000000000000000001a0",
            "0000000000000000000000000000000000000000000000000000000000000260",
            "00000000000000000000000000000000000000000000000000000000000002e0",
            "0000000000000000000000000000000000000000000000000000000000000005",
            "68656c6c6f000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0102000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000007",
            "0000000000000000000000000000000000000000000000000000000000000008",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "6100000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "6262000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000005",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "6869000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000009",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000000000000000000000000000000000040",
            "0000000000000000000000000000000000000000000000000000000000000006",
            "6e65737465640000000000000000000000000000000000000000000000000000"
        );

        let decoded = registry
            .decode_log(&[topic, sender, indexed_tag_hash.clone()], data)
            .expect("decode dynamic event");

        assert_eq!(
            decoded.args[0].value,
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
        assert_eq!(decoded.args[1].value, "hello");
        assert_eq!(decoded.args[2].value, "0x0102");
        assert_eq!(decoded.args[3].value, json!([7, 8]));
        assert_eq!(decoded.args[4].value, json!(["a", "bb"]));
        assert_eq!(decoded.args[5].value, json!([5, "hi"]));
        assert_eq!(
            decoded.args[6].value,
            json!([9, ["0x0000000000000000000000000000000000000002", "nested"]])
        );
        assert_eq!(decoded.args[7].value, indexed_tag_hash);
    }

    #[test]
    fn parses_event_abis_from_compiler_json_object() {
        let wrapped = format!(r#"{{"abi": {BALANCE_UPDATED_ABI}}}"#);
        let events = parse_event_abis(&wrapped).expect("parse wrapped abi");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].inputs[0].name, "user");
    }
}
