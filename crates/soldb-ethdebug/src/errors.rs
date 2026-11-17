//! Decoding revert data against error ABIs.
//!
//! An [`ErrorRegistry`] is built from the error entries of contract ABIs and keyed by
//! selector. It always knows Solidity's `Error(string)` and `Panic(uint256)`. Revert data
//! comes from the chain and is not trusted; decoding reuses the checked event decoder.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::Value;
use soldb_core::{SoldbError, SoldbResult};

use crate::abi::keccak256;
use crate::artifacts::find_abi_file;
use crate::events::{
    abi_items, canonical_event_type, decode_param_at, event_param_head_words, parse_abi_json,
    parse_event_param, parse_hex_data, EventParam,
};
use crate::source_map::load_combined_errors;

/// An error declared in an ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorAbi {
    pub name: String,
    pub inputs: Vec<EventParam>,
}

impl ErrorAbi {
    #[must_use]
    pub fn signature(&self) -> String {
        let types = self
            .inputs
            .iter()
            .map(canonical_event_type)
            .collect::<Vec<_>>()
            .join(",");
        format!("{}({types})", self.name)
    }

    #[must_use]
    pub fn selector(&self) -> [u8; 4] {
        let hash = keccak256(self.signature().as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }
}

/// Errors by selector; several errors may share one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorRegistry {
    errors: BTreeMap<[u8; 4], Vec<ErrorAbi>>,
}

impl Default for ErrorRegistry {
    fn default() -> Self {
        let mut registry = Self {
            errors: BTreeMap::new(),
        };
        registry.insert(builtin("Error", "string"));
        registry.insert(builtin("Panic", "uint256"));
        registry
    }
}

impl ErrorRegistry {
    pub fn insert(&mut self, error: ErrorAbi) {
        let errors = self.errors.entry(error.selector()).or_default();
        if !errors.contains(&error) {
            errors.push(error);
        }
    }

    /// `data`, `0x`-prefixed hex revert data, decoded as `Name(arg, …)`, or `None` when no
    /// known error matches it.
    #[must_use]
    pub fn decode(&self, data: &str) -> Option<String> {
        let bytes = parse_hex_data(data).ok()?;
        let selector: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
        let args = &bytes[4..];
        self.errors
            .get(&selector)?
            .iter()
            .find_map(|error| format_error(error, args).ok())
    }
}

impl Extend<ErrorAbi> for ErrorRegistry {
    fn extend<I: IntoIterator<Item = ErrorAbi>>(&mut self, errors: I) {
        for error in errors {
            self.insert(error);
        }
    }
}

/// The error entries of an ABI, a JSON array or an object with an `abi` array.
pub fn parse_error_abis(input: &str) -> SoldbResult<Vec<ErrorAbi>> {
    error_abis(&parse_abi_json(input)?)
}

/// The error entries of an ABI already parsed as JSON.
pub fn error_abis(abi: &Value) -> SoldbResult<Vec<ErrorAbi>> {
    Ok(abi_items(abi)?
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("error"))
        .filter_map(|item| {
            Some(ErrorAbi {
                name: item.get("name")?.as_str()?.to_owned(),
                inputs: item
                    .get("inputs")
                    .and_then(Value::as_array)
                    .map(|inputs| inputs.iter().filter_map(parse_event_param).collect())
                    .unwrap_or_default(),
            })
        })
        .collect())
}

/// The errors in the ABI that solc writes for `contract_name` in `root`, as `<Contract>.abi`
/// or in a legacy `combined.json`. A missing ABI is not an error, as custom errors then show
/// as raw data; an unreadable one is.
pub fn load_error_abis(root: &Path, contract_name: &str) -> SoldbResult<Vec<ErrorAbi>> {
    let Some(path) = find_abi_file(root, contract_name) else {
        return load_combined_errors(root, contract_name);
    };
    fs::read_to_string(&path)
        .map_err(|error| SoldbError::Message(error.to_string()))
        .and_then(|content| parse_error_abis(&content))
        .map_err(|error| SoldbError::Message(format!("{}: {error}", path.display())))
}

fn builtin(name: &str, ty: &str) -> ErrorAbi {
    ErrorAbi {
        name: name.to_owned(),
        inputs: vec![EventParam {
            name: String::new(),
            ty: ty.to_owned(),
            indexed: false,
            components: Vec::new(),
        }],
    }
}

fn format_error(error: &ErrorAbi, data: &[u8]) -> SoldbResult<String> {
    let mut offset = 0;
    let mut values = Vec::with_capacity(error.inputs.len());
    for input in &error.inputs {
        values.push(decode_param_at(input, data, offset, 0)?);
        offset += event_param_head_words(input)? * 32;
    }
    // `revert("…")` shows the text alone, as forge and the summary line do.
    if let ("Error", [Value::String(reason)]) = (error.name.as_str(), values.as_slice()) {
        return Ok(reason.clone());
    }
    let args = error
        .inputs
        .iter()
        .zip(&values)
        .map(|(input, value)| format_value(&input.ty, value))
        .collect::<Vec<_>>();
    if error.name == "Panic" {
        if let Ok(code) = args[0].parse::<u64>() {
            return Ok(match panic_label(code) {
                Some(label) => format!("Panic({code:#04x}: {label})"),
                None => format!("Panic({code:#04x})"),
            });
        }
    }
    Ok(format!("{}({})", error.name, args.join(", ")))
}

fn format_value(ty: &str, value: &Value) -> String {
    match value {
        Value::String(text) if ty == "string" => format!("{text:?}"),
        Value::String(text) => text.clone(),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(|item| format_value("", item))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => other.to_string(),
    }
}

/// What a Solidity panic code means. The codes are solc's
/// <https://github.com/ethereum/solidity/blob/develop/libsolutil/ErrorCodes.h>; the texts
/// are alloy's `PanicKind::as_str`, so the debugger words a panic the way forge does.
fn panic_label(code: u64) -> Option<&'static str> {
    Some(match code {
        0x00 => "generic/unspecified error",
        0x01 => "assertion failed",
        0x11 => "arithmetic underflow or overflow",
        0x12 => "division or modulo by zero",
        0x21 => "failed to convert value into enum type",
        0x22 => "storage byte array incorrectly encoded",
        0x31 => "called `.pop()` on an empty array",
        0x32 => "array out-of-bounds access",
        0x41 => "memory allocation error",
        0x51 => "called an invalid internal function",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_error_abis, ErrorRegistry};

    const TOKEN_ABI: &str = r#"[
        {"type": "function", "name": "mint", "inputs": []},
        {
            "type": "error",
            "name": "InsufficientBalance",
            "inputs": [
                {"name": "available", "type": "uint256"},
                {"name": "required", "type": "uint256"},
                {"name": "token", "type": "address"}
            ]
        }
    ]"#;

    fn word(value: &str) -> String {
        format!("{value:0>64}")
    }

    fn token_registry() -> ErrorRegistry {
        let mut registry = ErrorRegistry::default();
        for error in parse_error_abis(TOKEN_ABI).unwrap() {
            registry.insert(error);
        }
        registry
    }

    #[test]
    fn decodes_a_custom_error() {
        let data = format!(
            "0x832f98b5{}{}{}",
            word("f4240"),
            word("5e69ec0"),
            word("5615deb798bb3e4dfa0139dfa1b3d433cc23b72f")
        );
        assert_eq!(
            token_registry().decode(&data).as_deref(),
            Some("InsufficientBalance(1000000, 99000000, 0x5615deb798bb3e4dfa0139dfa1b3d433cc23b72f)")
        );
    }

    #[test]
    fn decodes_a_uint256_wider_than_128_bits() {
        let data = format!("0x832f98b5{}{}{}", "f".repeat(64), word("1"), word("2"));
        assert_eq!(
            token_registry().decode(&data).as_deref(),
            Some(
                "InsufficientBalance(115792089237316195423570985008687907853269984665640564039457584007913129639935, 1, 0x0000000000000000000000000000000000000002)"
            )
        );
    }

    #[test]
    fn decodes_error_string_and_panic() {
        let registry = ErrorRegistry::default();
        let boom = format!("0x08c379a0{}{}{:0<64}", word("20"), word("4"), "626f6f6d");
        assert_eq!(registry.decode(&boom).as_deref(), Some("boom"));
        let overflow = format!("0x4e487b71{}", word("11"));
        assert_eq!(
            registry.decode(&overflow).as_deref(),
            Some("Panic(0x11: arithmetic underflow or overflow)")
        );
        let unknown_panic = format!("0x4e487b71{}", word("99"));
        assert_eq!(
            registry.decode(&unknown_panic).as_deref(),
            Some("Panic(0x99)")
        );
    }

    #[test]
    fn unknown_or_malformed_data_is_not_decoded() {
        let registry = token_registry();
        assert_eq!(registry.decode("0x"), None);
        assert_eq!(registry.decode("0x832f98"), None);
        assert_eq!(registry.decode(&format!("0xdeadbeef{}", word("1"))), None);
        // One argument missing.
        assert_eq!(
            registry.decode(&format!("0x832f98b5{}{}", word("1"), word("2"))),
            None
        );
        // A string whose length runs past the data.
        assert_eq!(
            registry.decode(&format!("0x08c379a0{}{}", word("20"), word("ffff"))),
            None
        );
        assert_eq!(registry.decode("0xzz"), None);
    }
}
