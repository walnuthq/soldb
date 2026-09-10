//! Values of variables, read through their declared types.
//!
//! A variable's stack word is the value itself for a value type, and a pointer for a
//! reference type: into memory, into storage, or into calldata, as the declaration's
//! data location says. Each of those has a layout the language fixes — the same standing
//! as the storage layout — so a `string memory` is read as its bytes, a memory struct as
//! its members, a storage pointer through the storage layout, and a `calldata` array as
//! the words of the frame's calldata. Enums and user-defined value types are read through
//! the declarations the sources carry, so an enum shows as `Color.Red` rather than `1`.
//!
//! What cannot be read says so rather than printing a pointer as a number: memory the
//! backend did not capture, a slot the frame never touched, a struct whose declaration
//! is not in the loaded sources.

use soldb_ethdebug::{decode_value, parse_word, word_hex, StorageLayout, StorageRef, Word};

use crate::state::{short_hex, StorageWords};
use crate::types::SourceTypes;
use crate::{
    array_shape, decode_static_word, hex_of, is_value_type, memory_bytes, memory_word,
    word_as_usize, DebugValue, DebugValueStatus,
};

/// How many nested reference values are followed before a pointer is shown as such.
const MAX_DEPTH: usize = 3;
/// How many elements of an array are shown before the rest are counted.
const SHOWN_ELEMENTS: usize = 8;

/// The data a step offers to read values from.
#[derive(Clone, Copy)]
pub(crate) struct ValueReader<'a> {
    /// Memory as one unprefixed hex string, when the backend captured it.
    pub memory: Option<&'a str>,
    /// The calldata of the executing frame.
    pub calldata: &'a str,
    /// The storage words known at the step, for storage pointers.
    pub storage: Option<&'a StorageWords<'a>>,
    pub layout: Option<&'a StorageLayout>,
    pub types: &'a SourceTypes,
}

impl ValueReader<'_> {
    /// The value of a variable declared as `ty` (with its data location, such as
    /// `uint256[] memory`) whose stack words are `words`, bottom first.
    pub(crate) fn variable(&self, ty: &str, words: &[&str]) -> DebugValue {
        let (base, location) = split_location(ty);
        let Some(first) = words.first() else {
            return unavailable();
        };
        match location {
            Some("memory") => self.memory_pointer(first, base),
            Some("storage") => self.storage_pointer(first, base),
            Some("calldata") => match words {
                [offset, length] => self.calldata_slice(base, offset, length),
                [offset] => self.calldata_static(offset, base),
                _ => unavailable(),
            },
            _ => self.value_word(first, base),
        }
    }

    /// A one-word value: a value type, an enum, a user-defined value type, or a contract.
    pub(crate) fn value_word(&self, word: &str, ty: &str) -> DebugValue {
        let ty = self.resolve_value_type(ty);
        let normalized = normalize_hex(word);
        let digits = normalized.trim_start_matches("0x");
        let raw = Some(normalized.clone());
        if let Some(variants) = self.types.enum_variants(ty) {
            let index = u64::from_str_radix(digits, 16).ok();
            let display = match index.and_then(|index| variants.get(index as usize)) {
                Some(variant) => format!("{ty}.{variant}"),
                None => digits.trim_start_matches('0').to_owned(),
            };
            return DebugValue {
                display: if display.is_empty() {
                    "0".to_owned()
                } else {
                    display
                },
                raw,
                status: DebugValueStatus::Decoded,
            };
        }
        if let Some(display) = decode_static_word(digits, ty) {
            return DebugValue {
                display,
                raw,
                status: DebugValueStatus::Decoded,
            };
        }
        // A contract or interface type is an address on the stack.
        if is_type_name(ty) && !self.is_reference(ty) {
            if let Ok(parsed) = parse_word(&normalized) {
                if parsed[..12].iter().all(|byte| *byte == 0) {
                    return DebugValue {
                        display: decode_value(&parsed[12..], "address"),
                        raw,
                        status: DebugValueStatus::Decoded,
                    };
                }
            }
        }
        DebugValue {
            display: normalized,
            raw,
            status: DebugValueStatus::Raw,
        }
    }

    /// The type a user-defined value type wraps, through any chain of them.
    fn resolve_value_type<'t>(&'t self, ty: &'t str) -> &'t str {
        let mut ty = ty;
        for _ in 0..4 {
            match self.types.underlying(ty) {
                Some(underlying) => ty = underlying,
                None => break,
            }
        }
        ty
    }

    /// Whether a value of `ty` lives behind a pointer rather than in its own word.
    fn is_reference(&self, ty: &str) -> bool {
        ty == "bytes" || ty == "string" || ty.ends_with(']') || self.types.is_struct(ty)
    }

    fn memory_pointer(&self, word: &str, ty: &str) -> DebugValue {
        let Ok(parsed) = parse_word(&normalize_hex(word)) else {
            return unreadable(word);
        };
        let raw = Some(short_hex(&parsed));
        let pointer = word_as_usize(&parsed);
        let display = match (pointer, self.memory) {
            (Some(pointer), Some(_)) => self.read_memory(pointer, ty, 0).unwrap_or_else(|| {
                format!(
                    "<{ty} in memory at {}, beyond what this step captured>",
                    short_hex(&parsed)
                )
            }),
            (_, None) => format!(
                "<{ty} in memory at {}; this backend captured no memory>",
                short_hex(&parsed)
            ),
            (None, _) => format!("<{ty} at {}>", short_hex(&parsed)),
        };
        let status = if display.starts_with('<') {
            DebugValueStatus::Raw
        } else {
            DebugValueStatus::Decoded
        };
        DebugValue {
            display,
            raw,
            status,
        }
    }

    /// A value at `pointer` of memory, or `None` when the capture does not reach it or
    /// the type is not one memory holds.
    pub(crate) fn read_memory(&self, pointer: usize, ty: &str, depth: usize) -> Option<String> {
        let memory = self.memory?;
        if depth > MAX_DEPTH {
            return Some(format!("<{ty} at {pointer:#x}>"));
        }
        if ty == "string" || ty == "bytes" {
            let length = word_as_usize(&memory_word(memory, pointer)?)?;
            let bytes = memory_bytes(memory, pointer.checked_add(32)?, length)?;
            if ty == "string" {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    return Some(format!("{text:?}"));
                }
            }
            return Some(format!("0x{}", hex_of(&bytes)));
        }
        if let Some((element, count)) = array_shape(ty) {
            let (first, count) = match count {
                // Dynamic: the length is the first word, the elements follow it.
                None => (
                    pointer.checked_add(32)?,
                    word_as_usize(&memory_word(memory, pointer)?)?,
                ),
                Some(count) => (pointer, count),
            };
            let shown = count.min(SHOWN_ELEMENTS);
            let mut parts = Vec::with_capacity(shown + 1);
            for index in 0..shown {
                let word = memory_word(memory, first.checked_add(index.checked_mul(32)?)?)?;
                parts.push(self.memory_element(&word, element, depth));
            }
            if count > shown {
                parts.push(format!("... {} more", count - shown));
            }
            return Some(format!("[{}]", parts.join(", ")));
        }
        if let Some(members) = self.types.struct_members(ty) {
            let mut parts = Vec::with_capacity(members.len());
            for (index, member) in members.iter().enumerate() {
                let word = memory_word(memory, pointer.checked_add(index.checked_mul(32)?)?)?;
                parts.push(format!(
                    "{}: {}",
                    member.name,
                    self.memory_element(&word, &member.ty, depth)
                ));
            }
            return Some(format!("{{ {} }}", parts.join(", ")));
        }
        None
    }

    /// One word of a memory array or struct: the value, or the value behind the pointer.
    fn memory_element(&self, word: &Word, ty: &str, depth: usize) -> String {
        if self.is_reference(ty) {
            let pointer = word_as_usize(word);
            return pointer
                .and_then(|pointer| self.read_memory(pointer, ty, depth + 1))
                .unwrap_or_else(|| format!("<{ty} at {}>", short_hex(word)));
        }
        self.value_word(&word_hex(word), ty).display
    }

    fn storage_pointer(&self, word: &str, ty: &str) -> DebugValue {
        let Ok(slot) = parse_word(&normalize_hex(word)) else {
            return unreadable(word);
        };
        let raw = Some(short_hex(&slot));
        let placeholder = |reason: &str| DebugValue {
            display: format!("<{ty} in storage at slot {}{reason}>", short_hex(&slot)),
            raw: raw.clone(),
            status: DebugValueStatus::Raw,
        };
        let Some(layout) = self.layout else {
            return placeholder("; no storage layout is loaded");
        };
        let Some(type_id) = storage_type_id(layout, ty) else {
            return placeholder("; the storage layout has no such type");
        };
        let Some(words) = self.storage else {
            return placeholder("; no storage was recorded");
        };
        let reference = StorageRef {
            path: ty.to_owned(),
            slot,
            offset: 0,
            type_id,
        };
        match layout.decode(&reference, &|slot| {
            words.get(slot).or_else(|| words.chain_word(slot))
        }) {
            Ok(decoded) => DebugValue {
                display: decoded.display,
                raw: decoded.raw.or(raw),
                status: DebugValueStatus::Decoded,
            },
            Err(missing) => DebugValue {
                display: words.unavailable(&missing),
                raw,
                status: DebugValueStatus::Unavailable,
            },
        }
    }

    /// A `calldata` slice: the bytes of `bytes` and `string`, or the elements of an
    /// array. `offset` is where the slice's data starts in the calldata, the way the
    /// legacy decoder leaves it on the stack, and `length` its element count.
    fn calldata_slice(&self, ty: &str, offset: &str, length: &str) -> DebugValue {
        let word = |value: &str| usize::from_str_radix(value.trim_start_matches("0x"), 16).ok();
        let (Some(offset), Some(length)) = (word(offset), word(length)) else {
            return unavailable();
        };
        let data = self.calldata.trim_start_matches("0x");
        if ty == "bytes" || ty == "string" {
            let Some(hex) = offset
                .checked_add(length)
                .and_then(|end| data.get(offset * 2..end * 2))
            else {
                return unavailable();
            };
            let raw = format!("0x{hex}");
            let display = if ty == "string" {
                let bytes = (0..length)
                    .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16))
                    .collect::<Result<Vec<_>, _>>()
                    .ok();
                match bytes.map(String::from_utf8) {
                    Some(Ok(text)) if text.chars().all(|character| !character.is_control()) => {
                        format!("\"{text}\"")
                    }
                    _ => raw.clone(),
                }
            } else {
                raw.clone()
            };
            return DebugValue {
                display,
                raw: Some(raw),
                status: DebugValueStatus::Decoded,
            };
        }
        let Some(element) = ty.strip_suffix("[]") else {
            return unavailable();
        };
        if self.is_reference(element) {
            return DebugValue {
                display: format!("[{length} items at calldata offset {offset:#x}]"),
                raw: None,
                status: DebugValueStatus::Raw,
            };
        }
        let shown = length.min(SHOWN_ELEMENTS);
        let mut elements = Vec::with_capacity(shown + 1);
        for index in 0..shown {
            let Some(hex) = offset
                .checked_add(index * 32)
                .and_then(|start| data.get(start * 2..(start + 32) * 2))
            else {
                return unavailable();
            };
            elements.push(self.value_word(&format!("0x{hex}"), element).display);
        }
        if length > shown {
            elements.push(format!("... {} more", length - shown));
        }
        DebugValue {
            display: format!("[{}]", elements.join(", ")),
            raw: None,
            status: DebugValueStatus::Decoded,
        }
    }

    /// A one-word `calldata` reference: a fixed-size array or a struct of value types
    /// starts at the word's offset, one word per element.
    fn calldata_static(&self, offset: &str, ty: &str) -> DebugValue {
        let Some(offset) = usize::from_str_radix(offset.trim_start_matches("0x"), 16).ok() else {
            return unavailable();
        };
        let data = self.calldata.trim_start_matches("0x");
        let word_at = |index: usize| -> Option<String> {
            offset
                .checked_add(index * 32)
                .and_then(|start| data.get(start * 2..(start + 32) * 2))
                .map(|hex| format!("0x{hex}"))
        };
        let placeholder = DebugValue {
            display: format!("<{ty} calldata at offset {offset:#x}>"),
            raw: None,
            status: DebugValueStatus::Raw,
        };
        if let Some((element, Some(count))) = array_shape(ty) {
            if self.is_reference(element) {
                return placeholder;
            }
            let shown = count.min(SHOWN_ELEMENTS);
            let mut elements = Vec::with_capacity(shown + 1);
            for index in 0..shown {
                let Some(word) = word_at(index) else {
                    return unavailable();
                };
                elements.push(self.value_word(&word, element).display);
            }
            if count > shown {
                elements.push(format!("... {} more", count - shown));
            }
            return DebugValue {
                display: format!("[{}]", elements.join(", ")),
                raw: None,
                status: DebugValueStatus::Decoded,
            };
        }
        if let Some(members) = self.types.struct_members(ty) {
            if members.iter().any(|member| self.is_reference(&member.ty)) {
                return placeholder;
            }
            let mut parts = Vec::with_capacity(members.len());
            for (index, member) in members.iter().enumerate() {
                let Some(word) = word_at(index) else {
                    return unavailable();
                };
                parts.push(format!(
                    "{}: {}",
                    member.name,
                    self.value_word(&word, &member.ty).display
                ));
            }
            return DebugValue {
                display: format!("{{ {} }}", parts.join(", ")),
                raw: None,
                status: DebugValueStatus::Decoded,
            };
        }
        placeholder
    }
}

/// A declared type split into its type and its data location: `uint256[] memory` is
/// `uint256[]` in `memory`.
pub(crate) fn split_location(ty: &str) -> (&str, Option<&str>) {
    let ty = ty.trim();
    for location in ["memory", "storage", "calldata"] {
        if let Some(base) = ty.strip_suffix(location) {
            let base = base.trim_end();
            if base.len() < ty.len() - location.len() {
                return (base, Some(location));
            }
        }
    }
    (ty, None)
}

/// Whether `ty` is written as a declared type's name: identifiers joined by dots.
fn is_type_name(ty: &str) -> bool {
    !ty.is_empty()
        && ty.split('.').all(|segment| {
            let mut bytes = segment.bytes();
            bytes
                .next()
                .is_some_and(|first| first == b'_' || first.is_ascii_alphabetic())
                && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        })
        && !is_value_type(ty)
        && !matches!(ty, "bytes" | "string")
}

/// The storage layout's identifier for the type declared as `ty`, matched by label: the
/// layout labels a struct `struct Shop.Item` where the declaration says `Item`.
fn storage_type_id(layout: &StorageLayout, ty: &str) -> Option<String> {
    let wanted = unqualified(ty);
    layout
        .types
        .iter()
        .find(|(_, candidate)| unqualified(&candidate.label) == wanted)
        .map(|(id, _)| id.clone())
}

/// A type label without `struct`/`enum`/`contract` prefixes and contract qualifiers, so
/// `struct Shop.Item[]` and `Item[]` compare equal.
fn unqualified(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    let mut rest = label;
    while !rest.is_empty() {
        for prefix in ["struct ", "enum ", "contract "] {
            if let Some(stripped) = rest.strip_prefix(prefix) {
                rest = stripped;
            }
        }
        let identifier_end = rest
            .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .unwrap_or(rest.len());
        if identifier_end > 0 && rest[identifier_end..].starts_with('.') {
            // A qualifier: drop it and its dot.
            rest = &rest[identifier_end + 1..];
            continue;
        }
        let take = identifier_end.max(1);
        out.push_str(&rest[..take]);
        rest = &rest[take..];
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_hex(value: &str) -> String {
    let value = value.trim();
    let hex = value.strip_prefix("0x").unwrap_or(value);
    format!("0x{}", hex.to_ascii_lowercase())
}

fn unavailable() -> DebugValue {
    DebugValue {
        display: "<unavailable>".to_owned(),
        raw: None,
        status: DebugValueStatus::Unavailable,
    }
}

fn unreadable(word: &str) -> DebugValue {
    DebugValue {
        display: "<unreadable stack word>".to_owned(),
        raw: Some(word.to_owned()),
        status: DebugValueStatus::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use soldb_ethdebug::StorageLayout;

    use super::{split_location, unqualified, ValueReader};
    use crate::types::SourceTypes;
    use crate::DebugValueStatus;

    const SOURCE: &str = "\
contract Shop {
    enum Color { Red, Green, Blue }
    type Price is uint128;
    struct Item { uint256 id; string name; Color color; uint256[] tags; }
    struct Pair { uint128 a; uint128 b; }
}
";

    fn word(value: u64) -> String {
        format!("{value:064x}")
    }

    fn reader<'a>(memory: Option<&'a str>, types: &'a SourceTypes) -> ValueReader<'a> {
        ValueReader {
            memory,
            calldata: "0x",
            storage: None,
            layout: None,
            types,
        }
    }

    #[test]
    fn splits_data_locations() {
        assert_eq!(
            split_location("uint256[] memory"),
            ("uint256[]", Some("memory"))
        );
        assert_eq!(split_location("Item storage"), ("Item", Some("storage")));
        assert_eq!(split_location("uint256"), ("uint256", None));
        assert_eq!(split_location("memory"), ("memory", None));
    }

    #[test]
    fn enums_value_types_and_contracts_decode_from_one_word() {
        let types = SourceTypes::parse(SOURCE);
        let reader = reader(None, &types);
        assert_eq!(reader.value_word("0x1", "Color").display, "Color.Green");
        assert_eq!(
            reader.value_word("0x2", "Shop.Color").display,
            "Shop.Color.Blue"
        );
        assert_eq!(reader.value_word("0x7", "Color").display, "7");
        assert_eq!(reader.value_word("0xff", "Price").display, "255");
        assert_eq!(
            reader.value_word("0xabc", "Shop").display,
            "0x0000000000000000000000000000000000000abc"
        );
        let unknown = reader.value_word("0x1", "Item");
        assert_eq!(unknown.status, DebugValueStatus::Raw);
    }

    #[test]
    fn memory_structs_arrays_and_strings_are_read_through_their_layout() {
        let types = SourceTypes::parse(SOURCE);
        // Item at 0x80: id 7, name -> 0x100, color Blue, tags -> 0x140.
        // String at 0x100: length 2, "hi". Array at 0x140: length 2, [3, 4].
        let mut memory = String::new();
        for _ in 0..4 {
            memory.push_str(&word(0));
        }
        memory.push_str(&word(7));
        memory.push_str(&word(0x100));
        memory.push_str(&word(2));
        memory.push_str(&word(0x140));
        memory.push_str(&word(2));
        memory.push_str(&format!("{:0<64}", "6869"));
        memory.push_str(&word(2));
        memory.push_str(&word(3));
        memory.push_str(&word(4));
        let reader = reader(Some(&memory), &types);
        let item = reader.variable("Item memory", &["0x80"]);
        assert_eq!(item.status, DebugValueStatus::Decoded);
        assert_eq!(
            item.display,
            "{ id: 7, name: \"hi\", color: Color.Blue, tags: [3, 4] }"
        );
        assert_eq!(
            reader.variable("uint256[] memory", &["0x140"]).display,
            "[3, 4]"
        );
        assert_eq!(
            reader.variable("string memory", &["0x100"]).display,
            "\"hi\""
        );
        // An array of structs follows each element's pointer.
        let mut nested = memory.clone();
        nested.push_str(&word(1));
        nested.push_str(&word(0x80));
        assert_eq!(
            reader.variable("Item[] memory", &["0x1a0"]).display,
            "<Item[] in memory at 0x1a0, beyond what this step captured>"
        );
        let reader = ValueReader {
            memory: Some(&nested),
            ..reader
        };
        assert_eq!(
            reader.variable("Item[] memory", &["0x1a0"]).display,
            "[{ id: 7, name: \"hi\", color: Color.Blue, tags: [3, 4] }]"
        );
        // Without memory the pointer is shown as such.
        let blind = ValueReader {
            memory: None,
            ..reader
        };
        let value = blind.variable("Item memory", &["0x80"]);
        assert_eq!(value.status, DebugValueStatus::Raw);
        assert!(
            value.display.contains("captured no memory"),
            "{}",
            value.display
        );
    }

    #[test]
    fn calldata_slices_and_static_references_are_read_from_the_calldata() {
        let types = SourceTypes::parse(SOURCE);
        let calldata = format!("0x{}{}{}{}", word(1), word(2), word(5), word(6));
        let reader = ValueReader {
            calldata: &calldata,
            ..reader(None, &types)
        };
        assert_eq!(
            reader
                .variable("Color[] calldata", &["0x20", "0x2"])
                .display,
            "[Color.Blue, 5]"
        );
        assert_eq!(
            reader.variable("Pair calldata", &["0x40"]).display,
            "{ a: 5, b: 6 }"
        );
        assert_eq!(
            reader.variable("uint256[2] calldata", &["0x0"]).display,
            "[1, 2]"
        );
    }

    #[test]
    fn storage_pointers_are_read_through_the_storage_layout() {
        let layout = StorageLayout::parse(&json!({
            "storage": [
                {"label": "items", "slot": "0", "offset": 0, "type": "t_array(t_struct(Pair)5_storage)dyn_storage"}
            ],
            "types": {
                "t_array(t_struct(Pair)5_storage)dyn_storage": {"label": "struct Shop.Pair[]", "encoding": "dynamic_array", "numberOfBytes": "32", "base": "t_struct(Pair)5_storage"},
                "t_struct(Pair)5_storage": {"label": "struct Shop.Pair", "encoding": "inplace", "numberOfBytes": "32", "members": [
                    {"label": "a", "slot": "0", "offset": 0, "type": "t_uint128"},
                    {"label": "b", "slot": "0", "offset": 16, "type": "t_uint128"}
                ]},
                "t_uint128": {"label": "uint128", "encoding": "inplace", "numberOfBytes": "16"}
            }
        }))
        .expect("layout");
        assert_eq!(
            super::storage_type_id(&layout, "Pair").as_deref(),
            Some("t_struct(Pair)5_storage")
        );
        assert_eq!(
            super::storage_type_id(&layout, "Shop.Pair[]").as_deref(),
            Some("t_array(t_struct(Pair)5_storage)dyn_storage")
        );
        assert_eq!(unqualified("struct Shop.Pair[]"), "Pair[]");
        assert_eq!(
            unqualified("mapping(address => struct A.B)"),
            "mapping(address => B)"
        );
        let types = SourceTypes::parse(SOURCE);
        let reader = ValueReader {
            layout: Some(&layout),
            ..reader(None, &types)
        };
        let value = reader.variable("Pair storage", &["0x5"]);
        assert_eq!(value.status, DebugValueStatus::Raw);
        assert_eq!(
            value.display,
            "<Pair in storage at slot 0x5; no storage was recorded>"
        );
    }
}
