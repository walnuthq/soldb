//! solc's storage layout: where every state variable lives and how it is encoded.
//!
//! `solc --storage-layout` (any release since 0.5.13, the legacy pipeline included) emits,
//! per contract, the slot, byte offset, and type of each state variable and a table of
//! the types with their encodings. That is compiler-issued fact, not inference, which is
//! why a debugger may read `counter`, `balances[0xabc]`, `config.owner`, or `items[2]`
//! from a storage snapshot without ETHDebug variable information: the slot arithmetic for
//! mappings, arrays, and structs is the language's own, fixed rule.
//!
//! [`StorageLayout::resolve`] turns a path into a slot and byte offset;
//! [`StorageLayout::decode`] turns the words at those slots into a value, reading each
//! word through a callback so the caller decides what "the storage at this step" means.
//! Nothing here reads a chain.

use std::collections::BTreeMap;

use serde_json::Value;

use soldb_core::{SoldbError, SoldbResult};

use crate::abi::keccak256;

/// A 256-bit storage word or slot number, big-endian.
pub type Word = [u8; 32];

/// The layout of one contract's storage as solc emitted it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageLayout {
    /// State variables in declaration order.
    pub variables: Vec<StorageVariable>,
    /// Types by solc's identifier, such as `t_uint256` or `t_mapping(t_address,t_uint256)`.
    pub types: BTreeMap<String, StorageType>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageVariable {
    pub label: String,
    pub slot: Word,
    /// Byte offset within the slot, counted from the least significant byte.
    pub offset: u64,
    pub type_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageEncoding {
    /// Stored in place, packed from the least significant byte of its slot.
    Inplace,
    /// Values live at `keccak256(key . slot)`.
    Mapping,
    /// The length at the slot, elements from `keccak256(slot)`.
    DynamicArray,
    /// A `bytes` or `string`: short values in the slot, long ones from `keccak256(slot)`.
    Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageType {
    /// The Solidity type as written, such as `uint256` or `mapping(address => uint256)`.
    pub label: String,
    pub encoding: StorageEncoding,
    pub number_of_bytes: u64,
    /// A mapping's key type.
    pub key: Option<String>,
    /// A mapping's value type.
    pub value: Option<String>,
    /// An array's element type.
    pub base: Option<String>,
    /// A struct's members.
    pub members: Vec<StorageMember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMember {
    pub label: String,
    /// Slot relative to the struct's first slot.
    pub slot: u64,
    pub offset: u64,
    pub type_id: String,
}

/// A resolved place in storage: what a path names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRef {
    /// The path as resolved, such as `balances[0xabc]`.
    pub path: String,
    pub slot: Word,
    pub offset: u64,
    pub type_id: String,
}

/// A value read out of storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedStorage {
    /// The value as the debugger shows it.
    pub display: String,
    /// The word the value came from, for value types, as `0x`-prefixed hex.
    pub raw: Option<String>,
}

impl StorageLayout {
    /// Parses the `<Contract>_storage.json` solc writes, or the `storageLayout` object of
    /// standard JSON output.
    pub fn parse(value: &Value) -> SoldbResult<Self> {
        let entries = value
            .get("storage")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                SoldbError::Message("storage layout has no `storage` array".to_owned())
            })?;
        let variables = entries
            .iter()
            .map(|entry| {
                Ok(StorageVariable {
                    label: text(entry, "label")?.to_owned(),
                    slot: parse_word(text(entry, "slot")?)?,
                    offset: number(entry, "offset")?,
                    type_id: text(entry, "type")?.to_owned(),
                })
            })
            .collect::<SoldbResult<Vec<_>>>()?;
        let types = value
            .get("types")
            .and_then(Value::as_object)
            .map(|types| {
                types
                    .iter()
                    .map(|(id, ty)| Ok((id.clone(), parse_type(ty)?)))
                    .collect::<SoldbResult<BTreeMap<_, _>>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(Self { variables, types })
    }

    #[must_use]
    pub fn variable(&self, label: &str) -> Option<&StorageVariable> {
        self.variables
            .iter()
            .find(|variable| variable.label == label)
    }

    #[must_use]
    pub fn type_of(&self, type_id: &str) -> Option<&StorageType> {
        self.types.get(type_id)
    }

    /// The type of a variable, when the layout describes it.
    pub fn variable_type(&self, variable: &StorageVariable) -> SoldbResult<&StorageType> {
        self.type_of(&variable.type_id).ok_or_else(|| {
            SoldbError::Message(format!(
                "storage layout does not describe type `{}` of `{}`",
                variable.type_id, variable.label
            ))
        })
    }

    /// Resolves a path to a place in storage: a variable, a mapping entry (`m[key]`), an
    /// array element (`a[i]`), a struct member (`s.member`), or any chain of those.
    pub fn resolve(&self, path: &str) -> SoldbResult<StorageRef> {
        let mut segments = parse_path(path)?.into_iter();
        let Some(PathSegment::Name(name)) = segments.next() else {
            return Err(SoldbError::Message(format!(
                "`{path}` does not start with a state variable name"
            )));
        };
        let variable = self.variable(&name).ok_or_else(|| {
            SoldbError::Message(format!(
                "no state variable named `{name}` in the storage layout"
            ))
        })?;
        let mut current = StorageRef {
            path: name.clone(),
            slot: variable.slot,
            offset: variable.offset,
            type_id: variable.type_id.clone(),
        };
        for segment in segments {
            current = self.step(current, segment)?;
        }
        Ok(current)
    }

    fn step(&self, current: StorageRef, segment: PathSegment) -> SoldbResult<StorageRef> {
        let ty = self.type_of(&current.type_id).ok_or_else(|| {
            SoldbError::Message(format!(
                "storage layout does not describe type `{}`",
                current.type_id
            ))
        })?;
        match segment {
            PathSegment::Index(key) => match ty.encoding {
                StorageEncoding::Mapping => {
                    let key_type_id = ty.key.as_deref().ok_or_else(|| {
                        SoldbError::Message(format!("mapping type `{}` has no key type", ty.label))
                    })?;
                    let key_type = self.type_of(key_type_id).ok_or_else(|| {
                        SoldbError::Message(format!(
                            "storage layout does not describe key type `{key_type_id}`"
                        ))
                    })?;
                    let value_type_id = ty.value.clone().ok_or_else(|| {
                        SoldbError::Message(format!(
                            "mapping type `{}` has no value type",
                            ty.label
                        ))
                    })?;
                    let slot = mapping_slot(&current.slot, &encode_mapping_key(&key, key_type)?);
                    Ok(StorageRef {
                        path: format!("{}[{key}]", current.path),
                        slot,
                        offset: 0,
                        type_id: value_type_id,
                    })
                }
                StorageEncoding::DynamicArray | StorageEncoding::Inplace if ty.base.is_some() => {
                    let index = parse_index(&key)?;
                    let base_id = ty.base.clone().expect("checked above");
                    let base = self.type_of(&base_id).ok_or_else(|| {
                        SoldbError::Message(format!(
                            "storage layout does not describe element type `{base_id}`"
                        ))
                    })?;
                    if ty.encoding == StorageEncoding::Inplace {
                        let length = static_array_length(&ty.label);
                        if length.is_some_and(|length| index >= length) {
                            return Err(SoldbError::Message(format!(
                                "index {index} is out of range for `{}` of type `{}`",
                                current.path, ty.label
                            )));
                        }
                    }
                    let first = match ty.encoding {
                        StorageEncoding::DynamicArray => keccak256(&current.slot),
                        _ => current.slot,
                    };
                    let (slot, offset) = element_place(&first, index, base.number_of_bytes);
                    Ok(StorageRef {
                        path: format!("{}[{index}]", current.path),
                        slot,
                        offset,
                        type_id: base_id,
                    })
                }
                _ => Err(SoldbError::Message(format!(
                    "`{}` is a `{}`, which cannot be indexed",
                    current.path, ty.label
                ))),
            },
            PathSegment::Member(member) => {
                if ty.members.is_empty() {
                    return Err(SoldbError::Message(format!(
                        "`{}` is a `{}`, which has no members",
                        current.path, ty.label
                    )));
                }
                let found = ty
                    .members
                    .iter()
                    .find(|candidate| candidate.label == member)
                    .ok_or_else(|| {
                        SoldbError::Message(format!(
                            "`{}` has no member `{member}`; it has {}",
                            ty.label,
                            ty.members
                                .iter()
                                .map(|member| member.label.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ))
                    })?;
                Ok(StorageRef {
                    path: format!("{}.{member}", current.path),
                    slot: add_word(&current.slot, found.slot),
                    offset: found.offset,
                    type_id: found.type_id.clone(),
                })
            }
            PathSegment::Name(name) => Err(SoldbError::Message(format!(
                "unexpected name `{name}` after `{}`",
                current.path
            ))),
        }
    }

    /// Decodes the value at `reference`, reading each storage word it needs through
    /// `read`. `Err` names the first slot whose word was not available.
    pub fn decode(
        &self,
        reference: &StorageRef,
        read: &dyn Fn(&Word) -> Option<Word>,
    ) -> Result<DecodedStorage, Word> {
        let Some(ty) = self.type_of(&reference.type_id) else {
            return Ok(DecodedStorage {
                display: format!(
                    "<type `{}` is not in the storage layout>",
                    reference.type_id
                ),
                raw: None,
            });
        };
        match ty.encoding {
            StorageEncoding::Mapping => Ok(DecodedStorage {
                display: "<mapping; index it with [key]>".to_owned(),
                raw: None,
            }),
            StorageEncoding::DynamicArray => {
                let length = read(&reference.slot).ok_or(reference.slot)?;
                Ok(DecodedStorage {
                    display: format!(
                        "<{} element(s); index it with [i]>",
                        word_to_decimal(&length)
                    ),
                    raw: Some(word_hex(&length)),
                })
            }
            StorageEncoding::Bytes => {
                let head = read(&reference.slot).ok_or(reference.slot)?;
                let bytes = if head[31] & 1 == 0 {
                    // Short: the data sits in the slot and the last byte is twice the length.
                    let length = usize::from(head[31] / 2);
                    head[..length.min(31)].to_vec()
                } else {
                    // Long: the slot holds twice the length plus one, the data follows
                    // keccak256(slot) word by word.
                    let length = usize::try_from(u128::from_be_bytes(
                        head[16..].try_into().expect("16 bytes"),
                    ))
                    .map(|doubled| doubled / 2)
                    .unwrap_or(usize::MAX);
                    let mut bytes = Vec::with_capacity(length.min(1 << 16));
                    let mut slot = keccak256(&reference.slot);
                    while bytes.len() < length {
                        let word = read(&slot).ok_or(slot)?;
                        let take = (length - bytes.len()).min(32);
                        bytes.extend_from_slice(&word[..take]);
                        slot = add_word(&slot, 1);
                    }
                    bytes
                };
                let display = if ty.label == "string" {
                    match std::str::from_utf8(&bytes) {
                        Ok(text) => format!("{text:?}"),
                        Err(_) => format!("0x{}", hex(&bytes)),
                    }
                } else {
                    format!("0x{}", hex(&bytes))
                };
                Ok(DecodedStorage {
                    display,
                    raw: Some(word_hex(&head)),
                })
            }
            StorageEncoding::Inplace if !ty.members.is_empty() => {
                let mut parts = Vec::with_capacity(ty.members.len());
                for member in &ty.members {
                    let inner = StorageRef {
                        path: format!("{}.{}", reference.path, member.label),
                        slot: add_word(&reference.slot, member.slot),
                        offset: member.offset,
                        type_id: member.type_id.clone(),
                    };
                    let value = self.decode(&inner, read)?;
                    parts.push(format!("{}: {}", member.label, value.display));
                }
                Ok(DecodedStorage {
                    display: format!("{{ {} }}", parts.join(", ")),
                    raw: None,
                })
            }
            StorageEncoding::Inplace if ty.base.is_some() => {
                let base_id = ty.base.as_deref().expect("checked above");
                let Some(base) = self.type_of(base_id) else {
                    return Ok(DecodedStorage {
                        display: format!("<element type `{base_id}` is not in the storage layout>"),
                        raw: None,
                    });
                };
                let length = static_array_length(&ty.label).unwrap_or(0);
                let shown = length.min(8);
                let mut parts = Vec::with_capacity(shown as usize);
                for index in 0..shown {
                    let (slot, offset) =
                        element_place(&reference.slot, index, base.number_of_bytes);
                    let inner = StorageRef {
                        path: format!("{}[{index}]", reference.path),
                        slot,
                        offset,
                        type_id: base_id.to_owned(),
                    };
                    parts.push(self.decode(&inner, read)?.display);
                }
                if length > shown {
                    parts.push(format!("... {} more", length - shown));
                }
                Ok(DecodedStorage {
                    display: format!("[{}]", parts.join(", ")),
                    raw: None,
                })
            }
            StorageEncoding::Inplace => {
                let word = read(&reference.slot).ok_or(reference.slot)?;
                let size = usize::try_from(ty.number_of_bytes)
                    .unwrap_or(32)
                    .clamp(1, 32);
                let offset = usize::try_from(reference.offset)
                    .unwrap_or(0)
                    .min(32 - size);
                let end = 32 - offset;
                let bytes = &word[end - size..end];
                Ok(DecodedStorage {
                    display: decode_value(bytes, &ty.label),
                    raw: Some(word_hex(&word)),
                })
            }
        }
    }
}

/// One step of a storage path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PathSegment {
    Name(String),
    Index(String),
    Member(String),
}

fn parse_path(path: &str) -> SoldbResult<Vec<PathSegment>> {
    let path = path.trim();
    let bytes = path.as_bytes();
    let mut segments = Vec::new();
    let mut index = 0;
    let identifier_end = |from: usize| {
        let mut end = from;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_' || bytes[end] == b'$')
        {
            end += 1;
        }
        end
    };
    let end = identifier_end(0);
    if end == 0 {
        return Err(SoldbError::Message(format!(
            "`{path}` does not start with a state variable name"
        )));
    }
    segments.push(PathSegment::Name(path[..end].to_owned()));
    index = end.max(index);
    while index < bytes.len() {
        match bytes[index] {
            b'[' => {
                let mut depth = 1;
                let mut close = index + 1;
                while close < bytes.len() && depth > 0 {
                    match bytes[close] {
                        b'[' => depth += 1,
                        b']' => depth -= 1,
                        _ => {}
                    }
                    close += 1;
                }
                if depth != 0 {
                    return Err(SoldbError::Message(format!("`{path}` has an unclosed `[`")));
                }
                let key = path[index + 1..close - 1].trim();
                if key.is_empty() {
                    return Err(SoldbError::Message(format!("`{path}` has an empty index")));
                }
                segments.push(PathSegment::Index(key.to_owned()));
                index = close;
            }
            b'.' => {
                let end = identifier_end(index + 1);
                if end == index + 1 {
                    return Err(SoldbError::Message(format!(
                        "`{path}` has a `.` with no member name after it"
                    )));
                }
                segments.push(PathSegment::Member(path[index + 1..end].to_owned()));
                index = end;
            }
            _ => {
                return Err(SoldbError::Message(format!(
                    "unexpected `{}` in `{path}`; use `name`, `name[key]`, or `name.member`",
                    &path[index..index + 1]
                )))
            }
        }
    }
    Ok(segments)
}

fn parse_type(value: &Value) -> SoldbResult<StorageType> {
    let encoding = match text(value, "encoding")? {
        "inplace" => StorageEncoding::Inplace,
        "mapping" => StorageEncoding::Mapping,
        "dynamic_array" => StorageEncoding::DynamicArray,
        "bytes" => StorageEncoding::Bytes,
        other => {
            return Err(SoldbError::Message(format!(
                "unknown storage encoding `{other}`"
            )))
        }
    };
    let members = value
        .get("members")
        .and_then(Value::as_array)
        .map(|members| {
            members
                .iter()
                .map(|member| {
                    Ok(StorageMember {
                        label: text(member, "label")?.to_owned(),
                        slot: text(member, "slot")?.parse::<u64>().map_err(|error| {
                            SoldbError::Message(format!("invalid member slot: {error}"))
                        })?,
                        offset: number(member, "offset")?,
                        type_id: text(member, "type")?.to_owned(),
                    })
                })
                .collect::<SoldbResult<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(StorageType {
        label: text(value, "label")?.to_owned(),
        encoding,
        number_of_bytes: text(value, "numberOfBytes")?
            .parse::<u64>()
            .map_err(|error| SoldbError::Message(format!("invalid numberOfBytes: {error}")))?,
        key: value.get("key").and_then(Value::as_str).map(str::to_owned),
        value: value
            .get("value")
            .and_then(Value::as_str)
            .map(str::to_owned),
        base: value.get("base").and_then(Value::as_str).map(str::to_owned),
        members,
    })
}

fn text<'a>(value: &'a Value, key: &str) -> SoldbResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| SoldbError::Message(format!("storage layout entry has no `{key}`")))
}

fn number(value: &Value, key: &str) -> SoldbResult<u64> {
    match value.get(key) {
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| SoldbError::Message(format!("`{key}` is not a whole number"))),
        Some(Value::String(text)) => text
            .parse::<u64>()
            .map_err(|error| SoldbError::Message(format!("invalid `{key}`: {error}"))),
        _ => Err(SoldbError::Message(format!(
            "storage layout entry has no `{key}`"
        ))),
    }
}

/// Parses a decimal or `0x` hex number into a word.
pub fn parse_word(text: &str) -> SoldbResult<Word> {
    let text = text.trim();
    let mut word = [0_u8; 32];
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        if hex.is_empty() || hex.len() > 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(SoldbError::Message(format!(
                "`{text}` is not a 256-bit hex number"
            )));
        }
        let padded = format!("{hex:0>64}");
        for (index, chunk) in padded.as_bytes().chunks(2).enumerate() {
            word[index] = u8::from_str_radix(std::str::from_utf8(chunk).expect("ascii"), 16)
                .expect("hex digits");
        }
        return Ok(word);
    }
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SoldbError::Message(format!(
            "`{text}` is not a decimal or `0x` hex number"
        )));
    }
    for digit in text.bytes() {
        // word = word * 10 + digit, big-endian with a carry.
        let mut carry = u32::from(digit - b'0');
        for byte in word.iter_mut().rev() {
            let value = u32::from(*byte) * 10 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        if carry != 0 {
            return Err(SoldbError::Message(format!(
                "`{text}` does not fit in 256 bits"
            )));
        }
    }
    Ok(word)
}

fn parse_index(text: &str) -> SoldbResult<u64> {
    let word = parse_word(text)?;
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(SoldbError::Message(format!("index `{text}` is too large")));
    }
    Ok(u64::from_be_bytes(word[24..].try_into().expect("8 bytes")))
}

/// The word a mapping key hashes as: value types padded to a word, `string` and `bytes`
/// as their raw bytes.
fn encode_mapping_key(key: &str, key_type: &StorageType) -> SoldbResult<Vec<u8>> {
    let label = key_type.label.as_str();
    if label == "string" {
        let text = key.trim().trim_matches('"');
        return Ok(text.as_bytes().to_vec());
    }
    if label == "bytes" {
        return hex_bytes(key.trim());
    }
    if label == "bool" {
        return match key.trim() {
            "true" | "1" => Ok(pad_left(&[1])),
            "false" | "0" => Ok([0_u8; 32].to_vec()),
            other => Err(SoldbError::Message(format!("`{other}` is not a bool key"))),
        };
    }
    if let Some(width) = label
        .strip_prefix("bytes")
        .and_then(|width| width.parse::<usize>().ok())
    {
        let bytes = hex_bytes(key.trim())?;
        if bytes.len() > width {
            return Err(SoldbError::Message(format!(
                "`{key}` is longer than {width} bytes"
            )));
        }
        let mut word = [0_u8; 32];
        word[..bytes.len()].copy_from_slice(&bytes);
        return Ok(word.to_vec());
    }
    if let Some(rest) = label.strip_prefix("int") {
        if rest.chars().all(|character| character.is_ascii_digit()) {
            return Ok(parse_signed_word(key.trim())?.to_vec());
        }
    }
    // Addresses, contracts, enums, and unsigned integers are all a number padded left.
    Ok(parse_word(key.trim())?.to_vec())
}

fn parse_signed_word(text: &str) -> SoldbResult<Word> {
    if let Some(magnitude) = text.strip_prefix('-') {
        let word = parse_word(magnitude)?;
        // Two's complement: invert and add one.
        let mut negated = [0_u8; 32];
        let mut carry = 1_u16;
        for (index, byte) in word.iter().enumerate().rev() {
            let value = u16::from(!byte) + carry;
            negated[index] = (value & 0xff) as u8;
            carry = value >> 8;
        }
        return Ok(negated);
    }
    parse_word(text)
}

fn pad_left(bytes: &[u8]) -> Vec<u8> {
    let mut word = [0_u8; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    word.to_vec()
}

fn hex_bytes(text: &str) -> SoldbResult<Vec<u8>> {
    let hex = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SoldbError::Message(format!("`{text}` is not hex bytes")));
    }
    Ok(hex
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            u8::from_str_radix(std::str::from_utf8(chunk).expect("ascii"), 16).expect("hex")
        })
        .collect())
}

/// `keccak256(key . slot)`, the slot of a mapping entry.
#[must_use]
pub fn mapping_slot(slot: &Word, key: &[u8]) -> Word {
    let mut input = Vec::with_capacity(key.len() + 32);
    input.extend_from_slice(key);
    input.extend_from_slice(slot);
    keccak256(&input)
}

/// Where element `index` of an array whose elements take `element_bytes` sits, counting
/// from `first`: small elements pack several to a slot, never straddling one; larger
/// elements take whole slots.
#[must_use]
pub fn element_place(first: &Word, index: u64, element_bytes: u64) -> (Word, u64) {
    let element_bytes = element_bytes.max(1);
    if element_bytes < 32 {
        let per_slot = 32 / element_bytes;
        (
            add_word(first, index / per_slot),
            (index % per_slot) * element_bytes,
        )
    } else {
        (add_word(first, index * element_bytes.div_ceil(32)), 0)
    }
}

/// `word + addend`, wrapping at 256 bits like the EVM does.
#[must_use]
pub fn add_word(word: &Word, addend: u64) -> Word {
    let mut result = *word;
    let mut carry = u128::from(addend);
    for byte in result.iter_mut().rev() {
        if carry == 0 {
            break;
        }
        let value = u128::from(*byte) + (carry & 0xff);
        *byte = (value & 0xff) as u8;
        carry = (carry >> 8) + (value >> 8);
    }
    result
}

/// The `N` of a static array label such as `uint256[3]` or `Item[2][4]`; `None` for
/// anything else.
fn static_array_length(label: &str) -> Option<u64> {
    let inner = label.strip_suffix(']')?;
    let open = inner.rfind('[')?;
    inner[open + 1..].parse::<u64>().ok()
}

/// Decodes the bytes of an in-place value by its Solidity type label.
#[must_use]
pub fn decode_value(bytes: &[u8], label: &str) -> String {
    if label == "bool" {
        return (bytes.iter().any(|byte| *byte != 0)).to_string();
    }
    if label == "address" || label == "address payable" || label.starts_with("contract ") {
        return format!("0x{}", hex(&bytes[bytes.len().saturating_sub(20)..]));
    }
    if label.starts_with("bytes") && label.len() > 5 {
        return format!("0x{}", hex(bytes));
    }
    if label.starts_with("int") {
        return signed_to_decimal(bytes);
    }
    if label.starts_with("uint") || label.starts_with("enum ") {
        return word_to_decimal(bytes);
    }
    format!("0x{}", hex(bytes))
}

/// A big-endian unsigned number as decimal text.
#[must_use]
pub fn word_to_decimal(bytes: &[u8]) -> String {
    let mut digits = Vec::new();
    let mut value = bytes.to_vec();
    while value.iter().any(|byte| *byte != 0) {
        let mut remainder = 0_u32;
        for byte in value.iter_mut() {
            let current = (remainder << 8) | u32::from(*byte);
            *byte = (current / 10) as u8;
            remainder = current % 10;
        }
        digits.push(b'0' + remainder as u8);
    }
    if digits.is_empty() {
        return "0".to_owned();
    }
    digits.reverse();
    String::from_utf8(digits).expect("ascii digits")
}

fn signed_to_decimal(bytes: &[u8]) -> String {
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        // Negative: negate the two's complement to get the magnitude.
        let mut magnitude = bytes.iter().map(|byte| !byte).collect::<Vec<_>>();
        let mut carry = 1_u16;
        for byte in magnitude.iter_mut().rev() {
            let value = u16::from(*byte) + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        return format!("-{}", word_to_decimal(&magnitude));
    }
    word_to_decimal(bytes)
}

/// A word as `0x`-prefixed hex.
#[must_use]
pub fn word_hex(word: &Word) -> String {
    format!("0x{}", hex(word))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::{
        add_word, decode_value, element_place, mapping_slot, parse_word, word_to_decimal,
        StorageEncoding, StorageLayout, Word,
    };
    use crate::abi::keccak256;

    fn layout() -> StorageLayout {
        StorageLayout::parse(&json!({
            "storage": [
                {"astId": 4, "contract": "T.sol:T", "label": "counter", "offset": 0, "slot": "0", "type": "t_uint256"},
                {"astId": 8, "contract": "T.sol:T", "label": "balances", "offset": 0, "slot": "1", "type": "t_mapping(t_address,t_uint256)"},
                {"astId": 9, "contract": "T.sol:T", "label": "flag", "offset": 0, "slot": "2", "type": "t_bool"},
                {"astId": 10, "contract": "T.sol:T", "label": "owner", "offset": 1, "slot": "2", "type": "t_address"},
                {"astId": 11, "contract": "T.sol:T", "label": "delta", "offset": 21, "slot": "2", "type": "t_int8"},
                {"astId": 12, "contract": "T.sol:T", "label": "name", "offset": 0, "slot": "3", "type": "t_string_storage"},
                {"astId": 13, "contract": "T.sol:T", "label": "items", "offset": 0, "slot": "4", "type": "t_array(t_uint256)dyn_storage"},
                {"astId": 14, "contract": "T.sol:T", "label": "config", "offset": 0, "slot": "5", "type": "t_struct(Config)15_storage"},
                {"astId": 16, "contract": "T.sol:T", "label": "small", "offset": 0, "slot": "7", "type": "t_array(t_uint8)3_storage"},
                {"astId": 17, "contract": "T.sol:T", "label": "names", "offset": 0, "slot": "8", "type": "t_mapping(t_string_memory_ptr,t_uint256)"}
            ],
            "types": {
                "t_uint256": {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"},
                "t_uint8": {"encoding": "inplace", "label": "uint8", "numberOfBytes": "1"},
                "t_int8": {"encoding": "inplace", "label": "int8", "numberOfBytes": "1"},
                "t_bool": {"encoding": "inplace", "label": "bool", "numberOfBytes": "1"},
                "t_address": {"encoding": "inplace", "label": "address", "numberOfBytes": "20"},
                "t_string_memory_ptr": {"encoding": "inplace", "label": "string", "numberOfBytes": "32"},
                "t_string_storage": {"encoding": "bytes", "label": "string", "numberOfBytes": "32"},
                "t_mapping(t_address,t_uint256)": {"encoding": "mapping", "key": "t_address", "label": "mapping(address => uint256)", "numberOfBytes": "32", "value": "t_uint256"},
                "t_mapping(t_string_memory_ptr,t_uint256)": {"encoding": "mapping", "key": "t_string_memory_ptr", "label": "mapping(string => uint256)", "numberOfBytes": "32", "value": "t_uint256"},
                "t_array(t_uint256)dyn_storage": {"encoding": "dynamic_array", "base": "t_uint256", "label": "uint256[]", "numberOfBytes": "32"},
                "t_array(t_uint8)3_storage": {"encoding": "inplace", "base": "t_uint8", "label": "uint8[3]", "numberOfBytes": "32"},
                "t_struct(Config)15_storage": {"encoding": "inplace", "label": "struct T.Config", "numberOfBytes": "64", "members": [
                    {"astId": 1, "contract": "T.sol:T", "label": "owner", "offset": 0, "slot": "0", "type": "t_address"},
                    {"astId": 2, "contract": "T.sol:T", "label": "limit", "offset": 0, "slot": "1", "type": "t_uint256"}
                ]}
            }
        }))
        .expect("layout")
    }

    fn word(number: u64) -> Word {
        let mut word = [0_u8; 32];
        word[24..].copy_from_slice(&number.to_be_bytes());
        word
    }

    fn storage(entries: &[(Word, Word)]) -> BTreeMap<Word, Word> {
        entries.iter().copied().collect()
    }

    #[test]
    fn parses_the_layout_solc_writes() {
        let layout = layout();
        assert_eq!(layout.variables.len(), 10);
        assert_eq!(layout.variable("balances").expect("balances").slot, word(1));
        assert_eq!(layout.variable("owner").expect("owner").offset, 1);
        let mapping = layout
            .type_of("t_mapping(t_address,t_uint256)")
            .expect("type");
        assert_eq!(mapping.encoding, StorageEncoding::Mapping);
        assert_eq!(mapping.key.as_deref(), Some("t_address"));
        assert_eq!(
            layout
                .type_of("t_struct(Config)15_storage")
                .expect("struct")
                .members
                .len(),
            2
        );
        assert!(StorageLayout::parse(&json!({"types": {}})).is_err());
    }

    #[test]
    fn resolves_variables_mappings_arrays_and_members() {
        let layout = layout();
        let counter = layout.resolve("counter").expect("counter");
        assert_eq!((counter.slot, counter.offset), (word(0), 0));

        let key = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        let entry = layout.resolve(&format!("balances[{key}]")).expect("entry");
        let mut padded = [0_u8; 32];
        padded[12..].copy_from_slice(&[
            0xf3, 0x9f, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xf6, 0xf4, 0xce, 0x6a, 0xb8, 0x82, 0x72,
            0x79, 0xcf, 0xff, 0xb9, 0x22, 0x66,
        ]);
        assert_eq!(entry.slot, mapping_slot(&word(1), &padded));
        assert_eq!(entry.type_id, "t_uint256");
        assert_eq!(entry.path, format!("balances[{key}]"));
        // Mixed-case and checksummed keys hash the same.
        assert_eq!(
            layout
                .resolve("balances[0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266]")
                .expect("entry")
                .slot,
            entry.slot
        );

        // A string key hashes its bytes, not a padded word.
        let by_name = layout.resolve("names[\"alice\"]").expect("string key");
        assert_eq!(by_name.slot, mapping_slot(&word(8), b"alice"));

        // Dynamic array elements start at keccak256(slot).
        let second = layout.resolve("items[1]").expect("items[1]");
        assert_eq!(second.slot, add_word(&keccak256(&word(4)), 1));
        // Small static-array elements pack into one slot, least significant first.
        let third = layout.resolve("small[2]").expect("small[2]");
        assert_eq!((third.slot, third.offset), (word(7), 2));
        assert!(layout.resolve("small[3]").is_err());

        let limit = layout.resolve("config.limit").expect("member");
        assert_eq!(
            (limit.slot, limit.offset, limit.type_id.as_str()),
            (word(6), 0, "t_uint256")
        );

        for bad in [
            "missing",
            "counter[1]",
            "counter.x",
            "config.nothing",
            "balances",
            "items[",
            "counter+1",
            "balances[]",
        ] {
            let outcome = layout.resolve(bad);
            if bad == "balances" {
                assert!(outcome.is_ok());
            } else {
                assert!(outcome.is_err(), "{bad}");
            }
        }
    }

    #[test]
    fn decodes_values_from_storage_words() {
        let layout = layout();
        let mut packed = [0_u8; 32];
        packed[31] = 1; // flag = true at offset 0
        packed[11..31].copy_from_slice(&[0xab; 20]); // owner at offset 1
        packed[10] = 0xfe; // delta = -2 at offset 21
        let long_text = "a string that is longer than thirty-one bytes, so it lives elsewhere";
        let mut long_head = [0_u8; 32];
        long_head[31] = (long_text.len() as u8) * 2 + 1;
        let data_slot = keccak256(&word(3));
        let mut words = storage(&[
            (word(0), word(42)),
            (word(2), packed),
            (word(3), long_head),
            (word(4), word(2)),
            (add_word(&keccak256(&word(4)), 1), word(7)),
            (word(5), {
                let mut owner = [0_u8; 32];
                owner[12..].copy_from_slice(&[0x11; 20]);
                owner
            }),
            (word(6), word(99)),
            (word(7), {
                let mut small = [0_u8; 32];
                small[31] = 1;
                small[30] = 2;
                small[29] = 3;
                small
            }),
        ]);
        for (index, chunk) in long_text.as_bytes().chunks(32).enumerate() {
            let mut piece = [0_u8; 32];
            piece[..chunk.len()].copy_from_slice(chunk);
            words.insert(add_word(&data_slot, index as u64), piece);
        }
        let read = |slot: &Word| words.get(slot).copied();
        let show = |path: &str| {
            layout
                .decode(&layout.resolve(path).expect(path), &read)
                .map(|value| value.display)
        };

        assert_eq!(show("counter"), Ok("42".to_owned()));
        assert_eq!(show("flag"), Ok("true".to_owned()));
        assert_eq!(show("owner"), Ok(format!("0x{}", "ab".repeat(20))));
        assert_eq!(show("delta"), Ok("-2".to_owned()));
        assert_eq!(show("name"), Ok(format!("{long_text:?}")));
        assert_eq!(
            show("items"),
            Ok("<2 element(s); index it with [i]>".to_owned())
        );
        assert_eq!(show("items[1]"), Ok("7".to_owned()));
        assert_eq!(
            show("config"),
            Ok(format!("{{ owner: 0x{}, limit: 99 }}", "11".repeat(20)))
        );
        assert_eq!(show("small"), Ok("[1, 2, 3]".to_owned()));
        assert_eq!(
            show("balances"),
            Ok("<mapping; index it with [key]>".to_owned())
        );
        // A word the snapshot does not hold is reported by slot.
        assert_eq!(show("items[0]"), Err(keccak256(&word(4))));

        // A short string sits in its own slot.
        let mut short = [0_u8; 32];
        short[..5].copy_from_slice(b"hello");
        short[31] = 10;
        let words = storage(&[(word(3), short)]);
        let read = |slot: &Word| words.get(slot).copied();
        assert_eq!(
            layout
                .decode(&layout.resolve("name").expect("name"), &read)
                .map(|value| value.display),
            Ok("\"hello\"".to_owned())
        );
    }

    #[test]
    fn number_helpers_handle_256_bits() {
        assert_eq!(parse_word("255").expect("decimal"), word(255));
        assert_eq!(parse_word("0xff").expect("hex"), word(255));
        assert_eq!(
            word_to_decimal(&[0xff; 32]),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
        assert_eq!(word_to_decimal(&[0; 32]), "0");
        assert!(parse_word("1e3").is_err());
        assert!(parse_word("").is_err());
        let mut max = [0xff_u8; 32];
        assert_eq!(add_word(&max, 1), [0_u8; 32]);
        max[31] = 0xfe;
        assert_eq!(add_word(&max, 1), [0xff_u8; 32]);
        assert_eq!(element_place(&word(10), 5, 32), (word(15), 0));
        assert_eq!(element_place(&word(10), 5, 64), (word(20), 0));
        assert_eq!(element_place(&word(10), 33, 1), (word(11), 1));
        assert_eq!(decode_value(&[0x80], "int8"), "-128");
        assert_eq!(decode_value(&[0x7f], "int8"), "127");
        assert_eq!(decode_value(&[0x01, 0x02], "bytes2"), "0x0102");
        assert_eq!(decode_value(&[0x02], "enum T.Kind"), "2");
    }
}
