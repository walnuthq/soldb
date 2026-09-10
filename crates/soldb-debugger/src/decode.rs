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
//! A path such as `item.tags[1]` or `stored.owners[0xabc]` is followed the same way, one
//! segment at a time, from the variable's [`Place`] to the place it names.
//!
//! What cannot be read says so rather than printing a pointer as a number: memory the
//! backend did not capture, a slot the frame never touched, a struct whose declaration
//! is not in the loaded sources.

use soldb_ethdebug::{
    decode_value, parse_word, word_hex, PathSegment, StorageEncoding, StorageLayout, StorageRef,
    Word,
};

use crate::condition::Value;
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
    /// The contract whose code declares the variables read, which is where a bare type
    /// name such as `Item` resolves.
    pub scope: Option<&'a str>,
}

/// Where a value is, as far as a path has been followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Place {
    /// One word holding a value: a value type, an enum, a user-defined value type, or a
    /// contract.
    Word { word: Word, ty: String },
    /// A value in memory, starting at `pointer`.
    Memory { pointer: usize, ty: String },
    /// A place in storage, as the storage layout describes it.
    Storage { reference: StorageRef, ty: String },
    /// A value in calldata: a slice of `length` elements or bytes, or a fixed-size value
    /// at `offset`.
    Calldata {
        offset: usize,
        length: Option<usize>,
        ty: String,
    },
}

impl Place {
    /// The declared type of the value here, as it is shown.
    pub(crate) fn ty(&self) -> String {
        match self {
            Self::Word { ty, .. } => ty.clone(),
            Self::Memory { ty, .. } => format!("{ty} memory"),
            Self::Storage { ty, .. } => format!("{ty} storage"),
            Self::Calldata { ty, .. } => format!("{ty} calldata"),
        }
    }
}

impl<'a> ValueReader<'a> {
    /// The value of a variable declared as `ty` (with its data location, such as
    /// `uint256[] memory`) whose stack words are `words`, bottom first.
    pub(crate) fn variable(&self, ty: &str, words: &[&str]) -> DebugValue {
        match self.root(ty, words) {
            Ok(place) => self.show(&place),
            Err(shown) => shown,
        }
    }

    /// Where a variable declared as `ty` with the stack words `words` lives, or the value
    /// to show when the words do not lead anywhere readable.
    pub(crate) fn root(&self, ty: &str, words: &[&str]) -> Result<Place, DebugValue> {
        let (base, location) = split_location(ty);
        let Some(first) = words.first() else {
            return Err(unavailable());
        };
        let parsed = parse_word(&normalize_hex(first)).map_err(|_| unreadable(first))?;
        match location {
            Some("memory") => match word_as_usize(&parsed) {
                Some(pointer) => Ok(Place::Memory {
                    pointer,
                    ty: base.to_owned(),
                }),
                None => Err(DebugValue {
                    display: format!("<{base} at {}>", short_hex(&parsed)),
                    raw: Some(short_hex(&parsed)),
                    status: DebugValueStatus::Raw,
                }),
            },
            Some("storage") => {
                let raw = Some(short_hex(&parsed));
                let placeholder = |reason: &str| DebugValue {
                    display: format!("<{base} in storage at slot {}{reason}>", short_hex(&parsed)),
                    raw: raw.clone(),
                    status: DebugValueStatus::Raw,
                };
                let Some(layout) = self.layout else {
                    return Err(placeholder("; no storage layout is loaded"));
                };
                let Some(type_id) = storage_type_id(layout, base) else {
                    return Err(placeholder("; the storage layout has no such type"));
                };
                Ok(Place::Storage {
                    reference: StorageRef {
                        path: base.to_owned(),
                        slot: parsed,
                        offset: 0,
                        type_id,
                    },
                    ty: base.to_owned(),
                })
            }
            Some("calldata") => {
                let offset = word_as_usize(&parsed).ok_or_else(unavailable)?;
                let length = match words {
                    [_, length] => Some(
                        usize::from_str_radix(length.trim_start_matches("0x"), 16)
                            .map_err(|_| unavailable())?,
                    ),
                    [_] => None,
                    _ => return Err(unavailable()),
                };
                Ok(Place::Calldata {
                    offset,
                    length,
                    ty: base.to_owned(),
                })
            }
            _ => Ok(Place::Word {
                word: parsed,
                ty: base.to_owned(),
            }),
        }
    }

    /// The place one path segment names from `place`: a member, an element, a mapping
    /// entry, or `length`. `path` is what has been followed so far, for the messages.
    pub(crate) fn follow(
        &self,
        place: Place,
        segment: &PathSegment,
        path: &str,
    ) -> Result<Place, String> {
        match (place, segment) {
            (_, PathSegment::Name(name)) => Err(format!("unexpected name `{name}` after `{path}`")),
            (Place::Word { ty, .. }, PathSegment::Member(member)) => Err(format!(
                "`{path}` is a `{ty}`, which has no member `{member}`"
            )),
            (Place::Word { ty, .. }, PathSegment::Index(_)) => {
                Err(format!("`{path}` is a `{ty}`, which cannot be indexed"))
            }
            (Place::Memory { pointer, ty }, PathSegment::Member(member)) => {
                if member == "length" {
                    if let Some(count) = self.memory_length(pointer, &ty)? {
                        return Ok(Place::Word {
                            word: word_of_usize(count),
                            ty: "uint256".to_owned(),
                        });
                    }
                }
                let Some(members) = self.types.struct_members(self.scope, &ty) else {
                    return Err(format!(
                        "`{path}` is a `{ty} memory`, which has no member `{member}`"
                    ));
                };
                let Some((index, found)) = members
                    .iter()
                    .enumerate()
                    .find(|(_, candidate)| candidate.name == *member)
                else {
                    return Err(format!(
                        "`{ty}` has no member `{member}`; it has {}",
                        members
                            .iter()
                            .map(|member| member.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                };
                let word = self.memory_word_at(pointer, index, path)?;
                Ok(self.memory_element(word, &found.ty))
            }
            (Place::Memory { pointer, ty }, PathSegment::Index(key)) => {
                let index = parse_index(key)?;
                if ty == "bytes" || ty == "string" {
                    let length = self.memory_length(pointer, &ty)?.unwrap_or(0);
                    if index >= length {
                        return Err(format!(
                            "index {index} is out of range; `{path}` has {length} bytes"
                        ));
                    }
                    let memory = self.memory.ok_or_else(|| no_memory(path))?;
                    let byte = memory_bytes(memory, pointer + 32 + index, 1)
                        .ok_or_else(|| beyond_memory(path))?;
                    let mut word = [0_u8; 32];
                    word[0] = byte[0];
                    return Ok(Place::Word {
                        word,
                        ty: "bytes1".to_owned(),
                    });
                }
                let Some((element, count)) = array_shape(&ty) else {
                    return Err(format!(
                        "`{path}` is a `{ty} memory`, which cannot be indexed"
                    ));
                };
                let (first, count) = match count {
                    None => (pointer + 32, self.memory_length(pointer, &ty)?.unwrap_or(0)),
                    Some(count) => (pointer, count),
                };
                if index >= count {
                    return Err(format!(
                        "index {index} is out of range; `{path}` has {count} elements"
                    ));
                }
                let word = self.memory_word_at(first, index, path)?;
                Ok(self.memory_element(word, element))
            }
            (Place::Storage { reference, ty }, PathSegment::Member(member))
                if member == "length" =>
            {
                let layout = self.layout.ok_or("no storage layout is loaded")?;
                let encoding = layout
                    .type_of(&reference.type_id)
                    .map(|storage_type| storage_type.encoding);
                let words = self.storage.ok_or_else(|| {
                    format!("no storage was recorded, so `{path}` cannot be read")
                })?;
                let head = words
                    .get(&reference.slot)
                    .or_else(|| words.chain_word(&reference.slot))
                    .ok_or_else(|| format!("`{path}` is {}", words.unavailable(&reference.slot)))?;
                let length = match encoding {
                    Some(StorageEncoding::DynamicArray) => head,
                    Some(StorageEncoding::Bytes) => bytes_length(&head),
                    _ => {
                        return Err(format!(
                            "`{path}` is a `{ty} storage`, which has no member `length`"
                        ))
                    }
                };
                Ok(Place::Word {
                    word: length,
                    ty: "uint256".to_owned(),
                })
            }
            (Place::Storage { reference, .. }, segment) => {
                let layout = self.layout.ok_or("no storage layout is loaded")?;
                let reference = layout
                    .walk(reference, [segment.clone()])
                    .map_err(|error| error.to_string())?;
                let ty = layout
                    .type_of(&reference.type_id)
                    .map_or_else(|| reference.type_id.clone(), |ty| ty.label.clone());
                Ok(Place::Storage { reference, ty })
            }
            (
                Place::Calldata {
                    length: Some(length),
                    ..
                },
                PathSegment::Member(member),
            ) if member == "length" => Ok(Place::Word {
                word: word_of_usize(length),
                ty: "uint256".to_owned(),
            }),
            (
                Place::Calldata {
                    offset,
                    length: Some(length),
                    ty,
                },
                PathSegment::Index(key),
            ) => {
                let index = parse_index(key)?;
                if index >= length {
                    return Err(format!(
                        "index {index} is out of range; `{path}` has {length} {}",
                        if ty == "bytes" || ty == "string" {
                            "bytes"
                        } else {
                            "elements"
                        }
                    ));
                }
                if ty == "bytes" || ty == "string" {
                    let byte = self
                        .calldata_bytes(offset + index, 1)
                        .ok_or_else(|| beyond_calldata(path))?;
                    let mut word = [0_u8; 32];
                    word[0] = byte[0];
                    return Ok(Place::Word {
                        word,
                        ty: "bytes1".to_owned(),
                    });
                }
                let element = ty.strip_suffix("[]").ok_or_else(|| {
                    format!("`{path}` is a `{ty} calldata`, which cannot be indexed")
                })?;
                self.calldata_element(offset + index * 32, element, path)
            }
            (
                Place::Calldata {
                    offset,
                    length: None,
                    ty,
                },
                PathSegment::Index(key),
            ) => {
                let index = parse_index(key)?;
                let Some((element, Some(count))) = array_shape(&ty) else {
                    return Err(format!(
                        "`{path}` is a `{ty} calldata`, which cannot be indexed"
                    ));
                };
                if index >= count {
                    return Err(format!(
                        "index {index} is out of range; `{path}` has {count} elements"
                    ));
                }
                self.calldata_element(offset + index * 32, element, path)
            }
            (
                Place::Calldata {
                    offset,
                    length: None,
                    ty,
                },
                PathSegment::Member(member),
            ) => {
                let Some(members) = self.types.struct_members(self.scope, &ty) else {
                    return Err(format!(
                        "`{path}` is a `{ty} calldata`, which has no member `{member}`"
                    ));
                };
                let Some((index, found)) = members
                    .iter()
                    .enumerate()
                    .find(|(_, candidate)| candidate.name == *member)
                else {
                    return Err(format!(
                        "`{ty}` has no member `{member}`; it has {}",
                        members
                            .iter()
                            .map(|member| member.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                };
                if members.iter().any(|member| self.is_reference(&member.ty)) {
                    return Err(format!(
                        "`{path}` is a `{ty} calldata` with dynamic members, whose layout is not followed"
                    ));
                }
                self.calldata_element(offset + index * 32, &found.ty, path)
            }
            (Place::Calldata { ty, .. }, PathSegment::Member(member)) => Err(format!(
                "`{path}` is a `{ty} calldata`, which has no member `{member}`"
            )),
        }
    }

    /// The value at `place`, decoded by its type.
    pub(crate) fn show(&self, place: &Place) -> DebugValue {
        match place {
            Place::Word { word, ty } => self.value_word(&word_hex(word), ty),
            Place::Memory { pointer, ty } => {
                let raw = Some(format!("{pointer:#x}"));
                let display = match self.memory {
                    Some(_) => self.read_memory(*pointer, ty, 0).unwrap_or_else(|| {
                        format!("<{ty} in memory at {pointer:#x}, beyond what this step captured>")
                    }),
                    None => {
                        format!("<{ty} in memory at {pointer:#x}; this backend captured no memory>")
                    }
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
            Place::Storage { reference, ty } => self.storage_value(reference, ty),
            Place::Calldata {
                offset,
                length: Some(length),
                ty,
            } => self.calldata_slice(ty, *offset, *length),
            Place::Calldata {
                offset,
                length: None,
                ty,
            } => self.calldata_static(*offset, ty),
        }
    }

    /// The value at `place` as a breakpoint condition compares it: a value type as its
    /// word, a `string` as its text, a `bytes` as its hex text.
    pub(crate) fn condition_value(&self, place: &Place, path: &str) -> Result<Value, String> {
        match place {
            Place::Word { word, ty } => {
                let ty = self.resolve_value_type(ty);
                if ty == "bool" {
                    return Ok(Value::Bool(*word != [0_u8; 32]));
                }
                Ok(Value::Word(*word, ty.starts_with("int")))
            }
            Place::Memory { pointer, ty } if ty == "string" || ty == "bytes" => {
                let memory = self.memory.ok_or_else(|| no_memory(path))?;
                let bytes = word_as_usize(
                    &memory_word(memory, *pointer).ok_or_else(|| beyond_memory(path))?,
                )
                .and_then(|length| memory_bytes(memory, pointer + 32, length))
                .ok_or_else(|| beyond_memory(path))?;
                text_value(bytes, ty, path)
            }
            Place::Calldata {
                offset,
                length: Some(length),
                ty,
            } if ty == "string" || ty == "bytes" => {
                let bytes = self
                    .calldata_bytes(*offset, *length)
                    .ok_or_else(|| beyond_calldata(path))?;
                text_value(bytes, ty, path)
            }
            Place::Storage { reference, ty } => {
                let value = self.storage_value(reference, ty);
                if value.status == DebugValueStatus::Unavailable {
                    return Err(format!("`{path}` is {}", value.display));
                }
                if ty == "string" {
                    return Ok(Value::Text(
                        value
                            .display
                            .strip_prefix('"')
                            .and_then(|text| text.strip_suffix('"'))
                            .unwrap_or(&value.display)
                            .to_owned(),
                    ));
                }
                if ty == "bytes" {
                    return Ok(Value::Text(value.display));
                }
                let raw = value.raw.as_deref().ok_or_else(|| {
                    format!("`{path}` is a `{ty}`, which a condition cannot compare")
                })?;
                let word = parse_word(raw).map_err(|error| error.to_string())?;
                if ty == "bool" {
                    return Ok(Value::Bool(word != [0_u8; 32]));
                }
                Ok(Value::Word(word, ty.starts_with("int")))
            }
            other => Err(format!(
                "`{path}` is a `{}`, which a condition cannot compare",
                other.ty()
            )),
        }
    }

    /// A one-word value: a value type, an enum, a user-defined value type, or a contract.
    pub(crate) fn value_word(&self, word: &str, ty: &str) -> DebugValue {
        let ty = self.resolve_value_type(ty);
        let normalized = normalize_hex(word);
        let digits = normalized.trim_start_matches("0x");
        let raw = Some(normalized.clone());
        if let Some(variants) = self.types.enum_variants(self.scope, ty) {
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
            match self.types.underlying(self.scope, ty) {
                Some(underlying) => ty = underlying,
                None => break,
            }
        }
        ty
    }

    /// Whether a value of `ty` lives behind a pointer rather than in its own word.
    fn is_reference(&self, ty: &str) -> bool {
        ty == "bytes" || ty == "string" || ty.ends_with(']') || self.types.is_struct(self.scope, ty)
    }

    /// The element count of a memory array, the byte count of a memory `bytes` or
    /// `string`, or `None` for a type without a length.
    fn memory_length(&self, pointer: usize, ty: &str) -> Result<Option<usize>, String> {
        if ty == "bytes" || ty == "string" || ty.ends_with("[]") {
            let memory = self.memory.ok_or_else(|| no_memory(ty))?;
            let word = memory_word(memory, pointer).ok_or_else(|| beyond_memory(ty))?;
            return Ok(Some(
                word_as_usize(&word).ok_or_else(|| format!("`{ty}` has an unreadable length"))?,
            ));
        }
        Ok(array_shape(ty).and_then(|(_, count)| count))
    }

    /// The `index`th word from `base` in memory.
    fn memory_word_at(&self, base: usize, index: usize, path: &str) -> Result<Word, String> {
        let memory = self.memory.ok_or_else(|| no_memory(path))?;
        base.checked_add(index.saturating_mul(32))
            .and_then(|offset| memory_word(memory, offset))
            .ok_or_else(|| beyond_memory(path))
    }

    /// The place a word of a memory array or struct names: the value, or what the
    /// pointer refers to.
    fn memory_element(&self, word: Word, ty: &str) -> Place {
        if self.is_reference(ty) {
            if let Some(pointer) = word_as_usize(&word) {
                return Place::Memory {
                    pointer,
                    ty: ty.to_owned(),
                };
            }
        }
        Place::Word {
            word,
            ty: ty.to_owned(),
        }
    }

    /// A value of `ty` at `offset` of the calldata: a word for a value type.
    fn calldata_element(&self, offset: usize, ty: &str, path: &str) -> Result<Place, String> {
        if self.is_reference(ty) {
            return Err(format!(
                "`{path}` holds `{ty}` values, which are not followed through calldata"
            ));
        }
        let bytes = self
            .calldata_bytes(offset, 32)
            .ok_or_else(|| beyond_calldata(path))?;
        let mut word = [0_u8; 32];
        word.copy_from_slice(&bytes);
        Ok(Place::Word {
            word,
            ty: ty.to_owned(),
        })
    }

    fn calldata_bytes(&self, offset: usize, length: usize) -> Option<Vec<u8>> {
        memory_bytes(self.calldata.trim_start_matches("0x"), offset, length)
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
                parts.push(self.memory_element_display(&word, element, depth));
            }
            if count > shown {
                parts.push(format!("... {} more", count - shown));
            }
            return Some(format!("[{}]", parts.join(", ")));
        }
        if let Some(members) = self.types.struct_members(self.scope, ty) {
            let mut parts = Vec::with_capacity(members.len());
            for (index, member) in members.iter().enumerate() {
                let word = memory_word(memory, pointer.checked_add(index.checked_mul(32)?)?)?;
                parts.push(format!(
                    "{}: {}",
                    member.name,
                    self.memory_element_display(&word, &member.ty, depth)
                ));
            }
            return Some(format!("{{ {} }}", parts.join(", ")));
        }
        None
    }

    /// One word of a memory array or struct: the value, or the value behind the pointer.
    fn memory_element_display(&self, word: &Word, ty: &str, depth: usize) -> String {
        if self.is_reference(ty) {
            let pointer = word_as_usize(word);
            return pointer
                .and_then(|pointer| self.read_memory(pointer, ty, depth + 1))
                .unwrap_or_else(|| format!("<{ty} at {}>", short_hex(word)));
        }
        self.value_word(&word_hex(word), ty).display
    }

    fn storage_value(&self, reference: &StorageRef, ty: &str) -> DebugValue {
        let raw = Some(short_hex(&reference.slot));
        let placeholder = |reason: &str| DebugValue {
            display: format!(
                "<{ty} in storage at slot {}{reason}>",
                short_hex(&reference.slot)
            ),
            raw: raw.clone(),
            status: DebugValueStatus::Raw,
        };
        let Some(layout) = self.layout else {
            return placeholder("; no storage layout is loaded");
        };
        let Some(words) = self.storage else {
            return placeholder("; no storage was recorded");
        };
        match layout.decode(reference, &|slot| {
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
    fn calldata_slice(&self, ty: &str, offset: usize, length: usize) -> DebugValue {
        if ty == "bytes" || ty == "string" {
            let Some(bytes) = self.calldata_bytes(offset, length) else {
                return unavailable();
            };
            let raw = format!("0x{}", hex_of(&bytes));
            let display = if ty == "string" {
                match String::from_utf8(bytes) {
                    Ok(text) if text.chars().all(|character| !character.is_control()) => {
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
            let Some(bytes) = self.calldata_bytes(offset + index * 32, 32) else {
                return unavailable();
            };
            elements.push(
                self.value_word(&format!("0x{}", hex_of(&bytes)), element)
                    .display,
            );
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
    fn calldata_static(&self, offset: usize, ty: &str) -> DebugValue {
        let word_at = |index: usize| -> Option<String> {
            self.calldata_bytes(offset + index * 32, 32)
                .map(|bytes| format!("0x{}", hex_of(&bytes)))
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
        if let Some(members) = self.types.struct_members(self.scope, ty) {
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

/// A `string` as its text and a `bytes` as its hex, for a condition.
fn text_value(bytes: Vec<u8>, ty: &str, path: &str) -> Result<Value, String> {
    if ty == "string" {
        return String::from_utf8(bytes)
            .map(Value::Text)
            .map_err(|_| format!("`{path}` is not valid UTF-8 text"));
    }
    Ok(Value::Text(format!("0x{}", hex_of(&bytes))))
}

/// The byte length a `bytes` or `string` storage head word encodes.
fn bytes_length(head: &Word) -> Word {
    let length = if head[31] & 1 == 0 {
        u128::from(head[31] / 2)
    } else {
        u128::from_be_bytes(head[16..].try_into().expect("16 bytes")) / 2
    };
    let mut word = [0_u8; 32];
    word[16..].copy_from_slice(&length.to_be_bytes());
    word
}

/// A decimal or `0x` index as a number.
fn parse_index(key: &str) -> Result<usize, String> {
    let word = parse_word(key).map_err(|error| error.to_string())?;
    word_as_usize(&word).ok_or_else(|| format!("index `{key}` is too large"))
}

fn word_of_usize(value: usize) -> Word {
    let mut word = [0_u8; 32];
    word[24..].copy_from_slice(&(value as u64).to_be_bytes());
    word
}

fn no_memory(path: &str) -> String {
    format!("`{path}` lives in memory, which this backend did not capture")
}

fn beyond_memory(path: &str) -> String {
    format!("`{path}` points beyond the memory this step captured")
}

fn beyond_calldata(path: &str) -> String {
    format!("`{path}` points beyond the frame's calldata")
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
    use soldb_ethdebug::{parse_path, StorageLayout};

    use super::{split_location, unqualified, Place, ValueReader};
    use crate::condition::Value;
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
            scope: None,
        }
    }

    /// Follows `path` from the variable `ty` with the words `words`.
    fn at(reader: &ValueReader<'_>, ty: &str, words: &[&str], path: &str) -> Result<Place, String> {
        let segments = parse_path(path).map_err(|error| error.to_string())?;
        let mut place = reader.root(ty, words).map_err(|shown| shown.display)?;
        let mut followed = segments[0].clone();
        let mut so_far = match &followed {
            soldb_ethdebug::PathSegment::Name(name) => name.clone(),
            _ => unreachable!(),
        };
        for segment in &segments[1..] {
            place = reader.follow(place, segment, &so_far)?;
            followed = segment.clone();
            so_far = match &followed {
                soldb_ethdebug::PathSegment::Member(member) => format!("{so_far}.{member}"),
                soldb_ethdebug::PathSegment::Index(key) => format!("{so_far}[{key}]"),
                soldb_ethdebug::PathSegment::Name(_) => so_far,
            };
        }
        Ok(place)
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
    fn paths_follow_members_elements_and_lengths_through_memory() {
        let types = SourceTypes::parse(SOURCE);
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
        memory.push_str(&word(1));
        memory.push_str(&word(0x80));
        let reader = reader(Some(&memory), &types);
        let show = |path: &str| -> Result<String, String> {
            at(&reader, "Item memory", &["0x80"], path).map(|place| reader.show(&place).display)
        };
        assert_eq!(show("item.id").as_deref(), Ok("7"));
        assert_eq!(show("item.color").as_deref(), Ok("Color.Blue"));
        assert_eq!(show("item.name").as_deref(), Ok("\"hi\""));
        assert_eq!(show("item.name.length").as_deref(), Ok("2"));
        assert_eq!(show("item.name[1]").as_deref(), Ok("0x69"));
        assert_eq!(show("item.tags").as_deref(), Ok("[3, 4]"));
        assert_eq!(show("item.tags[1]").as_deref(), Ok("4"));
        assert_eq!(show("item.tags.length").as_deref(), Ok("2"));
        assert_eq!(
            show("item.tags[2]").unwrap_err(),
            "index 2 is out of range; `item.tags` has 2 elements"
        );
        assert_eq!(
            show("item.nothing").unwrap_err(),
            "`Item` has no member `nothing`; it has id, name, color, tags"
        );
        assert_eq!(
            show("item.id.x").unwrap_err(),
            "`item.id` is a `uint256`, which has no member `x`"
        );
        let items = |path: &str| -> Result<String, String> {
            at(&reader, "Item[] memory", &["0x1a0"], path).map(|place| reader.show(&place).display)
        };
        assert_eq!(items("items[0].tags[0]").as_deref(), Ok("3"));
        assert_eq!(items("items.length").as_deref(), Ok("1"));
        // Conditions read the same places.
        let value = |path: &str| -> Result<Value, String> {
            at(&reader, "Item memory", &["0x80"], path)
                .and_then(|place| reader.condition_value(&place, path))
        };
        assert_eq!(value("item.name"), Ok(Value::Text("hi".to_owned())));
        let mut seven = [0_u8; 32];
        seven[31] = 7;
        assert_eq!(value("item.id"), Ok(Value::Word(seven, false)));
        assert_eq!(
            value("item.tags").unwrap_err(),
            "`item.tags` is a `uint256[] memory`, which a condition cannot compare"
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
        let show = |ty: &str, words: &[&str], path: &str| -> Result<String, String> {
            at(&reader, ty, words, path).map(|place| reader.show(&place).display)
        };
        assert_eq!(
            show("Color[] calldata", &["0x20", "0x2"], "xs[0]").as_deref(),
            Ok("Color.Blue")
        );
        assert_eq!(
            show("Color[] calldata", &["0x20", "0x2"], "xs.length").as_deref(),
            Ok("2")
        );
        assert_eq!(show("Pair calldata", &["0x40"], "p.b").as_deref(), Ok("6"));
        assert_eq!(
            show("uint256[2] calldata", &["0x0"], "a[1]").as_deref(),
            Ok("2")
        );
        assert_eq!(
            show("uint256[2] calldata", &["0x0"], "a[2]").unwrap_err(),
            "index 2 is out of range; `a` has 2 elements"
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
        // A path walks the layout from the pointer's slot.
        let place = at(&reader, "Pair storage", &["0x5"], "p.b").expect("member");
        let Place::Storage { reference, ty } = place else {
            panic!("{place:?}");
        };
        assert_eq!(ty, "uint128");
        assert_eq!(reference.offset, 16);
        assert_eq!(reference.path, "Pair.b");
        assert_eq!(
            at(&reader, "Pair storage", &["0x5"], "p.c").unwrap_err(),
            "`struct Shop.Pair` has no member `c`; it has a, b"
        );
    }
}
