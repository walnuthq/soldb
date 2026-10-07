//! The type and pointer tables of the ETHDebug resources.
//!
//! `ethdebug_resources.json` carries, next to the compilation, a `types` table with one
//! ethdebug/format/type document per type the compiler describes, keyed by the type
//! identifier the storage layout uses too (`t_uint256`, `t_mapping$_t_address_$_t_uint256_$`),
//! and a `pointers` table with one ethdebug/format/pointer/template per struct, array and
//! mapping type a state variable has or is composed of, keyed by the same identifier:
//! how a value of the type is laid out from a base slot, which the template expects as
//! `slot`; a mapping's template expects `key` as well and locates one entry. Value types
//! have no template, they are single regions wherever they occur, and where a state
//! variable starts is what the storage layout and the program-level context say. solc
//! fills both tables from 0.8.38; earlier releases write empty tables, which parse to
//! empty tables here, and a debugger then reads state variables through the storage
//! layout as before.
//!
//! [`Resources::parse`] reads the tables and rejects documents that do not follow the
//! schemas, since a type read loosely decodes the wrong bytes. A type document says how
//! to read a value ([`TypeDocument::decode`]); the pointer template of the variable says
//! where ([`crate::pointers`]).

use std::collections::BTreeMap;

use serde_json::Value;

use soldb_core::{SoldbError, SoldbResult};

use crate::metadata::SourceLocation;
use crate::pointers::{dereference_pointer, read_region, Machine, Pointer, PointerTemplate};
use crate::storage_layout::word_to_decimal;

/// The tables of an ETHDebug resources record.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resources {
    /// Type documents by the compiler's type identifier.
    pub types: BTreeMap<String, TypeDocument>,
    /// Pointer templates by name.
    pub pointers: BTreeMap<String, PointerTemplate>,
}

/// Where a type, struct member, or function is defined in the sources.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Definition {
    pub name: Option<String>,
    pub location: Option<SourceLocation>,
}

/// A reference to a type: by identifier into the type table, or written inline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeReference {
    Id(String),
    Inline(Box<TypeDocument>),
}

/// A member of a struct or a component of a tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: Option<String>,
    pub ty: TypeReference,
}

/// An ethdebug/format/type document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeDocument {
    Uint {
        bits: u64,
    },
    Int {
        bits: u64,
    },
    Bool,
    Address {
        payable: Option<bool>,
    },
    /// `bytesN` with a size, `bytes` without.
    Bytes {
        size: Option<u64>,
    },
    String {
        encoding: Option<String>,
    },
    UFixed {
        bits: u64,
        places: u64,
    },
    Fixed {
        bits: u64,
        places: u64,
    },
    Contract {
        library: bool,
        interface: bool,
        payable: Option<bool>,
        definition: Option<Definition>,
    },
    Enum {
        values: Vec<String>,
        definition: Option<Definition>,
    },
    /// A user-defined value type over `contains`.
    Alias {
        contains: TypeReference,
        definition: Option<Definition>,
    },
    /// Dynamically sized without a `count`.
    Array {
        contains: TypeReference,
        count: Option<u64>,
    },
    Mapping {
        key: TypeReference,
        value: TypeReference,
    },
    Struct {
        members: Vec<Member>,
        definition: Option<Definition>,
    },
    Tuple {
        members: Vec<Member>,
    },
    Function {
        external: bool,
        parameters: Box<TypeReference>,
        returns: Option<Box<TypeReference>>,
        definition: Option<Definition>,
    },
}

impl Resources {
    /// Parses the `types` and `pointers` tables of a resources record. A record without
    /// them, as older compilers write, has empty tables.
    pub fn parse(resources: &Value) -> SoldbResult<Self> {
        let object = resources.as_object().ok_or_else(|| {
            SoldbError::Message("the resources record is not an object".to_owned())
        })?;
        let mut types = BTreeMap::new();
        if let Some(table) = object.get("types") {
            let table = table
                .as_object()
                .ok_or_else(|| SoldbError::Message("`types` is not an object".to_owned()))?;
            for (id, document) in table {
                let document = TypeDocument::parse(document)
                    .map_err(|error| SoldbError::Message(format!("type `{id}`: {error}")))?;
                types.insert(id.clone(), document);
            }
        }
        let mut pointers = BTreeMap::new();
        if let Some(table) = object.get("pointers") {
            let table = table
                .as_object()
                .ok_or_else(|| SoldbError::Message("`pointers` is not an object".to_owned()))?;
            for (name, template) in table {
                if !crate::pointers::is_identifier(name) {
                    return Err(SoldbError::Message(format!(
                        "pointer template name `{name}` is not an identifier"
                    )));
                }
                let template = PointerTemplate::parse(template)
                    .map_err(|error| SoldbError::Message(format!("pointer `{name}`: {error}")))?;
                pointers.insert(name.clone(), template);
            }
        }
        Ok(Self { types, pointers })
    }

    /// Whether the compiler filled the tables at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty() && self.pointers.is_empty()
    }

    #[must_use]
    pub fn type_document(&self, id: &str) -> Option<&TypeDocument> {
        self.types.get(id)
    }

    /// The document a reference names, following identifiers into the table.
    pub fn resolve<'a>(&'a self, reference: &'a TypeReference) -> SoldbResult<&'a TypeDocument> {
        match reference {
            TypeReference::Inline(document) => Ok(document),
            TypeReference::Id(id) => self
                .types
                .get(id)
                .ok_or_else(|| SoldbError::Message(format!("the type table has no `{id}`"))),
        }
    }

    /// The identifiers referenced by the documents that are not in the table. Empty for
    /// a well-formed table.
    #[must_use]
    pub fn dangling_references(&self) -> Vec<String> {
        let mut dangling = Vec::new();
        for document in self.types.values() {
            document.collect_dangling(self, &mut dangling);
        }
        dangling.sort();
        dangling.dedup();
        dangling
    }

    /// The template of a struct, array or mapping type, by the identifier the type table
    /// uses; `None` for a value type, whose values are single regions.
    #[must_use]
    pub fn template_for_type(&self, type_id: &str) -> Option<&PointerTemplate> {
        self.pointers.get(type_id)
    }

    /// The Solidity-like spelling of a type, such as `mapping(address => uint256)`.
    #[must_use]
    pub fn label(&self, reference: &TypeReference) -> String {
        match self.resolve(reference) {
            Ok(document) => document.label(self),
            Err(_) => match reference {
                TypeReference::Id(id) => id.clone(),
                TypeReference::Inline(_) => "?".to_owned(),
            },
        }
    }
}

impl TypeReference {
    /// Parses an ethdebug/format/type/specifier: a reference by id or an inline document.
    pub fn parse(specifier: &Value) -> SoldbResult<Self> {
        parse_specifier(specifier, 0)
    }
}

impl TypeDocument {
    /// Parses an ethdebug/format/type document, inline references included.
    pub fn parse(value: &Value) -> SoldbResult<Self> {
        parse_type(value, 0)
    }

    /// The `kind` the format names the document by.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Uint { .. } => "uint",
            Self::Int { .. } => "int",
            Self::Bool => "bool",
            Self::Address { .. } => "address",
            Self::Bytes { .. } => "bytes",
            Self::String { .. } => "string",
            Self::UFixed { .. } => "ufixed",
            Self::Fixed { .. } => "fixed",
            Self::Contract { .. } => "contract",
            Self::Enum { .. } => "enum",
            Self::Alias { .. } => "alias",
            Self::Array { .. } => "array",
            Self::Mapping { .. } => "mapping",
            Self::Struct { .. } => "struct",
            Self::Tuple { .. } => "tuple",
            Self::Function { .. } => "function",
        }
    }

    /// The definition of a user-defined type, when the document carries one.
    #[must_use]
    pub const fn definition(&self) -> Option<&Definition> {
        match self {
            Self::Contract { definition, .. }
            | Self::Enum { definition, .. }
            | Self::Alias { definition, .. }
            | Self::Struct { definition, .. }
            | Self::Function { definition, .. } => definition.as_ref(),
            _ => None,
        }
    }

    /// Whether a value of the type is one word or less, read from a single region.
    #[must_use]
    pub const fn is_value_type(&self) -> bool {
        matches!(
            self,
            Self::Uint { .. }
                | Self::Int { .. }
                | Self::Bool
                | Self::Address { .. }
                | Self::Bytes { size: Some(_) }
                | Self::UFixed { .. }
                | Self::Fixed { .. }
                | Self::Contract { .. }
                | Self::Enum { .. }
                | Self::Alias { .. }
                | Self::Function { .. }
        )
    }

    /// The Solidity-like spelling of the type.
    #[must_use]
    pub fn label(&self, resources: &Resources) -> String {
        let named = |definition: &Option<Definition>, fallback: &str| {
            definition
                .as_ref()
                .and_then(|definition| definition.name.clone())
                .unwrap_or_else(|| fallback.to_owned())
        };
        match self {
            Self::Uint { bits } => format!("uint{bits}"),
            Self::Int { bits } => format!("int{bits}"),
            Self::Bool => "bool".to_owned(),
            Self::Address {
                payable: Some(true),
            } => "address payable".to_owned(),
            Self::Address { .. } => "address".to_owned(),
            Self::Bytes { size: Some(size) } => format!("bytes{size}"),
            Self::Bytes { size: None } => "bytes".to_owned(),
            Self::String { .. } => "string".to_owned(),
            Self::UFixed { bits, places } => format!("ufixed{bits}x{places}"),
            Self::Fixed { bits, places } => format!("fixed{bits}x{places}"),
            Self::Contract { definition, .. } => named(definition, "contract"),
            Self::Enum { definition, .. } => format!("enum {}", named(definition, "?")),
            Self::Alias { definition, .. } => named(definition, "alias"),
            Self::Array { contains, count } => match count {
                Some(count) => format!("{}[{count}]", resources.label(contains)),
                None => format!("{}[]", resources.label(contains)),
            },
            Self::Mapping { key, value } => {
                format!(
                    "mapping({} => {})",
                    resources.label(key),
                    resources.label(value)
                )
            }
            Self::Struct { definition, .. } => format!("struct {}", named(definition, "?")),
            Self::Tuple { members } => format!(
                "({})",
                members
                    .iter()
                    .map(|member| resources.label(&member.ty))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Function { external, .. } => {
                if *external {
                    "function external".to_owned()
                } else {
                    "function internal".to_owned()
                }
            }
        }
    }

    /// Decodes the bytes of a value of the type, as read from its region, the way the
    /// debugger shows values: numbers in decimal, addresses and bytes in hex, strings
    /// quoted, enums by their variant. `Err` says why the type is not decoded from bytes,
    /// which is the case for the composed kinds whose pointers name their parts.
    pub fn decode(&self, bytes: &[u8], resources: &Resources) -> SoldbResult<String> {
        match self {
            Self::Uint { .. } => Ok(word_to_decimal(bytes)),
            Self::Int { bits } => Ok(signed_decimal(bytes, *bits)),
            Self::Bool => Ok(if bytes.iter().any(|byte| *byte != 0) {
                "true".to_owned()
            } else {
                "false".to_owned()
            }),
            Self::Address { .. } | Self::Contract { .. } => {
                let start = bytes.len().saturating_sub(20);
                Ok(format!("0x{}", hex(&bytes[start..])))
            }
            Self::Bytes { size: Some(size) } => {
                let size = usize::try_from(*size)
                    .unwrap_or(bytes.len())
                    .min(bytes.len());
                Ok(format!("0x{}", hex(&bytes[..size])))
            }
            Self::Bytes { size: None } => Ok(format!("0x{}", hex(bytes))),
            Self::String { .. } => Ok(match std::str::from_utf8(bytes) {
                Ok(text) => format!("{text:?}"),
                Err(_) => format!("0x{}", hex(bytes)),
            }),
            Self::UFixed { places, .. } => Ok(fixed_point(word_to_decimal(bytes), *places)),
            Self::Fixed { bits, places } => Ok(fixed_point(signed_decimal(bytes, *bits), *places)),
            Self::Enum { values, definition } => {
                let index =
                    usize::try_from(u64::from_str_radix(&hex(bytes), 16).unwrap_or(u64::MAX))
                        .unwrap_or(usize::MAX);
                let name = definition
                    .as_ref()
                    .and_then(|definition| definition.name.as_deref())
                    .unwrap_or("enum");
                Ok(match values.get(index) {
                    Some(variant) => format!("{name}.{variant}"),
                    None => format!("<{name} value {} is out of range>", word_to_decimal(bytes)),
                })
            }
            Self::Alias { contains, .. } => resources.resolve(contains)?.decode(bytes, resources),
            Self::Function { .. } => Ok(format!("0x{}", hex(bytes))),
            Self::Mapping { .. } => Err(SoldbError::Message(
                "a mapping's entries are located through its pointer template; index it with a key"
                    .to_owned(),
            )),
            Self::Array { .. } | Self::Struct { .. } | Self::Tuple { .. } => {
                Err(SoldbError::Message(format!(
                    "a {} is read through the regions of its parts, not from bytes",
                    self.kind()
                )))
            }
        }
    }

    fn collect_dangling(&self, resources: &Resources, dangling: &mut Vec<String>) {
        let mut check = |reference: &TypeReference| match reference {
            TypeReference::Id(id) => {
                if !resources.types.contains_key(id) {
                    dangling.push(id.clone());
                }
            }
            TypeReference::Inline(document) => document.collect_dangling(resources, dangling),
        };
        match self {
            Self::Alias { contains, .. } | Self::Array { contains, .. } => check(contains),
            Self::Mapping { key, value } => {
                check(key);
                check(value);
            }
            Self::Struct { members, .. } | Self::Tuple { members } => {
                for member in members {
                    check(&member.ty);
                }
            }
            Self::Function {
                parameters,
                returns,
                ..
            } => {
                check(parameters);
                if let Some(returns) = returns {
                    check(returns);
                }
            }
            _ => {}
        }
    }
}

fn signed_decimal(bytes: &[u8], bits: u64) -> String {
    let width = usize::try_from(bits / 8).unwrap_or(32).max(1);
    // The sign bit of an `intN` is the top bit of its N bits, which sit at the end of
    // whatever was read; fewer bytes than that cannot hold a negative value.
    let negative = bytes.len() >= width && bytes[bytes.len() - width] & 0x80 != 0;
    if !negative {
        return word_to_decimal(bytes);
    }
    // Two's complement over the value's own width: negate and add one.
    let mut magnitude = bytes[bytes.len() - width..].to_vec();
    for byte in &mut magnitude {
        *byte = !*byte;
    }
    for byte in magnitude.iter_mut().rev() {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            break;
        }
    }
    format!("-{}", word_to_decimal(&magnitude))
}

fn fixed_point(decimal: String, places: u64) -> String {
    let places = usize::try_from(places).unwrap_or(0);
    if places == 0 {
        return decimal;
    }
    let (sign, digits) = match decimal.strip_prefix('-') {
        Some(digits) => ("-", digits.to_owned()),
        None => ("", decimal),
    };
    let padded = format!("{digits:0>width$}", width = places + 1);
    let (whole, fraction) = padded.split_at(padded.len() - places);
    format!("{sign}{whole}.{fraction}")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One region of a state variable, read: its name and what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateValue {
    /// The region's name: the variable's identifier for its own value, `<identifier>-<member>`
    /// for a struct member, `<identifier>-item` for an array element, nested as the value is.
    pub name: String,
    /// The value as the debugger shows it, or, when `available` is false, why it could not
    /// be read.
    pub display: String,
    pub available: bool,
}

impl Resources {
    /// Reads a state variable of type `ty` through `pointer`, the pointer its program
    /// context carries, against `machine`: one value per region the pointer names,
    /// decoded by the type the region's name leads to from `ty`. The names are relative
    /// to the variable: `x` is a struct member, `item` an array element, `from-x` a member
    /// of a member, and the `data` of a `bytes` or `string` is the value itself. Regions
    /// that only carry bookkeeping, such as a dynamic array's length or a string's length
    /// flag, are left out. A region the machine has no words for is reported, not read
    /// as zero.
    pub fn read_variable(
        &self,
        ty: &TypeReference,
        pointer: &Pointer,
        machine: &dyn Machine,
    ) -> SoldbResult<Vec<StateValue>> {
        let root = self.resolve(ty)?;
        let regions = dereference_pointer(pointer, &self.pointers, machine)?;
        let mut values = Vec::with_capacity(regions.len());
        for region in &regions {
            let mut path = region
                .name
                .as_deref()
                .map_or_else(Vec::new, |name| name.split('-').collect::<Vec<_>>());
            let document = match self.type_at_path(root, &path) {
                Some(document) => document,
                None if is_bookkeeping(&path) => continue,
                None => {
                    values.push(StateValue {
                        name: path.join("-"),
                        display: format!("<no type for region `{}`>", path.join("-")),
                        available: false,
                    });
                    continue;
                }
            };
            // The `data` of a `bytes` or `string` is the value, not a part of it.
            let is_bytes = matches!(
                document,
                TypeDocument::Bytes { size: None } | TypeDocument::String { .. }
            );
            if path.last() == Some(&"data") && is_bytes {
                path.pop();
            }
            let name = path.join("-");
            // A mapping's base slot holds nothing to read; its entries are elsewhere.
            if let TypeDocument::Mapping { .. } = document {
                values.push(StateValue {
                    name,
                    display: "<mapping; index it with [key]>".to_owned(),
                    available: false,
                });
                continue;
            }
            values.push(match read_region(region, machine) {
                Ok(bytes) => match document.decode(&bytes, self) {
                    Ok(display) => StateValue {
                        name,
                        display,
                        available: true,
                    },
                    Err(error) => StateValue {
                        name,
                        display: format!("<{error}>"),
                        available: false,
                    },
                },
                Err(error) => StateValue {
                    name,
                    display: format!("<{error}>"),
                    available: false,
                },
            });
        }
        Ok(values)
    }

    /// The type a region's name leads to from the variable's type: `item` steps into an
    /// array's element, a member name into a struct's member, `value` into a mapping's
    /// value, `data` stays at a `bytes` or `string`, an alias into what it wraps.
    fn type_at_path<'a>(
        &'a self,
        root: &'a TypeDocument,
        path: &[&str],
    ) -> Option<&'a TypeDocument> {
        let mut current = root;
        for segment in path {
            current = match current {
                TypeDocument::Alias { contains, .. } => self.resolve(contains).ok()?,
                _ => current,
            };
            current = match current {
                TypeDocument::Array { contains, .. } if *segment == "item" => {
                    self.resolve(contains).ok()?
                }
                TypeDocument::Mapping { value, .. } if *segment == "value" => {
                    self.resolve(value).ok()?
                }
                TypeDocument::Bytes { size: None } | TypeDocument::String { .. }
                    if *segment == "data" =>
                {
                    current
                }
                TypeDocument::Struct { members, .. } => {
                    let member = members
                        .iter()
                        .find(|member| member.name.as_deref() == Some(segment))?;
                    self.resolve(&member.ty).ok()?
                }
                _ => return None,
            };
        }
        Some(current)
    }
}

/// Whether a region name path ends in the bookkeeping the storage layouts add: the
/// `length` of a dynamic array, the `length-flag` and `long-length` of bytes and strings.
/// The segments come from splitting the name on `-`; a struct member that happens to be
/// called `length` resolves to its type first and is never taken for bookkeeping.
fn is_bookkeeping(path: &[&str]) -> bool {
    matches!(path, [.., "length"] | [.., "length", "flag"])
}

// ---------------------------------------------------------------------------
// Parsing

const MAX_DEPTH: usize = 256;

fn parse_type(value: &Value, depth: usize) -> SoldbResult<TypeDocument> {
    if depth >= MAX_DEPTH {
        return Err(SoldbError::Message(format!(
            "a type nests deeper than {MAX_DEPTH} levels"
        )));
    }
    let object = value
        .as_object()
        .ok_or_else(|| SoldbError::Message("a type document is not an object".to_owned()))?;
    let kind = string(object, "kind", "a type document")?;
    let class = |expected: &str| -> SoldbResult<()> {
        match object.get("class").and_then(Value::as_str) {
            Some(class) if class != expected => Err(SoldbError::Message(format!(
                "kind `{kind}` is {expected}, not `{class}`"
            ))),
            _ => Ok(()),
        }
    };
    let only = |allowed: &[&str]| -> SoldbResult<()> {
        for key in object.keys() {
            if key != "kind" && key != "class" && !allowed.contains(&key.as_str()) {
                return Err(SoldbError::Message(format!(
                    "kind `{kind}` has an unknown member `{key}`"
                )));
            }
        }
        Ok(())
    };
    let definition = || -> SoldbResult<Option<Definition>> {
        object.get("definition").map(parse_definition).transpose()
    };
    let contains = || -> SoldbResult<&Value> {
        object
            .get("contains")
            .ok_or_else(|| SoldbError::Message(format!("kind `{kind}` has no `contains`")))
    };
    let flag = |key: &str| -> SoldbResult<Option<bool>> {
        match object.get(key) {
            None => Ok(None),
            Some(Value::Bool(value)) => Ok(Some(*value)),
            Some(_) => Err(SoldbError::Message(format!(
                "`{key}` of kind `{kind}` is not a boolean"
            ))),
        }
    };
    let bits = || -> SoldbResult<u64> {
        let bits = number(object, "bits", "a numeric type")?;
        if bits == 0 || bits > 256 || bits % 8 != 0 {
            return Err(SoldbError::Message(format!(
                "`bits` must be a multiple of 8 up to 256, not {bits}"
            )));
        }
        Ok(bits)
    };
    let places = || -> SoldbResult<u64> {
        let places = number(object, "places", "a fixed-point type")?;
        if places == 0 || places > 80 {
            return Err(SoldbError::Message(format!(
                "`places` must be between 1 and 80, not {places}"
            )));
        }
        Ok(places)
    };
    match kind {
        "uint" => {
            class("elementary")?;
            only(&["bits"])?;
            Ok(TypeDocument::Uint { bits: bits()? })
        }
        "int" => {
            class("elementary")?;
            only(&["bits"])?;
            Ok(TypeDocument::Int { bits: bits()? })
        }
        "bool" => {
            class("elementary")?;
            only(&[])?;
            Ok(TypeDocument::Bool)
        }
        "address" => {
            class("elementary")?;
            only(&["payable"])?;
            Ok(TypeDocument::Address {
                payable: flag("payable")?,
            })
        }
        "bytes" => {
            class("elementary")?;
            only(&["size"])?;
            Ok(TypeDocument::Bytes {
                size: optional_number(object, "size", "a bytes type")?,
            })
        }
        "string" => {
            class("elementary")?;
            only(&["encoding"])?;
            Ok(TypeDocument::String {
                encoding: object
                    .get("encoding")
                    .map(|encoding| {
                        encoding.as_str().map(str::to_owned).ok_or_else(|| {
                            SoldbError::Message("`encoding` is not a string".to_owned())
                        })
                    })
                    .transpose()?,
            })
        }
        "ufixed" => {
            class("elementary")?;
            only(&["bits", "places"])?;
            Ok(TypeDocument::UFixed {
                bits: bits()?,
                places: places()?,
            })
        }
        "fixed" => {
            class("elementary")?;
            only(&["bits", "places"])?;
            Ok(TypeDocument::Fixed {
                bits: bits()?,
                places: places()?,
            })
        }
        "contract" => {
            class("elementary")?;
            only(&["payable", "library", "interface", "definition"])?;
            let library = flag("library")?.unwrap_or(false);
            let interface = flag("interface")?.unwrap_or(false);
            if library && interface {
                return Err(SoldbError::Message(
                    "a contract is not both a library and an interface".to_owned(),
                ));
            }
            Ok(TypeDocument::Contract {
                library,
                interface,
                payable: flag("payable")?,
                definition: definition()?,
            })
        }
        "enum" => {
            class("elementary")?;
            only(&["values", "definition"])?;
            let values = object
                .get("values")
                .and_then(Value::as_array)
                .ok_or_else(|| SoldbError::Message("an enum has no `values` array".to_owned()))?
                .iter()
                .map(|value| {
                    value.as_str().map(str::to_owned).ok_or_else(|| {
                        SoldbError::Message("an enum value is not a string".to_owned())
                    })
                })
                .collect::<SoldbResult<Vec<_>>>()?;
            Ok(TypeDocument::Enum {
                values,
                definition: definition()?,
            })
        }
        "alias" => {
            class("complex")?;
            only(&["contains", "definition"])?;
            Ok(TypeDocument::Alias {
                contains: parse_wrapper(contains()?, depth + 1)?.ty,
                definition: definition()?,
            })
        }
        "array" => {
            class("complex")?;
            only(&["contains", "count"])?;
            Ok(TypeDocument::Array {
                contains: parse_wrapper(contains()?, depth + 1)?.ty,
                count: optional_number(object, "count", "an array")?,
            })
        }
        "mapping" => {
            class("complex")?;
            only(&["contains"])?;
            let contains = contains()?.as_object().ok_or_else(|| {
                SoldbError::Message("a mapping's `contains` is not an object".to_owned())
            })?;
            for key in contains.keys() {
                if key != "key" && key != "value" {
                    return Err(SoldbError::Message(format!(
                        "a mapping's `contains` has an unknown member `{key}`"
                    )));
                }
            }
            let part = |name: &str| -> SoldbResult<TypeReference> {
                let wrapper = contains
                    .get(name)
                    .ok_or_else(|| SoldbError::Message(format!("a mapping has no `{name}`")))?;
                Ok(parse_wrapper(wrapper, depth + 1)?.ty)
            };
            Ok(TypeDocument::Mapping {
                key: part("key")?,
                value: part("value")?,
            })
        }
        "struct" => {
            class("complex")?;
            only(&["contains", "definition"])?;
            Ok(TypeDocument::Struct {
                members: parse_members(contains()?, depth + 1)?,
                definition: definition()?,
            })
        }
        "tuple" => {
            class("complex")?;
            only(&["contains"])?;
            Ok(TypeDocument::Tuple {
                members: parse_members(contains()?, depth + 1)?,
            })
        }
        "function" => {
            class("complex")?;
            only(&["contains", "internal", "external", "definition"])?;
            let internal = flag("internal")?.unwrap_or(false);
            let external = flag("external")?.unwrap_or(false);
            if internal == external {
                return Err(SoldbError::Message(
                    "a function type is either internal or external".to_owned(),
                ));
            }
            let contains = contains()?.as_object().ok_or_else(|| {
                SoldbError::Message("a function's `contains` is not an object".to_owned())
            })?;
            for key in contains.keys() {
                if key != "parameters" && key != "returns" {
                    return Err(SoldbError::Message(format!(
                        "a function's `contains` has an unknown member `{key}`"
                    )));
                }
            }
            let parameters = contains.get("parameters").ok_or_else(|| {
                SoldbError::Message("a function type has no `parameters`".to_owned())
            })?;
            Ok(TypeDocument::Function {
                external,
                parameters: Box::new(parse_wrapper(parameters, depth + 1)?.ty),
                returns: contains
                    .get("returns")
                    .map(|returns| {
                        parse_wrapper(returns, depth + 1).map(|wrapper| Box::new(wrapper.ty))
                    })
                    .transpose()?,
                definition: definition()?,
            })
        }
        other => Err(SoldbError::Message(format!("`{other}` is not a type kind"))),
    }
}

/// A type wrapper, `{ "name"?: ..., "type": <reference or document> }`.
fn parse_wrapper(value: &Value, depth: usize) -> SoldbResult<Member> {
    let object = value
        .as_object()
        .ok_or_else(|| SoldbError::Message("a type wrapper is not an object".to_owned()))?;
    for key in object.keys() {
        if key != "name" && key != "type" {
            return Err(SoldbError::Message(format!(
                "a type wrapper has an unknown member `{key}`"
            )));
        }
    }
    let name = object
        .get("name")
        .map(|name| {
            name.as_str()
                .map(str::to_owned)
                .ok_or_else(|| SoldbError::Message("a member name is not a string".to_owned()))
        })
        .transpose()?;
    let ty = object
        .get("type")
        .ok_or_else(|| SoldbError::Message("a type wrapper has no `type`".to_owned()))?;
    let ty = parse_specifier(ty, depth)?;
    Ok(Member { name, ty })
}

/// A type specifier: a reference `{ "id": ... }` or a type document.
fn parse_specifier(value: &Value, depth: usize) -> SoldbResult<TypeReference> {
    let specifier = value
        .as_object()
        .ok_or_else(|| SoldbError::Message("a type specifier is not an object".to_owned()))?;
    if let Some(id) = specifier.get("id") {
        if specifier.len() != 1 {
            return Err(SoldbError::Message(
                "a type reference has only an `id`".to_owned(),
            ));
        }
        return Ok(TypeReference::Id(match id {
            Value::String(id) => id.clone(),
            Value::Number(id) => id.to_string(),
            _ => {
                return Err(SoldbError::Message(
                    "a type id is a string or a number".to_owned(),
                ))
            }
        }));
    }
    Ok(TypeReference::Inline(Box::new(parse_type(value, depth)?)))
}

fn parse_members(value: &Value, depth: usize) -> SoldbResult<Vec<Member>> {
    value
        .as_array()
        .ok_or_else(|| SoldbError::Message("`contains` is not an array of members".to_owned()))?
        .iter()
        .map(|member| parse_wrapper(member, depth))
        .collect()
}

fn parse_definition(value: &Value) -> SoldbResult<Definition> {
    let object = value
        .as_object()
        .ok_or_else(|| SoldbError::Message("a definition is not an object".to_owned()))?;
    for key in object.keys() {
        if key != "name" && key != "location" {
            return Err(SoldbError::Message(format!(
                "a definition has an unknown member `{key}`"
            )));
        }
    }
    let name = object
        .get("name")
        .map(|name| {
            name.as_str()
                .map(str::to_owned)
                .ok_or_else(|| SoldbError::Message("a definition name is not a string".to_owned()))
        })
        .transpose()?;
    let location = object
        .get("location")
        .map(|location| {
            let source_id = location
                .get("source")
                .and_then(|source| source.get("id"))
                .and_then(Value::as_u64);
            let range = location.get("range");
            match (source_id, range) {
                (Some(source_id), Some(range)) => Ok(SourceLocation {
                    source_id,
                    offset: number_of(range, "offset")?,
                    length: number_of(range, "length")?,
                }),
                _ => Err(SoldbError::Message(
                    "a definition location has a numeric source id and a range".to_owned(),
                )),
            }
        })
        .transpose()?;
    if name.is_none() && location.is_none() {
        return Err(SoldbError::Message(
            "a definition has a name or a location".to_owned(),
        ));
    }
    Ok(Definition { name, location })
}

fn string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    what: &str,
) -> SoldbResult<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| SoldbError::Message(format!("{what} has no string `{key}`")))
}

/// An ethdebug/format/data/value: a number or a `0x`-prefixed hex string.
fn number_of(value: &Value, key: &str) -> SoldbResult<u64> {
    let value = value
        .get(key)
        .ok_or_else(|| SoldbError::Message(format!("`{key}` is missing")))?;
    parse_number(value)
        .ok_or_else(|| SoldbError::Message(format!("`{key}` is not a number: {value}")))
}

fn number(object: &serde_json::Map<String, Value>, key: &str, what: &str) -> SoldbResult<u64> {
    let value = object
        .get(key)
        .ok_or_else(|| SoldbError::Message(format!("{what} has no `{key}`")))?;
    parse_number(value)
        .ok_or_else(|| SoldbError::Message(format!("`{key}` of {what} is not a number: {value}")))
}

fn optional_number(
    object: &serde_json::Map<String, Value>,
    key: &str,
    what: &str,
) -> SoldbResult<Option<u64>> {
    object
        .get(key)
        .map(|value| {
            parse_number(value).ok_or_else(|| {
                SoldbError::Message(format!("`{key}` of {what} is not a number: {value}"))
            })
        })
        .transpose()
}

fn parse_number(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => {
            let digits = text.strip_prefix("0x")?;
            if digits.is_empty() || digits.len() > 16 {
                return None;
            }
            u64::from_str_radix(digits, 16).ok()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::{json, Value};

    use super::{Resources, StateValue, TypeDocument, TypeReference};
    use crate::abi::keccak256;
    use crate::metadata::{parse_context_variables, ContextVariable, EthdebugInfo};
    use crate::pointers::{dereference, Location, Machine, Pointer, StorageMachine};
    use crate::storage_layout::{mapping_slot, parse_word, StorageLayout, Word};

    const FIXTURE: &str =
        include_str!("../../../test/fixtures/ethdebug-resources/ethdebug_resources.json");
    const LAYOUT: &str =
        include_str!("../../../test/fixtures/ethdebug-resources/Resources_storage.json");
    const PROGRAM: &str =
        include_str!("../../../test/fixtures/ethdebug-resources/Resources_ethdebug-runtime.json");

    fn fixture() -> Resources {
        let value: Value = serde_json::from_str(FIXTURE).expect("fixture json");
        Resources::parse(&value).expect("fixture resources")
    }

    fn layout() -> StorageLayout {
        StorageLayout::parse(&serde_json::from_str(LAYOUT).expect("layout json")).expect("layout")
    }

    /// The identifier the type table uses for a storage layout type.
    fn escaped(rich: &str) -> String {
        rich.replace('(', "$_")
            .replace(')', "_$")
            .replace(',', "_$_")
    }

    fn word(number: u64) -> Word {
        let mut word = [0_u8; 32];
        word[24..].copy_from_slice(&number.to_be_bytes());
        word
    }

    struct Storage(BTreeMap<Word, Word>);

    impl Machine for Storage {
        fn word(&self, location: Location, slot: &Word) -> Option<Word> {
            (location == Location::Storage)
                .then(|| self.0.get(slot).copied())
                .flatten()
        }

        fn bytes(&self, _: Location, _: u64, _: u64) -> Option<Vec<u8>> {
            None
        }
    }

    #[test]
    fn older_compilers_write_empty_tables() {
        let resources =
            Resources::parse(&json!({"compilation": {"sources": []}})).expect("no tables");
        assert!(resources.is_empty());
        let resources = Resources::parse(&json!({"compilation": {}, "types": {}, "pointers": {}}))
            .expect("empty");
        assert!(resources.is_empty());
        assert!(Resources::parse(&json!([])).is_err());
        assert!(Resources::parse(&json!({"types": []})).is_err());
        assert!(Resources::parse(
            &json!({"pointers": {"1x": {"expect": [], "for": {"location": "storage", "slot": 0}}}})
        )
        .is_err());
    }

    #[test]
    fn the_fixture_has_a_document_for_every_layout_type_and_is_closed() {
        let resources = fixture();
        let layout = layout();
        assert!(!resources.is_empty());
        for variable in &layout.variables {
            let id = escaped(&variable.type_id);
            let document = resources
                .type_document(&id)
                .unwrap_or_else(|| panic!("no document for {id}"));
            // The documents spell the types the way the layout's labels do.
            let label = layout
                .type_of(&variable.type_id)
                .expect("layout type")
                .label
                .clone();
            let expected = match label.as_str() {
                "enum Color" => "enum Color".to_owned(),
                "struct Point" => "struct Point".to_owned(),
                "Price" => "Price".to_owned(),
                other => other.to_owned(),
            };
            assert_eq!(document.label(&resources), expected, "{id}");
        }
        assert_eq!(resources.dangling_references(), Vec::<String>::new());
    }

    #[test]
    fn documents_carry_what_a_decoder_needs() {
        let resources = fixture();
        assert_eq!(
            resources.type_document("t_uint8"),
            Some(&TypeDocument::Uint { bits: 8 })
        );
        assert_eq!(
            resources.type_document("t_bytes32"),
            Some(&TypeDocument::Bytes { size: Some(32) })
        );
        assert_eq!(
            resources.type_document("t_bytes_storage"),
            Some(&TypeDocument::Bytes { size: None })
        );
        let (_, color) = resources
            .types
            .iter()
            .find(|(_, document)| matches!(document, TypeDocument::Enum { .. }))
            .expect("enum");
        match color {
            TypeDocument::Enum { values, definition } => {
                assert_eq!(values, &["Red", "Green", "Blue"]);
                let definition = definition.as_ref().expect("definition");
                assert_eq!(definition.name.as_deref(), Some("Color"));
                assert_eq!(definition.location.as_ref().expect("location").source_id, 0);
            }
            _ => unreachable!(),
        }
        let point = resources
            .types
            .values()
            .find(|document| matches!(document, TypeDocument::Struct { .. }))
            .expect("struct");
        match point {
            TypeDocument::Struct { members, .. } => {
                assert_eq!(
                    members
                        .iter()
                        .map(|member| member.name.as_deref())
                        .collect::<Vec<_>>(),
                    vec![Some("x"), Some("y")]
                );
                assert_eq!(members[0].ty, TypeReference::Id("t_uint8".to_owned()));
            }
            _ => unreachable!(),
        }
        let price = resources
            .types
            .values()
            .find(|document| matches!(document, TypeDocument::Alias { .. }))
            .expect("alias");
        assert_eq!(
            resources.label(&TypeReference::Inline(Box::new(price.clone()))),
            "Price"
        );
        assert_eq!(
            resources.label(&TypeReference::Id(
                "t_mapping$_t_address_$_t_mapping$_t_uint256_$_t_bool_$_$".to_owned()
            )),
            "mapping(address => mapping(uint256 => bool))"
        );
        assert_eq!(
            resources.label(&TypeReference::Id(
                "t_array$_t_uint16_$4_storage".to_owned()
            )),
            "uint16[4]"
        );
    }

    #[test]
    fn malformed_documents_are_rejected() {
        for bad in [
            json!({"kind": "uint"}),
            json!({"kind": "uint", "bits": 12}),
            json!({"kind": "uint", "bits": 8, "size": 1}),
            json!({"kind": "uint", "bits": 8, "class": "complex"}),
            json!({"kind": "ufixed", "bits": 128, "places": 81}),
            json!({"kind": "contract", "library": true, "interface": true}),
            json!({"kind": "enum"}),
            json!({"kind": "array"}),
            json!({"kind": "array", "contains": {"type": {"id": "t_uint8", "extra": 1}}}),
            json!({"kind": "mapping", "contains": {"key": {"type": {"id": "a"}}}}),
            json!({"kind": "struct", "contains": {}}),
            json!({"kind": "function", "contains": {"parameters": {"type": {"kind": "tuple", "contains": []}}}}),
            json!({"kind": "alias", "contains": {"type": {"id": "a"}}, "definition": {}}),
            json!({"kind": "nope"}),
            json!(7),
        ] {
            assert!(TypeDocument::parse(&bad).is_err(), "{bad} should not parse");
        }
        let inline = TypeDocument::parse(
            &json!({"kind": "array", "contains": {"type": {"kind": "bool"}}, "count": "0x04"}),
        )
        .expect("inline element type");
        assert_eq!(
            inline,
            TypeDocument::Array {
                contains: TypeReference::Inline(Box::new(TypeDocument::Bool)),
                count: Some(4)
            }
        );
    }

    #[test]
    fn values_decode_by_their_documents() {
        let resources = fixture();
        let decode = |id: &str, bytes: &[u8]| {
            resources
                .type_document(id)
                .expect(id)
                .decode(bytes, &resources)
                .expect("decode")
        };
        assert_eq!(decode("t_uint256", &word(1234)), "1234");
        assert_eq!(decode("t_uint8", &[7]), "7");
        assert_eq!(decode("t_bool", &[1]), "true");
        assert_eq!(decode("t_bool", &[0]), "false");
        assert_eq!(
            decode("t_address", &[0xab; 20]),
            format!("0x{}", "ab".repeat(20))
        );
        assert_eq!(
            decode("t_bytes32", &[0x11; 32]),
            format!("0x{}", "11".repeat(32))
        );
        assert_eq!(decode("t_string_storage", b"hi"), "\"hi\"");
        assert_eq!(decode("t_bytes_storage", &[1, 2]), "0x0102");
        let color = resources
            .types
            .iter()
            .find(|(_, document)| matches!(document, TypeDocument::Enum { .. }))
            .expect("enum")
            .0;
        assert_eq!(decode(color, &[2]), "Color.Blue");
        assert!(decode(color, &[3]).contains("out of range"));
        let price = resources
            .types
            .iter()
            .find(|(_, document)| matches!(document, TypeDocument::Alias { .. }))
            .expect("alias")
            .0;
        assert_eq!(decode(price, &word(99)[16..]), "99");
        assert!(resources
            .type_document("t_array$_t_uint256_$dyn_storage")
            .expect("array")
            .decode(&[], &resources)
            .is_err());

        assert_eq!(
            TypeDocument::Int { bits: 8 }
                .decode(&[0xff], &resources)
                .expect("int8"),
            "-1"
        );
        assert_eq!(
            TypeDocument::Int { bits: 8 }
                .decode(&[0x7f], &resources)
                .expect("int8"),
            "127"
        );
        assert_eq!(
            TypeDocument::Int { bits: 256 }
                .decode(&[0xff; 32], &resources)
                .expect("int256"),
            "-1"
        );
        assert_eq!(
            TypeDocument::UFixed {
                bits: 128,
                places: 2
            }
            .decode(&[0x04, 0xd2], &resources)
            .expect("ufixed"),
            "12.34"
        );
        assert_eq!(
            TypeDocument::Fixed { bits: 8, places: 1 }
                .decode(&[0xff], &resources)
                .expect("fixed"),
            "-0.1"
        );
    }

    #[test]
    fn every_composed_layout_type_has_a_template_and_no_value_type_does() {
        let resources = fixture();
        let layout = layout();
        for variable in &layout.variables {
            let type_id = escaped(&variable.type_id);
            let document = resources.type_document(&type_id).expect(&type_id);
            let template = resources.template_for_type(&type_id);
            match document {
                TypeDocument::Mapping { .. } => {
                    assert_eq!(
                        template.expect(&type_id).expect,
                        ["slot", "key"],
                        "{type_id}"
                    );
                }
                TypeDocument::Struct { .. }
                | TypeDocument::Array { .. }
                | TypeDocument::Bytes { size: None }
                | TypeDocument::String { .. } => {
                    assert_eq!(template.expect(&type_id).expect, ["slot"], "{type_id}");
                }
                _ => assert!(template.is_none(), "{type_id} is a value type"),
            }
        }
        // Every template dereferences against an empty machine up to the lengths it
        // reads, so it references only templates that are in the table.
        for (name, template) in &resources.pointers {
            let storage = Storage(BTreeMap::new());
            let mut arguments = vec![("slot".to_owned(), vec![7])];
            if template.expect.len() > 1 {
                arguments.push(("key".to_owned(), vec![1]));
            }
            match dereference(template, &arguments, &resources.pointers, &storage) {
                Ok(regions) => assert!(!regions.is_empty(), "{name}"),
                Err(error) => assert!(
                    error.to_string().contains("has not been read"),
                    "{name}: {error}"
                ),
            }
        }
    }

    #[test]
    fn a_template_bound_to_a_layout_slot_starts_where_the_layout_says() {
        let resources = fixture();
        let layout = layout();
        for variable in &layout.variables {
            let type_id = escaped(&variable.type_id);
            let Some(template) = resources.template_for_type(&type_id) else {
                continue;
            };
            // A zero word at the slot makes a dynamic array empty and a string short.
            let storage = Storage([(variable.slot, word(0))].into_iter().collect());
            let mut arguments = vec![("slot".to_owned(), variable.slot.to_vec())];
            let mut expected_slot = variable.slot;
            if template.expect.len() > 1 {
                // A 20-byte key, which the template pads to a word before hashing.
                let mut key = [0_u8; 32];
                key[12..].fill(0xab);
                arguments.push(("key".to_owned(), key[12..].to_vec()));
                expected_slot = mapping_slot(&variable.slot, &key);
            }
            let regions = dereference(template, &arguments, &resources.pointers, &storage)
                .unwrap_or_else(|error| panic!("{}: {error}", variable.label));
            // The first region is in the base slot: a member, the first element, a length.
            assert_eq!(regions[0].slot, Some(expected_slot), "{}", variable.label);
        }
    }

    #[test]
    fn a_nested_mapping_is_followed_one_key_per_level() {
        let resources = fixture();
        let layout = layout();
        let nested = layout.variable("nested").expect("nested");
        let outer = resources
            .template_for_type(&escaped(&nested.type_id))
            .expect("outer template");
        let key = parse_word("0x000000000000000000000000abababababababababababababababababababab")
            .expect("key");
        let storage = Storage(BTreeMap::new());
        let regions = dereference(
            outer,
            &[
                ("slot".to_owned(), nested.slot.to_vec()),
                ("key".to_owned(), key[12..].to_vec()),
            ],
            &resources.pointers,
            &storage,
        )
        .expect("outer entry");
        // The entry of the outer mapping is the base slot of the inner one, a whole slot.
        let inner_slot = mapping_slot(&nested.slot, &key);
        assert_eq!(regions[0].slot, Some(inner_slot));
        assert_eq!((regions[0].offset, regions[0].length), (0, 32));
        let inner = resources
            .template_for_type("t_mapping$_t_uint256_$_t_bool_$")
            .expect("inner template");
        let regions = dereference(
            inner,
            &[
                ("slot".to_owned(), inner_slot.to_vec()),
                ("key".to_owned(), vec![5]),
            ],
            &resources.pointers,
            &storage,
        )
        .expect("inner entry");
        assert_eq!(regions[0].slot, Some(mapping_slot(&inner_slot, &word(5))));
        assert_eq!((regions[0].offset, regions[0].length), (31, 1));
    }

    #[test]
    fn templates_are_keyed_by_type() {
        let resources = fixture();
        let point = resources
            .template_for_type("t_struct$_Point_$12_storage")
            .expect("Point");
        assert_eq!(point.expect, vec!["slot".to_owned()]);
        assert!(resources.template_for_type("t_uint256").is_none());
        assert!(resources.template_for_type("t_enum$_Color_$7").is_none());
        // The same identifier keys the type document.
        assert!(resources
            .type_document("t_struct$_Point_$12_storage")
            .is_some());
    }

    fn program() -> EthdebugInfo {
        let resources: Value = serde_json::from_str(FIXTURE).expect("fixture json");
        let program: Value = serde_json::from_str(PROGRAM).expect("program json");
        EthdebugInfo::from_artifacts("Resources", "call", &resources, &program).expect("program")
    }

    #[test]
    fn the_program_context_lists_the_state_variables() {
        let program = program();
        let layout = layout();
        let mut expected = layout
            .variables
            .iter()
            .map(|variable| variable.label.clone())
            .collect::<Vec<_>>();
        // The transient variable follows, then the immutable the runtime code reads.
        expected.push("scratch".to_owned());
        expected.push("createdAt".to_owned());
        assert_eq!(
            program
                .state_variables
                .iter()
                .map(ContextVariable::name)
                .collect::<Vec<_>>(),
            expected
        );
        let flag = &program.state_variables[3];
        assert_eq!(flag.identifier.as_deref(), Some("flag"));
        assert_eq!(
            flag.declaration
                .as_ref()
                .map(|declaration| declaration.source_id),
            Some(0)
        );
        assert_eq!(
            flag.type_reference().expect("type"),
            Some(TypeReference::Id("t_bool".to_owned()))
        );
        assert!(matches!(
            flag.parsed_pointer().expect("pointer"),
            Some(Pointer::Region(_))
        ));
        let balances = program
            .state_variables
            .iter()
            .find(|variable| variable.identifier.as_deref() == Some("balances"))
            .expect("balances");
        // A mapping is listed with the region of its base slot; a struct with a reference
        // to the template of its type, the slot bound.
        assert!(matches!(
            balances.parsed_pointer().expect("pointer"),
            Some(Pointer::Region(_))
        ));
        let origin = program
            .state_variables
            .iter()
            .find(|variable| variable.identifier.as_deref() == Some("origin"))
            .expect("origin");
        assert!(matches!(
            origin.parsed_pointer().expect("pointer"),
            Some(Pointer::Scope { .. })
        ));

        // A compiler that does not emit the context lists nothing; a context of the wrong
        // shape is an error rather than a guess.
        assert!(parse_context_variables(&json!({"instructions": []}))
            .expect("no context")
            .is_empty());
        assert!(parse_context_variables(&json!({"context": {"code": {}}}))
            .expect("no variables")
            .is_empty());
        assert!(parse_context_variables(&json!({"context": {"variables": 1}})).is_err());
        assert!(parse_context_variables(&json!({"context": {"variables": [{}]}})).is_err());
        assert!(
            parse_context_variables(&json!({"context": {"variables": [{"identifier": ""}]}}))
                .is_err()
        );
        assert!(parse_context_variables(
            &json!({"context": {"variables": [{"declaration": {"source": {}}}]}})
        )
        .is_err());
        let declared_only = parse_context_variables(&json!({"context": {"variables": [
            {"declaration": {"source": {"id": 0}, "range": {"offset": 5, "length": 3}}}
        ]}}))
        .expect("declaration only");
        assert_eq!(declared_only[0].name(), "<declared at 0:5>");
    }

    #[test]
    fn state_variables_are_read_through_their_context() {
        let resources = fixture();
        let program = program();
        let mut packed = [0_u8; 32];
        for (index, element) in [1_u8, 2, 3, 4].into_iter().enumerate() {
            // Two-byte elements packed from the least significant byte.
            packed[31 - index * 2] = element;
        }
        let mut origin = [0_u8; 32];
        origin[31] = 1; // x
        origin[30] = 2; // y
        let mut text = [0_u8; 32];
        text[..2].copy_from_slice(b"hi");
        text[31] = 4;
        let values_data = keccak256(&word(7));
        let mut second_value = values_data;
        second_value[31] += 1;
        let mut packed_slot = [0_u8; 32];
        packed_slot[30] = 1; // flag
        packed_slot[31] = 9; // small
        let storage = Storage(
            [
                (word(2), packed_slot),
                (word(5), origin),
                (word(6), packed),
                (word(7), word(2)),
                (values_data, word(10)),
                (second_value, word(20)),
                (word(9), text),
            ]
            .into_iter()
            .collect(),
        );
        let read = |identifier: &str| -> Vec<StateValue> {
            let variable = program
                .state_variables
                .iter()
                .find(|variable| variable.identifier.as_deref() == Some(identifier))
                .expect(identifier);
            let ty = variable.type_reference().expect("type").expect("typed");
            let pointer = variable.parsed_pointer().expect("pointer").expect("closed");
            resources
                .read_variable(&ty, &pointer, &storage)
                .expect(identifier)
        };
        let shown = |values: Vec<StateValue>| {
            values
                .into_iter()
                .map(|value| format!("{}={}", value.name, value.display))
                .collect::<Vec<_>>()
        };
        assert_eq!(shown(read("flag")), ["=true"]);
        assert_eq!(shown(read("small")), ["=9"]);
        assert_eq!(shown(read("origin")), ["x=1", "y=2"]);
        assert_eq!(
            shown(read("packed")),
            ["item=1", "item=2", "item=3", "item=4"]
        );
        // The length region is bookkeeping; the elements are read at keccak256(slot).
        assert_eq!(shown(read("values")), ["item=10", "item=20"]);
        assert_eq!(shown(read("text")), ["=\"hi\""]);
        // A mapping's base slot holds no value; its entries need a key.
        let balances = read("balances");
        assert_eq!(balances.len(), 1);
        assert!(
            !balances[0].available && balances[0].display.contains("key"),
            "{}",
            balances[0].display
        );
        // A slot the machine never recorded is reported, not read as zero.
        let total = read("total");
        assert_eq!(total.len(), 1);
        assert!(
            !total[0].available && total[0].display.contains("slot"),
            "{}",
            total[0].display
        );
    }

    #[test]
    fn immutables_are_read_from_the_code() {
        let resources = fixture();
        let program = program();
        let created_at = program
            .state_variables
            .iter()
            .find(|variable| variable.identifier.as_deref() == Some("createdAt"))
            .expect("createdAt");
        let ty = created_at.type_reference().expect("type").expect("typed");
        let pointer = created_at
            .parsed_pointer()
            .expect("pointer")
            .expect("closed");
        let no_state = StorageMachine {
            storage: &|_| None,
            transient: None,
            code: None,
        };
        let regions =
            super::dereference_pointer(&pointer, &resources.pointers, &no_state).expect("regions");
        assert_eq!(regions.len(), 1);
        assert_eq!(
            (regions[0].location, regions[0].length),
            (Location::Code, 32)
        );
        // The deployed code, with the value filled into the copy the region covers.
        let offset = usize::try_from(regions[0].offset).expect("offset");
        let mut code = vec![0_u8; offset + 64];
        code[offset..offset + 32].copy_from_slice(&word(1234));
        let read = |code: Option<&[u8]>| {
            let machine = StorageMachine {
                storage: &|_| None,
                transient: None,
                code,
            };
            resources
                .read_variable(&ty, &pointer, &machine)
                .expect("createdAt")
        };
        let values = read(Some(&code));
        assert_eq!(values.len(), 1);
        assert_eq!(
            (values[0].display.as_str(), values[0].available),
            ("1234", true)
        );
        // Without the code, the value is reported missing.
        let values = read(None);
        assert!(
            !values[0].available && values[0].display.contains("code"),
            "{}",
            values[0].display
        );
    }
}
