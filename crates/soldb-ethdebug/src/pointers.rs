//! ethdebug/format pointers: where a value lives, and how to find out.
//!
//! A pointer names regions of the machine state in terms of expressions: a state
//! variable is a storage region at a slot, a packed one a byte range in it, a dynamic
//! array a region for the length and a list of element regions at `keccak256(slot)`, a
//! mapping entry a region whose slot hashes the key with the slot. The compiler writes
//! them as templates, one per state variable, with the mapping keys as the parameters a
//! debugger binds when it wants one entry.
//!
//! [`Pointer::parse`] and [`PointerTemplate::parse`] read what a compiler wrote and
//! reject what does not follow the schema, since a pointer read loosely reads the wrong
//! slot. [`dereference`] evaluates a template against a [`Machine`], the state under
//! inspection, into the concrete [`Region`]s it describes: it binds the parameters, the
//! variables a scope defines and the index of a list, follows the branch a conditional
//! takes, expands lists, and reads the regions an expression looks up. Nothing here
//! reads a chain or a file; the machine is whatever the caller has recorded.
//!
//! Byte offsets inside a storage slot count from the most significant byte, as the
//! format's segment addressing does, not from the least significant one as solc's
//! storage layout does.

use std::collections::BTreeMap;
use std::fmt;

use ruint::aliases::U256;
use serde_json::Value;

use soldb_core::{SoldbError, SoldbResult};

use crate::abi::keccak256;
use crate::storage_layout::Word;

/// How deeply pointers and expressions may nest before the input is rejected as
/// runaway rather than parsed with unbounded recursion.
const MAX_DEPTH: usize = 256;
/// How many elements a list is expanded to before the count is reported as implausible.
pub const MAX_LIST_ELEMENTS: u64 = 4096;
/// How many template references may be followed from one root before the chain is
/// reported as circular.
const MAX_TEMPLATE_DEPTH: usize = 32;

/// A data location a region lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    Stack,
    Memory,
    Storage,
    Calldata,
    Returndata,
    Transient,
    Code,
}

impl Location {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "stack" => Self::Stack,
            "memory" => Self::Memory,
            "storage" => Self::Storage,
            "calldata" => Self::Calldata,
            "returndata" => Self::Returndata,
            "transient" => Self::Transient,
            "code" => Self::Code,
            _ => return None,
        })
    }

    /// The name the format uses.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stack => "stack",
            Self::Memory => "memory",
            Self::Storage => "storage",
            Self::Calldata => "calldata",
            Self::Returndata => "returndata",
            Self::Transient => "transient",
            Self::Code => "code",
        }
    }

    /// Whether the location is addressed by word-sized slots (stack, storage,
    /// transient) rather than by byte offset (memory, calldata, returndata, code).
    #[must_use]
    pub const fn is_slotted(self) -> bool {
        matches!(self, Self::Stack | Self::Storage | Self::Transient)
    }
}

impl fmt::Display for Location {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// A property of a named region an expression can look up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Property {
    Slot,
    Offset,
    Length,
}

/// An ethdebug/format/pointer/expression: it evaluates to bytes, which arithmetic
/// reads as an unsigned big-endian integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expression {
    /// Literal bytes: a hex string as written, a number in its shortest encoding.
    Literal(Vec<u8>),
    /// A variable bound by a template parameter, a scope definition, or a list index.
    Variable(String),
    /// `$wordsize`, 32.
    WordSize,
    /// `{ ".slot" | ".offset" | ".length": <region> }`, a property of a named region or of
    /// `$this`, the region the expression is part of.
    Lookup {
        property: Property,
        region: String,
    },
    /// `{ "$read": <region> }`, the bytes in a named region or in `$this`.
    Read(String),
    Sum(Vec<Expression>),
    /// `a - b`, zero when `b` exceeds `a`.
    Difference(Box<Expression>, Box<Expression>),
    Product(Vec<Expression>),
    Quotient(Box<Expression>, Box<Expression>),
    Remainder(Box<Expression>, Box<Expression>),
    /// keccak256 of the operands' bytes, tightly packed.
    Keccak256(Vec<Expression>),
    /// The operands' bytes, concatenated at their own widths.
    Concat(Vec<Expression>),
    /// `{ "$sized<N>": e }` or, with `size` unset, `{ "$wordsized": e }`: `e` left-padded
    /// with zeros or with its most significant bytes dropped to the width.
    Resize {
        size: Option<u64>,
        operand: Box<Expression>,
    },
}

/// An ethdebug/format/pointer/region before evaluation: expressions for where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionPointer {
    pub name: Option<String>,
    pub location: Location,
    /// The slot of a stack, storage, or transient region.
    pub slot: Option<Expression>,
    /// The byte offset: within the slot for a slotted location, counted from its most
    /// significant byte and defaulting to zero; in the data for a byte-addressed one.
    pub offset: Option<Expression>,
    /// The byte length, defaulting to the rest of the slot for a slotted location.
    pub length: Option<Expression>,
}

/// An ethdebug/format/pointer: a region or a collection of pointers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pointer {
    Region(RegionPointer),
    Group(Vec<Pointer>),
    List {
        count: Expression,
        each: String,
        is: Box<Pointer>,
    },
    Conditional {
        condition: Expression,
        then: Box<Pointer>,
        otherwise: Option<Box<Pointer>>,
    },
    /// Variables defined in order, each in scope of the later ones and of `inner`.
    Scope {
        definitions: Vec<(String, Expression)>,
        inner: Box<Pointer>,
    },
    /// A reference to a template defined in an enclosing `Templates` or in the
    /// resources, with the region names it produces renamed by `yields`.
    Template {
        name: String,
        yields: BTreeMap<String, String>,
    },
    /// Templates defined for the references inside `inner`.
    Templates {
        templates: BTreeMap<String, PointerTemplate>,
        inner: Box<Pointer>,
    },
}

/// An ethdebug/format/pointer/template: a pointer in terms of the variables it expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerTemplate {
    pub expect: Vec<String>,
    pub body: Pointer,
}

/// A region as dereferenced: a concrete place in the machine state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub name: Option<String>,
    pub location: Location,
    /// The slot of a stack, storage, or transient region.
    pub slot: Option<Word>,
    /// The byte offset: within the slot, from its most significant byte, for a slotted
    /// location; in the data for a byte-addressed one.
    pub offset: u64,
    /// The byte length; for a slotted location it may run past the slot into the next
    /// ones.
    pub length: u64,
}

/// The machine state a pointer is dereferenced against. Everything is optional: a
/// recording that never touched a slot has no word for it, and the dereferencer reports
/// what it could not read instead of reading zero.
pub trait Machine {
    /// The word at `slot` of a slotted location (stack, storage, transient).
    fn word(&self, location: Location, slot: &Word) -> Option<Word>;
    /// `length` bytes from `offset` of a byte-addressed location (memory, calldata,
    /// returndata, code).
    fn bytes(&self, location: Location, offset: u64, length: u64) -> Option<Vec<u8>>;
}

/// A callback reading the word at a slot, `None` when it is not known.
pub type WordReader<'a> = &'a dyn Fn(&Word) -> Option<Word>;

/// Storage words read through a callback, for the common case of a storage-only machine.
pub struct StorageMachine<'a> {
    pub storage: WordReader<'a>,
    pub transient: Option<WordReader<'a>>,
}

impl Machine for StorageMachine<'_> {
    fn word(&self, location: Location, slot: &Word) -> Option<Word> {
        match location {
            Location::Storage => (self.storage)(slot),
            Location::Transient => self.transient.and_then(|read| read(slot)),
            _ => None,
        }
    }

    fn bytes(&self, _location: Location, _offset: u64, _length: u64) -> Option<Vec<u8>> {
        None
    }
}

/// Reads the bytes of a dereferenced region. `Err` names what was not available.
pub fn read_region(region: &Region, machine: &dyn Machine) -> SoldbResult<Vec<u8>> {
    if region.location.is_slotted() {
        let slot = region.slot.ok_or_else(|| {
            SoldbError::Message(format!("{} region has no slot", region.location))
        })?;
        let mut bytes =
            Vec::with_capacity(usize::try_from(region.length).unwrap_or(0).min(1 << 16));
        let mut current = slot;
        let mut skip = region.offset;
        let mut remaining = region.length;
        while remaining > 0 {
            let word = machine.word(region.location, &current).ok_or_else(|| {
                SoldbError::Message(format!(
                    "{} slot {} has not been read or written here",
                    region.location,
                    hex_of(&current)
                ))
            })?;
            let start = usize::try_from(skip.min(32)).unwrap_or(32);
            let take = usize::try_from(remaining.min(32 - start as u64)).unwrap_or(0);
            bytes.extend_from_slice(&word[start..start + take]);
            remaining -= take as u64;
            skip = 0;
            current = next_slot(&current);
        }
        Ok(bytes)
    } else {
        machine
            .bytes(region.location, region.offset, region.length)
            .ok_or_else(|| {
                SoldbError::Message(format!(
                    "{} at offset {} is not available here",
                    region.location, region.offset
                ))
            })
    }
}

/// Dereferences `template` with `arguments` bound to the variables it expects, against
/// `machine`, into the regions it describes, in the order the pointer lists them.
/// `templates` resolves the references to other templates, normally the pointer table
/// of the resources.
pub fn dereference(
    template: &PointerTemplate,
    arguments: &[(String, Vec<u8>)],
    templates: &BTreeMap<String, PointerTemplate>,
    machine: &dyn Machine,
) -> SoldbResult<Vec<Region>> {
    let mut bindings = BTreeMap::new();
    for expected in &template.expect {
        let (_, value) = arguments
            .iter()
            .find(|(name, _)| name == expected)
            .ok_or_else(|| {
                SoldbError::Message(format!(
                    "the template expects `{expected}`, which was not given"
                ))
            })?;
        bindings.insert(expected.clone(), value.clone());
    }
    let mut dereferencer = Dereferencer {
        templates,
        machine,
        regions: Vec::new(),
        named: BTreeMap::new(),
        template_depth: 0,
    };
    dereferencer.pointer(
        &template.body,
        &bindings,
        &BTreeMap::new(),
        &BTreeMap::new(),
    )?;
    Ok(dereferencer.regions)
}

/// Dereferences a pointer that expects nothing, such as one inlined into a program
/// context.
pub fn dereference_pointer(
    pointer: &Pointer,
    templates: &BTreeMap<String, PointerTemplate>,
    machine: &dyn Machine,
) -> SoldbResult<Vec<Region>> {
    let template = PointerTemplate {
        expect: Vec::new(),
        body: pointer.clone(),
    };
    dereference(&template, &[], templates, machine)
}

struct Dereferencer<'a> {
    templates: &'a BTreeMap<String, PointerTemplate>,
    machine: &'a dyn Machine,
    /// The regions produced so far, in order.
    regions: Vec<Region>,
    /// The named regions produced so far, for lookups and reads.
    named: BTreeMap<String, Region>,
    template_depth: usize,
}

type Bindings = BTreeMap<String, Vec<u8>>;
type LocalTemplates<'a> = BTreeMap<String, &'a PointerTemplate>;
type Renames = BTreeMap<String, String>;

impl Dereferencer<'_> {
    fn pointer(
        &mut self,
        pointer: &Pointer,
        bindings: &Bindings,
        local: &LocalTemplates<'_>,
        renames: &Renames,
    ) -> SoldbResult<()> {
        match pointer {
            Pointer::Region(region) => {
                let region = self.region(region, bindings, renames)?;
                if let Some(name) = &region.name {
                    self.named.insert(name.clone(), region.clone());
                }
                self.regions.push(region);
                Ok(())
            }
            Pointer::Group(members) => {
                for member in members {
                    self.pointer(member, bindings, local, renames)?;
                }
                Ok(())
            }
            Pointer::List { count, each, is } => {
                let count = as_number(&self.expression(count, bindings, None)?, "the list count")?;
                if count > MAX_LIST_ELEMENTS {
                    return Err(SoldbError::Message(format!(
                        "a list of {count} elements exceeds the {MAX_LIST_ELEMENTS} the debugger expands"
                    )));
                }
                for index in 0..count {
                    let mut inner = bindings.clone();
                    inner.insert(each.clone(), number_bytes(index));
                    self.pointer(is, &inner, local, renames)?;
                }
                Ok(())
            }
            Pointer::Conditional {
                condition,
                then,
                otherwise,
            } => {
                let value = self.expression(condition, bindings, None)?;
                if value.iter().any(|byte| *byte != 0) {
                    self.pointer(then, bindings, local, renames)
                } else if let Some(otherwise) = otherwise {
                    self.pointer(otherwise, bindings, local, renames)
                } else {
                    Ok(())
                }
            }
            Pointer::Scope { definitions, inner } => {
                let mut scoped = bindings.clone();
                for (name, expression) in definitions {
                    let value = self.expression(expression, &scoped, None)?;
                    scoped.insert(name.clone(), value);
                }
                self.pointer(inner, &scoped, local, renames)
            }
            Pointer::Template { name, yields } => {
                let template = local
                    .get(name.as_str())
                    .copied()
                    .or_else(|| self.templates.get(name))
                    .ok_or_else(|| {
                        SoldbError::Message(format!("no pointer template named `{name}`"))
                    })?;
                if self.template_depth >= MAX_TEMPLATE_DEPTH {
                    return Err(SoldbError::Message(format!(
                        "pointer templates nest deeper than {MAX_TEMPLATE_DEPTH} at `{name}`; they reference each other in a cycle"
                    )));
                }
                // The template's parameters are bound from the variables in scope; its
                // regions are renamed as the reference says, on top of the renames in force.
                let mut inner = Bindings::new();
                for expected in &template.expect {
                    let value = bindings.get(expected).ok_or_else(|| {
                        SoldbError::Message(format!(
                            "template `{name}` expects `{expected}`, which is not bound here"
                        ))
                    })?;
                    inner.insert(expected.clone(), value.clone());
                }
                let mut combined = renames.clone();
                for (produced, new_name) in yields {
                    let renamed = renames
                        .get(new_name)
                        .cloned()
                        .unwrap_or_else(|| new_name.clone());
                    combined.insert(produced.clone(), renamed);
                }
                self.template_depth += 1;
                let result = self.pointer(&template.body, &inner, local, &combined);
                self.template_depth -= 1;
                result
            }
            Pointer::Templates { templates, inner } => {
                let mut visible = local.clone();
                for (name, template) in templates {
                    visible.insert(name.clone(), template);
                }
                self.pointer(inner, bindings, &visible, renames)
            }
        }
    }

    fn region(
        &self,
        pointer: &RegionPointer,
        bindings: &Bindings,
        renames: &Renames,
    ) -> SoldbResult<Region> {
        let name = pointer
            .name
            .as_ref()
            .map(|name| renames.get(name).cloned().unwrap_or_else(|| name.clone()));
        // The properties are evaluated in order, so `$this` can refer to the earlier ones.
        let mut region = Region {
            name,
            location: pointer.location,
            slot: None,
            offset: 0,
            length: 0,
        };
        if pointer.location.is_slotted() {
            let slot = pointer.slot.as_ref().ok_or_else(|| {
                SoldbError::Message(format!("{} region has no slot", pointer.location))
            })?;
            region.slot = Some(as_word(
                &self.expression(slot, bindings, Some(&region))?,
                "the slot",
            )?);
            region.offset = match &pointer.offset {
                Some(offset) => as_number(
                    &self.expression(offset, bindings, Some(&region))?,
                    "the offset",
                )?,
                None => 0,
            };
            if region.offset >= 32 {
                return Err(SoldbError::Message(format!(
                    "offset {} does not start inside the slot",
                    region.offset
                )));
            }
            region.length = match &pointer.length {
                Some(length) => as_number(
                    &self.expression(length, bindings, Some(&region))?,
                    "the length",
                )?,
                None => 32 - region.offset,
            };
        } else {
            if pointer.slot.is_some() {
                return Err(SoldbError::Message(format!(
                    "{} region has a slot; it is addressed by offset and length",
                    pointer.location
                )));
            }
            let offset = pointer.offset.as_ref().ok_or_else(|| {
                SoldbError::Message(format!("{} region has no offset", pointer.location))
            })?;
            region.offset = as_number(
                &self.expression(offset, bindings, Some(&region))?,
                "the offset",
            )?;
            let length = pointer.length.as_ref().ok_or_else(|| {
                SoldbError::Message(format!("{} region has no length", pointer.location))
            })?;
            region.length = as_number(
                &self.expression(length, bindings, Some(&region))?,
                "the length",
            )?;
        }
        Ok(region)
    }

    /// The bytes `expression` evaluates to. `this` is the region under construction,
    /// for `$this` lookups and reads.
    fn expression(
        &self,
        expression: &Expression,
        bindings: &Bindings,
        this: Option<&Region>,
    ) -> SoldbResult<Vec<u8>> {
        match expression {
            Expression::Literal(bytes) => Ok(bytes.clone()),
            Expression::Variable(name) => bindings.get(name).cloned().ok_or_else(|| {
                SoldbError::Message(format!("the pointer reads `{name}`, which nothing binds"))
            }),
            Expression::WordSize => Ok(number_bytes(32)),
            Expression::Lookup { property, region } => {
                let region = self.lookup(region, this)?;
                Ok(match property {
                    Property::Slot => {
                        let slot = region.slot.ok_or_else(|| {
                            SoldbError::Message(format!(
                                "`.slot` of a {} region, which has none",
                                region.location
                            ))
                        })?;
                        slot.to_vec()
                    }
                    Property::Offset => number_bytes(region.offset),
                    Property::Length => number_bytes(region.length),
                })
            }
            Expression::Read(region) => {
                let region = self.lookup(region, this)?;
                read_region(region, self.machine)
            }
            Expression::Sum(operands) => {
                let mut total = U256::ZERO;
                for operand in operands {
                    let value =
                        as_uint(&self.expression(operand, bindings, this)?, "a sum operand")?;
                    total = total.checked_add(value).ok_or_else(|| {
                        SoldbError::Message("a sum in the pointer overflows 256 bits".to_owned())
                    })?;
                }
                Ok(uint_bytes(total))
            }
            Expression::Difference(minuend, subtrahend) => {
                let minuend = as_uint(
                    &self.expression(minuend, bindings, this)?,
                    "a difference operand",
                )?;
                let subtrahend = as_uint(
                    &self.expression(subtrahend, bindings, this)?,
                    "a difference operand",
                )?;
                Ok(uint_bytes(minuend.saturating_sub(subtrahend)))
            }
            Expression::Product(operands) => {
                let mut total = U256::from(1_u64);
                for operand in operands {
                    let value = as_uint(
                        &self.expression(operand, bindings, this)?,
                        "a product operand",
                    )?;
                    total = total.checked_mul(value).ok_or_else(|| {
                        SoldbError::Message(
                            "a product in the pointer overflows 256 bits".to_owned(),
                        )
                    })?;
                }
                Ok(uint_bytes(total))
            }
            Expression::Quotient(dividend, divisor) => {
                let dividend = as_uint(&self.expression(dividend, bindings, this)?, "a dividend")?;
                let divisor = as_uint(&self.expression(divisor, bindings, this)?, "a divisor")?;
                dividend
                    .checked_div(divisor)
                    .map(uint_bytes)
                    .ok_or_else(|| SoldbError::Message("the pointer divides by zero".to_owned()))
            }
            Expression::Remainder(dividend, divisor) => {
                let dividend = as_uint(&self.expression(dividend, bindings, this)?, "a dividend")?;
                let divisor = as_uint(&self.expression(divisor, bindings, this)?, "a divisor")?;
                dividend
                    .checked_rem(divisor)
                    .map(uint_bytes)
                    .ok_or_else(|| SoldbError::Message("the pointer divides by zero".to_owned()))
            }
            Expression::Keccak256(operands) => {
                let packed = self.concat(operands, bindings, this)?;
                Ok(keccak256(&packed).to_vec())
            }
            Expression::Concat(operands) => self.concat(operands, bindings, this),
            Expression::Resize { size, operand } => {
                let value = self.expression(operand, bindings, this)?;
                let width = usize::try_from(size.unwrap_or(32)).map_err(|_| {
                    SoldbError::Message(format!(
                        "the pointer resizes to {} bytes",
                        size.unwrap_or(32)
                    ))
                })?;
                Ok(resize(&value, width))
            }
        }
    }

    fn concat(
        &self,
        operands: &[Expression],
        bindings: &Bindings,
        this: Option<&Region>,
    ) -> SoldbResult<Vec<u8>> {
        let mut bytes = Vec::new();
        for operand in operands {
            bytes.extend(self.expression(operand, bindings, this)?);
        }
        Ok(bytes)
    }

    fn lookup<'r>(&'r self, region: &str, this: Option<&'r Region>) -> SoldbResult<&'r Region> {
        if region == "$this" {
            return this.ok_or_else(|| {
                SoldbError::Message("`$this` is used outside of a region".to_owned())
            });
        }
        self.named.get(region).ok_or_else(|| {
            SoldbError::Message(format!(
                "the pointer refers to region `{region}` before it is defined"
            ))
        })
    }
}

/// The bytes of a number in their shortest encoding; `0` is one zero byte.
#[must_use]
pub fn number_bytes(number: u64) -> Vec<u8> {
    let bytes = number.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
    bytes[first..].to_vec()
}

fn uint_bytes(value: U256) -> Vec<u8> {
    let bytes = value.to_be_bytes::<32>();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(31);
    bytes[first..].to_vec()
}

fn resize(value: &[u8], width: usize) -> Vec<u8> {
    if value.len() >= width {
        value[value.len() - width..].to_vec()
    } else {
        let mut resized = vec![0_u8; width - value.len()];
        resized.extend_from_slice(value);
        resized
    }
}

fn as_uint(bytes: &[u8], what: &str) -> SoldbResult<U256> {
    let trimmed = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&[][..], |first| &bytes[first..]);
    if trimmed.len() > 32 {
        return Err(SoldbError::Message(format!(
            "{what} is {} bytes, more than a word",
            trimmed.len()
        )));
    }
    Ok(U256::from_be_slice(trimmed))
}

fn as_number(bytes: &[u8], what: &str) -> SoldbResult<u64> {
    let value = as_uint(bytes, what)?;
    u64::try_from(value)
        .map_err(|_| SoldbError::Message(format!("{what} is larger than 64 bits: {value}")))
}

fn as_word(bytes: &[u8], what: &str) -> SoldbResult<Word> {
    Ok(as_uint(bytes, what)?.to_be_bytes::<32>())
}

fn next_slot(slot: &Word) -> Word {
    let mut next = *slot;
    for byte in next.iter_mut().rev() {
        let (sum, carry) = byte.overflowing_add(1);
        *byte = sum;
        if !carry {
            break;
        }
    }
    next
}

fn hex_of(word: &Word) -> String {
    let mut text = String::with_capacity(66);
    text.push_str("0x");
    for byte in word {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

// ---------------------------------------------------------------------------
// Parsing

impl PointerTemplate {
    /// Parses an ethdebug/format/pointer/template.
    pub fn parse(value: &Value) -> SoldbResult<Self> {
        let object = require_object(value, "a pointer template")?;
        require_only(object, &["expect", "for"], "a pointer template")?;
        let expect = object
            .get("expect")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                SoldbError::Message("a pointer template has no `expect` array".to_owned())
            })?
            .iter()
            .map(|name| identifier(name, "a template parameter"))
            .collect::<SoldbResult<Vec<_>>>()?;
        let body = object.get("for").ok_or_else(|| {
            SoldbError::Message("a pointer template has no `for` pointer".to_owned())
        })?;
        Ok(Self {
            expect,
            body: parse_pointer(body, 0)?,
        })
    }
}

impl Pointer {
    /// Parses an ethdebug/format/pointer.
    pub fn parse(value: &Value) -> SoldbResult<Self> {
        parse_pointer(value, 0)
    }
}

impl Expression {
    /// Parses an ethdebug/format/pointer/expression.
    pub fn parse(value: &Value) -> SoldbResult<Self> {
        parse_expression(value, 0)
    }
}

fn parse_pointer(value: &Value, depth: usize) -> SoldbResult<Pointer> {
    require_depth(depth)?;
    let object = require_object(value, "a pointer")?;
    if object.contains_key("location") {
        require_only(
            object,
            &["name", "location", "slot", "offset", "length"],
            "a region",
        )?;
        let location_name = text(object, "location", "a region")?;
        let location = Location::parse(location_name).ok_or_else(|| {
            SoldbError::Message(format!("`{location_name}` is not a data location"))
        })?;
        let expression = |key: &str| -> SoldbResult<Option<Expression>> {
            object
                .get(key)
                .map(|value| parse_expression(value, depth + 1))
                .transpose()
        };
        let region = RegionPointer {
            name: object
                .get("name")
                .map(|name| identifier(name, "a region name"))
                .transpose()?,
            location,
            slot: expression("slot")?,
            offset: expression("offset")?,
            length: expression("length")?,
        };
        if location.is_slotted() && region.slot.is_none() {
            return Err(SoldbError::Message(format!(
                "a {location} region has no slot"
            )));
        }
        if !location.is_slotted()
            && (region.slot.is_some() || region.offset.is_none() || region.length.is_none())
        {
            return Err(SoldbError::Message(format!(
                "a {location} region is addressed by offset and length, without a slot"
            )));
        }
        return Ok(Pointer::Region(region));
    }
    if let Some(members) = object.get("group") {
        require_only(object, &["group"], "a group")?;
        let members = members
            .as_array()
            .ok_or_else(|| SoldbError::Message("a group is not an array".to_owned()))?;
        if members.is_empty() {
            return Err(SoldbError::Message("a group has no members".to_owned()));
        }
        return members
            .iter()
            .map(|member| parse_pointer(member, depth + 1))
            .collect::<SoldbResult<Vec<_>>>()
            .map(Pointer::Group);
    }
    if let Some(list) = object.get("list") {
        require_only(object, &["list"], "a list")?;
        let list = require_object(list, "a list")?;
        require_only(list, &["count", "each", "is"], "a list")?;
        return Ok(Pointer::List {
            count: parse_expression(required(list, "count", "a list")?, depth + 1)?,
            each: identifier(required(list, "each", "a list")?, "a list index")?,
            is: Box::new(parse_pointer(required(list, "is", "a list")?, depth + 1)?),
        });
    }
    if let Some(condition) = object.get("if") {
        require_only(object, &["if", "then", "else"], "a conditional")?;
        return Ok(Pointer::Conditional {
            condition: parse_expression(condition, depth + 1)?,
            then: Box::new(parse_pointer(
                required(object, "then", "a conditional")?,
                depth + 1,
            )?),
            otherwise: object
                .get("else")
                .map(|otherwise| parse_pointer(otherwise, depth + 1).map(Box::new))
                .transpose()?,
        });
    }
    if object.contains_key("define") {
        // A define/in chain folds into one ordered definition list.
        let mut definitions = Vec::new();
        let mut current = object;
        let mut inner_depth = depth;
        loop {
            require_only(current, &["define", "in"], "a scope")?;
            let define = require_object(
                required(current, "define", "a scope")?,
                "a scope's definitions",
            )?;
            if define.is_empty() {
                return Err(SoldbError::Message("a scope defines nothing".to_owned()));
            }
            for (name, expression) in define {
                if !is_identifier(name) {
                    return Err(SoldbError::Message(format!(
                        "`{name}` is not an identifier"
                    )));
                }
                definitions.push((name.clone(), parse_expression(expression, inner_depth + 1)?));
            }
            let inner = required(current, "in", "a scope")?;
            inner_depth += 1;
            require_depth(inner_depth)?;
            match inner.as_object() {
                Some(next) if next.contains_key("define") => current = next,
                _ => {
                    return Ok(Pointer::Scope {
                        definitions,
                        inner: Box::new(parse_pointer(inner, inner_depth + 1)?),
                    });
                }
            }
        }
    }
    if let Some(name) = object.get("template") {
        require_only(object, &["template", "yields"], "a template reference")?;
        let mut yields = BTreeMap::new();
        if let Some(renames) = object.get("yields") {
            for (produced, new_name) in require_object(renames, "`yields`")? {
                if !is_identifier(produced) {
                    return Err(SoldbError::Message(format!(
                        "`{produced}` is not an identifier"
                    )));
                }
                yields.insert(
                    produced.clone(),
                    identifier(new_name, "a yielded region name")?,
                );
            }
        }
        return Ok(Pointer::Template {
            name: identifier(name, "a template name")?,
            yields,
        });
    }
    if let Some(definitions) = object.get("templates") {
        require_only(object, &["templates", "in"], "a templates block")?;
        let mut templates = BTreeMap::new();
        for (name, definition) in require_object(definitions, "`templates`")? {
            if !is_identifier(name) {
                return Err(SoldbError::Message(format!(
                    "`{name}` is not an identifier"
                )));
            }
            require_depth(depth + 1)?;
            templates.insert(name.clone(), PointerTemplate::parse(definition)?);
        }
        return Ok(Pointer::Templates {
            templates,
            inner: Box::new(parse_pointer(
                required(object, "in", "a templates block")?,
                depth + 1,
            )?),
        });
    }
    Err(SoldbError::Message(format!(
        "a pointer is one of location, group, list, if, define, template, or templates; found {}",
        keys_of(object)
    )))
}

fn parse_expression(value: &Value, depth: usize) -> SoldbResult<Expression> {
    require_depth(depth)?;
    match value {
        Value::Number(number) => {
            let number = number.as_u64().ok_or_else(|| {
                SoldbError::Message(format!("`{number}` is not an unsigned integer"))
            })?;
            Ok(Expression::Literal(number_bytes(number)))
        }
        Value::String(string) => {
            if string == "$wordsize" {
                Ok(Expression::WordSize)
            } else if let Some(bytes) = hex_bytes(string) {
                Ok(Expression::Literal(bytes))
            } else if is_identifier(string) {
                Ok(Expression::Variable(string.clone()))
            } else {
                Err(SoldbError::Message(format!(
                    "`{string}` is neither a hex literal, `$wordsize`, nor a variable"
                )))
            }
        }
        Value::Object(object) => {
            if object.len() != 1 {
                return Err(SoldbError::Message(format!(
                    "an expression object has exactly one key; found {}",
                    keys_of(object)
                )));
            }
            let (key, operand) = object.iter().next().expect("one entry");
            let operands = |what: &str| -> SoldbResult<Vec<Expression>> {
                operand
                    .as_array()
                    .ok_or_else(|| {
                        SoldbError::Message(format!("`{what}` takes an array of operands"))
                    })?
                    .iter()
                    .map(|operand| parse_expression(operand, depth + 1))
                    .collect()
            };
            let pair = |what: &str| -> SoldbResult<(Box<Expression>, Box<Expression>)> {
                let mut operands = operands(what)?;
                if operands.len() != 2 {
                    return Err(SoldbError::Message(format!(
                        "`{what}` takes exactly two operands"
                    )));
                }
                let second = operands.pop().expect("two");
                let first = operands.pop().expect("two");
                Ok((Box::new(first), Box::new(second)))
            };
            let region = || region_reference(operand);
            match key.as_str() {
                ".slot" => Ok(Expression::Lookup {
                    property: Property::Slot,
                    region: region()?,
                }),
                ".offset" => Ok(Expression::Lookup {
                    property: Property::Offset,
                    region: region()?,
                }),
                ".length" => Ok(Expression::Lookup {
                    property: Property::Length,
                    region: region()?,
                }),
                "$read" => Ok(Expression::Read(region()?)),
                "$sum" => Ok(Expression::Sum(operands("$sum")?)),
                "$product" => Ok(Expression::Product(operands("$product")?)),
                "$difference" => {
                    let (first, second) = pair("$difference")?;
                    Ok(Expression::Difference(first, second))
                }
                "$quotient" => {
                    let (first, second) = pair("$quotient")?;
                    Ok(Expression::Quotient(first, second))
                }
                "$remainder" => {
                    let (first, second) = pair("$remainder")?;
                    Ok(Expression::Remainder(first, second))
                }
                "$keccak256" => Ok(Expression::Keccak256(operands("$keccak256")?)),
                "$concat" => Ok(Expression::Concat(operands("$concat")?)),
                "$wordsized" => Ok(Expression::Resize {
                    size: None,
                    operand: Box::new(parse_expression(operand, depth + 1)?),
                }),
                key if key.starts_with("$sized") => {
                    let digits = &key["$sized".len()..];
                    let size = match digits.parse::<u64>() {
                        Ok(size) if size > 0 && !digits.starts_with('0') => size,
                        _ => {
                            return Err(SoldbError::Message(format!(
                                "`{key}` is not a resize to a positive number of bytes"
                            )))
                        }
                    };
                    Ok(Expression::Resize {
                        size: Some(size),
                        operand: Box::new(parse_expression(operand, depth + 1)?),
                    })
                }
                _ => Err(SoldbError::Message(format!(
                    "`{key}` is not a pointer expression"
                ))),
            }
        }
        _ => Err(SoldbError::Message(format!(
            "an expression is a number, a string, or an object; found {value}"
        ))),
    }
}

fn region_reference(value: &Value) -> SoldbResult<String> {
    let name = value
        .as_str()
        .ok_or_else(|| SoldbError::Message("a region reference is not a string".to_owned()))?;
    if name == "$this" || is_identifier(name) {
        Ok(name.to_owned())
    } else {
        Err(SoldbError::Message(format!(
            "`{name}` does not name a region"
        )))
    }
}

/// The identifier grammar of ethdebug/format/pointer/identifier:
/// `^[a-zA-Z_\-]+[a-zA-Z0-9$_\-]*$`.
#[must_use]
pub fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    let starts = |c: char| c.is_ascii_alphabetic() || c == '_' || c == '-';
    match chars.next() {
        Some(first) if starts(first) => chars.all(|c| starts(c) || c.is_ascii_digit() || c == '$'),
        _ => false,
    }
}

fn identifier(value: &Value, what: &str) -> SoldbResult<String> {
    let name = value
        .as_str()
        .ok_or_else(|| SoldbError::Message(format!("{what} is not a string")))?;
    if is_identifier(name) {
        Ok(name.to_owned())
    } else {
        Err(SoldbError::Message(format!(
            "{what} `{name}` is not an identifier"
        )))
    }
}

/// The bytes of a `0x`-prefixed hex string of whole bytes.
fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let digits = text.strip_prefix("0x")?;
    if digits.is_empty() || digits.len() % 2 != 0 {
        return None;
    }
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

fn require_depth(depth: usize) -> SoldbResult<()> {
    if depth >= MAX_DEPTH {
        return Err(SoldbError::Message(format!(
            "a pointer nests deeper than {MAX_DEPTH} levels"
        )));
    }
    Ok(())
}

fn require_object<'a>(
    value: &'a Value,
    what: &str,
) -> SoldbResult<&'a serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| SoldbError::Message(format!("{what} is not an object")))
}

fn require_only(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    what: &str,
) -> SoldbResult<()> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(SoldbError::Message(format!(
                "{what} has an unknown member `{key}`"
            )));
        }
    }
    Ok(())
}

fn required<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    what: &str,
) -> SoldbResult<&'a Value> {
    object
        .get(key)
        .ok_or_else(|| SoldbError::Message(format!("{what} has no `{key}`")))
}

fn text<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
    what: &str,
) -> SoldbResult<&'a str> {
    required(object, key, what)?
        .as_str()
        .ok_or_else(|| SoldbError::Message(format!("`{key}` of {what} is not a string")))
}

fn keys_of(object: &serde_json::Map<String, Value>) -> String {
    let keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    if keys.is_empty() {
        "no keys".to_owned()
    } else {
        keys.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::{
        dereference, is_identifier, number_bytes, read_region, Expression, Location, Machine,
        Pointer, PointerTemplate, Region, StorageMachine, MAX_LIST_ELEMENTS,
    };
    use crate::abi::keccak256;
    use crate::storage_layout::{mapping_slot, Word};

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

    fn parse_template(value: serde_json::Value) -> PointerTemplate {
        PointerTemplate::parse(&value).expect("template")
    }

    fn dereferenced(
        template: &PointerTemplate,
        arguments: &[(&str, Vec<u8>)],
        storage: &Storage,
    ) -> Vec<Region> {
        let arguments = arguments
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect::<Vec<_>>();
        dereference(template, &arguments, &BTreeMap::new(), storage).expect("dereference")
    }

    #[test]
    fn identifiers_follow_the_format_grammar() {
        assert!(is_identifier("balances"));
        assert!(is_identifier("_$items-data"));
        assert!(is_identifier("key1"));
        assert!(!is_identifier("$this"));
        assert!(!is_identifier("1abc"));
        assert!(!is_identifier(""));
    }

    #[test]
    fn literals_variables_and_operations_parse() {
        assert_eq!(
            Expression::parse(&json!(5)).expect("number"),
            Expression::Literal(vec![5])
        );
        assert_eq!(
            Expression::parse(&json!(0)).expect("zero"),
            Expression::Literal(vec![0])
        );
        assert_eq!(
            Expression::parse(&json!("0x0a0b")).expect("hex"),
            Expression::Literal(vec![0x0a, 0x0b])
        );
        assert_eq!(
            Expression::parse(&json!("$wordsize")).expect("wordsize"),
            Expression::WordSize
        );
        assert_eq!(
            Expression::parse(&json!("key")).expect("variable"),
            Expression::Variable("key".to_owned())
        );
        assert_eq!(
            Expression::parse(&json!({"$sized2": {"$read": "$this"}})).expect("resize"),
            Expression::Resize {
                size: Some(2),
                operand: Box::new(Expression::Read("$this".to_owned())),
            }
        );
        for bad in [
            json!("0x0"),
            json!(-1),
            json!({"$sum": 1}),
            json!({"$difference": [1]}),
            json!({"$sized0": 1}),
            json!({"$sized01": 1}),
            json!({"$nope": []}),
            json!({"$read": "$that"}),
        ] {
            assert!(Expression::parse(&bad).is_err(), "{bad} should not parse");
        }
    }

    #[test]
    fn malformed_pointers_are_rejected() {
        for bad in [
            json!({"location": "storage"}),
            json!({"location": "memory", "slot": 1}),
            json!({"location": "memory", "offset": 1}),
            json!({"location": "heap", "slot": 1}),
            json!({"location": "storage", "slot": 1, "extra": true}),
            json!({"group": []}),
            json!({"list": {"count": 1, "is": {"location": "storage", "slot": 1}}}),
            json!({"if": 1}),
            json!({"define": {}, "in": {"location": "storage", "slot": 1}}),
            json!({"define": {"1x": 1}, "in": {"location": "storage", "slot": 1}}),
            json!({"template": "t", "yields": {"a": "$this"}}),
            json!({"templates": {}}),
            json!({"unknown": 1}),
            json!([]),
        ] {
            assert!(Pointer::parse(&bad).is_err(), "{bad} should not parse");
        }
        assert!(PointerTemplate::parse(
            &json!({"expect": ["1x"], "for": {"location": "storage", "slot": 0}})
        )
        .is_err());
        assert!(
            PointerTemplate::parse(&json!({"for": {"location": "storage", "slot": 0}})).is_err()
        );
    }

    #[test]
    fn a_packed_value_is_a_byte_range_of_its_slot() {
        // solc's `uint8` at layout offset 1: the byte before the least significant one.
        let template = parse_template(json!({
            "expect": [],
            "for": {"name": "flag", "location": "storage", "slot": "0x02", "offset": "0x1e", "length": "0x01"}
        }));
        let mut slot = [0_u8; 32];
        slot[30] = 1;
        slot[31] = 7;
        let storage = Storage([(word(2), slot)].into_iter().collect());
        let regions = dereferenced(&template, &[], &storage);
        assert_eq!(
            regions,
            vec![Region {
                name: Some("flag".to_owned()),
                location: Location::Storage,
                slot: Some(word(2)),
                offset: 30,
                length: 1,
            }]
        );
        assert_eq!(read_region(&regions[0], &storage).expect("bytes"), vec![1]);

        // Without an offset and length the region is the whole slot.
        let whole =
            parse_template(json!({"expect": [], "for": {"location": "storage", "slot": 2}}));
        let regions = dereferenced(&whole, &[], &storage);
        assert_eq!((regions[0].offset, regions[0].length), (0, 32));
        assert_eq!(
            read_region(&regions[0], &storage).expect("bytes"),
            slot.to_vec()
        );
    }

    #[test]
    fn a_mapping_entry_hashes_the_key_with_the_slot() {
        let template = parse_template(json!({
            "expect": ["key"],
            "for": {
                "name": "balances",
                "location": "storage",
                "slot": {"$keccak256": [{"$wordsized": "key"}, {"$wordsized": "0x0a"}]}
            }
        }));
        let key = vec![0xab; 20];
        let storage = Storage(BTreeMap::new());
        let regions = dereferenced(&template, &[("key", key.clone())], &storage);
        // The same slot the storage layout arithmetic computes for `balances[key]`.
        let mut padded = [0_u8; 32];
        padded[12..].copy_from_slice(&key);
        assert_eq!(regions[0].slot, Some(mapping_slot(&word(10), &padded)));

        let unbound =
            dereference(&template, &[], &BTreeMap::new(), &storage).expect_err("key missing");
        assert!(unbound.to_string().contains("expects `key`"), "{unbound}");
    }

    #[test]
    fn a_dynamic_array_lists_its_elements_after_the_length() {
        let template = parse_template(json!({
            "expect": [],
            "for": {"group": [
                {"name": "values-length", "location": "storage", "slot": "0x07"},
                {"define": {"values-data": {"$keccak256": [{"$wordsized": "0x07"}]}},
                 "in": {"list": {
                    "count": {"$read": "values-length"},
                    "each": "values-index",
                    "is": {"name": "values-item", "location": "storage", "slot": {"$sum": ["values-data", "values-index"]}}
                 }}}
            ]}
        }));
        let storage = Storage([(word(7), word(3))].into_iter().collect());
        let regions = dereferenced(&template, &[], &storage);
        let data = keccak256(&word(7));
        assert_eq!(regions.len(), 4);
        assert_eq!(regions[0].name.as_deref(), Some("values-length"));
        for (index, region) in regions[1..].iter().enumerate() {
            assert_eq!(region.name.as_deref(), Some("values-item"));
            let mut expected = data;
            expected[31] += u8::try_from(index).expect("small");
            assert_eq!(region.slot, Some(expected));
        }

        // An unrecorded length cannot be expanded, and says which slot is missing.
        let missing = dereference(&template, &[], &BTreeMap::new(), &Storage(BTreeMap::new()))
            .expect_err("no length");
        assert!(
            missing.to_string().contains(
                "slot 0x0000000000000000000000000000000000000000000000000000000000000007"
            ),
            "{missing}"
        );

        // A garbage length is reported rather than expanded.
        let huge = Storage(
            [(word(7), word(MAX_LIST_ELEMENTS + 1))]
                .into_iter()
                .collect(),
        );
        let error = dereference(&template, &[], &BTreeMap::new(), &huge).expect_err("too many");
        assert!(error.to_string().contains("exceeds"), "{error}");
    }

    #[test]
    fn a_string_chooses_its_encoding_by_the_length_flag() {
        let template = parse_template(json!({
            "expect": [],
            "for": {"group": [
                {"name": "text-length-flag", "location": "storage", "slot": "0x09",
                 "offset": {"$difference": ["$wordsize", "0x01"]}, "length": "0x01"},
                {"if": {"$remainder": [{"$sum": [{"$read": "text-length-flag"}, "0x01"]}, "0x02"]},
                 "then": {"define": {"text-length": {"$quotient": [{"$read": "text-length-flag"}, "0x02"]}},
                          "in": {"name": "text", "location": "storage", "slot": "0x09", "length": "text-length"}},
                 "else": {"group": [
                    {"name": "text-long-length", "location": "storage", "slot": "0x09"},
                    {"define": {"text-length": {"$quotient": [{"$difference": [{"$read": "text-long-length"}, "0x01"]}, "0x02"]}},
                     "in": {"define": {"text-data": {"$keccak256": [{"$wordsized": "0x09"}]}},
                            "in": {"name": "text", "location": "storage", "slot": "text-data", "length": "text-length"}}}
                 ]}}
            ]}
        }));

        // Short: "hi" left-aligned, twice the length in the last byte.
        let mut short = [0_u8; 32];
        short[..2].copy_from_slice(b"hi");
        short[31] = 4;
        let storage = Storage([(word(9), short)].into_iter().collect());
        let regions = dereferenced(&template, &[], &storage);
        let text = regions
            .iter()
            .find(|region| region.name.as_deref() == Some("text"))
            .expect("text");
        assert_eq!((text.slot, text.offset, text.length), (Some(word(9)), 0, 2));
        assert_eq!(read_region(text, &storage).expect("bytes"), b"hi".to_vec());

        // Long: 40 bytes, twice the length plus one in the slot, the data at keccak256(slot).
        let data = keccak256(&word(9));
        let mut second = data;
        second[31] += 1;
        let mut first_word = [b'a'; 32];
        first_word[0] = b'A';
        let mut second_word = [0_u8; 32];
        second_word[..8].copy_from_slice(b"bbbbbbbb");
        let storage = Storage(
            [
                (word(9), word(81)),
                (data, first_word),
                (second, second_word),
            ]
            .into_iter()
            .collect(),
        );
        let regions = dereferenced(&template, &[], &storage);
        let text = regions
            .iter()
            .find(|region| region.name.as_deref() == Some("text"))
            .expect("text");
        assert_eq!((text.slot, text.length), (Some(data), 40));
        let bytes = read_region(text, &storage).expect("bytes");
        assert_eq!(bytes.len(), 40);
        assert_eq!(&bytes[..1], b"A");
        assert_eq!(&bytes[32..], b"bbbbbbbb");
    }

    #[test]
    fn packed_array_elements_count_from_the_least_significant_byte() {
        // Two-byte elements, sixteen to a slot: element 0 is the last two bytes.
        let template = parse_template(json!({
            "expect": [],
            "for": {"list": {"count": "0x03", "each": "i", "is": {
                "name": "item", "location": "storage",
                "slot": {"$sum": ["0x06", {"$quotient": ["i", "0x10"]}]},
                "offset": {"$difference": ["$wordsize", {"$product": [{"$sum": [{"$remainder": ["i", "0x10"]}, "0x01"]}, "0x02"]}]},
                "length": "0x02"
            }}}
        }));
        let regions = dereferenced(&template, &[], &Storage(BTreeMap::new()));
        assert_eq!(
            regions
                .iter()
                .map(|region| region.offset)
                .collect::<Vec<_>>(),
            vec![30, 28, 26]
        );
        assert!(regions
            .iter()
            .all(|region| region.slot == Some(word(6)) && region.length == 2));
    }

    #[test]
    fn templates_are_resolved_and_their_regions_renamed() {
        let mut templates = BTreeMap::new();
        templates.insert(
            "slot-of".to_owned(),
            parse_template(json!({"expect": ["n"], "for": {"name": "value", "location": "storage", "slot": "n"}})),
        );
        let root = parse_template(json!({
            "expect": ["n"],
            "for": {"group": [
                {"template": "slot-of", "yields": {"value": "first"}},
                {"templates": {"local": {"expect": [], "for": {"name": "value", "location": "storage", "slot": {"$sum": [{".slot": "first"}, 1]}}}},
                 "in": {"template": "local"}}
            ]}
        }));
        let regions = dereference(
            &root,
            &[("n".to_owned(), vec![5])],
            &templates,
            &Storage(BTreeMap::new()),
        )
        .expect("dereference");
        assert_eq!(
            regions
                .iter()
                .map(|region| region.name.clone())
                .collect::<Vec<_>>(),
            vec![Some("first".to_owned()), Some("value".to_owned())]
        );
        assert_eq!(regions[1].slot, Some(word(6)));

        let unknown = parse_template(json!({"expect": [], "for": {"template": "missing"}}));
        let error =
            dereference(&unknown, &[], &templates, &Storage(BTreeMap::new())).expect_err("unknown");
        assert!(
            error
                .to_string()
                .contains("no pointer template named `missing`"),
            "{error}"
        );

        let mut cyclic = BTreeMap::new();
        cyclic.insert(
            "loop".to_owned(),
            parse_template(json!({"expect": [], "for": {"template": "loop"}})),
        );
        let error = dereference(&cyclic["loop"], &[], &cyclic, &Storage(BTreeMap::new()))
            .expect_err("cycle");
        assert!(error.to_string().contains("cycle"), "{error}");
    }

    #[test]
    fn regions_spanning_slots_read_the_following_slots() {
        let region = Region {
            name: None,
            location: Location::Storage,
            slot: Some(word(1)),
            offset: 30,
            length: 4,
        };
        let mut first = [0_u8; 32];
        first[30] = 1;
        first[31] = 2;
        let mut second = [0_u8; 32];
        second[0] = 3;
        second[1] = 4;
        let storage = Storage([(word(1), first), (word(2), second)].into_iter().collect());
        assert_eq!(
            read_region(&region, &storage).expect("bytes"),
            vec![1, 2, 3, 4]
        );
        let machine = StorageMachine {
            storage: &|slot| storage.0.get(slot).copied(),
            transient: None,
        };
        assert_eq!(
            read_region(&region, &machine).expect("bytes"),
            vec![1, 2, 3, 4]
        );
        let transient = Region {
            location: Location::Transient,
            ..region.clone()
        };
        assert!(read_region(&transient, &machine).is_err());
    }

    #[test]
    fn arithmetic_follows_the_format() {
        let storage = Storage(BTreeMap::new());
        let evaluate = |expression: serde_json::Value| {
            let template = parse_template(
                json!({"expect": [], "for": {"location": "storage", "slot": expression}}),
            );
            dereferenced(&template, &[], &storage)[0]
                .slot
                .expect("slot")
        };
        assert_eq!(evaluate(json!({"$sum": [1, 2, 3]})), word(6));
        assert_eq!(evaluate(json!({"$difference": [3, 5]})), word(0));
        assert_eq!(evaluate(json!({"$product": [4, 5]})), word(20));
        assert_eq!(evaluate(json!({"$quotient": [7, 2]})), word(3));
        assert_eq!(evaluate(json!({"$remainder": [7, 2]})), word(1));
        assert_eq!(evaluate(json!({"$sized1": "0xffff"})), word(0xff));
        assert_eq!(evaluate(json!({"$concat": ["0x01", "0x02"]})), word(0x0102));
        assert_eq!(number_bytes(0), vec![0]);
        assert_eq!(number_bytes(256), vec![1, 0]);

        let division = parse_template(
            json!({"expect": [], "for": {"location": "storage", "slot": {"$quotient": [1, 0]}}}),
        );
        assert!(dereference(&division, &[], &BTreeMap::new(), &storage).is_err());
        let overflow = parse_template(
            json!({"expect": [], "for": {"location": "storage", "slot": {"$product": [
            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 2]}}}),
        );
        assert!(dereference(&overflow, &[], &BTreeMap::new(), &storage).is_err());
    }
}
