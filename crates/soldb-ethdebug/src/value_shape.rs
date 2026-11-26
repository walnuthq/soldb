//! A decoded value as the parts it is made of.
//!
//! Decoding a variable reads words through its type and produces the text a debugger
//! shows by default: `1500000000000000000`, `{ owner: 0xabc…, limit: 5 }`. A frontend
//! that lets users choose how values look — token amounts in their decimals, a timestamp
//! as a date, a struct as a one-line summary — needs more than that text: it needs to
//! know which part is a number of which type, and what each member is called. A
//! [`ValueShape`] is that structure, built alongside the default text and rendering
//! back to exactly it, so showing a value another way never decodes it a second time.

use crate::storage_layout::word_to_decimal;

/// What one decoded value is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueShape {
    /// A value type in one word, or in part of one: the part a format applies to.
    Scalar(Scalar),
    /// A struct's members, in declaration order.
    Struct {
        /// The struct type as written, such as `Item` or `Pool.Position`.
        ty: String,
        members: Vec<(String, ValueShape)>,
    },
    /// The first elements of an array, and how many more it has.
    Array {
        elements: Vec<ValueShape>,
        more: u64,
    },
    /// Shown as it is: a string, bytes, a pointer, or a placeholder.
    Text(String),
}

/// Whether a scalar is a number, and how its bytes are read as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarKind {
    /// An unsigned integer, or a user-defined value type over one.
    Unsigned,
    /// A two's-complement integer, or a user-defined value type over one.
    Signed,
    /// Anything else in one word: an address, a contract, a `bool`, fixed bytes, an enum.
    Other,
}

/// One value type, with the text it decodes to by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scalar {
    /// The declared type, such as `uint256`, `Price`, or `Shop.Color`.
    pub ty: String,
    pub kind: ScalarKind,
    /// The value's bytes, big-endian: as many as the type occupies in storage, or the
    /// whole word on the stack and in memory.
    pub bytes: Vec<u8>,
    /// The default text, as the debugger shows the value without a format.
    pub shown: String,
}

impl Scalar {
    /// A scalar of type `ty`, whose kind follows `underlying`: the type itself, or the
    /// type a user-defined value type wraps.
    #[must_use]
    pub fn new(ty: &str, underlying: &str, bytes: &[u8], shown: String) -> Self {
        Self {
            ty: ty.to_owned(),
            kind: scalar_kind(underlying),
            bytes: bytes.to_vec(),
            shown,
        }
    }

    /// Whether the value is an integer, which numeric formats apply to.
    #[must_use]
    pub fn is_integer(&self) -> bool {
        self.kind != ScalarKind::Other
    }

    /// The value as a sign and a big-endian magnitude.
    #[must_use]
    pub fn magnitude(&self) -> (bool, Vec<u8>) {
        let negative = self.kind == ScalarKind::Signed
            && self.bytes.first().is_some_and(|byte| byte & 0x80 != 0);
        if !negative {
            return (false, self.bytes.clone());
        }
        // Negate the two's complement: invert every byte and add one.
        let mut magnitude = self.bytes.iter().map(|byte| !byte).collect::<Vec<_>>();
        for byte in magnitude.iter_mut().rev() {
            let (sum, carry) = byte.overflowing_add(1);
            *byte = sum;
            if !carry {
                break;
            }
        }
        (true, magnitude)
    }

    /// The value in decimal, sign included, however wide it is.
    #[must_use]
    pub fn decimal(&self) -> String {
        let (negative, magnitude) = self.magnitude();
        let digits = word_to_decimal(&magnitude);
        if negative {
            format!("-{digits}")
        } else {
            digits
        }
    }
}

/// How the bytes of a value of type `ty` read as a number.
#[must_use]
pub fn scalar_kind(ty: &str) -> ScalarKind {
    let ty = ty.trim();
    if is_integer_named(ty, "uint") {
        ScalarKind::Unsigned
    } else if is_integer_named(ty, "int") {
        ScalarKind::Signed
    } else {
        ScalarKind::Other
    }
}

/// Whether `ty` is `prefix` alone or followed by a bit width, as `uint` and `uint128` are.
fn is_integer_named(ty: &str, prefix: &str) -> bool {
    ty.strip_prefix(prefix)
        .is_some_and(|bits| bits.bytes().all(|byte| byte.is_ascii_digit()))
}

impl ValueShape {
    /// A shape shown as `text`, with no parts a format could apply to.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text(text.into())
    }

    /// The text the debugger shows for the value by default.
    #[must_use]
    pub fn render(&self) -> String {
        self.render_named("", &mut |_, scalar| scalar.shown.clone())
    }

    /// The value's text with each scalar shown by `scalar`, which is given the name the
    /// scalar is shown under: its member's name, or `name` for the value itself and for
    /// the elements of an array.
    pub fn render_named(
        &self,
        name: &str,
        scalar: &mut dyn FnMut(&str, &Scalar) -> String,
    ) -> String {
        match self {
            Self::Scalar(value) => scalar(name, value),
            Self::Struct { members, .. } => struct_text(
                members
                    .iter()
                    .map(|(member, shape)| (member.as_str(), shape.render_named(member, scalar))),
            ),
            Self::Array { elements, more } => array_text(
                elements
                    .iter()
                    .map(|element| element.render_named(name, scalar)),
                *more,
            ),
            Self::Text(text) => text.clone(),
        }
    }
}

/// A struct's members as the debugger shows them: `{ a: 1, b: 2 }`.
pub fn struct_text<'a>(members: impl IntoIterator<Item = (&'a str, String)>) -> String {
    let parts = members
        .into_iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect::<Vec<_>>();
    format!("{{ {} }}", parts.join(", "))
}

/// An array's elements as the debugger shows them: `[1, 2, ... 3 more]`.
pub fn array_text(elements: impl IntoIterator<Item = String>, more: u64) -> String {
    let mut parts = elements.into_iter().collect::<Vec<_>>();
    if more > 0 {
        parts.push(format!("... {more} more"));
    }
    format!("[{}]", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::{scalar_kind, Scalar, ScalarKind, ValueShape};

    fn number(ty: &str, bytes: &[u8]) -> ValueShape {
        let scalar = Scalar::new(ty, ty, bytes, String::new());
        let shown = scalar.decimal();
        ValueShape::Scalar(Scalar { shown, ..scalar })
    }

    #[test]
    fn integer_kinds_follow_the_type_name() {
        assert_eq!(scalar_kind("uint256"), ScalarKind::Unsigned);
        assert_eq!(scalar_kind("uint"), ScalarKind::Unsigned);
        assert_eq!(scalar_kind("int8"), ScalarKind::Signed);
        assert_eq!(scalar_kind("address"), ScalarKind::Other);
        assert_eq!(scalar_kind("bytes32"), ScalarKind::Other);
        assert_eq!(scalar_kind("interface IERC20"), ScalarKind::Other);
        assert_eq!(scalar_kind("uintx"), ScalarKind::Other);
    }

    #[test]
    fn signed_scalars_read_their_twos_complement() {
        let minus_two = Scalar::new("int8", "int8", &[0xfe], String::new());
        assert_eq!(minus_two.magnitude(), (true, vec![0x02]));
        assert_eq!(minus_two.decimal(), "-2");
        let max = Scalar::new("uint256", "uint256", &[0xff; 32], String::new());
        assert_eq!(
            max.decimal(),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }

    #[test]
    fn shapes_render_back_to_the_default_text() {
        let shape = ValueShape::Struct {
            ty: "Item".to_owned(),
            members: vec![
                ("price".to_owned(), number("uint256", &[0x10])),
                (
                    "tags".to_owned(),
                    ValueShape::Array {
                        elements: vec![number("uint8", &[1]), number("uint8", &[2])],
                        more: 3,
                    },
                ),
                ("name".to_owned(), ValueShape::text("\"pen\"")),
            ],
        };
        assert_eq!(
            shape.render(),
            "{ price: 16, tags: [1, 2, ... 3 more], name: \"pen\" }"
        );
        let empty = ValueShape::Struct {
            ty: "Empty".to_owned(),
            members: Vec::new(),
        };
        assert_eq!(empty.render(), "{  }");
        let mut names = Vec::new();
        shape.render_named("item", &mut |name, scalar| {
            names.push(name.to_owned());
            scalar.shown.clone()
        });
        assert_eq!(names, ["price", "tags", "tags"]);
    }
}
