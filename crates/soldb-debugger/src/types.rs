//! Type declarations found in the sources: structs, enums, and user-defined value types.
//!
//! A legacy source map says where a variable's slot is, and the declaration says its
//! type; what the type *means* — which members a struct has, what an enum's values are
//! called, what a `type Price is uint128` wraps — is declared elsewhere in the sources.
//! This scanner collects those declarations so a value can be shown as `Color.Red` rather
//! than `1`, and a memory struct as its members rather than as a pointer.
//!
//! Like the local scanner, it reads the text rather than parsing the language: it finds
//! each declaration keyword outside comments and strings, reads the declaration that
//! follows, and remembers which contract it was declared in, so `Shop.Item` and a bare
//! `Item` both resolve.

use crate::locals::{skip_string, skip_trivia};
use crate::{find_matching_delimiter, find_solidity_keyword, is_identifier, parse_identifier};

/// One member of a struct, in declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructMember {
    pub name: String,
    /// The type as written, with whitespace collapsed: `uint256`, `Item[]`, `mapping(address => uint256)`.
    pub ty: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StructDecl {
    name: String,
    /// The contract, library, or interface the struct is declared in; `None` at file level.
    scope: Option<String>,
    members: Vec<StructMember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnumDecl {
    name: String,
    scope: Option<String>,
    variants: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValueTypeDecl {
    name: String,
    scope: Option<String>,
    underlying: String,
}

/// The struct, enum, and user-defined value type declarations of a set of sources.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceTypes {
    structs: Vec<StructDecl>,
    enums: Vec<EnumDecl>,
    value_types: Vec<ValueTypeDecl>,
}

impl SourceTypes {
    /// The declarations of one source.
    #[must_use]
    pub fn parse(source: &str) -> Self {
        let mut types = Self::default();
        types.add_source(source);
        types
    }

    /// Adds the declarations of another source.
    pub fn add_source(&mut self, source: &str) {
        let code = code_ranges(source);
        let scopes = scan_scopes(source, &code);
        let scope_of = |offset: usize| -> Option<String> {
            scopes
                .iter()
                .filter(|(_, start, end)| *start <= offset && offset < *end)
                .min_by_key(|(_, start, end)| end - start)
                .map(|(name, _, _)| name.clone())
        };
        let mut cursor = 0;
        while let Some(at) = find_keyword(source, &code, "struct", cursor) {
            cursor = at + "struct".len();
            let Some((name, open, close)) = braced_declaration(source, cursor) else {
                continue;
            };
            self.structs.push(StructDecl {
                name: name.to_owned(),
                scope: scope_of(at),
                members: parse_members(&source[open + 1..close]),
            });
            cursor = close + 1;
        }
        let mut cursor = 0;
        while let Some(at) = find_keyword(source, &code, "enum", cursor) {
            cursor = at + "enum".len();
            let Some((name, open, close)) = braced_declaration(source, cursor) else {
                continue;
            };
            let variants = source[open + 1..close]
                .split(',')
                .map(str::trim)
                .filter(|variant| !variant.is_empty())
                .map(str::to_owned)
                .collect();
            self.enums.push(EnumDecl {
                name: name.to_owned(),
                scope: scope_of(at),
                variants,
            });
            cursor = close + 1;
        }
        let mut cursor = 0;
        while let Some(at) = find_keyword(source, &code, "type", cursor) {
            cursor = at + "type".len();
            let Some((name, name_end)) = parse_identifier(source, skip_trivia(source, cursor))
            else {
                continue;
            };
            let after = skip_trivia(source, name_end);
            let Some(("is", is_end)) = parse_identifier(source, after) else {
                continue;
            };
            let underlying_start = skip_trivia(source, is_end);
            let Some(end) = source[underlying_start..].find(';') else {
                continue;
            };
            let underlying = source[underlying_start..underlying_start + end].trim();
            if underlying.is_empty() {
                continue;
            }
            self.value_types.push(ValueTypeDecl {
                name: name.to_owned(),
                scope: scope_of(at),
                underlying: underlying.to_owned(),
            });
            cursor = underlying_start + end;
        }
    }

    /// Whether any declaration was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.structs.is_empty() && self.enums.is_empty() && self.value_types.is_empty()
    }

    /// The members of the struct `name` names, which may be qualified as `Contract.Name`.
    #[must_use]
    pub fn struct_members(&self, name: &str) -> Option<&[StructMember]> {
        resolve(
            self.structs.iter(),
            |decl| (&decl.name, decl.scope.as_deref()),
            name,
        )
        .map(|decl| decl.members.as_slice())
    }

    /// The variants of the enum `name` names, in declaration order.
    #[must_use]
    pub fn enum_variants(&self, name: &str) -> Option<&[String]> {
        resolve(
            self.enums.iter(),
            |decl| (&decl.name, decl.scope.as_deref()),
            name,
        )
        .map(|decl| decl.variants.as_slice())
    }

    /// The type a user-defined value type wraps.
    #[must_use]
    pub fn underlying(&self, name: &str) -> Option<&str> {
        resolve(
            self.value_types.iter(),
            |decl| (&decl.name, decl.scope.as_deref()),
            name,
        )
        .map(|decl| decl.underlying.as_str())
    }

    /// The value of an enum literal such as `Color.Red` or `Shop.Color.Red`.
    #[must_use]
    pub fn enum_literal(&self, path: &str) -> Option<u64> {
        let (enum_name, variant) = path.rsplit_once('.')?;
        let variants = self.enum_variants(enum_name)?;
        variants
            .iter()
            .position(|candidate| candidate == variant)
            .map(|index| index as u64)
    }

    /// Whether `name` is a struct, however qualified.
    #[must_use]
    pub fn is_struct(&self, name: &str) -> bool {
        self.struct_members(name).is_some()
    }
}

/// Finds the declaration `name` refers to: a qualified name must match the scope, a bare
/// name matches any scope, a declaration in one scope over one at file level.
fn resolve<'a, T>(
    declarations: impl Iterator<Item = &'a T>,
    key: impl Fn(&'a T) -> (&'a String, Option<&'a str>),
    name: &str,
) -> Option<&'a T> {
    let (scope, bare) = match name.rsplit_once('.') {
        Some((scope, bare)) => (Some(scope), bare),
        None => (None, name),
    };
    let mut fallback = None;
    for declaration in declarations {
        let (declared, declared_scope) = key(declaration);
        if declared != bare {
            continue;
        }
        match scope {
            Some(scope) => {
                if declared_scope == Some(scope) {
                    return Some(declaration);
                }
                // `A.Item` where the declaration is `B.Item`: the wrong scope, unless
                // nothing better turns up (inheritance is not modelled here).
                fallback.get_or_insert(declaration);
            }
            None => return Some(declaration),
        }
    }
    fallback
}

/// The byte ranges of a source that are code: outside comments and string literals.
fn code_ranges(source: &str) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut ranges = Vec::new();
    let mut index = 0;
    let mut start = 0;
    while index < bytes.len() {
        let skipped = skip_trivia(source, index);
        if skipped != index {
            if start < index {
                ranges.push((start, index));
            }
            index = skipped;
            start = index;
            continue;
        }
        match bytes[index] {
            b'"' | b'\'' => {
                if start < index {
                    ranges.push((start, index));
                }
                index = skip_string(source, index);
                start = index;
            }
            _ => index += 1,
        }
    }
    if start < bytes.len() {
        ranges.push((start, bytes.len()));
    }
    ranges
}

/// The next `keyword` at or after `start` that is code rather than a comment or a string.
fn find_keyword(
    source: &str,
    code: &[(usize, usize)],
    keyword: &str,
    start: usize,
) -> Option<usize> {
    let mut cursor = start;
    while let Some(at) = find_solidity_keyword(source, keyword, cursor) {
        if code.iter().any(|(from, to)| *from <= at && at < *to) {
            return Some(at);
        }
        cursor = at + keyword.len();
    }
    None
}

/// The `contract`, `library`, and `interface` blocks of a source, as (name, open, close).
fn scan_scopes(source: &str, code: &[(usize, usize)]) -> Vec<(String, usize, usize)> {
    let mut scopes = Vec::new();
    for keyword in ["contract", "library", "interface"] {
        let mut cursor = 0;
        while let Some(at) = find_keyword(source, code, keyword, cursor) {
            cursor = at + keyword.len();
            let Some((name, name_end)) = parse_identifier(source, skip_trivia(source, cursor))
            else {
                continue;
            };
            // `abstract contract X is Y, Z {`: the block opens after the inheritance list.
            let Some(open) = source[name_end..].find('{').map(|found| name_end + found) else {
                continue;
            };
            if source[name_end..open].contains(';') {
                continue;
            }
            let Some(close) = find_matching_delimiter(source, open, b'{', b'}') else {
                continue;
            };
            scopes.push((name.to_owned(), open, close));
            cursor = open + 1;
        }
    }
    scopes
}

/// `Name { ... }` after a `struct` or `enum` keyword ending at `after`: the name and the
/// braces.
fn braced_declaration(source: &str, after: usize) -> Option<(&str, usize, usize)> {
    let (name, name_end) = parse_identifier(source, skip_trivia(source, after))?;
    let open = skip_trivia(source, name_end);
    if source.as_bytes().get(open) != Some(&b'{') {
        return None;
    }
    let close = find_matching_delimiter(source, open, b'{', b'}')?;
    Some((name, open, close))
}

/// The `type name;` members between a struct's braces.
fn parse_members(body: &str) -> Vec<StructMember> {
    let mut members = Vec::new();
    let mut index = 0;
    while index < body.len() {
        index = skip_trivia(body, index);
        if index >= body.len() {
            break;
        }
        let Some(end) = find_member_end(body, index) else {
            break;
        };
        if let Some((ty, name)) = split_member(&body[index..end]) {
            members.push(StructMember { name, ty });
        }
        index = end + 1;
    }
    members
}

/// A member's `type name` text as its type, with whitespace collapsed, and its name.
fn split_member(text: &str) -> Option<(String, String)> {
    let text = text.trim();
    let name_start = text
        .rfind(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .map_or(0, |index| index + 1);
    let name = &text[name_start..];
    let ty = text[..name_start]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if !is_identifier(name) || ty.is_empty() {
        return None;
    }
    Some((ty, name.to_owned()))
}

/// The `;` that ends the member starting at `index`, outside any parentheses (a mapping
/// type carries `=>` and could carry a nested mapping's parentheses).
fn find_member_end(body: &str, index: usize) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut depth = 0_i32;
    for (offset, byte) in bytes.iter().enumerate().skip(index) {
        match byte {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b';' if depth <= 0 => return Some(offset),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{SourceTypes, StructMember};

    const SOURCE: &str = "\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

type Price is uint128;

struct Pair {
    uint256 a;
    uint256 b;
}

enum Level { Low, High }

contract Shop {
    enum Color { Red, Green, Blue }
    struct Item {
        uint256 id;
        string name;
        Color color;
        uint256[] tags;
        mapping(address => uint256) owners;
        Pair[2] pairs;
    }
    type Money is uint256;
    function f() public pure returns (uint256) { return 0; } // struct in a comment
}

library Math {
    struct Item { uint8 x; }
}
";

    #[test]
    fn finds_structs_enums_and_value_types_with_their_scopes() {
        let types = SourceTypes::parse(SOURCE);
        assert_eq!(
            types.struct_members("Pair"),
            Some(
                &[
                    StructMember {
                        name: "a".to_owned(),
                        ty: "uint256".to_owned()
                    },
                    StructMember {
                        name: "b".to_owned(),
                        ty: "uint256".to_owned()
                    },
                ][..]
            )
        );
        let item = types.struct_members("Shop.Item").expect("Shop.Item");
        assert_eq!(
            item.iter()
                .map(|member| (member.name.as_str(), member.ty.as_str()))
                .collect::<Vec<_>>(),
            [
                ("id", "uint256"),
                ("name", "string"),
                ("color", "Color"),
                ("tags", "uint256[]"),
                ("owners", "mapping(address => uint256)"),
                ("pairs", "Pair[2]"),
            ]
        );
        // A bare name resolves to the first declaration; a qualified one to its scope.
        assert_eq!(types.struct_members("Item").map(<[_]>::len), Some(6));
        assert_eq!(types.struct_members("Math.Item").map(<[_]>::len), Some(1));
        assert_eq!(
            types
                .enum_variants("Color")
                .map(|variants| variants.join(",")),
            Some("Red,Green,Blue".to_owned())
        );
        assert_eq!(
            types
                .enum_variants("Level")
                .map(|variants| variants.join(",")),
            Some("Low,High".to_owned())
        );
        assert_eq!(types.underlying("Price"), Some("uint128"));
        assert_eq!(types.underlying("Shop.Money"), Some("uint256"));
        assert_eq!(types.enum_literal("Color.Green"), Some(1));
        assert_eq!(types.enum_literal("Shop.Color.Blue"), Some(2));
        assert_eq!(types.enum_literal("Color.Purple"), None);
        assert_eq!(types.enum_literal("Missing.Red"), None);
        assert!(types.struct_members("Nothing").is_none());
    }

    #[test]
    fn ignores_keywords_inside_identifiers_and_comments() {
        let types = SourceTypes::parse(
            "contract C { uint256 mystruct; /* struct Hidden { uint256 x; } */ enum E { A } }",
        );
        assert!(types.struct_members("Hidden").is_none());
        assert_eq!(types.enum_variants("E").map(<[_]>::len), Some(1));
    }
}
