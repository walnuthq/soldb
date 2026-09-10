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
//! follows, and remembers which contract it was declared in and which contracts that one
//! inherits from, so a bare `Item` resolves the way the language resolves it: in the
//! contract whose code is executing, then in its bases, then at file level.

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

/// A `contract`, `library`, or `interface` block.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Scope {
    name: String,
    source_id: u64,
    start: usize,
    end: usize,
    /// The contracts named after `is`, in order.
    bases: Vec<String>,
}

/// The struct, enum, and user-defined value type declarations of a set of sources.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceTypes {
    structs: Vec<StructDecl>,
    enums: Vec<EnumDecl>,
    value_types: Vec<ValueTypeDecl>,
    scopes: Vec<Scope>,
}

impl SourceTypes {
    /// The declarations of one source, given id 0.
    #[must_use]
    pub fn parse(source: &str) -> Self {
        let mut types = Self::default();
        types.add_source(0, source);
        types
    }

    /// Adds the declarations of another source.
    pub fn add_source(&mut self, source_id: u64, source: &str) {
        let code = code_ranges(source);
        let scopes = scan_scopes(source, source_id, &code);
        let scope_of = |offset: usize| -> Option<String> {
            scopes
                .iter()
                .filter(|scope| scope.start <= offset && offset < scope.end)
                .min_by_key(|scope| scope.end - scope.start)
                .map(|scope| scope.name.clone())
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
        self.scopes.extend(scopes);
    }

    /// Whether any declaration was found.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.structs.is_empty() && self.enums.is_empty() && self.value_types.is_empty()
    }

    /// The contract, library, or interface whose block contains `offset` of the source,
    /// innermost first: the scope a name written there resolves in.
    #[must_use]
    pub fn scope_at(&self, source_id: u64, offset: u64) -> Option<&str> {
        let offset = usize::try_from(offset).ok()?;
        self.scopes
            .iter()
            .filter(|scope| {
                scope.source_id == source_id && scope.start <= offset && offset < scope.end
            })
            .min_by_key(|scope| scope.end - scope.start)
            .map(|scope| scope.name.as_str())
    }

    /// The members of the struct `name` names, as written in `scope` (a contract name,
    /// or `None` for file level); `name` may be qualified as `Contract.Name`.
    #[must_use]
    pub fn struct_members(&self, scope: Option<&str>, name: &str) -> Option<&[StructMember]> {
        self.resolve(
            self.structs.iter(),
            |decl| (&decl.name, decl.scope.as_deref()),
            scope,
            name,
        )
        .map(|decl| decl.members.as_slice())
    }

    /// The variants of the enum `name` names, in declaration order.
    #[must_use]
    pub fn enum_variants(&self, scope: Option<&str>, name: &str) -> Option<&[String]> {
        self.resolve(
            self.enums.iter(),
            |decl| (&decl.name, decl.scope.as_deref()),
            scope,
            name,
        )
        .map(|decl| decl.variants.as_slice())
    }

    /// The type a user-defined value type wraps.
    #[must_use]
    pub fn underlying(&self, scope: Option<&str>, name: &str) -> Option<&str> {
        self.resolve(
            self.value_types.iter(),
            |decl| (&decl.name, decl.scope.as_deref()),
            scope,
            name,
        )
        .map(|decl| decl.underlying.as_str())
    }

    /// The value of an enum literal such as `Color.Red` or `Shop.Color.Red`.
    #[must_use]
    pub fn enum_literal(&self, scope: Option<&str>, path: &str) -> Option<u64> {
        let (enum_name, variant) = path.rsplit_once('.')?;
        let variants = self.enum_variants(scope, enum_name)?;
        variants
            .iter()
            .position(|candidate| candidate == variant)
            .map(|index| index as u64)
    }

    /// Whether `name` is a struct, however qualified.
    #[must_use]
    pub fn is_struct(&self, scope: Option<&str>, name: &str) -> bool {
        self.struct_members(scope, name).is_some()
    }

    /// Every enum's variants, keyed the way a storage layout labels the type
    /// (`Shop.Color`) and by its bare name (`Color`), for
    /// [`soldb_ethdebug::StorageLayout::enum_variants`]. A bare name declared twice keeps
    /// its first declaration.
    #[must_use]
    pub fn enum_variants_by_name(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        let mut names = std::collections::BTreeMap::new();
        for decl in &self.enums {
            if let Some(scope) = &decl.scope {
                names
                    .entry(format!("{scope}.{}", decl.name))
                    .or_insert_with(|| decl.variants.clone());
            }
            names
                .entry(decl.name.clone())
                .or_insert_with(|| decl.variants.clone());
        }
        names
    }

    /// The contracts `scope` inherits from, nearest first, transitively.
    fn bases(&self, scope: &str) -> Vec<&str> {
        let mut seen = Vec::<&str>::new();
        let mut queue = self
            .scopes
            .iter()
            .filter(|candidate| candidate.name == scope)
            .flat_map(|candidate| candidate.bases.iter().map(String::as_str))
            .collect::<std::collections::VecDeque<_>>();
        while let Some(base) = queue.pop_front() {
            if seen.contains(&base) {
                continue;
            }
            seen.push(base);
            queue.extend(
                self.scopes
                    .iter()
                    .filter(|candidate| candidate.name == base)
                    .flat_map(|candidate| candidate.bases.iter().map(String::as_str)),
            );
        }
        seen
    }

    /// Finds the declaration `name` refers to from `scope`. A qualified name must match
    /// its scope; a bare name is looked up in `scope`, then in the contracts it inherits
    /// from, then at file level, and failing all of those wherever it is declared.
    fn resolve<'a, T>(
        &'a self,
        declarations: impl Iterator<Item = &'a T> + Clone,
        key: impl Fn(&'a T) -> (&'a String, Option<&'a str>),
        scope: Option<&str>,
        name: &str,
    ) -> Option<&'a T> {
        let (qualifier, bare) = match name.rsplit_once('.') {
            Some((qualifier, bare)) => (Some(qualifier), bare),
            None => (None, name),
        };
        let candidates = declarations
            .filter(|declaration| key(declaration).0 == bare)
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return None;
        }
        let in_scope = |wanted: Option<&str>| {
            candidates
                .iter()
                .copied()
                .find(|declaration| key(declaration).1 == wanted)
        };
        if let Some(qualifier) = qualifier {
            // `A.Item` where the declaration is `B.Item`: the wrong scope, unless nothing
            // better turns up.
            return in_scope(Some(qualifier)).or_else(|| candidates.first().copied());
        }
        if let Some(scope) = scope {
            if let Some(found) = in_scope(Some(scope)) {
                return Some(found);
            }
            for base in self.bases(scope) {
                if let Some(found) = in_scope(Some(base)) {
                    return Some(found);
                }
            }
        }
        in_scope(None).or_else(|| candidates.first().copied())
    }
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

/// The `contract`, `library`, and `interface` blocks of a source, with what they inherit.
fn scan_scopes(source: &str, source_id: u64, code: &[(usize, usize)]) -> Vec<Scope> {
    let mut scopes = Vec::new();
    for keyword in ["contract", "library", "interface"] {
        let mut cursor = 0;
        while let Some(at) = find_keyword(source, code, keyword, cursor) {
            cursor = at + keyword.len();
            let Some((name, name_end)) = parse_identifier(source, skip_trivia(source, cursor))
            else {
                continue;
            };
            // `abstract contract X is Y, Z(1) {`: the block opens after the inheritance
            // list, which names the bases.
            let Some(open) = source[name_end..].find('{').map(|found| name_end + found) else {
                continue;
            };
            let header = &source[name_end..open];
            if header.contains(';') {
                continue;
            }
            let Some(close) = find_matching_delimiter(source, open, b'{', b'}') else {
                continue;
            };
            scopes.push(Scope {
                name: name.to_owned(),
                source_id,
                start: open,
                end: close,
                bases: parse_bases(header),
            });
            cursor = open + 1;
        }
    }
    scopes
}

/// The contracts named in an `is A, B(1), C` header, in order.
fn parse_bases(header: &str) -> Vec<String> {
    let trimmed = skip_trivia(header, 0);
    let Some(rest) = header[trimmed..].strip_prefix("is") else {
        return Vec::new();
    };
    if rest
        .bytes()
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return Vec::new();
    }
    let mut bases = Vec::new();
    let mut depth = 0_i32;
    let mut start = 0;
    let bytes = rest.as_bytes();
    for index in 0..=bytes.len() {
        match bytes.get(index) {
            Some(b'(') => {
                if depth == 0 {
                    push_base(&mut bases, &rest[start..index]);
                    start = bytes.len();
                }
                depth += 1;
            }
            Some(b')') => depth -= 1,
            Some(b',') | None if depth == 0 => {
                if start < index {
                    push_base(&mut bases, &rest[start..index]);
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    bases
}

fn push_base(bases: &mut Vec<String>, text: &str) {
    let name = text.trim();
    if is_identifier(name) {
        bases.push(name.to_owned());
    }
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

abstract contract Base is Shop {
    struct Item { uint16 y; }
}

contract Outlet is Base, Math(1) {
    function g() public pure returns (uint256) { return 1; }
}
";

    #[test]
    fn finds_structs_enums_and_value_types_with_their_scopes() {
        let types = SourceTypes::parse(SOURCE);
        assert_eq!(
            types.struct_members(None, "Pair"),
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
        let item = types.struct_members(None, "Shop.Item").expect("Shop.Item");
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
        assert_eq!(
            types.struct_members(None, "Math.Item").map(<[_]>::len),
            Some(1)
        );
        assert_eq!(
            types
                .enum_variants(None, "Color")
                .map(|variants| variants.join(",")),
            Some("Red,Green,Blue".to_owned())
        );
        assert_eq!(
            types
                .enum_variants(None, "Level")
                .map(|variants| variants.join(",")),
            Some("Low,High".to_owned())
        );
        assert_eq!(types.underlying(None, "Price"), Some("uint128"));
        assert_eq!(types.underlying(None, "Shop.Money"), Some("uint256"));
        assert_eq!(types.enum_literal(None, "Color.Green"), Some(1));
        assert_eq!(types.enum_literal(None, "Shop.Color.Blue"), Some(2));
        assert_eq!(types.enum_literal(None, "Color.Purple"), None);
        assert_eq!(types.enum_literal(None, "Missing.Red"), None);
        assert!(types.struct_members(None, "Nothing").is_none());
        let names = types.enum_variants_by_name();
        assert_eq!(names["Shop.Color"], ["Red", "Green", "Blue"]);
        assert_eq!(names["Color"], ["Red", "Green", "Blue"]);
        assert_eq!(names["Level"], ["Low", "High"]);
    }

    #[test]
    fn a_bare_name_resolves_in_the_executing_contract_then_its_bases() {
        let types = SourceTypes::parse(SOURCE);
        // Which `Item` a bare name means depends on where it is written.
        let width = |scope: Option<&str>| {
            types
                .struct_members(scope, "Item")
                .map(|members| members[0].ty.clone())
        };
        assert_eq!(width(Some("Shop")).as_deref(), Some("uint256"));
        assert_eq!(width(Some("Math")).as_deref(), Some("uint8"));
        assert_eq!(width(Some("Base")).as_deref(), Some("uint16"));
        // `Outlet` declares none: its nearest base `Base` does.
        assert_eq!(width(Some("Outlet")).as_deref(), Some("uint16"));
        // An unrelated contract falls back to the first declaration.
        assert_eq!(width(Some("Other")).as_deref(), Some("uint256"));
        assert_eq!(width(None).as_deref(), Some("uint256"));
        // A file-level type wins over another contract's for a bare name.
        assert_eq!(
            types.struct_members(Some("Math"), "Pair").map(<[_]>::len),
            Some(2)
        );
        // Inherited enums resolve the same way.
        assert_eq!(types.enum_literal(Some("Outlet"), "Color.Blue"), Some(2));
        // The scope of an offset is the innermost block containing it.
        let offset = SOURCE.find("function g()").expect("g") as u64;
        assert_eq!(types.scope_at(0, offset), Some("Outlet"));
        assert_eq!(types.scope_at(0, 0), None);
        assert_eq!(types.scope_at(1, offset), None);
    }

    #[test]
    fn ignores_keywords_inside_identifiers_and_comments() {
        let types = SourceTypes::parse(
            "contract C { uint256 mystruct; /* struct Hidden { uint256 x; } */ enum E { A } }",
        );
        assert!(types.struct_members(None, "Hidden").is_none());
        assert_eq!(types.enum_variants(None, "E").map(<[_]>::len), Some(1));
    }
}
