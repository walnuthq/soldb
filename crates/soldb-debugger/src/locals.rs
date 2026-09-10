//! Local variable declarations, found by scanning a function body.
//!
//! solc's legacy code generator reserves one stack slot for a local variable when its
//! declaration executes and frees it at the end of the enclosing block, so a debugger that
//! knows where each declaration is in the source, and which block it belongs to, can
//! follow the slot through the trace. This scanner finds those declarations: plain ones
//! (`uint256 twice = a * 2;`), tuple ones (`(uint256 q, uint256 r) = divmod(x, y);`), and
//! `for` initialisers, each with the span the compiler attributes the reservation to,
//! the statement it belongs to, and the block it lives in.
//!
//! It is a scanner, not a parser: it walks the body byte by byte, skips comments and
//! strings, and only looks closely at the start of each statement. What it cannot read
//! it leaves out, and a variable it leaves out is simply not shown, which is the right
//! failure for a debugger.

use crate::{
    find_matching_delimiter, find_solidity_keyword, is_identifier, parse_identifier,
    skip_ascii_whitespace, ByteRange, SourceLocal,
};

/// Words that neither begin a local declaration's type nor name a variable.
const RESERVED: [&str; 45] = [
    "abstract",
    "as",
    "assembly",
    "assert",
    "break",
    "catch",
    "constant",
    "continue",
    "contract",
    "delete",
    "do",
    "else",
    "emit",
    "enum",
    "error",
    "event",
    "external",
    "false",
    "for",
    "from",
    "function",
    "if",
    "immutable",
    "import",
    "interface",
    "internal",
    "is",
    "library",
    "mapping",
    "modifier",
    "new",
    "override",
    "payable",
    "pragma",
    "private",
    "public",
    "pure",
    "require",
    "return",
    "returns",
    "revert",
    "struct",
    "true",
    "try",
    "unchecked",
];

/// The data locations a declaration may carry between its type and its name.
const LOCATIONS: [&str; 3] = ["memory", "storage", "calldata"];

/// One variable a declaration introduces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Declared {
    pub name: String,
    pub ty: String,
    pub location: Option<String>,
    /// `type [location] name`, or the type alone for an unnamed return parameter.
    pub span: ByteRange,
}

/// Every local variable declared in the body that opens at `body_start` and closes at
/// `body_end`, in declaration order.
pub(crate) fn scan_locals(source: &str, body_start: usize, body_end: usize) -> Vec<SourceLocal> {
    let mut locals = Vec::new();
    if body_start < body_end && body_end <= source.len() {
        scan_block(source, body_start, body_end, &mut locals);
    }
    locals
}

/// Scans the statements of the block whose braces are at `open` and `close`.
fn scan_block(source: &str, open: usize, close: usize, out: &mut Vec<SourceLocal>) {
    let bytes = source.as_bytes();
    let mut index = open + 1;
    let mut statement_start = true;
    while index < close {
        index = skip_trivia(source, index);
        if index >= close {
            break;
        }
        match bytes[index] {
            b'{' => {
                let Some(end) = find_matching_delimiter(source, index, b'{', b'}') else {
                    return;
                };
                scan_block(source, index, end.min(close), out);
                index = end + 1;
                statement_start = true;
                continue;
            }
            b'}' | b';' => {
                index += 1;
                statement_start = true;
                continue;
            }
            b'"' | b'\'' => {
                index = skip_string(source, index);
                statement_start = false;
                continue;
            }
            _ => {}
        }
        if !statement_start {
            index = match parse_identifier(source, index) {
                Some((_, end)) => end,
                None => index + 1,
            };
            continue;
        }
        statement_start = false;
        if let Some((word, end)) = parse_identifier(source, index) {
            match word {
                "for" => {
                    if let Some(next) = scan_for(source, end, close, out) {
                        index = next;
                        statement_start = true;
                        continue;
                    }
                }
                "assembly" => {
                    // A Yul block declares no Solidity locals; skip it whole, including a
                    // dialect string such as `assembly ("memory-safe")`.
                    if let Some(block) = find_byte(source, end, close, b'{') {
                        if let Some(block_end) = find_matching_delimiter(source, block, b'{', b'}')
                        {
                            index = block_end + 1;
                            statement_start = true;
                            continue;
                        }
                    }
                }
                // A `try` clause's return parameters and a `catch` clause's parameters are
                // variables of the clause block that follows.
                "try" | "catch" => {
                    if let Some(block) = scan_clause(source, word, end, close, out) {
                        index = block;
                        continue;
                    }
                }
                // What follows these is a statement of its own.
                "else" | "unchecked" | "do" => {
                    index = end;
                    statement_start = true;
                    continue;
                }
                _ => {}
            }
        }
        if let Some((declared, end)) = parse_declaration(source, index, close) {
            let statement = ByteRange {
                start: index as u64,
                end: find_statement_end(source, end, close) as u64,
            };
            for (position, variable) in declared.into_iter().enumerate() {
                out.push(SourceLocal {
                    name: variable.name,
                    ty: variable.ty,
                    location: variable.location,
                    declaration: variable.span,
                    statement,
                    position,
                    scope: ByteRange {
                        start: variable.span.start,
                        end: close as u64,
                    },
                });
            }
            index = statement.end as usize;
            continue;
        }
        index = match parse_identifier(source, index) {
            Some((_, end)) => end,
            None => index + 1,
        };
    }
}

/// A `for` statement whose keyword ends at `after_for`: its initialiser's variables are in
/// scope for the whole statement, loop body included. Returns where scanning resumes.
fn scan_for(
    source: &str,
    after_for: usize,
    close: usize,
    out: &mut Vec<SourceLocal>,
) -> Option<usize> {
    let bytes = source.as_bytes();
    let paren = skip_trivia(source, after_for);
    if bytes.get(paren) != Some(&b'(') {
        return None;
    }
    let paren_end = find_matching_delimiter(source, paren, b'(', b')')?;
    if paren_end > close {
        return None;
    }
    let body = skip_trivia(source, paren_end + 1);
    let for_end = if bytes.get(body) == Some(&b'{') {
        find_matching_delimiter(source, body, b'{', b'}')?
    } else {
        find_statement_end(source, body, close)
    };
    let keyword = source[..after_for].rfind("for").unwrap_or(after_for);
    let init = skip_trivia(source, paren + 1);
    if let Some((declared, end)) = parse_declaration(source, init, paren_end) {
        let statement = ByteRange {
            start: init as u64,
            end: find_statement_end(source, end, paren_end) as u64,
        };
        for (position, variable) in declared.into_iter().enumerate() {
            out.push(SourceLocal {
                name: variable.name,
                ty: variable.ty,
                location: variable.location,
                declaration: variable.span,
                statement,
                position,
                // Instructions of the loop itself carry the statement's span, which begins
                // at `for`; the variable must stay in scope through them.
                scope: ByteRange {
                    start: keyword as u64,
                    end: for_end as u64 + 1,
                },
            });
        }
    }
    // The body block is scanned by the caller like any other block.
    Some(paren_end + 1)
}

/// A `try` or `catch` clause whose keyword ends at `after`: `try <call> [returns (params)]
/// { ... }` or `catch [Error|Panic] [(params)] { ... }`. The parameters are variables of
/// the clause block. Returns the position of the block's opening brace.
fn scan_clause(
    source: &str,
    keyword: &str,
    after: usize,
    close: usize,
    out: &mut Vec<SourceLocal>,
) -> Option<usize> {
    let bytes = source.as_bytes();
    let block = find_block_open(source, after, close)?;
    let open = if keyword == "try" {
        let returns = find_solidity_keyword(source, "returns", after).filter(|at| *at < block)?;
        skip_trivia(source, returns + "returns".len())
    } else {
        let mut cursor = skip_trivia(source, after);
        if let Some((_, end)) = parse_identifier(source, cursor) {
            cursor = skip_trivia(source, end);
        }
        cursor
    };
    if bytes.get(open) != Some(&b'(') {
        return Some(block);
    }
    let close_paren = find_matching_delimiter(source, open, b'(', b')').filter(|at| *at < block)?;
    let block_end = find_matching_delimiter(source, block, b'{', b'}').unwrap_or(close);
    let mut start = open + 1;
    let mut depth = 0_i32;
    let mut position = 0;
    for (index, byte) in bytes
        .iter()
        .enumerate()
        .take(close_paren + 1)
        .skip(open + 1)
    {
        match *byte {
            b'(' | b'[' => depth += 1,
            b')' | b']' if depth > 0 => depth -= 1,
            b',' | b')' => {
                if let Some((component_start, component_end)) = trimmed_range(source, start, index)
                {
                    if let Some(variable) = parse_typed_name(source, component_start, component_end)
                    {
                        out.push(SourceLocal {
                            name: variable.name,
                            ty: variable.ty,
                            location: variable.location,
                            declaration: variable.span,
                            statement: variable.span,
                            position,
                            scope: ByteRange {
                                start: variable.span.start,
                                end: block_end as u64,
                            },
                        });
                        position += 1;
                    }
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    Some(block)
}

/// The `_;` placeholder of a modifier body, where the function it modifies runs.
pub(crate) fn find_placeholder(source: &str, body_start: usize, body_end: usize) -> Option<u64> {
    let bytes = source.as_bytes();
    let mut index = body_start + 1;
    while index < body_end {
        index = skip_trivia(source, index);
        match bytes.get(index) {
            Some(b'"' | b'\'') => {
                index = skip_string(source, index);
                continue;
            }
            Some(b'_') => {
                let before = bytes.get(index.wrapping_sub(1)).copied();
                let after = skip_trivia(source, index + 1);
                if before.is_none_or(|byte| !crate::is_identifier_byte(byte))
                    && bytes.get(after) == Some(&b';')
                {
                    return Some(index as u64);
                }
                index += 1;
            }
            Some(_) => {
                index = match parse_identifier(source, index) {
                    Some((_, end)) => end,
                    None => index + 1,
                };
            }
            None => break,
        }
    }
    None
}

/// The first `{` at or after `from` and before `limit` that is not inside parentheses,
/// strings, or comments: the opening brace of a clause block.
fn find_block_open(source: &str, from: usize, limit: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = from;
    let mut depth = 0_i32;
    while index < limit {
        index = skip_trivia(source, index);
        match bytes.get(index) {
            Some(b'"' | b'\'') => {
                index = skip_string(source, index);
                continue;
            }
            Some(b'(' | b'[') => depth += 1,
            Some(b')' | b']') => depth -= 1,
            Some(b'{') if depth <= 0 => return Some(index),
            Some(b';') if depth <= 0 => return None,
            Some(_) => {}
            None => break,
        }
        index += 1;
    }
    None
}

/// The variables a declaration statement starting at `index` introduces, and where its
/// declaration part ends: a `type [location] name` followed by `=` or `;`, or a tuple of
/// them followed by `=`. Anything else, an assignment or a call, is not a declaration.
pub(crate) fn parse_declaration(
    source: &str,
    index: usize,
    limit: usize,
) -> Option<(Vec<Declared>, usize)> {
    let bytes = source.as_bytes();
    if bytes.get(index) == Some(&b'(') {
        let close = find_matching_delimiter(source, index, b'(', b')')?;
        if close > limit || !starts_assignment(source, close + 1) {
            return None;
        }
        let mut declared = Vec::new();
        let mut start = index + 1;
        let mut depth = 0_i32;
        for (position, byte) in bytes.iter().enumerate().take(close + 1).skip(index + 1) {
            match *byte {
                b'(' | b'[' => depth += 1,
                b')' | b']' if depth > 0 => depth -= 1,
                b',' | b')' => {
                    let component = trimmed_range(source, start, position);
                    if let Some((component_start, component_end)) = component {
                        declared.push(parse_typed_name(source, component_start, component_end)?);
                    }
                    start = position + 1;
                }
                _ => {}
            }
        }
        return (!declared.is_empty()).then_some((declared, close + 1));
    }
    let variable = parse_typed_name(source, index, limit)?;
    let end = variable.span.end as usize;
    let after = skip_trivia(source, end);
    if bytes.get(after) == Some(&b';') || starts_assignment(source, after) {
        return Some((vec![variable], end));
    }
    None
}

/// `type [payable] [location] name` at `index`, ending before `limit`.
fn parse_typed_name(source: &str, index: usize, limit: usize) -> Option<Declared> {
    let (ty, ty_end) = parse_type(source, index, limit)?;
    let mut cursor = skip_trivia(source, ty_end);
    let mut location = None;
    if let Some((word, end)) = parse_identifier(source, cursor) {
        if LOCATIONS.contains(&word) {
            location = Some(word.to_owned());
            cursor = skip_trivia(source, end);
        }
    }
    let (name, name_end) = parse_identifier(source, cursor)?;
    if name_end > limit || RESERVED.contains(&name) || !is_identifier(name) {
        return None;
    }
    Some(Declared {
        name: name.to_owned(),
        ty,
        location,
        span: ByteRange {
            start: index as u64,
            end: name_end as u64,
        },
    })
}

/// A return parameter at `index`: like a typed name, but the name is optional and an
/// unnamed one takes `retN`.
pub(crate) fn parse_return(
    source: &str,
    index: usize,
    limit: usize,
    position: usize,
) -> Option<Declared> {
    if let Some(named) = parse_typed_name(source, index, limit) {
        return Some(named);
    }
    let (ty, ty_end) = parse_type(source, index, limit)?;
    let mut end = ty_end;
    if let Some((word, word_end)) = parse_identifier(source, skip_trivia(source, ty_end)) {
        if LOCATIONS.contains(&word) {
            end = word_end;
        }
    }
    let location = source[ty_end..end].trim();
    Some(Declared {
        name: format!("ret{position}"),
        ty,
        location: (!location.is_empty()).then(|| location.to_owned()),
        span: ByteRange {
            start: index as u64,
            end: ty_end as u64,
        },
    })
}

/// A type name at `index`: an identifier, qualified with `.` segments, with array
/// suffixes and an `address payable` marker. Returns the type text and where it ends.
fn parse_type(source: &str, index: usize, limit: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let (first, mut end) = parse_identifier(source, index)?;
    if RESERVED.contains(&first) {
        return None;
    }
    loop {
        let dot = skip_trivia(source, end);
        if bytes.get(dot) != Some(&b'.') {
            break;
        }
        let (_, segment_end) = parse_identifier(source, skip_trivia(source, dot + 1))?;
        end = segment_end;
    }
    loop {
        let bracket = skip_trivia(source, end);
        if bytes.get(bracket) != Some(&b'[') {
            break;
        }
        end = find_matching_delimiter(source, bracket, b'[', b']')? + 1;
    }
    if let Some(("payable", payable_end)) = parse_identifier(source, skip_trivia(source, end)) {
        end = payable_end;
    }
    if end > limit {
        return None;
    }
    let ty = source[index..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    Some((ty, end))
}

/// Whether `=`, and not `==`, is the next token at or after `index`.
fn starts_assignment(source: &str, index: usize) -> bool {
    let bytes = source.as_bytes();
    let at = skip_trivia(source, index);
    bytes.get(at) == Some(&b'=') && bytes.get(at + 1) != Some(&b'=')
}

/// The end of the statement that continues at `from`: the index of its `;`, or `limit`.
fn find_statement_end(source: &str, from: usize, limit: usize) -> usize {
    let bytes = source.as_bytes();
    let mut index = from;
    let mut depth = 0_i32;
    while index < limit {
        index = skip_trivia(source, index);
        match bytes.get(index) {
            None => break,
            Some(b'"' | b'\'') => {
                index = skip_string(source, index);
                continue;
            }
            Some(b'(' | b'[' | b'{') => depth += 1,
            Some(b')' | b']' | b'}') => depth -= 1,
            Some(b';') if depth <= 0 => return index,
            _ => {}
        }
        index += 1;
    }
    limit
}

/// The range of the non-blank text in `source[start..end]`, when there is any.
fn trimmed_range(source: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    let text = &source[start..end];
    let leading = text.len() - text.trim_start().len();
    let trailing = text.len() - text.trim_end().len();
    (leading + trailing < text.len()).then_some((start + leading, end - trailing))
}

/// The first `needle` at or after `from` and before `limit`, outside comments.
fn find_byte(source: &str, from: usize, limit: usize, needle: u8) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = from;
    while index < limit {
        index = skip_trivia(source, index);
        match bytes.get(index) {
            Some(byte) if *byte == needle => return Some(index),
            Some(b'"' | b'\'') => index = skip_string(source, index),
            Some(_) => index += 1,
            None => break,
        }
    }
    None
}

/// Skips whitespace and comments.
pub(crate) fn skip_trivia(source: &str, mut index: usize) -> usize {
    let bytes = source.as_bytes();
    loop {
        index = skip_ascii_whitespace(source, index);
        match (bytes.get(index), bytes.get(index + 1)) {
            (Some(b'/'), Some(b'/')) => {
                index = source[index..]
                    .find('\n')
                    .map_or(source.len(), |newline| index + newline + 1);
            }
            (Some(b'/'), Some(b'*')) => {
                index = source[index + 2..]
                    .find("*/")
                    .map_or(source.len(), |close| index + 2 + close + 2);
            }
            _ => return index,
        }
    }
}

/// Skips a string literal opening at `index`, escapes included.
fn skip_string(source: &str, index: usize) -> usize {
    let bytes = source.as_bytes();
    let quote = bytes[index];
    let mut cursor = index + 1;
    while let Some(byte) = bytes.get(cursor) {
        match byte {
            b'\\' => cursor += 2,
            byte if *byte == quote => return cursor + 1,
            _ => cursor += 1,
        }
    }
    source.len()
}

#[cfg(test)]
mod tests {
    use super::{parse_declaration, scan_locals};
    use crate::ByteRange;

    const BODY: &str = r#"function walk(uint256 n) public tracked(7) returns (uint256 acc) {
        string memory label = "walk"; // a comment; with a semicolon
        for (uint256 i = 0; i < n; i++) {
            uint256 twice = i * 2;
            if (twice > 2) {
                uint256 inner = twice - 2;
                acc += inner;
            }
            (uint256 q, , uint256 r) = divmod(twice, 3);
            acc += q + r;
        }
        assembly { let x := 1 }
        address payable to = payable(msg.sender);
        Counter[] memory counters;
        total = acc;
        acc += bytes(label).length;
    }"#;

    fn offset(needle: &str) -> u64 {
        BODY.find(needle).expect(needle) as u64
    }

    fn range(needle: &str) -> ByteRange {
        ByteRange {
            start: offset(needle),
            end: offset(needle) + needle.len() as u64,
        }
    }

    #[test]
    fn finds_declarations_with_their_spans_and_scopes() {
        let body_start = BODY.find('{').unwrap();
        let body_end = BODY.rfind('}').unwrap();
        let locals = scan_locals(BODY, body_start, body_end);
        let names = locals
            .iter()
            .map(|local| local.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            ["label", "i", "twice", "inner", "q", "r", "to", "counters"]
        );

        let label = &locals[0];
        assert_eq!(
            (label.ty.as_str(), label.location.as_deref()),
            ("string", Some("memory"))
        );
        assert_eq!(label.declaration, range("string memory label"));
        assert_eq!(label.statement, range("string memory label = \"walk\""));
        assert_eq!(label.scope.end, body_end as u64);

        // The loop variable is in scope for the whole `for` statement.
        let i = &locals[1];
        assert_eq!(i.declaration, range("uint256 i"));
        assert_eq!(i.statement, range("uint256 i = 0"));
        assert_eq!(i.scope.start, offset("for (uint256 i"));
        let loop_close = BODY.find("        assembly").unwrap() - 1;
        assert!(i.scope.end as usize > BODY[..loop_close].rfind('}').unwrap());

        // Block locals end with their block.
        let twice = &locals[2];
        let inner = &locals[3];
        assert!(twice.scope.end > inner.scope.end);
        assert_eq!(inner.scope.start, offset("uint256 inner"));

        // Tuple components share a statement and count only declared slots.
        let (q, r) = (&locals[4], &locals[5]);
        assert_eq!(
            q.statement,
            range("(uint256 q, , uint256 r) = divmod(twice, 3)")
        );
        assert_eq!(q.statement, r.statement);
        assert_eq!((q.position, r.position), (0, 1));
        assert_eq!(q.declaration, range("uint256 q"));
        assert_eq!(r.declaration, range("uint256 r"));

        assert_eq!(locals[6].ty, "address payable");
        assert_eq!(locals[7].ty, "Counter[]");
        assert_eq!(locals[7].statement, range("Counter[] memory counters"));
    }

    #[test]
    fn clause_parameters_belong_to_their_blocks() {
        let body = r#"function probe(address target) public returns (uint256 got) {
        uint256[] memory xs = new uint256[](2);
        try Clauses(target).sum(xs, S({a: 1})) returns (uint256 value, bool ok) {
            got = value + 1;
        } catch Error(string memory reason) {
            got = bytes(reason).length;
        } catch (bytes memory data) {
            got = data.length;
        }
        uint256 after = got;
    }"#;
        let offset = |needle: &str| body.find(needle).expect(needle) as u64;
        let locals = scan_locals(body, body.find('{').unwrap(), body.rfind('}').unwrap());
        let names = locals
            .iter()
            .map(|local| local.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["xs", "value", "ok", "reason", "data", "after"]);
        let value = &locals[1];
        assert_eq!(value.declaration.start, offset("uint256 value"));
        assert_eq!(value.scope.end, offset("} catch Error"));
        assert_eq!(locals[2].position, 1);
        let reason = &locals[3];
        assert_eq!(
            (reason.ty.as_str(), reason.location.as_deref()),
            ("string", Some("memory"))
        );
        assert!(reason.scope.contains(offset("got = bytes(reason)")));
        assert!(!reason.scope.contains(offset("got = data.length")));
        let data = &locals[4];
        assert!(data.scope.contains(offset("got = data.length")));
        assert_eq!(locals[5].declaration.start, offset("uint256 after"));
    }

    #[test]
    fn a_modifier_placeholder_is_found() {
        let body = "modifier tracked(uint256 tag) {\n    uint256 before = total_; // _;\n    _;\n    total = before;\n}";
        let placeholder =
            super::find_placeholder(body, body.find('{').unwrap(), body.rfind('}').unwrap());
        assert_eq!(placeholder, Some(body.find("\n    _;").unwrap() as u64 + 5));
        assert_eq!(super::find_placeholder("{ total = 1; }", 0, 13), None);
    }

    #[test]
    fn assignments_calls_and_keywords_are_not_declarations() {
        for statement in [
            "total = acc;",
            "a.b = c;",
            "foo(1);",
            "return x;",
            "delete x;",
            "emit Moved(1);",
            "(a, b) = f();",
            "x == y;",
            "mapping(uint256 => uint256) storage m = self;",
            "payable(x).transfer(1);",
        ] {
            assert!(
                parse_declaration(statement, 0, statement.len()).is_none(),
                "{statement}"
            );
        }
        let (declared, _) = parse_declaration("uint256 x;", 0, 10).unwrap();
        assert_eq!(declared[0].name, "x");
        let (declared, _) = parse_declaration("IERC20.Info memory info = x;", 0, 28).unwrap();
        assert_eq!(
            (declared[0].ty.as_str(), declared[0].name.as_str()),
            ("IERC20.Info", "info")
        );
    }
}
