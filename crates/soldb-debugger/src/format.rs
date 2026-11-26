//! How values are shown: formats and summaries the user chooses.
//!
//! Everything numeric in a contract is an integer, and most integers are not the number
//! they mean: a token amount is scaled by the token's decimals, a price by `1e18` or by
//! `2**96`, a deadline counts seconds since 1970. The debugger decodes a value by its
//! type, which shows `1500000000000000000`; a format shows the same value as `1.5`.
//!
//! The model follows LLDB's data formatters. A *format* says how one number is written
//! (`decimals:18`, `hex`, `timestamp`); a *summary* is a one-line template for a value,
//! such as `${amount%decimals:6} USDC` or `${liquidity} in [${tickLower}, ${tickUpper}]`
//! for a struct. Each applies to the values a [`Matcher`] selects: by declared type,
//! which suits user-defined value types such as `UD60x18`, by the name a value is shown
//! under, which suits Solidity, where nearly every amount is a `uint256`, and optionally
//! only in one contract's code. The most recently added rule that matches wins, so a
//! later, narrower rule overrides an earlier, broader one.
//!
//! Formats change what is shown and nothing else: a breakpoint condition still compares
//! the word, and `raw` still carries it. What a view applied comes back with the text
//! ([`Rendered::format`]), so a frontend can say that `1500` is a scaled amount rather
//! than leave it looking like the integer 1500.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use soldb_ethdebug::{Scalar, ValueShape};

use crate::DebugValue;

/// The most decimal places a format accepts: a 256-bit value has 78 digits.
const MAX_DECIMALS: u32 = 77;
/// How many fractional digits a binary fixed-point value is shown with.
const BINARY_FIXED_DIGITS: usize = 18;
/// The last second of year 9999, past which a number is not shown as a date.
const MAX_TIMESTAMP: u64 = 253_402_300_799;

/// How one number is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueFormat {
    /// As the debugger decodes it by its type: used to exempt values from a broader rule.
    Default,
    Decimal,
    Hex,
    Binary,
    /// A fixed-point number with this many decimal places: a token amount, a `wad`.
    Decimals(Decimals),
    /// Basis points, shown as a percentage: `250` is `2.5%`.
    BasisPoints,
    /// A binary fixed-point number with this many fractional bits, as `sqrtPriceX96` is.
    BinaryFixed(u16),
    /// Seconds since 1970, shown as a UTC date and time.
    Timestamp,
    /// A number of seconds, shown in days, hours, minutes, and seconds.
    Duration,
    /// Bytes shown as the ASCII text they spell, as a `bytes32` symbol is stored.
    Text,
}

/// Where a fixed-point format takes its number of decimal places from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decimals {
    Fixed(u32),
    /// A state variable of the contract executing, such as a token's `decimals`.
    State(String),
}

impl ValueFormat {
    /// Every format and alias, as `help` lists them.
    pub const NAMES: &'static [&'static str] = &[
        "decimal (d)",
        "hex (x)",
        "binary (t)",
        "decimals:<n>",
        "decimals:@<state variable>",
        "ether, wad (decimals:18)",
        "gwei (decimals:9)",
        "ray (decimals:27)",
        "bps",
        "q<bits>",
        "timestamp",
        "duration",
        "string (s)",
        "default",
    ];

    /// Parses a format as typed: `hex`, `x`, `decimals:6`, `decimals:@decimals`, `q96`.
    ///
    /// # Errors
    ///
    /// Says what is wrong with a format that is not one of [`ValueFormat::NAMES`].
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let lower = text.to_ascii_lowercase();
        let format = match lower.as_str() {
            "default" => Self::Default,
            "decimal" | "d" => Self::Decimal,
            "hex" | "x" => Self::Hex,
            "binary" | "t" => Self::Binary,
            "ether" | "wad" => Self::Decimals(Decimals::Fixed(18)),
            "gwei" => Self::Decimals(Decimals::Fixed(9)),
            "ray" => Self::Decimals(Decimals::Fixed(27)),
            "bps" => Self::BasisPoints,
            "timestamp" | "time" => Self::Timestamp,
            "duration" => Self::Duration,
            "string" | "s" => Self::Text,
            _ => {
                if lower.starts_with("decimals:") || lower.starts_with("decimals=") {
                    return parse_decimals(&text["decimals:".len()..]).map(Self::Decimals);
                }
                if let Some(bits) = lower.strip_prefix('q') {
                    return match bits.parse::<u16>() {
                        Ok(bits) if (1..=255).contains(&bits) => Ok(Self::BinaryFixed(bits)),
                        _ => Err(format!(
                            "`{text}` is not a binary fixed-point format; write `q<bits>` with \
                             1 to 255 fractional bits, such as `q96`"
                        )),
                    };
                }
                return Err(format!(
                    "unknown format `{text}`; formats are {}",
                    Self::NAMES.join(", ")
                ));
            }
        };
        Ok(format)
    }

    /// Whether the format reads a value as a number, so it applies only to integers.
    fn is_numeric(&self) -> bool {
        !matches!(self, Self::Default | Self::Hex | Self::Binary | Self::Text)
    }
}

fn parse_decimals(places: &str) -> Result<Decimals, String> {
    if let Some(path) = places.strip_prefix('@') {
        if path.is_empty() {
            return Err(
                "`decimals:@` needs a state variable, such as `decimals:@decimals`".to_owned(),
            );
        }
        return Ok(Decimals::State(path.to_owned()));
    }
    match places.parse::<u32>() {
        Ok(places) if places <= MAX_DECIMALS => Ok(Decimals::Fixed(places)),
        _ => Err(format!(
            "`decimals:{places}` needs a number of decimal places from 0 to {MAX_DECIMALS}, \
             or `@<state variable>` to read it from the contract"
        )),
    }
}

impl fmt::Display for ValueFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => formatter.write_str("default"),
            Self::Decimal => formatter.write_str("decimal"),
            Self::Hex => formatter.write_str("hex"),
            Self::Binary => formatter.write_str("binary"),
            Self::Decimals(Decimals::Fixed(places)) => write!(formatter, "decimals:{places}"),
            Self::Decimals(Decimals::State(path)) => write!(formatter, "decimals:@{path}"),
            Self::BasisPoints => formatter.write_str("bps"),
            Self::BinaryFixed(bits) => write!(formatter, "q{bits}"),
            Self::Timestamp => formatter.write_str("timestamp"),
            Self::Duration => formatter.write_str("duration"),
            Self::Text => formatter.write_str("string"),
        }
    }
}

/// Which values a rule applies to. Every criterion given must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matcher {
    /// Declared types, as globs: `uint256`, `UD60x18`, `Pool.Position`, `uint*`.
    pub types: Vec<String>,
    /// Names a value is shown under, as globs: a variable's, a struct member's, or, for
    /// the elements of an array or the entries of a mapping, the collection's.
    pub vars: Vec<String>,
    /// The contract whose code is executing, as a glob.
    pub contract: Option<String>,
}

impl Matcher {
    /// A matcher selecting by type, by name, or both, optionally in one contract.
    ///
    /// # Errors
    ///
    /// A rule needs at least one type or name; one that would match every value is
    /// refused rather than silently reformatting everything.
    pub fn new(
        types: Vec<String>,
        vars: Vec<String>,
        contract: Option<String>,
    ) -> Result<Self, String> {
        if types.is_empty() && vars.is_empty() {
            return Err(
                "name the values it applies to: one or more types, `--var <name>`, or both"
                    .to_owned(),
            );
        }
        Ok(Self {
            types,
            vars,
            contract,
        })
    }

    fn matches(&self, contract: Option<&str>, name: &str, ty: Option<&str>) -> bool {
        if let Some(pattern) = &self.contract {
            if !contract.is_some_and(|contract| glob(pattern, contract)) {
                return false;
            }
        }
        if !self.vars.is_empty() && !self.vars.iter().any(|pattern| glob(pattern, name)) {
            return false;
        }
        if self.types.is_empty() {
            return true;
        }
        let Some(ty) = ty else {
            return false;
        };
        let full = bare_type(ty);
        let short = full.rsplit('.').next().unwrap_or(full);
        self.types
            .iter()
            .any(|pattern| glob(pattern, full) || glob(pattern, short))
    }
}

impl fmt::Display for Matcher {
    /// The matcher as the arguments that set it, so a listed rule can be typed again.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = self.types.clone();
        parts.extend(self.vars.iter().map(|var| format!("--var {var}")));
        if let Some(contract) = &self.contract {
            parts.push(format!("--contract {contract}"));
        }
        formatter.write_str(&parts.join(" "))
    }
}

/// A type without the keyword a layout labels it with: `struct Pool.Position` is
/// `Pool.Position`.
fn bare_type(ty: &str) -> &str {
    let ty = ty.trim();
    ["struct ", "enum ", "contract ", "interface ", "library "]
        .iter()
        .find_map(|keyword| ty.strip_prefix(keyword))
        .unwrap_or(ty)
}

/// Whether `text` matches `pattern`, where `*` matches any run of characters and `?`
/// any one.
fn glob(pattern: &str, text: &str) -> bool {
    let pattern = pattern.chars().collect::<Vec<_>>();
    let text = text.chars().collect::<Vec<_>>();
    let (mut p, mut t) = (0, 0);
    // Where the last `*` was, and the text position it is matching up to.
    let mut star = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, star_t + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|character| *character == '*')
}

/// A one-line template for a value: text with `${...}` placeholders.
///
/// `${var}` is the value itself, `${var.owner}` or just `${owner}` a member of it,
/// `${var.tags[1]}` an element, and a placeholder may end in `%<format>` to write that
/// part in a format: `${var.amount%decimals:6} USDC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    template: String,
    parts: Vec<SummaryPart>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SummaryPart {
    Text(String),
    Value {
        path: Vec<Step>,
        format: Option<ValueFormat>,
    },
}

/// One step from a value to a part of it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Member(String),
    Index(usize),
}

impl Summary {
    /// Parses a summary template.
    ///
    /// # Errors
    ///
    /// Says which placeholder is malformed: unclosed, an unreadable path, or an unknown
    /// format.
    pub fn parse(template: &str) -> Result<Self, String> {
        let mut parts = Vec::new();
        let mut rest = template;
        while let Some(start) = rest.find("${") {
            if start > 0 {
                parts.push(SummaryPart::Text(rest[..start].to_owned()));
            }
            let after = &rest[start + 2..];
            let Some(end) = after.find('}') else {
                return Err(format!("`{}` has no closing `}}`", &rest[start..]));
            };
            let placeholder = &after[..end];
            let (path, format) = match placeholder.split_once('%') {
                Some((path, format)) => (path, Some(ValueFormat::parse(format)?)),
                None => (placeholder, None),
            };
            parts.push(SummaryPart::Value {
                path: parse_steps(path.trim()).ok_or_else(|| {
                    format!("`${{{placeholder}}}` does not name a part of the value")
                })?,
                format,
            });
            rest = &after[end + 1..];
        }
        if !rest.is_empty() {
            parts.push(SummaryPart::Text(rest.to_owned()));
        }
        if !parts
            .iter()
            .any(|part| matches!(part, SummaryPart::Value { .. }))
        {
            return Err(format!(
                "`{template}` shows nothing of the value; use `${{var}}` for the value itself or \
                 `${{var.<member>}}` for a member"
            ));
        }
        Ok(Self {
            template: template.to_owned(),
            parts,
        })
    }

    /// The template as typed.
    #[must_use]
    pub fn template(&self) -> &str {
        &self.template
    }
}

/// The steps of `var.a.b[2]`, `a.b`, or `var`; `None` when the text is not a path.
fn parse_steps(path: &str) -> Option<Vec<Step>> {
    let path = path
        .strip_prefix("var")
        .filter(|rest| rest.is_empty() || rest.starts_with(['.', '[']))
        .map_or(path, |rest| rest.strip_prefix('.').unwrap_or(rest));
    let mut steps = Vec::new();
    let mut rest = path;
    while !rest.is_empty() {
        if let Some(inner) = rest.strip_prefix('[') {
            let close = inner.find(']')?;
            steps.push(Step::Index(inner[..close].trim().parse().ok()?));
            rest = &inner[close + 1..];
            rest = rest.strip_prefix('.').unwrap_or(rest);
            continue;
        }
        let end = rest.find(['.', '[']).unwrap_or(rest.len());
        let member = &rest[..end];
        if member.is_empty()
            || !member.chars().all(|character| {
                character.is_ascii_alphanumeric() || character == '_' || character == '$'
            })
        {
            return None;
        }
        steps.push(Step::Member(member.to_owned()));
        rest = &rest[end..];
        rest = rest.strip_prefix('.').unwrap_or(rest);
    }
    Some(steps)
}

/// A format set by `type format add`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatRule {
    pub id: u32,
    pub format: ValueFormat,
    pub matcher: Matcher,
}

impl FormatRule {
    /// The rule as `type format list` shows it: `decimals:6 for --var balances`.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} for {}", self.format, self.matcher)
    }
}

/// A summary set by `type summary add`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryRule {
    pub id: u32,
    pub summary: Summary,
    pub matcher: Matcher,
}

impl SummaryRule {
    /// The rule as `type summary list` shows it, its template quoted.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{:?} for {}", self.summary.template(), self.matcher)
    }
}

/// Which kind of rule a command is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FormatterKind {
    Format,
    Summary,
}

impl FormatterKind {
    /// What the kind is called in a command: `type format …`, `type summary …`.
    #[must_use]
    pub fn noun(self) -> &'static str {
        match self {
            Self::Format => "format",
            Self::Summary => "summary",
        }
    }

    /// `count` rules of the kind, in words: `1 format`, `3 summaries`.
    #[must_use]
    pub fn counted(self, count: usize) -> String {
        let noun = match (self, count) {
            (Self::Format, 1) => "format",
            (Self::Format, _) => "formats",
            (Self::Summary, 1) => "summary",
            (Self::Summary, _) => "summaries",
        };
        format!("{count} {noun}")
    }
}

/// A `type format …` or `type summary …` command: what the REPL, the DAP debug console,
/// and the WebAssembly bindings take to change how values are shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatterCommand {
    /// Add a format (`rule` is the format) or a summary (`rule` is the template) for the
    /// values the types, names, and contract select.
    Add {
        kind: FormatterKind,
        rule: String,
        types: Vec<String>,
        vars: Vec<String>,
        contract: Option<String>,
    },
    List(FormatterKind),
    Delete(FormatterKind, u32),
    Clear(FormatterKind),
}

impl FormatterCommand {
    /// Parses what follows `type`: `format add -f hex uint256`, `summary list`, and the
    /// like. Quotes group words, so a summary template may hold spaces.
    ///
    /// # Errors
    ///
    /// Says what is wrong with a line that is not one of these commands.
    pub fn parse(input: &str) -> Result<Self, String> {
        parse_command(input)
    }
}

/// What a [`FormatterCommand`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatterAnswer {
    Added {
        kind: FormatterKind,
        id: u32,
        /// What the rule is and what it applies to, as the command that sets it again.
        label: String,
    },
    Deleted {
        kind: FormatterKind,
        id: u32,
    },
    /// The rules of a kind, numbered and labeled, in the order they were added.
    Listed {
        kind: FormatterKind,
        rules: Vec<(u32, String)>,
    },
    /// Every rule of a kind was deleted, and this many there were.
    Cleared {
        kind: FormatterKind,
        count: usize,
    },
}

/// Parses what follows `type`: `format add -f hex uint256`, `summary list`, and the like.
fn parse_command(input: &str) -> Result<FormatterCommand, String> {
    let words = split_words(input)?;
    let mut words = words.iter().map(String::as_str);
    let kind = match words.next() {
        Some("format") => FormatterKind::Format,
        Some("summary") => FormatterKind::Summary,
        Some(other) => return Err(format!("`type {other}` is not a command")),
        None => return Err("`type` needs `format` or `summary`".to_owned()),
    };
    let noun = kind.noun();
    match words.next() {
        Some("add") => parse_add(kind, words),
        Some("list") => Ok(FormatterCommand::List(kind)),
        Some("clear") => Ok(FormatterCommand::Clear(kind)),
        Some("delete") => {
            let number = words.next().unwrap_or_default().trim_start_matches('#');
            number
                .parse::<u32>()
                .map(|id| FormatterCommand::Delete(kind, id))
                .map_err(|_| {
                    format!("`type {noun} delete` needs the number `type {noun} list` shows")
                })
        }
        Some(other) => Err(format!("`type {noun} {other}` is not a command")),
        None => Err(format!(
            "`type {noun}` needs `add`, `list`, `delete`, or `clear`"
        )),
    }
}

fn parse_add<'a>(
    kind: FormatterKind,
    mut words: impl Iterator<Item = &'a str>,
) -> Result<FormatterCommand, String> {
    let (flag, long) = match kind {
        FormatterKind::Format => ("-f", "--format"),
        FormatterKind::Summary => ("-s", "--summary-string"),
    };
    let mut rule = None;
    let mut types = Vec::new();
    let mut vars = Vec::new();
    let mut contract = None;
    while let Some(word) = words.next() {
        // `--var=amount` is `--var amount`.
        let (option, inline) = match word.split_once('=') {
            Some((option, value)) if option.starts_with('-') => (option, Some(value.to_owned())),
            _ => (word, None),
        };
        let mut value = |name: &str| {
            inline
                .clone()
                .or_else(|| words.next().map(str::to_owned))
                .ok_or_else(|| format!("`{name}` needs a value"))
        };
        match option {
            _ if option == flag || option == long => rule = Some(value(option)?),
            "-v" | "--var" => vars.push(value(option)?),
            "--contract" => contract = Some(value(option)?),
            _ if option.starts_with('-') && option.len() > 1 => {
                return Err(format!(
                    "unknown option `{option}`; `type {} add` takes `{flag} <{}>`, `--var <name>`, and `--contract <name>`",
                    kind.noun(),
                    match kind {
                        FormatterKind::Format => "format",
                        FormatterKind::Summary => "template",
                    }
                ))
            }
            _ => types.push(word.to_owned()),
        }
    }
    let rule = rule.ok_or_else(|| match kind {
        FormatterKind::Format => {
            "`type format add` needs `-f <format>`, such as `-f decimals:18`".to_owned()
        }
        FormatterKind::Summary => {
            "`type summary add` needs `-s <template>`, such as `-s \"${var} wei\"`".to_owned()
        }
    })?;
    Ok(FormatterCommand::Add {
        kind,
        rule,
        types,
        vars,
        contract,
    })
}

/// Splits a line into words the way a shell does for quotes: `"a b"` and `'a b'` are one
/// word each, and a backslash in double quotes escapes the next character.
fn split_words(input: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = input.chars();
    while let Some(character) = chars.next() {
        match character {
            '"' | '\'' => {
                in_word = true;
                let quote = character;
                loop {
                    match chars.next() {
                        Some(inner) if inner == quote => break,
                        Some('\\') if quote == '"' => match chars.next() {
                            Some(escaped) => word.push(escaped),
                            None => return Err("a quoted word ends in `\\`".to_owned()),
                        },
                        Some(inner) => word.push(inner),
                        None => return Err(format!("a word quoted with {quote} is not closed")),
                    }
                }
            }
            character if character.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            character => {
                in_word = true;
                word.push(character);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    Ok(words)
}

/// The formats and summaries of a session, in the order they were added.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Formatters {
    formats: Vec<FormatRule>,
    summaries: Vec<SummaryRule>,
    next_id: u32,
}

impl Formatters {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether no format or summary is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.formats.is_empty() && self.summaries.is_empty()
    }

    #[must_use]
    pub fn formats(&self) -> &[FormatRule] {
        &self.formats
    }

    #[must_use]
    pub fn summaries(&self) -> &[SummaryRule] {
        &self.summaries
    }

    /// Adds a format; it takes precedence over every rule added before it.
    pub fn add_format(&mut self, format: ValueFormat, matcher: Matcher) -> &FormatRule {
        let id = self.take_id();
        self.formats.push(FormatRule {
            id,
            format,
            matcher,
        });
        self.formats.last().expect("just pushed")
    }

    /// Adds a summary; it takes precedence over every summary added before it.
    pub fn add_summary(&mut self, summary: Summary, matcher: Matcher) -> &SummaryRule {
        let id = self.take_id();
        self.summaries.push(SummaryRule {
            id,
            summary,
            matcher,
        });
        self.summaries.last().expect("just pushed")
    }

    /// Removes a rule by number; `false` when there is none of that kind with it.
    pub fn delete(&mut self, kind: FormatterKind, id: u32) -> bool {
        let position = match kind {
            FormatterKind::Format => self.formats.iter().position(|rule| rule.id == id),
            FormatterKind::Summary => self.summaries.iter().position(|rule| rule.id == id),
        };
        let Some(position) = position else {
            return false;
        };
        match kind {
            FormatterKind::Format => drop(self.formats.remove(position)),
            FormatterKind::Summary => drop(self.summaries.remove(position)),
        }
        true
    }

    /// Removes every rule of a kind, and says how many there were.
    pub fn clear(&mut self, kind: FormatterKind) -> usize {
        let count = self.len(kind);
        match kind {
            FormatterKind::Format => self.formats.clear(),
            FormatterKind::Summary => self.summaries.clear(),
        }
        count
    }

    fn len(&self, kind: FormatterKind) -> usize {
        match kind {
            FormatterKind::Format => self.formats.len(),
            FormatterKind::Summary => self.summaries.len(),
        }
    }

    /// Runs a `type format` or `type summary` command.
    ///
    /// # Errors
    ///
    /// The sentence to show when a rule cannot be added, or there is none to delete.
    pub fn run(&mut self, command: FormatterCommand) -> Result<FormatterAnswer, String> {
        match command {
            FormatterCommand::Add {
                kind,
                rule,
                types,
                vars,
                contract,
            } => {
                let cannot = |reason: String| format!("Cannot add the {}: {reason}", kind.noun());
                let matcher = Matcher::new(types, vars, contract).map_err(&cannot)?;
                let (id, label) = match kind {
                    FormatterKind::Format => {
                        let format = ValueFormat::parse(&rule).map_err(&cannot)?;
                        let rule = self.add_format(format, matcher);
                        (rule.id, rule.label())
                    }
                    FormatterKind::Summary => {
                        let summary = Summary::parse(&rule).map_err(&cannot)?;
                        let rule = self.add_summary(summary, matcher);
                        (rule.id, rule.label())
                    }
                };
                Ok(FormatterAnswer::Added { kind, id, label })
            }
            FormatterCommand::List(kind) => Ok(FormatterAnswer::Listed {
                kind,
                rules: match kind {
                    FormatterKind::Format => self
                        .formats
                        .iter()
                        .map(|rule| (rule.id, rule.label()))
                        .collect(),
                    FormatterKind::Summary => self
                        .summaries
                        .iter()
                        .map(|rule| (rule.id, rule.label()))
                        .collect(),
                },
            }),
            FormatterCommand::Delete(kind, id) => {
                if self.delete(kind, id) {
                    Ok(FormatterAnswer::Deleted { kind, id })
                } else {
                    let noun = kind.noun();
                    Err(format!("No {noun} {id}; `type {noun} list` shows them"))
                }
            }
            FormatterCommand::Clear(kind) => Ok(FormatterAnswer::Cleared {
                kind,
                count: self.clear(kind),
            }),
        }
    }

    fn take_id(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }

    /// Renders values as they are seen in `contract`'s code, reading the state variables
    /// a `decimals:@<name>` format names through `state`, which says why when it cannot.
    #[must_use]
    pub fn view<'a>(
        &'a self,
        contract: Option<&'a str>,
        state: &'a dyn Fn(&str) -> Result<DebugValue, String>,
    ) -> ValueFormatter<'a> {
        ValueFormatter {
            formatters: self,
            contract,
            state,
            decimals: RefCell::new(BTreeMap::new()),
            applied: RefCell::new(Vec::new()),
        }
    }

    fn format_for(&self, contract: Option<&str>, name: &str, ty: &str) -> Option<&ValueFormat> {
        self.formats
            .iter()
            .rev()
            .find(|rule| rule.matcher.matches(contract, name, Some(ty)))
            .map(|rule| &rule.format)
    }

    fn summary_for(&self, contract: Option<&str>, name: &str, ty: &str) -> Option<&Summary> {
        self.summaries
            .iter()
            .rev()
            .find(|rule| rule.matcher.matches(contract, name, Some(ty)))
            .map(|rule| &rule.summary)
    }
}

/// A value as a view shows it, and what was applied to show it so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub text: String,
    /// The formats and summaries applied, as the decimals were resolved (`decimals:6`,
    /// `timestamp`, `summary`), joined with `, `; `None` when the value is shown as
    /// decoded.
    pub format: Option<String>,
}

impl Rendered {
    fn decoded(text: String) -> Self {
        Self { text, format: None }
    }
}

/// The formats of a session applied at one step.
pub struct ValueFormatter<'a> {
    formatters: &'a Formatters,
    contract: Option<&'a str>,
    state: &'a dyn Fn(&str) -> Result<DebugValue, String>,
    /// The decimals each `decimals:@<name>` read, once per view.
    decimals: RefCell<BTreeMap<String, Result<u32, String>>>,
    /// What the value being rendered was shown with so far.
    applied: RefCell<Vec<String>>,
}

impl ValueFormatter<'_> {
    /// The value shown under `name` (a variable or a path into one, such as
    /// `balances[0xabc]`), with the formats and summaries that match it applied.
    #[must_use]
    pub fn render(&self, name: &str, value: &DebugValue) -> Rendered {
        match value.shape.as_deref() {
            Some(shape) if !self.formatters.is_empty() => {
                self.applied.borrow_mut().clear();
                let text = self.node(leaf_name(name), shape, true);
                self.rendered(text)
            }
            _ => Rendered::decoded(value.display.clone()),
        }
    }

    /// The value with every number in it written in `format`, the way `print/x` writes
    /// it; rules and summaries do not apply.
    #[must_use]
    pub fn render_as(&self, value: &DebugValue, format: &ValueFormat) -> Rendered {
        match value.shape.as_deref() {
            Some(shape) => {
                self.applied.borrow_mut().clear();
                let text = self.forced(shape, format);
                self.rendered(text)
            }
            None => Rendered::decoded(value.display.clone()),
        }
    }

    fn rendered(&self, text: String) -> Rendered {
        let applied = std::mem::take(&mut *self.applied.borrow_mut());
        Rendered {
            text,
            format: (!applied.is_empty()).then(|| applied.join(", ")),
        }
    }

    /// Notes that `label` was applied to the value being rendered.
    fn note(&self, label: String) {
        let mut applied = self.applied.borrow_mut();
        if !applied.contains(&label) {
            applied.push(label);
        }
    }

    fn node(&self, name: &str, shape: &ValueShape, summaries: bool) -> String {
        if summaries {
            if let Some(summary) = self.summary(name, shape) {
                // A summary is what was applied, whatever formats its parts were written in.
                let before = self.applied.borrow().len();
                let text = self.summarize(name, shape, summary);
                self.applied.borrow_mut().truncate(before);
                self.note("summary".to_owned());
                return text;
            }
        }
        match shape {
            ValueShape::Scalar(scalar) => {
                match self.formatters.format_for(self.contract, name, &scalar.ty) {
                    // The variable the decimals are read from is not scaled by them: a
                    // broad `decimals:@decimals` rule would show `decimals = 6` as
                    // `0.000006`, which is never what anyone wants.
                    Some(ValueFormat::Decimals(Decimals::State(path)))
                        if leaf_name(path) == name =>
                    {
                        scalar.shown.clone()
                    }
                    Some(format) => self.scalar(scalar, format),
                    None => scalar.shown.clone(),
                }
            }
            ValueShape::Struct { members, .. } => soldb_ethdebug::struct_text(
                members
                    .iter()
                    .map(|(member, shape)| (member.as_str(), self.node(member, shape, true))),
            ),
            ValueShape::Array { elements, more } => soldb_ethdebug::array_text(
                elements
                    .iter()
                    .map(|element| self.node(name, element, true)),
                *more,
            ),
            ValueShape::Text(text) => text.clone(),
        }
    }

    fn summary(&self, name: &str, shape: &ValueShape) -> Option<&Summary> {
        let ty = match shape {
            ValueShape::Scalar(scalar) => &scalar.ty,
            ValueShape::Struct { ty, .. } => ty,
            ValueShape::Array { .. } | ValueShape::Text(_) => return None,
        };
        self.formatters.summary_for(self.contract, name, ty)
    }

    fn summarize(&self, name: &str, shape: &ValueShape, summary: &Summary) -> String {
        let mut text = String::new();
        for part in &summary.parts {
            match part {
                SummaryPart::Text(literal) => text.push_str(literal),
                SummaryPart::Value { path, format } => {
                    let Some((part_name, part)) = descend(name, shape, path) else {
                        text.push_str(&format!("<no {}>", describe(path)));
                        continue;
                    };
                    let shown = match format {
                        Some(format) => self.forced(part, format),
                        // The value itself, without the summary that is being written.
                        None => self.node(part_name, part, !path.is_empty()),
                    };
                    text.push_str(&shown);
                }
            }
        }
        text
    }

    fn forced(&self, shape: &ValueShape, format: &ValueFormat) -> String {
        shape.render_named("", &mut |_, scalar| self.scalar(scalar, format))
    }

    /// A scalar in `format`, or as decoded when the format does not apply to it.
    fn scalar(&self, scalar: &Scalar, format: &ValueFormat) -> String {
        if format.is_numeric() && !scalar.is_integer() {
            return scalar.shown.clone();
        }
        let places = match format {
            ValueFormat::Decimals(Decimals::State(path)) => match self.state_decimals(path) {
                Ok(places) => Some(places),
                Err(reason) => return format!("{} <{reason}>", scalar.shown),
            },
            ValueFormat::Decimals(Decimals::Fixed(places)) => Some(*places),
            _ => None,
        };
        match write_scalar(scalar, format, places) {
            Ok(text) => {
                match (format, places) {
                    (ValueFormat::Default, _) => {}
                    (ValueFormat::Decimals(_), Some(places)) => {
                        self.note(format!("decimals:{places}"));
                    }
                    (format, _) => self.note(format.to_string()),
                }
                text
            }
            Err(reason) => format!("{} <{reason}>", scalar.shown),
        }
    }

    fn state_decimals(&self, path: &str) -> Result<u32, String> {
        if let Some(found) = self.decimals.borrow().get(path) {
            return found.clone();
        }
        let found = self.read_decimals(path);
        self.decimals
            .borrow_mut()
            .insert(path.to_owned(), found.clone());
        found
    }

    fn read_decimals(&self, path: &str) -> Result<u32, String> {
        let value = (self.state)(path).map_err(|reason| format!("decimals unknown: {reason}"))?;
        let Some(ValueShape::Scalar(scalar)) = value.shape.as_deref() else {
            return Err(format!("decimals unknown: `{path}` is {}", value.display));
        };
        let (negative, magnitude) = scalar.magnitude();
        match BigUint::from_be_bytes(&magnitude).to_u64() {
            Some(places) if !negative && places <= u64::from(MAX_DECIMALS) => Ok(places as u32),
            _ => Err(format!(
                "decimals unknown: `{path}` is {}, not a number of decimal places",
                scalar.shown
            )),
        }
    }
}

/// The name a rule's `--var` is matched against for a path: the last name in it, so
/// `balances[0xabc]` is `balances` and `item.tags[1]` is `tags`.
fn leaf_name(path: &str) -> &str {
    let mut name = path.trim();
    while let Some(open) = name.strip_suffix(']').and_then(|inner| inner.rfind('[')) {
        name = &name[..open];
    }
    name.rsplit('.').next().unwrap_or(name)
}

/// The part of `shape` that `path` names, with the name it is shown under.
fn descend<'s>(
    name: &'s str,
    shape: &'s ValueShape,
    path: &'s [Step],
) -> Option<(&'s str, &'s ValueShape)> {
    let mut name = name;
    let mut shape = shape;
    for step in path {
        match (step, shape) {
            (Step::Member(member), ValueShape::Struct { members, .. }) => {
                let (found_name, found) = members.iter().find(|(name, _)| name == member)?;
                name = found_name;
                shape = found;
            }
            (Step::Index(index), ValueShape::Array { elements, .. }) => {
                shape = elements.get(*index)?;
            }
            _ => return None,
        }
    }
    Some((name, shape))
}

fn describe(path: &[Step]) -> String {
    let mut text = String::from("var");
    for step in path {
        match step {
            Step::Member(member) => {
                text.push('.');
                text.push_str(member);
            }
            Step::Index(index) => text.push_str(&format!("[{index}]")),
        }
    }
    text
}

/// A scalar written in `format`; `places` are the decimal places a fixed-point format
/// resolved to.
fn write_scalar(
    scalar: &Scalar,
    format: &ValueFormat,
    places: Option<u32>,
) -> Result<String, String> {
    let (negative, magnitude) = scalar.magnitude();
    let magnitude = BigUint::from_be_bytes(&magnitude);
    let sign = if negative { "-" } else { "" };
    Ok(match format {
        ValueFormat::Default => scalar.shown.clone(),
        ValueFormat::Decimal => format!("{sign}{}", magnitude.to_decimal()),
        // Hex and binary write the bytes as they are, two's complement included.
        ValueFormat::Hex => format!("0x{}", BigUint::from_be_bytes(&scalar.bytes).to_radix(16)),
        ValueFormat::Binary => format!("0b{}", BigUint::from_be_bytes(&scalar.bytes).to_radix(2)),
        ValueFormat::Decimals(_) => {
            let places = places.expect("a fixed-point format resolves its places");
            format!(
                "{sign}{}",
                fixed_point(&magnitude.to_decimal(), places as usize)
            )
        }
        ValueFormat::BasisPoints => format!("{sign}{}%", fixed_point(&magnitude.to_decimal(), 2)),
        ValueFormat::BinaryFixed(bits) => format!("{sign}{}", binary_fixed(&magnitude, *bits)),
        ValueFormat::Timestamp => {
            let seconds = magnitude
                .to_u64()
                .filter(|seconds| !negative && *seconds <= MAX_TIMESTAMP)
                .ok_or("not a timestamp")?;
            timestamp(seconds)
        }
        ValueFormat::Duration => {
            let seconds = magnitude.to_u64().ok_or("too long for a duration")?;
            format!("{sign}{}", duration(seconds))
        }
        ValueFormat::Text => text(scalar)?,
    })
}

/// `digits` with a decimal point `places` from the right, and no trailing zeros.
fn fixed_point(digits: &str, places: usize) -> String {
    if places == 0 {
        return digits.to_owned();
    }
    let padded = format!("{digits:0>width$}", width = places + 1);
    let (whole, fraction) = padded.split_at(padded.len() - places);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        whole.to_owned()
    } else {
        format!("{whole}.{fraction}")
    }
}

/// `magnitude / 2**bits` in decimal: exact when it ends within
/// [`BINARY_FIXED_DIGITS`] fractional digits, cut there and marked with `…` otherwise.
fn binary_fixed(magnitude: &BigUint, bits: u16) -> String {
    let bits = usize::from(bits);
    let whole = magnitude.shr(bits).to_decimal();
    let mut fraction = magnitude.low_bits(bits);
    if fraction.is_zero() {
        return whole;
    }
    let mut digits = String::new();
    while !fraction.is_zero() && digits.len() < BINARY_FIXED_DIGITS {
        fraction = fraction.mul_small(10);
        let digit = fraction.shr(bits).to_u64().unwrap_or(0);
        digits.push(char::from(b'0' + digit as u8));
        fraction = fraction.low_bits(bits);
    }
    let cut = if fraction.is_zero() { "" } else { "…" };
    format!("{whole}.{digits}{cut}")
}

/// Seconds since 1970 as `2024-01-31T12:00:00Z`.
fn timestamp(seconds: u64) -> String {
    let days = seconds / 86_400;
    let time = seconds % 86_400;
    // Howard Hinnant's days-to-civil conversion, valid for every date the bound allows.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3_600,
        time % 3_600 / 60,
        time % 60
    )
}

/// Seconds as `3d 4h 5m 6s`, leaving out units that are zero.
fn duration(seconds: u64) -> String {
    let units = [(86_400, "d"), (3_600, "h"), (60, "m"), (1, "s")];
    let mut rest = seconds;
    let mut parts = Vec::new();
    for (size, unit) in units {
        let count = rest / size;
        rest %= size;
        if count > 0 {
            parts.push(format!("{count}{unit}"));
        }
    }
    if parts.is_empty() {
        "0s".to_owned()
    } else {
        parts.join(" ")
    }
}

/// The scalar's bytes as quoted text, without the zero bytes that pad it.
fn text(scalar: &Scalar) -> Result<String, String> {
    let start = scalar.bytes.iter().position(|byte| *byte != 0);
    let end = scalar.bytes.iter().rposition(|byte| *byte != 0);
    let bytes = match (start, end) {
        (Some(start), Some(end)) => &scalar.bytes[start..=end],
        _ => &[][..],
    };
    if !bytes.iter().all(|byte| (0x20..0x7f).contains(byte)) {
        return Err("not text".to_owned());
    }
    Ok(format!(
        "{:?}",
        std::str::from_utf8(bytes).expect("printable ASCII is UTF-8")
    ))
}

/// An unsigned integer of any width, as little-endian 32-bit limbs: what the formats
/// need of one, and no more. The limbs are 32 bits so that every product and quotient fits
/// in a `u64`, which WebAssembly does natively, rather than pulling in 128-bit division.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BigUint {
    limbs: Vec<u32>,
}

/// Bits in a limb.
const LIMB: usize = 32;

impl BigUint {
    fn from_be_bytes(bytes: &[u8]) -> Self {
        let limbs = bytes
            .rchunks(4)
            .map(|chunk| {
                chunk
                    .iter()
                    .fold(0_u32, |limb, byte| (limb << 8) | u32::from(*byte))
            })
            .collect();
        Self { limbs }.normalized()
    }

    fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    fn to_u64(&self) -> Option<u64> {
        match self.limbs.as_slice() {
            [] => Some(0),
            [low] => Some(u64::from(*low)),
            [low, high] => Some(u64::from(*high) << LIMB | u64::from(*low)),
            _ => None,
        }
    }

    fn normalized(mut self) -> Self {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
        self
    }

    fn shr(&self, bits: usize) -> Self {
        let (words, bits) = (bits / LIMB, bits % LIMB);
        let limbs = self.limbs.get(words..).unwrap_or_default();
        let shifted = (0..limbs.len())
            .map(|index| {
                let low = limbs[index] >> bits;
                let high = match limbs.get(index + 1) {
                    Some(next) if bits > 0 => next << (LIMB - bits),
                    _ => 0,
                };
                low | high
            })
            .collect();
        Self { limbs: shifted }.normalized()
    }

    fn low_bits(&self, bits: usize) -> Self {
        let (words, bits) = (bits / LIMB, bits % LIMB);
        let mut limbs = self.limbs.clone();
        limbs.truncate(words + 1);
        if let Some(top) = limbs.get_mut(words) {
            *top &= if bits == 0 {
                0
            } else {
                u32::MAX >> (LIMB - bits)
            };
        }
        Self { limbs }.normalized()
    }

    fn mul_small(&self, factor: u32) -> Self {
        let mut carry = 0_u64;
        let mut limbs = self
            .limbs
            .iter()
            .map(|limb| {
                let product = u64::from(*limb) * u64::from(factor) + carry;
                carry = product >> LIMB;
                product as u32
            })
            .collect::<Vec<_>>();
        if carry > 0 {
            limbs.push(carry as u32);
        }
        Self { limbs }
    }

    /// Divides by `divisor` in place and returns the remainder.
    fn div_small(&mut self, divisor: u32) -> u32 {
        let mut remainder = 0_u64;
        for limb in self.limbs.iter_mut().rev() {
            let current = remainder << LIMB | u64::from(*limb);
            *limb = (current / u64::from(divisor)) as u32;
            remainder = current % u64::from(divisor);
        }
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
        remainder as u32
    }

    fn to_decimal(&self) -> String {
        self.to_radix(10)
    }

    fn to_radix(&self, radix: u32) -> String {
        let mut value = self.clone();
        let mut digits = Vec::new();
        while !value.is_zero() {
            let digit = value.div_small(radix);
            digits.push(char::from_digit(digit, radix).expect("digit below radix"));
        }
        if digits.is_empty() {
            return "0".to_owned();
        }
        digits.iter().rev().collect()
    }
}

#[cfg(test)]
mod tests {
    use soldb_ethdebug::{Scalar, ValueShape};

    use super::{
        duration, fixed_point, glob, leaf_name, timestamp, BigUint, Decimals, Formatters, Matcher,
        Summary, ValueFormat,
    };
    use crate::{DebugValue, DebugValueStatus};

    fn word(value: u128) -> Vec<u8> {
        let mut word = vec![0_u8; 16];
        word.extend_from_slice(&value.to_be_bytes());
        word
    }

    fn scalar(ty: &str, bytes: Vec<u8>) -> ValueShape {
        let shown = Scalar::new(ty, ty, &bytes, String::new()).decimal();
        ValueShape::Scalar(Scalar::new(ty, ty, &bytes, shown))
    }

    fn value(shape: ValueShape) -> DebugValue {
        DebugValue {
            display: shape.render(),
            raw: None,
            status: DebugValueStatus::Decoded,
            shape: Some(Box::new(shape)),
        }
    }

    fn matcher(types: &[&str], vars: &[&str]) -> Matcher {
        Matcher::new(
            types.iter().map(|ty| (*ty).to_owned()).collect(),
            vars.iter().map(|var| (*var).to_owned()).collect(),
            None,
        )
        .expect("a type or a name")
    }

    fn no_state(_: &str) -> Result<DebugValue, String> {
        Err("no storage layout is loaded".to_owned())
    }

    fn written(format: &str, shape: &ValueShape) -> String {
        let formatters = Formatters::new();
        let format = ValueFormat::parse(format).expect("a format");
        formatters
            .view(None, &no_state)
            .render_as(&value(shape.clone()), &format)
            .text
    }

    #[test]
    fn formats_parse_with_their_aliases_and_print_canonically() {
        for (typed, canonical) in [
            ("x", "hex"),
            ("D", "decimal"),
            ("t", "binary"),
            ("wad", "decimals:18"),
            ("ether", "decimals:18"),
            ("gwei", "decimals:9"),
            ("ray", "decimals:27"),
            ("decimals:6", "decimals:6"),
            ("decimals=6", "decimals:6"),
            ("decimals:@decimals", "decimals:@decimals"),
            ("Q96", "q96"),
            ("time", "timestamp"),
            ("s", "string"),
            ("bps", "bps"),
            ("default", "default"),
        ] {
            assert_eq!(
                ValueFormat::parse(typed).map(|format| format.to_string()),
                Ok(canonical.to_owned()),
                "{typed}"
            );
        }
        for wrong in [
            "decimals:78",
            "decimals:",
            "decimals:@",
            "q0",
            "q256",
            "decimls:18",
        ] {
            assert!(ValueFormat::parse(wrong).is_err(), "{wrong}");
        }
        assert!(ValueFormat::parse("hexx")
            .unwrap_err()
            .contains("decimals:<n>"));
    }

    #[test]
    fn fixed_point_values_are_exact() {
        assert_eq!(fixed_point("1500000000000000000", 18), "1.5");
        assert_eq!(fixed_point("1", 18), "0.000000000000000001");
        assert_eq!(fixed_point("0", 6), "0");
        assert_eq!(fixed_point("1000000", 6), "1");
        assert_eq!(fixed_point("123", 0), "123");
        let amount = scalar("uint256", word(1_234_567_890));
        assert_eq!(written("decimals:6", &amount), "1234.56789");
        assert_eq!(written("bps", &scalar("uint16", word(250))), "2.5%");
        let negative = ValueShape::Scalar(Scalar::new(
            "int256",
            "int256",
            &[0xff; 32],
            "-1".to_owned(),
        ));
        assert_eq!(written("decimals:2", &negative), "-0.01");
        assert_eq!(written("decimal", &negative), "-1");
        assert_eq!(written("hex", &negative), format!("0x{}", "f".repeat(64)));
    }

    #[test]
    fn wide_values_are_written_in_full() {
        let max = scalar("uint256", vec![0xff; 32]);
        assert_eq!(
            written("decimal", &max),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
        assert_eq!(
            written("decimals:18", &max),
            "115792089237316195423570985008687907853269984665640564039457.584007913129639935"
        );
        assert_eq!(written("binary", &scalar("uint8", vec![5])), "0b101");
        assert_eq!(written("hex", &scalar("uint256", word(0))), "0x0");
        assert_eq!(
            BigUint::from_be_bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 0]).to_radix(16),
            "10000000000000000"
        );
    }

    #[test]
    fn binary_fixed_point_is_exact_or_marked_as_cut() {
        // sqrtPriceX96 of a price of 1: exactly 2**96.
        let mut one = vec![0_u8; 32];
        one[19] = 1;
        assert_eq!(written("q96", &scalar("uint160", one)), "1");
        assert_eq!(written("q2", &scalar("uint8", vec![0b110])), "1.5");
        assert_eq!(
            written("q64", &scalar("uint128", word(1))),
            "0.000000000000000000…"
        );
        let third = scalar("uint128", word((1_u128 << 64) / 3));
        assert_eq!(written("q64", &third), "0.333333333333333333…");
    }

    #[test]
    fn times_and_durations_read_as_dates_and_spans() {
        assert_eq!(timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(timestamp(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(timestamp(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(timestamp(253_402_300_799), "9999-12-31T23:59:59Z");
        assert_eq!(duration(0), "0s");
        assert_eq!(duration(90_061), "1d 1h 1m 1s");
        assert_eq!(duration(604_800), "7d");
        let far = scalar("uint256", vec![0xff; 32]);
        assert!(written("timestamp", &far).ends_with("<not a timestamp>"));
    }

    #[test]
    fn text_formats_read_padded_ascii() {
        let mut symbol = vec![0_u8; 32];
        symbol[..5].copy_from_slice(b"ETH-A");
        let ilk = ValueShape::Scalar(Scalar::new(
            "bytes32",
            "bytes32",
            &symbol,
            "0x...".to_owned(),
        ));
        assert_eq!(written("string", &ilk), "\"ETH-A\"");
        let binary = ValueShape::Scalar(Scalar::new(
            "bytes2",
            "bytes2",
            &[0x00, 0x01],
            "0x0001".to_owned(),
        ));
        assert_eq!(written("s", &binary), "0x0001 <not text>");
    }

    #[test]
    fn numeric_formats_leave_other_values_alone() {
        let owner = ValueShape::Scalar(Scalar::new(
            "address",
            "address",
            &[0xab; 20],
            "0xabab".to_owned(),
        ));
        assert_eq!(written("decimals:18", &owner), "0xabab");
        assert_eq!(written("timestamp", &owner), "0xabab");
    }

    #[test]
    fn globs_match_names_and_types() {
        assert!(glob("amount", "amount"));
        assert!(!glob("amount", "amounts"));
        assert!(glob("*Amount", "maxAmount"));
        assert!(glob("bal*", "balances"));
        assert!(glob("*", ""));
        assert!(glob("u?nt*", "uint256"));
        assert!(glob("*a*b*", "xaybz"));
        assert!(!glob("*a*b", "xaybz"));
        assert_eq!(leaf_name("balances[0xabc]"), "balances");
        assert_eq!(leaf_name("allowance[0x1][0x2]"), "allowance");
        assert_eq!(leaf_name("item.tags[1]"), "tags");
        assert_eq!(leaf_name("config.limit"), "limit");
        assert!(Matcher::new(Vec::new(), Vec::new(), None).is_err());
    }

    #[test]
    fn the_latest_matching_rule_wins_and_names_reach_into_structs_and_arrays() {
        let mut formatters = Formatters::new();
        formatters.add_format(
            ValueFormat::Decimals(Decimals::Fixed(18)),
            matcher(&["uint256"], &[]),
        );
        formatters.add_format(ValueFormat::Default, matcher(&[], &["nonce"]));
        formatters.add_format(
            ValueFormat::Decimals(Decimals::Fixed(6)),
            matcher(&[], &["usdc*"]),
        );
        let order = ValueShape::Struct {
            ty: "Shop.Order".to_owned(),
            members: vec![
                (
                    "price".to_owned(),
                    scalar("uint256", word(2_500_000_000_000_000_000)),
                ),
                ("nonce".to_owned(), scalar("uint256", word(7))),
                ("usdcPaid".to_owned(), scalar("uint256", word(2_500_000))),
                ("count".to_owned(), scalar("uint8", word(3))),
            ],
        };
        let view_state = no_state;
        let view = formatters.view(None, &view_state);
        assert_eq!(
            view.render("order", &value(order)).text,
            "{ price: 2.5, nonce: 7, usdcPaid: 2.5, count: 3 }"
        );
        let amounts = ValueShape::Array {
            elements: vec![
                scalar("uint128", word(1_000_000)),
                scalar("uint128", word(1)),
            ],
            more: 4,
        };
        assert_eq!(
            view.render("usdcAmounts", &value(amounts)).text,
            "[1, 0.000001, ... 4 more]"
        );
        // A mapping entry is shown under the mapping's name.
        assert_eq!(
            view.render(
                "usdcBalances[0xabc]",
                &value(scalar("uint256", word(5_000_000)))
            )
            .text,
            "5"
        );
        let text = DebugValue {
            display: "<mapping; index it with [key]>".to_owned(),
            raw: None,
            status: DebugValueStatus::Decoded,
            shape: None,
        };
        assert_eq!(
            view.render("usdcBalances", &text).text,
            "<mapping; index it with [key]>"
        );
    }

    #[test]
    fn rules_can_be_limited_to_one_contract_and_deleted() {
        let mut formatters = Formatters::new();
        let id = formatters
            .add_format(
                ValueFormat::Decimals(Decimals::Fixed(6)),
                Matcher::new(
                    Vec::new(),
                    vec!["balance".to_owned()],
                    Some("USDC".to_owned()),
                )
                .expect("a name"),
            )
            .id;
        let balance = value(scalar("uint256", word(1_000_000)));
        assert_eq!(
            formatters
                .view(Some("USDC"), &no_state)
                .render("balance", &balance)
                .text,
            "1"
        );
        assert_eq!(
            formatters
                .view(Some("WETH"), &no_state)
                .render("balance", &balance)
                .text,
            "1000000"
        );
        assert_eq!(
            formatters
                .view(None, &no_state)
                .render("balance", &balance)
                .text,
            "1000000"
        );
        assert_eq!(
            formatters.formats()[0].matcher.to_string(),
            "--var balance --contract USDC"
        );
        assert!(!formatters.delete(super::FormatterKind::Summary, id));
        assert!(formatters.delete(super::FormatterKind::Format, id));
        assert!(formatters.is_empty());
    }

    #[test]
    fn decimals_can_come_from_the_contracts_own_state() {
        let mut formatters = Formatters::new();
        formatters.add_format(
            ValueFormat::parse("decimals:@decimals").expect("a format"),
            matcher(&[], &["balance*"]),
        );
        let reads = std::cell::Cell::new(0);
        let state = |path: &str| {
            reads.set(reads.get() + 1);
            if path == "decimals" {
                Ok(value(scalar("uint8", vec![6])))
            } else {
                Err(format!(
                    "no state variable named `{path}` in the storage layout"
                ))
            }
        };
        let view = formatters.view(Some("USDC"), &state);
        let balance = value(scalar("uint256", word(12_500_000)));
        assert_eq!(view.render("balanceOf[0x1]", &balance).text, "12.5");
        assert_eq!(view.render("balances[0x2]", &balance).text, "12.5");
        assert_eq!(reads.get(), 1, "the state is read once a view");
        let missing = |path: &str| {
            Err(format!(
                "no state variable named `{path}` in the storage layout"
            ))
        };
        assert_eq!(
            formatters
                .view(Some("Vault"), &missing)
                .render("balance", &balance)
                .text,
            "12500000 <decimals unknown: no state variable named `decimals` in the storage layout>"
        );

        // The rule leaves the variable it reads alone, even when it matches it.
        formatters.add_format(
            ValueFormat::parse("decimals:@decimals").expect("a format"),
            matcher(&["uint*"], &[]),
        );
        let six = value(scalar("uint8", vec![6]));
        let broad = formatters.view(Some("USDC"), &state);
        assert_eq!(broad.render("decimals", &six).text, "6");
        assert_eq!(broad.render("decimals", &six).format, None);
        assert_eq!(broad.render("fee", &six).text, "0.000006");
    }

    #[test]
    fn summaries_compose_members_in_their_formats() {
        let mut formatters = Formatters::new();
        formatters.add_format(
            ValueFormat::Decimals(Decimals::Fixed(18)),
            matcher(&[], &["liquidity"]),
        );
        formatters.add_summary(
            Summary::parse("${liquidity} in [${var.tickLower}, ${tickUpper%x}]")
                .expect("a summary"),
            matcher(&["Position"], &[]),
        );
        formatters.add_summary(
            Summary::parse("${var%decimals:6} USDC").expect("a summary"),
            matcher(&[], &["fee"]),
        );
        let position = ValueShape::Struct {
            ty: "Pool.Position".to_owned(),
            members: vec![
                (
                    "liquidity".to_owned(),
                    scalar("uint128", word(3_000_000_000_000_000_000)),
                ),
                (
                    "tickLower".to_owned(),
                    scalar("int24", vec![0xff, 0xff, 0xf6]),
                ),
                ("tickUpper".to_owned(), scalar("int24", vec![0, 0, 10])),
                ("fee".to_owned(), scalar("uint256", word(1_500_000))),
            ],
        };
        let view = formatters.view(None, &no_state);
        assert_eq!(
            view.render("position", &value(position.clone())).text,
            "3 in [-10, 0xa]"
        );
        assert_eq!(
            view.render("fee", &value(scalar("uint256", word(1_500_000))))
                .text,
            "1.5 USDC"
        );
        formatters.add_summary(
            Summary::parse("${var.missing}!").expect("a summary"),
            matcher(&["Position"], &[]),
        );
        assert_eq!(
            formatters
                .view(None, &no_state)
                .render("position", &value(position))
                .text,
            "<no var.missing>!"
        );
    }

    #[test]
    fn a_rendered_value_says_what_was_applied_to_it() {
        let mut formatters = Formatters::new();
        formatters.add_format(
            ValueFormat::parse("decimals:@decimals").expect("a format"),
            matcher(&[], &["amount", "order"]),
        );
        formatters.add_format(ValueFormat::Timestamp, matcher(&[], &["deadline"]));
        formatters.add_format(ValueFormat::Default, matcher(&[], &["count"]));
        let state = |_: &str| Ok(value(scalar("uint8", vec![6])));
        let view = formatters.view(None, &state);
        let amount = value(scalar("uint256", word(1_500_000)));
        assert_eq!(
            view.render("amount", &amount),
            super::Rendered {
                text: "1.5".to_owned(),
                format: Some("decimals:6".to_owned())
            }
        );
        // `default` shows the value as decoded, and says nothing was applied.
        assert_eq!(view.render("count", &amount).format, None);
        assert_eq!(view.render("other", &amount).format, None);
        let order = ValueShape::Struct {
            ty: "Order".to_owned(),
            members: vec![
                ("amount".to_owned(), scalar("uint256", word(1_500_000))),
                ("deadline".to_owned(), scalar("uint256", word(0))),
            ],
        };
        assert_eq!(
            view.render("order", &value(order.clone()))
                .format
                .as_deref(),
            Some("decimals:6, timestamp")
        );
        assert_eq!(
            view.render_as(&amount, &ValueFormat::Hex).format.as_deref(),
            Some("hex")
        );
        formatters.add_summary(
            Summary::parse("${amount%wad} by ${deadline}").expect("a summary"),
            matcher(&["Order"], &[]),
        );
        let view = formatters.view(None, &state);
        assert_eq!(
            view.render("order", &value(order)).format.as_deref(),
            Some("summary")
        );
        // A format that could not be applied says why in the text, and is not claimed.
        let missing = |_: &str| Err("no storage layout is loaded".to_owned());
        let view = formatters.view(None, &missing);
        assert_eq!(view.render("amount", &amount).format, None);
    }

    #[test]
    fn summary_templates_are_checked_when_added() {
        assert!(Summary::parse("plain text").is_err());
        assert!(Summary::parse("${var").is_err());
        assert!(Summary::parse("${var.a b}").is_err());
        assert!(Summary::parse("${var%nope}").is_err());
        assert!(Summary::parse("${var[x]}").is_err());
        assert!(Summary::parse("${var.items[2].price} each").is_ok());
        assert_eq!(
            Summary::parse("${var} wei").expect("a summary").template(),
            "${var} wei"
        );
    }
}
