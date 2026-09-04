//! Conditions on a breakpoint: `break TestContract.sol:30 if counter > 4`.
//!
//! A condition is a comparison, or several joined by `&&` and `||`, over values the
//! debugger can actually read at a step: state variables through the storage layout
//! (including `balances[0xabc]` and `config.limit`), the arguments of the frame being
//! entered, and a few facts about the step itself (`pc`, `gas`, `depth`, `op`, `step`).
//! There is no arithmetic and no calls: a debugger that evaluated Solidity would have to
//! execute it, and this crate never executes anything.
//!
//! A condition that cannot be evaluated — a slot the transaction never touched, a name
//! nothing defines, a comparison between a number and a string — does not stop, and says
//! why through [`Evaluation::Unavailable`]. That is deliberate: stopping on an unreadable
//! condition would be a false positive, and silently treating it as false would hide the
//! reason it never fires.

use soldb_ethdebug::{parse_word, StorageLayout, Word};

use crate::state::{state_value, StorageWords};
use crate::stepping::{Frame, StepMap};
use crate::DebugValueStatus;

/// A parsed breakpoint condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    /// `||` groups of `&&` terms: the condition holds when any group holds.
    groups: Vec<Vec<Comparison>>,
    text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Comparison {
    left: Operand,
    /// `None` for a bare operand, which holds when it is true or non-zero.
    operator: Option<Operator>,
    right: Option<Operand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operator {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
}

impl Operator {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "==" => Some(Self::Equal),
            "!=" => Some(Self::NotEqual),
            "<" => Some(Self::Less),
            "<=" => Some(Self::LessOrEqual),
            ">" => Some(Self::Greater),
            ">=" => Some(Self::GreaterOrEqual),
            _ => None,
        }
    }

    fn holds(self, ordering: std::cmp::Ordering) -> bool {
        use std::cmp::Ordering;
        match self {
            Self::Equal => ordering == Ordering::Equal,
            Self::NotEqual => ordering != Ordering::Equal,
            Self::Less => ordering == Ordering::Less,
            Self::LessOrEqual => ordering != Ordering::Greater,
            Self::Greater => ordering == Ordering::Greater,
            Self::GreaterOrEqual => ordering != Ordering::Less,
        }
    }
}

/// One side of a comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Operand {
    /// A number, address, or `0x` word written in the condition.
    Literal(Word),
    Bool(bool),
    /// A quoted string, which only compares equal to another string.
    Text(String),
    /// A name to look up: a state variable path, a frame argument, or a step fact.
    Name(String),
}

/// A value a condition can compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A 256-bit word, and whether its type is signed.
    Word(Word, bool),
    Bool(bool),
    Text(String),
}

/// What a condition evaluated to at one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evaluation {
    True,
    False,
    /// The condition could not be evaluated here, and why.
    Unavailable(String),
}

impl Condition {
    /// Parses `counter > 4`, `amount == 5 && pc != 12`, or `active`.
    pub fn parse(input: &str) -> Result<Self, String> {
        let text = input.trim().to_owned();
        if text.is_empty() {
            return Err("a condition cannot be empty".to_owned());
        }
        let mut groups = Vec::new();
        for group in text.split("||") {
            let mut terms = Vec::new();
            for term in group.split("&&") {
                terms.push(Comparison::parse(term.trim())?);
            }
            groups.push(terms);
        }
        Ok(Self { groups, text })
    }

    /// The condition as the user wrote it.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Whether the condition holds at the step `context` describes.
    #[must_use]
    pub fn evaluate(&self, context: &ConditionContext<'_>) -> Evaluation {
        let mut unavailable = None;
        for group in &self.groups {
            let mut holds = true;
            for comparison in group {
                match comparison.evaluate(context) {
                    Evaluation::True => {}
                    Evaluation::False => {
                        holds = false;
                        break;
                    }
                    Evaluation::Unavailable(reason) => {
                        unavailable.get_or_insert(reason);
                        holds = false;
                        break;
                    }
                }
            }
            if holds {
                return Evaluation::True;
            }
        }
        match unavailable {
            Some(reason) => Evaluation::Unavailable(reason),
            None => Evaluation::False,
        }
    }
}

impl Comparison {
    fn parse(input: &str) -> Result<Self, String> {
        if input.is_empty() {
            return Err("a condition cannot have an empty term".to_owned());
        }
        // The two-character operators first, so `<=` does not parse as `<`.
        for symbol in ["==", "!=", "<=", ">=", "<", ">"] {
            let Some(index) = find_operator(input, symbol) else {
                continue;
            };
            let (left, rest) = input.split_at(index);
            let right = &rest[symbol.len()..];
            let operator = Operator::parse(symbol).expect("listed operator");
            return Ok(Self {
                left: Operand::parse(left.trim())?,
                operator: Some(operator),
                right: Some(Operand::parse(right.trim())?),
            });
        }
        Ok(Self {
            left: Operand::parse(input)?,
            operator: None,
            right: None,
        })
    }

    fn evaluate(&self, context: &ConditionContext<'_>) -> Evaluation {
        let left = match context.resolve(&self.left) {
            Ok(value) => value,
            Err(reason) => return Evaluation::Unavailable(reason),
        };
        let (Some(operator), Some(right)) = (self.operator, self.right.as_ref()) else {
            // A bare operand: true, or a non-zero word.
            return match left {
                Value::Bool(value) => Evaluation::from(value),
                Value::Word(word, _) => Evaluation::from(word != [0_u8; 32]),
                Value::Text(text) => Evaluation::from(!text.is_empty()),
            };
        };
        let right = match context.resolve(right) {
            Ok(value) => value,
            Err(reason) => return Evaluation::Unavailable(reason),
        };
        match compare(&left, &right) {
            Ok(ordering) => Evaluation::from(operator.holds(ordering)),
            Err(reason) => Evaluation::Unavailable(reason),
        }
    }
}

impl From<bool> for Evaluation {
    fn from(value: bool) -> Self {
        if value {
            Self::True
        } else {
            Self::False
        }
    }
}

/// Compares two values, or says why they cannot be compared.
fn compare(left: &Value, right: &Value) -> Result<std::cmp::Ordering, String> {
    match (left, right) {
        (Value::Bool(left), Value::Bool(right)) => Ok(left.cmp(right)),
        (Value::Text(left), Value::Text(right)) => Ok(left.cmp(right)),
        (Value::Word(left, left_signed), Value::Word(right, right_signed)) => {
            if *left_signed || *right_signed {
                return Ok(signed_value(left).cmp(&signed_value(right)));
            }
            Ok(left.cmp(right))
        }
        // A bool compares with 0 and 1, which is how a user writes `active == 1`.
        (Value::Bool(left), Value::Word(right, _)) => Ok(word_of_bool(*left).cmp(right)),
        (Value::Word(left, _), Value::Bool(right)) => Ok(left.cmp(&word_of_bool(*right))),
        _ => Err("a number and a string cannot be compared".to_owned()),
    }
}

/// A word as a signed 256-bit number, for ordering: the sign bit inverts the order of the
/// two halves, so a negative value sorts below every non-negative one.
fn signed_value(word: &Word) -> (bool, Word) {
    let negative = word[0] & 0x80 != 0;
    // Negatives compare among themselves in the same direction as their two's complement
    // bit patterns, so only the halves need separating.
    (!negative, *word)
}

fn word_of_bool(value: bool) -> Word {
    let mut word = [0_u8; 32];
    word[31] = u8::from(value);
    word
}

/// Finds `symbol` outside a `[...]` index or a quoted string, so `balances[0x1] == 2`
/// splits at the right place.
fn find_operator(input: &str, symbol: &str) -> Option<usize> {
    let bytes = input.as_bytes();
    let mut depth = 0_i32;
    let mut quoted = false;
    for index in 0..bytes.len() {
        match bytes[index] {
            b'"' => quoted = !quoted,
            b'[' if !quoted => depth += 1,
            b']' if !quoted => depth -= 1,
            _ => {}
        }
        if quoted || depth != 0 {
            continue;
        }
        if input[index..].starts_with(symbol) {
            // `<` must not match the `<` of `<=`, which the caller tries first, and `=`
            // of `==` must not split `!=`.
            return Some(index);
        }
    }
    None
}

impl Operand {
    fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("a comparison is missing one side".to_owned());
        }
        if let Some(text) = input
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
        {
            return Ok(Self::Text(text.to_owned()));
        }
        match input {
            "true" => return Ok(Self::Bool(true)),
            "false" => return Ok(Self::Bool(false)),
            _ => {}
        }
        if input.starts_with("0x") || input.bytes().all(|byte| byte.is_ascii_digit()) {
            return parse_word(input)
                .map(Self::Literal)
                .map_err(|error| error.to_string());
        }
        Ok(Self::Name(input.to_owned()))
    }
}

/// Everything a condition can read at one step.
pub struct ConditionContext<'a> {
    map: &'a StepMap,
    step: usize,
    words: Option<StorageWords<'a>>,
    op: &'a str,
    pc: u64,
    gas: u64,
    depth: u64,
    /// The frame being entered or executing, for reading its arguments by name.
    frame: Option<&'a Frame>,
}

impl<'a> ConditionContext<'a> {
    /// The context at `step`, given the trace step's own facts.
    #[must_use]
    pub fn new(
        map: &'a StepMap,
        step: usize,
        trace_step: &'a soldb_core::TraceStep,
        words: Option<StorageWords<'a>>,
    ) -> Self {
        Self {
            map,
            step,
            words,
            op: &trace_step.op,
            pc: trace_step.pc,
            gas: trace_step.gas,
            depth: trace_step.depth,
            frame: None,
        }
    }

    /// Reads the arguments of this frame by name, when the trace proved them.
    #[must_use]
    pub fn with_frame(mut self, frame: Option<&'a Frame>) -> Self {
        self.frame = frame;
        self
    }

    fn resolve(&self, operand: &Operand) -> Result<Value, String> {
        match operand {
            Operand::Literal(word) => Ok(Value::Word(*word, false)),
            Operand::Bool(value) => Ok(Value::Bool(*value)),
            Operand::Text(text) => Ok(Value::Text(text.clone())),
            Operand::Name(name) => self.value(name),
        }
    }

    /// The value of a name: a fact about the step, an argument of the frame, or a state
    /// variable read through the storage layout.
    fn value(&self, name: &str) -> Result<Value, String> {
        match name {
            "pc" => return Ok(Value::Word(word_of_u64(self.pc), false)),
            "gas" => return Ok(Value::Word(word_of_u64(self.gas), false)),
            "depth" => return Ok(Value::Word(word_of_u64(self.depth), false)),
            "step" => {
                return Ok(Value::Word(word_of_u64(self.step as u64), false));
            }
            "op" => return Ok(Value::Text(self.op.to_owned())),
            _ => {}
        }
        if let Some(argument) = self.frame.and_then(|frame| {
            frame
                .arguments
                .iter()
                .find(|argument| argument.name == name)
        }) {
            let word = parse_word(argument.value.raw.as_deref().unwrap_or("0x0"))
                .map_err(|error| error.to_string())?;
            return Ok(Value::Word(word, argument.ty.starts_with("int")));
        }
        let Some(layout) = self.layout() else {
            return Err(format!(
                "`{name}` is not a step value or an argument here, and no storage layout is loaded to look it up as a state variable"
            ));
        };
        let Some(words) = self.words.as_ref() else {
            return Err(format!(
                "no storage was recorded, so `{name}` cannot be read"
            ));
        };
        let variable = state_value(layout, words, name)?;
        if variable.value.status == DebugValueStatus::Unavailable {
            return Err(format!("`{name}` is {}", variable.value.display));
        }
        let Some(raw) = variable.value.raw.as_deref() else {
            return Err(format!(
                "`{name}` is a {}, which a condition cannot compare",
                variable.ty
            ));
        };
        let word = parse_word(raw).map_err(|error| error.to_string())?;
        Ok(Value::Word(word, variable.ty.starts_with("int")))
    }

    fn layout(&self) -> Option<&StorageLayout> {
        self.map
            .contract_at_step(self.step)?
            .storage_layout
            .as_ref()
    }
}

fn word_of_u64(value: u64) -> Word {
    let mut word = [0_u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

#[cfg(test)]
mod tests {
    use super::{Comparison, Condition, Evaluation, Operand, Operator, Value};

    fn parse(input: &str) -> Condition {
        Condition::parse(input).expect(input)
    }

    #[test]
    fn parses_comparisons_and_groups() {
        let condition = parse("counter > 4");
        assert_eq!(condition.text(), "counter > 4");
        assert_eq!(condition.groups.len(), 1);
        assert_eq!(
            condition.groups[0][0],
            Comparison {
                left: Operand::Name("counter".to_owned()),
                operator: Some(Operator::Greater),
                right: Some(Operand::Literal(super::word_of_u64(4))),
            }
        );

        // `<=` and `>=` are not read as `<` and `>`.
        let condition = parse("gas <= 100 && depth >= 1");
        assert_eq!(condition.groups[0].len(), 2);
        assert_eq!(condition.groups[0][0].operator, Some(Operator::LessOrEqual));
        assert_eq!(
            condition.groups[0][1].operator,
            Some(Operator::GreaterOrEqual)
        );

        // An index is not split at its contents.
        let condition = parse("balances[0x00000000000000000000000000000000000000aa] == 25");
        assert_eq!(
            condition.groups[0][0].left,
            Operand::Name("balances[0x00000000000000000000000000000000000000aa]".to_owned())
        );

        let condition = parse("active || counter == 0");
        assert_eq!(condition.groups.len(), 2);
        assert_eq!(condition.groups[0][0].operator, None);

        assert!(Condition::parse("").is_err());
        assert!(Condition::parse("counter >").is_err());
        assert!(Condition::parse("a && ").is_err());
    }

    #[test]
    fn compares_words_bools_and_text() {
        let one = super::word_of_u64(1);
        let two = super::word_of_u64(2);
        assert_eq!(
            super::compare(&Value::Word(one, false), &Value::Word(two, false)),
            Ok(std::cmp::Ordering::Less)
        );
        // Signed values order by their sign first: -1 is below 1.
        let minus_one = [0xff_u8; 32];
        assert_eq!(
            super::compare(&Value::Word(minus_one, true), &Value::Word(one, true)),
            Ok(std::cmp::Ordering::Less)
        );
        // Unsigned, the same word is the largest there is.
        assert_eq!(
            super::compare(&Value::Word(minus_one, false), &Value::Word(one, false)),
            Ok(std::cmp::Ordering::Greater)
        );
        assert_eq!(
            super::compare(&Value::Bool(true), &Value::Word(one, false)),
            Ok(std::cmp::Ordering::Equal)
        );
        assert_eq!(
            super::compare(
                &Value::Text("SSTORE".to_owned()),
                &Value::Text("SSTORE".to_owned())
            ),
            Ok(std::cmp::Ordering::Equal)
        );
        assert!(super::compare(&Value::Text("a".to_owned()), &Value::Bool(true)).is_err());
    }

    #[test]
    fn evaluation_of_groups_short_circuits_and_reports_the_first_reason() {
        let unavailable = Evaluation::Unavailable("no".to_owned());
        assert_ne!(unavailable, Evaluation::False);
        assert_eq!(Evaluation::from(true), Evaluation::True);
        assert_eq!(Evaluation::from(false), Evaluation::False);
    }
}
