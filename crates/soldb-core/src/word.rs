//! One machine word, as the EVM stack holds it.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// One 256-bit word, big-endian.
///
/// Printed the way traces spell stack words: `0x` and the value in lowercase hex without
/// leading zeros, and `0x0` for zero. A word read in any other spelling, padded or in
/// upper case, is printed in that one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct EvmWord(pub [u8; 32]);

/// Why a string is not a word.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WordError {
    /// The digits after the optional `0x` prefix are missing.
    #[error("no hex digits")]
    Empty,
    /// More digits than a 256-bit word holds, leading zeros aside.
    #[error("{0} significant hex digits do not fit in 256 bits")]
    TooLong(usize),
    /// A character that is not a hex digit, at its byte offset after any `0x` prefix.
    #[error("`{character}` at offset {offset} is not a hex digit")]
    InvalidDigit { offset: usize, character: char },
}

impl EvmWord {
    pub const ZERO: Self = Self([0; 32]);

    /// The word holding `value`.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }

    /// The word holding the big-endian `bytes`, which must be at most 32 of them.
    #[must_use]
    pub fn from_be_slice(bytes: &[u8]) -> Option<Self> {
        let start = 32_usize.checked_sub(bytes.len())?;
        let mut word = [0; 32];
        word[start..].copy_from_slice(bytes);
        Some(Self(word))
    }

    /// Reads hex digits, with or without a `0x` prefix and in either case.
    ///
    /// # Errors
    ///
    /// Returns a [`WordError`] when there are no digits, a character is not a hex digit,
    /// or the value does not fit in 256 bits.
    pub fn parse(text: &str) -> Result<Self, WordError> {
        let digits = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text);
        if digits.is_empty() {
            return Err(WordError::Empty);
        }
        // Decoded over bytes, never by slicing the string: input from a node or a file is
        // not guaranteed to be ASCII.
        let raw = digits.as_bytes();
        let mut first = raw.len();
        for (offset, digit) in raw.iter().enumerate() {
            match hex_value(*digit) {
                Some(0) => {}
                Some(_) => first = first.min(offset),
                None => {
                    // Every byte before `offset` is an ASCII digit, so it is a boundary.
                    let character = digits
                        .get(offset..)
                        .and_then(|rest| rest.chars().next())
                        .unwrap_or(char::REPLACEMENT_CHARACTER);
                    return Err(WordError::InvalidDigit { offset, character });
                }
            }
        }
        let significant = &raw[first..];
        if significant.len() > 64 {
            return Err(WordError::TooLong(significant.len()));
        }
        let mut word = [0_u8; 32];
        // Fill from the least significant digit up, two to a byte. Every digit was
        // checked above.
        for (position, digit) in significant.iter().rev().enumerate() {
            let value = hex_value(*digit).unwrap_or_default();
            let byte = &mut word[31 - position / 2];
            *byte |= if position % 2 == 0 { value } else { value << 4 };
        }
        Ok(Self(word))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }

    /// The value, when it fits in a `u64`.
    #[must_use]
    pub fn to_u64(&self) -> Option<u64> {
        if self.0[..24].iter().any(|byte| *byte != 0) {
            return None;
        }
        let mut low = [0; 8];
        low.copy_from_slice(&self.0[24..]);
        Some(u64::from_be_bytes(low))
    }

    /// The value, when it fits in a `usize`.
    #[must_use]
    pub fn to_usize(&self) -> Option<usize> {
        self.to_u64().and_then(|value| usize::try_from(value).ok())
    }
}

impl From<u64> for EvmWord {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl FromStr for EvmWord {
    type Err = WordError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl fmt::Display for EvmWord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut buffer = [0_u8; 66];
        buffer[0] = b'0';
        buffer[1] = b'x';
        let mut length = 2;
        for byte in self.0 {
            for nibble in [byte >> 4, byte & 0x0f] {
                // Leading zeros are dropped; the value starts at the first non-zero digit.
                if length == 2 && nibble == 0 {
                    continue;
                }
                buffer[length] = DIGITS[usize::from(nibble)];
                length += 1;
            }
        }
        if length == 2 {
            buffer[2] = b'0';
            length = 3;
        }
        formatter.write_str(std::str::from_utf8(&buffer[..length]).map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for EvmWord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl Serialize for EvmWord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EvmWord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::parse(&text).map_err(|error| serde::de::Error::custom(format!("stack word: {error}")))
    }
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prints_the_minimal_lowercase_spelling() {
        assert_eq!(EvmWord::ZERO.to_string(), "0x0");
        assert_eq!(EvmWord::from_u64(0x2a).to_string(), "0x2a");
        assert_eq!(EvmWord::parse("0x00FF").expect("word").to_string(), "0xff");
        assert_eq!(EvmWord::parse("ff").expect("word").to_string(), "0xff");
        let max = format!("0x{}", "f".repeat(64));
        assert_eq!(EvmWord::parse(&max).expect("word").to_string(), max);
        assert_eq!(
            EvmWord::parse(&format!("0x{}1", "0".repeat(80))).expect("word"),
            EvmWord::from_u64(1)
        );
    }

    #[test]
    fn refuses_what_is_not_a_word() {
        assert_eq!(EvmWord::parse("0x"), Err(WordError::Empty));
        assert_eq!(EvmWord::parse(&"1".repeat(65)), Err(WordError::TooLong(65)));
        assert_eq!(
            EvmWord::parse("0x1g"),
            Err(WordError::InvalidDigit {
                offset: 1,
                character: 'g'
            })
        );
    }

    #[test]
    fn converts_to_integers_when_they_fit() {
        assert_eq!(EvmWord::from_u64(7).to_u64(), Some(7));
        assert_eq!(EvmWord::from_u64(u64::MAX).to_u64(), Some(u64::MAX));
        assert_eq!(
            EvmWord::parse("0x10000000000000000")
                .expect("word")
                .to_u64(),
            None
        );
        assert_eq!(
            EvmWord::from_be_slice(&[1, 2]),
            Some(EvmWord::from_u64(0x0102))
        );
        assert_eq!(EvmWord::from_be_slice(&[0; 33]), None);
    }
}
