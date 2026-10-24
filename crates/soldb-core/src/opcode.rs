//! EVM opcodes by byte, with the mnemonics a trace spells them with.
//!
//! The names are REVM's, which is what the replay backend and Anvil's `structLogs`
//! report. A byte with no instruction is spelled `UNKNOWN(0x..)`, as the replay backend
//! spells it. A step whose backend spelled its mnemonic differently keeps that spelling;
//! see [`crate::StepTable`].

use std::collections::HashMap;
use std::sync::OnceLock;

pub const STOP: u8 = 0x00;
pub const KECCAK256: u8 = 0x20;
pub const CALLDATACOPY: u8 = 0x37;
pub const CODECOPY: u8 = 0x39;
pub const EXTCODECOPY: u8 = 0x3c;
pub const RETURNDATACOPY: u8 = 0x3e;
pub const MLOAD: u8 = 0x51;
pub const MSTORE: u8 = 0x52;
pub const MSTORE8: u8 = 0x53;
pub const SLOAD: u8 = 0x54;
pub const SSTORE: u8 = 0x55;
pub const JUMP: u8 = 0x56;
pub const JUMPI: u8 = 0x57;
pub const JUMPDEST: u8 = 0x5b;
pub const TLOAD: u8 = 0x5c;
pub const TSTORE: u8 = 0x5d;
pub const MCOPY: u8 = 0x5e;
pub const CREATE: u8 = 0xf0;
pub const CALL: u8 = 0xf1;
pub const CALLCODE: u8 = 0xf2;
pub const RETURN: u8 = 0xf3;
pub const DELEGATECALL: u8 = 0xf4;
pub const CREATE2: u8 = 0xf5;
pub const STATICCALL: u8 = 0xfa;
pub const REVERT: u8 = 0xfd;
pub const INVALID: u8 = 0xfe;
pub const SELFDESTRUCT: u8 = 0xff;

/// The mnemonic of every byte.
const NAMES: [&str; 256] = [
    "STOP",
    "ADD",
    "MUL",
    "SUB",
    "DIV",
    "SDIV",
    "MOD",
    "SMOD",
    "ADDMOD",
    "MULMOD",
    "EXP",
    "SIGNEXTEND",
    "UNKNOWN(0x0c)",
    "UNKNOWN(0x0d)",
    "UNKNOWN(0x0e)",
    "UNKNOWN(0x0f)",
    "LT",
    "GT",
    "SLT",
    "SGT",
    "EQ",
    "ISZERO",
    "AND",
    "OR",
    "XOR",
    "NOT",
    "BYTE",
    "SHL",
    "SHR",
    "SAR",
    "CLZ",
    "UNKNOWN(0x1f)",
    "KECCAK256",
    "UNKNOWN(0x21)",
    "UNKNOWN(0x22)",
    "UNKNOWN(0x23)",
    "UNKNOWN(0x24)",
    "UNKNOWN(0x25)",
    "UNKNOWN(0x26)",
    "UNKNOWN(0x27)",
    "UNKNOWN(0x28)",
    "UNKNOWN(0x29)",
    "UNKNOWN(0x2a)",
    "UNKNOWN(0x2b)",
    "UNKNOWN(0x2c)",
    "UNKNOWN(0x2d)",
    "UNKNOWN(0x2e)",
    "UNKNOWN(0x2f)",
    "ADDRESS",
    "BALANCE",
    "ORIGIN",
    "CALLER",
    "CALLVALUE",
    "CALLDATALOAD",
    "CALLDATASIZE",
    "CALLDATACOPY",
    "CODESIZE",
    "CODECOPY",
    "GASPRICE",
    "EXTCODESIZE",
    "EXTCODECOPY",
    "RETURNDATASIZE",
    "RETURNDATACOPY",
    "EXTCODEHASH",
    "BLOCKHASH",
    "COINBASE",
    "TIMESTAMP",
    "NUMBER",
    "DIFFICULTY",
    "GASLIMIT",
    "CHAINID",
    "SELFBALANCE",
    "BASEFEE",
    "BLOBHASH",
    "BLOBBASEFEE",
    "SLOTNUM",
    "UNKNOWN(0x4c)",
    "UNKNOWN(0x4d)",
    "UNKNOWN(0x4e)",
    "UNKNOWN(0x4f)",
    "POP",
    "MLOAD",
    "MSTORE",
    "MSTORE8",
    "SLOAD",
    "SSTORE",
    "JUMP",
    "JUMPI",
    "PC",
    "MSIZE",
    "GAS",
    "JUMPDEST",
    "TLOAD",
    "TSTORE",
    "MCOPY",
    "PUSH0",
    "PUSH1",
    "PUSH2",
    "PUSH3",
    "PUSH4",
    "PUSH5",
    "PUSH6",
    "PUSH7",
    "PUSH8",
    "PUSH9",
    "PUSH10",
    "PUSH11",
    "PUSH12",
    "PUSH13",
    "PUSH14",
    "PUSH15",
    "PUSH16",
    "PUSH17",
    "PUSH18",
    "PUSH19",
    "PUSH20",
    "PUSH21",
    "PUSH22",
    "PUSH23",
    "PUSH24",
    "PUSH25",
    "PUSH26",
    "PUSH27",
    "PUSH28",
    "PUSH29",
    "PUSH30",
    "PUSH31",
    "PUSH32",
    "DUP1",
    "DUP2",
    "DUP3",
    "DUP4",
    "DUP5",
    "DUP6",
    "DUP7",
    "DUP8",
    "DUP9",
    "DUP10",
    "DUP11",
    "DUP12",
    "DUP13",
    "DUP14",
    "DUP15",
    "DUP16",
    "SWAP1",
    "SWAP2",
    "SWAP3",
    "SWAP4",
    "SWAP5",
    "SWAP6",
    "SWAP7",
    "SWAP8",
    "SWAP9",
    "SWAP10",
    "SWAP11",
    "SWAP12",
    "SWAP13",
    "SWAP14",
    "SWAP15",
    "SWAP16",
    "LOG0",
    "LOG1",
    "LOG2",
    "LOG3",
    "LOG4",
    "UNKNOWN(0xa5)",
    "UNKNOWN(0xa6)",
    "UNKNOWN(0xa7)",
    "UNKNOWN(0xa8)",
    "UNKNOWN(0xa9)",
    "UNKNOWN(0xaa)",
    "UNKNOWN(0xab)",
    "UNKNOWN(0xac)",
    "UNKNOWN(0xad)",
    "UNKNOWN(0xae)",
    "UNKNOWN(0xaf)",
    "UNKNOWN(0xb0)",
    "UNKNOWN(0xb1)",
    "UNKNOWN(0xb2)",
    "UNKNOWN(0xb3)",
    "UNKNOWN(0xb4)",
    "UNKNOWN(0xb5)",
    "UNKNOWN(0xb6)",
    "UNKNOWN(0xb7)",
    "UNKNOWN(0xb8)",
    "UNKNOWN(0xb9)",
    "UNKNOWN(0xba)",
    "UNKNOWN(0xbb)",
    "UNKNOWN(0xbc)",
    "UNKNOWN(0xbd)",
    "UNKNOWN(0xbe)",
    "UNKNOWN(0xbf)",
    "UNKNOWN(0xc0)",
    "UNKNOWN(0xc1)",
    "UNKNOWN(0xc2)",
    "UNKNOWN(0xc3)",
    "UNKNOWN(0xc4)",
    "UNKNOWN(0xc5)",
    "UNKNOWN(0xc6)",
    "UNKNOWN(0xc7)",
    "UNKNOWN(0xc8)",
    "UNKNOWN(0xc9)",
    "UNKNOWN(0xca)",
    "UNKNOWN(0xcb)",
    "UNKNOWN(0xcc)",
    "UNKNOWN(0xcd)",
    "UNKNOWN(0xce)",
    "UNKNOWN(0xcf)",
    "UNKNOWN(0xd0)",
    "UNKNOWN(0xd1)",
    "UNKNOWN(0xd2)",
    "UNKNOWN(0xd3)",
    "UNKNOWN(0xd4)",
    "UNKNOWN(0xd5)",
    "UNKNOWN(0xd6)",
    "UNKNOWN(0xd7)",
    "UNKNOWN(0xd8)",
    "UNKNOWN(0xd9)",
    "UNKNOWN(0xda)",
    "UNKNOWN(0xdb)",
    "UNKNOWN(0xdc)",
    "UNKNOWN(0xdd)",
    "UNKNOWN(0xde)",
    "UNKNOWN(0xdf)",
    "UNKNOWN(0xe0)",
    "UNKNOWN(0xe1)",
    "UNKNOWN(0xe2)",
    "UNKNOWN(0xe3)",
    "UNKNOWN(0xe4)",
    "UNKNOWN(0xe5)",
    "DUPN",
    "SWAPN",
    "EXCHANGE",
    "UNKNOWN(0xe9)",
    "UNKNOWN(0xea)",
    "UNKNOWN(0xeb)",
    "UNKNOWN(0xec)",
    "UNKNOWN(0xed)",
    "UNKNOWN(0xee)",
    "UNKNOWN(0xef)",
    "CREATE",
    "CALL",
    "CALLCODE",
    "RETURN",
    "DELEGATECALL",
    "CREATE2",
    "UNKNOWN(0xf6)",
    "UNKNOWN(0xf7)",
    "UNKNOWN(0xf8)",
    "UNKNOWN(0xf9)",
    "STATICCALL",
    "UNKNOWN(0xfb)",
    "UNKNOWN(0xfc)",
    "REVERT",
    "INVALID",
    "SELFDESTRUCT",
];

/// The mnemonic of `op`.
#[must_use]
pub fn mnemonic(op: u8) -> &'static str {
    NAMES[usize::from(op)]
}

/// The byte whose mnemonic is `name`, exactly as [`mnemonic`] spells it.
#[must_use]
pub fn from_mnemonic(name: &str) -> Option<u8> {
    static BYTES: OnceLock<HashMap<&'static str, u8>> = OnceLock::new();
    BYTES
        .get_or_init(|| (0..=u8::MAX).map(|op| (mnemonic(op), op)).collect())
        .get(name)
        .copied()
}

/// The byte a backend means by `name`: the one [`from_mnemonic`] finds, the one another
/// client names differently (`SHA3`, `PREVRANDAO`, `SUICIDE`), or the one it spells out
/// for a byte without an instruction, such as geth's `opcode 0xef not defined`.
#[must_use]
pub fn from_spelling(name: &str) -> Option<u8> {
    if let Some(op) = from_mnemonic(name) {
        return Some(op);
    }
    match name {
        "SHA3" => Some(KECCAK256),
        "PREVRANDAO" | "RANDOM" => Some(0x44),
        "SUICIDE" => Some(SELFDESTRUCT),
        _ => {
            let start = name.find("0x").or_else(|| name.find("0X"))? + 2;
            let digits: String = name
                .get(start..)?
                .chars()
                .take_while(char::is_ascii_hexdigit)
                .collect();
            if digits.is_empty() || digits.len() > 2 {
                return None;
            }
            u8::from_str_radix(&digits, 16).ok()
        }
    }
}

/// Whether `op` is one of the four call instructions.
#[must_use]
pub fn is_call(op: u8) -> bool {
    matches!(op, CALL | CALLCODE | DELEGATECALL | STATICCALL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_byte_round_trips_through_its_mnemonic() {
        for op in 0..=u8::MAX {
            assert_eq!(from_mnemonic(mnemonic(op)), Some(op), "{}", mnemonic(op));
        }
        assert_eq!(mnemonic(SSTORE), "SSTORE");
        assert_eq!(mnemonic(0x0c), "UNKNOWN(0x0c)");
        assert_eq!(from_mnemonic("SHA3"), None);
    }

    #[test]
    fn other_clients_spellings_name_the_same_byte() {
        assert_eq!(from_spelling("SHA3"), Some(KECCAK256));
        assert_eq!(from_spelling("PREVRANDAO"), Some(0x44));
        assert_eq!(from_spelling("opcode 0xef not defined"), Some(0xef));
        assert_eq!(from_spelling("UNKNOWN(0x0c)"), Some(0x0c));
        assert_eq!(from_spelling("WHATEVER"), None);
        assert_eq!(from_spelling("opcode 0x123"), None);
    }
}
