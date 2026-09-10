//! EVM opcode mnemonics, for naming the instructions of legacy bytecode.
//!
//! Legacy source maps carry no mnemonics, so adapting one to the ETHDebug model means
//! naming each instruction from its byte. The table is the opcode set REVM knows, so the
//! names match what an execution backend records for the same steps and a `JUMPDEST` in an
//! artifact is a `JUMPDEST` in a trace. A byte with no mnemonic is an invalid instruction.

/// The mnemonic of `opcode`, or `None` for a byte that is not an instruction.
#[must_use]
pub fn mnemonic(opcode: u8) -> Option<&'static str> {
    MNEMONICS[usize::from(opcode)]
}

/// The number of immediate bytes following `opcode` in legacy bytecode: `n` for `PUSHn`
/// and zero for everything else.
#[must_use]
pub fn immediate_size(opcode: u8) -> usize {
    if (0x60..=0x7f).contains(&opcode) {
        usize::from(opcode - 0x5f)
    } else {
        0
    }
}

const MNEMONICS: [Option<&str>; 256] = [
    Some("STOP"),           // 0x00
    Some("ADD"),            // 0x01
    Some("MUL"),            // 0x02
    Some("SUB"),            // 0x03
    Some("DIV"),            // 0x04
    Some("SDIV"),           // 0x05
    Some("MOD"),            // 0x06
    Some("SMOD"),           // 0x07
    Some("ADDMOD"),         // 0x08
    Some("MULMOD"),         // 0x09
    Some("EXP"),            // 0x0a
    Some("SIGNEXTEND"),     // 0x0b
    None,                   // 0x0c
    None,                   // 0x0d
    None,                   // 0x0e
    None,                   // 0x0f
    Some("LT"),             // 0x10
    Some("GT"),             // 0x11
    Some("SLT"),            // 0x12
    Some("SGT"),            // 0x13
    Some("EQ"),             // 0x14
    Some("ISZERO"),         // 0x15
    Some("AND"),            // 0x16
    Some("OR"),             // 0x17
    Some("XOR"),            // 0x18
    Some("NOT"),            // 0x19
    Some("BYTE"),           // 0x1a
    Some("SHL"),            // 0x1b
    Some("SHR"),            // 0x1c
    Some("SAR"),            // 0x1d
    Some("CLZ"),            // 0x1e
    None,                   // 0x1f
    Some("KECCAK256"),      // 0x20
    None,                   // 0x21
    None,                   // 0x22
    None,                   // 0x23
    None,                   // 0x24
    None,                   // 0x25
    None,                   // 0x26
    None,                   // 0x27
    None,                   // 0x28
    None,                   // 0x29
    None,                   // 0x2a
    None,                   // 0x2b
    None,                   // 0x2c
    None,                   // 0x2d
    None,                   // 0x2e
    None,                   // 0x2f
    Some("ADDRESS"),        // 0x30
    Some("BALANCE"),        // 0x31
    Some("ORIGIN"),         // 0x32
    Some("CALLER"),         // 0x33
    Some("CALLVALUE"),      // 0x34
    Some("CALLDATALOAD"),   // 0x35
    Some("CALLDATASIZE"),   // 0x36
    Some("CALLDATACOPY"),   // 0x37
    Some("CODESIZE"),       // 0x38
    Some("CODECOPY"),       // 0x39
    Some("GASPRICE"),       // 0x3a
    Some("EXTCODESIZE"),    // 0x3b
    Some("EXTCODECOPY"),    // 0x3c
    Some("RETURNDATASIZE"), // 0x3d
    Some("RETURNDATACOPY"), // 0x3e
    Some("EXTCODEHASH"),    // 0x3f
    Some("BLOCKHASH"),      // 0x40
    Some("COINBASE"),       // 0x41
    Some("TIMESTAMP"),      // 0x42
    Some("NUMBER"),         // 0x43
    Some("DIFFICULTY"),     // 0x44
    Some("GASLIMIT"),       // 0x45
    Some("CHAINID"),        // 0x46
    Some("SELFBALANCE"),    // 0x47
    Some("BASEFEE"),        // 0x48
    Some("BLOBHASH"),       // 0x49
    Some("BLOBBASEFEE"),    // 0x4a
    Some("SLOTNUM"),        // 0x4b
    None,                   // 0x4c
    None,                   // 0x4d
    None,                   // 0x4e
    None,                   // 0x4f
    Some("POP"),            // 0x50
    Some("MLOAD"),          // 0x51
    Some("MSTORE"),         // 0x52
    Some("MSTORE8"),        // 0x53
    Some("SLOAD"),          // 0x54
    Some("SSTORE"),         // 0x55
    Some("JUMP"),           // 0x56
    Some("JUMPI"),          // 0x57
    Some("PC"),             // 0x58
    Some("MSIZE"),          // 0x59
    Some("GAS"),            // 0x5a
    Some("JUMPDEST"),       // 0x5b
    Some("TLOAD"),          // 0x5c
    Some("TSTORE"),         // 0x5d
    Some("MCOPY"),          // 0x5e
    Some("PUSH0"),          // 0x5f
    Some("PUSH1"),          // 0x60
    Some("PUSH2"),          // 0x61
    Some("PUSH3"),          // 0x62
    Some("PUSH4"),          // 0x63
    Some("PUSH5"),          // 0x64
    Some("PUSH6"),          // 0x65
    Some("PUSH7"),          // 0x66
    Some("PUSH8"),          // 0x67
    Some("PUSH9"),          // 0x68
    Some("PUSH10"),         // 0x69
    Some("PUSH11"),         // 0x6a
    Some("PUSH12"),         // 0x6b
    Some("PUSH13"),         // 0x6c
    Some("PUSH14"),         // 0x6d
    Some("PUSH15"),         // 0x6e
    Some("PUSH16"),         // 0x6f
    Some("PUSH17"),         // 0x70
    Some("PUSH18"),         // 0x71
    Some("PUSH19"),         // 0x72
    Some("PUSH20"),         // 0x73
    Some("PUSH21"),         // 0x74
    Some("PUSH22"),         // 0x75
    Some("PUSH23"),         // 0x76
    Some("PUSH24"),         // 0x77
    Some("PUSH25"),         // 0x78
    Some("PUSH26"),         // 0x79
    Some("PUSH27"),         // 0x7a
    Some("PUSH28"),         // 0x7b
    Some("PUSH29"),         // 0x7c
    Some("PUSH30"),         // 0x7d
    Some("PUSH31"),         // 0x7e
    Some("PUSH32"),         // 0x7f
    Some("DUP1"),           // 0x80
    Some("DUP2"),           // 0x81
    Some("DUP3"),           // 0x82
    Some("DUP4"),           // 0x83
    Some("DUP5"),           // 0x84
    Some("DUP6"),           // 0x85
    Some("DUP7"),           // 0x86
    Some("DUP8"),           // 0x87
    Some("DUP9"),           // 0x88
    Some("DUP10"),          // 0x89
    Some("DUP11"),          // 0x8a
    Some("DUP12"),          // 0x8b
    Some("DUP13"),          // 0x8c
    Some("DUP14"),          // 0x8d
    Some("DUP15"),          // 0x8e
    Some("DUP16"),          // 0x8f
    Some("SWAP1"),          // 0x90
    Some("SWAP2"),          // 0x91
    Some("SWAP3"),          // 0x92
    Some("SWAP4"),          // 0x93
    Some("SWAP5"),          // 0x94
    Some("SWAP6"),          // 0x95
    Some("SWAP7"),          // 0x96
    Some("SWAP8"),          // 0x97
    Some("SWAP9"),          // 0x98
    Some("SWAP10"),         // 0x99
    Some("SWAP11"),         // 0x9a
    Some("SWAP12"),         // 0x9b
    Some("SWAP13"),         // 0x9c
    Some("SWAP14"),         // 0x9d
    Some("SWAP15"),         // 0x9e
    Some("SWAP16"),         // 0x9f
    Some("LOG0"),           // 0xa0
    Some("LOG1"),           // 0xa1
    Some("LOG2"),           // 0xa2
    Some("LOG3"),           // 0xa3
    Some("LOG4"),           // 0xa4
    None,                   // 0xa5
    None,                   // 0xa6
    None,                   // 0xa7
    None,                   // 0xa8
    None,                   // 0xa9
    None,                   // 0xaa
    None,                   // 0xab
    None,                   // 0xac
    None,                   // 0xad
    None,                   // 0xae
    None,                   // 0xaf
    None,                   // 0xb0
    None,                   // 0xb1
    None,                   // 0xb2
    None,                   // 0xb3
    None,                   // 0xb4
    None,                   // 0xb5
    None,                   // 0xb6
    None,                   // 0xb7
    None,                   // 0xb8
    None,                   // 0xb9
    None,                   // 0xba
    None,                   // 0xbb
    None,                   // 0xbc
    None,                   // 0xbd
    None,                   // 0xbe
    None,                   // 0xbf
    None,                   // 0xc0
    None,                   // 0xc1
    None,                   // 0xc2
    None,                   // 0xc3
    None,                   // 0xc4
    None,                   // 0xc5
    None,                   // 0xc6
    None,                   // 0xc7
    None,                   // 0xc8
    None,                   // 0xc9
    None,                   // 0xca
    None,                   // 0xcb
    None,                   // 0xcc
    None,                   // 0xcd
    None,                   // 0xce
    None,                   // 0xcf
    None,                   // 0xd0
    None,                   // 0xd1
    None,                   // 0xd2
    None,                   // 0xd3
    None,                   // 0xd4
    None,                   // 0xd5
    None,                   // 0xd6
    None,                   // 0xd7
    None,                   // 0xd8
    None,                   // 0xd9
    None,                   // 0xda
    None,                   // 0xdb
    None,                   // 0xdc
    None,                   // 0xdd
    None,                   // 0xde
    None,                   // 0xdf
    None,                   // 0xe0
    None,                   // 0xe1
    None,                   // 0xe2
    None,                   // 0xe3
    None,                   // 0xe4
    None,                   // 0xe5
    Some("DUPN"),           // 0xe6
    Some("SWAPN"),          // 0xe7
    Some("EXCHANGE"),       // 0xe8
    None,                   // 0xe9
    None,                   // 0xea
    None,                   // 0xeb
    None,                   // 0xec
    None,                   // 0xed
    None,                   // 0xee
    None,                   // 0xef
    Some("CREATE"),         // 0xf0
    Some("CALL"),           // 0xf1
    Some("CALLCODE"),       // 0xf2
    Some("RETURN"),         // 0xf3
    Some("DELEGATECALL"),   // 0xf4
    Some("CREATE2"),        // 0xf5
    None,                   // 0xf6
    None,                   // 0xf7
    None,                   // 0xf8
    None,                   // 0xf9
    Some("STATICCALL"),     // 0xfa
    None,                   // 0xfb
    None,                   // 0xfc
    Some("REVERT"),         // 0xfd
    Some("INVALID"),        // 0xfe
    Some("SELFDESTRUCT"),   // 0xff
];

#[cfg(test)]
mod tests {
    use super::{immediate_size, mnemonic, MNEMONICS};

    #[test]
    fn names_the_evm_instruction_set() {
        assert_eq!(mnemonic(0x00), Some("STOP"));
        assert_eq!(mnemonic(0x1e), Some("CLZ"));
        assert_eq!(mnemonic(0x20), Some("KECCAK256"));
        assert_eq!(mnemonic(0x5b), Some("JUMPDEST"));
        assert_eq!(mnemonic(0x5e), Some("MCOPY"));
        assert_eq!(mnemonic(0x5f), Some("PUSH0"));
        assert_eq!(mnemonic(0x60), Some("PUSH1"));
        assert_eq!(mnemonic(0x7f), Some("PUSH32"));
        assert_eq!(mnemonic(0x80), Some("DUP1"));
        assert_eq!(mnemonic(0x8f), Some("DUP16"));
        assert_eq!(mnemonic(0x90), Some("SWAP1"));
        assert_eq!(mnemonic(0x9f), Some("SWAP16"));
        assert_eq!(mnemonic(0xa4), Some("LOG4"));
        assert_eq!(mnemonic(0xf5), Some("CREATE2"));
        assert_eq!(mnemonic(0xfa), Some("STATICCALL"));
        assert_eq!(mnemonic(0xff), Some("SELFDESTRUCT"));
        assert_eq!(mnemonic(0x0c), None);
        assert_eq!(mnemonic(0x21), None);
        assert_eq!(mnemonic(0xef), None);
        assert_eq!(mnemonic(0xfc), None);
        assert_eq!(MNEMONICS.iter().filter(|name| name.is_some()).count(), 154);
    }

    #[test]
    fn only_pushes_carry_immediates() {
        assert_eq!(immediate_size(0x5f), 0);
        assert_eq!(immediate_size(0x60), 1);
        assert_eq!(immediate_size(0x7f), 32);
        assert_eq!(immediate_size(0x80), 0);
        assert_eq!(immediate_size(0xff), 0);
    }
}
