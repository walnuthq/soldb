//! Loading and interpreting compiler-generated Solidity debug information.
//!
//! This is the metadata half of an ETHDebug-first debugger: it turns `solc` artifacts
//! into the program-counter, source-location, variable, and ABI lookups the rest of the
//! workspace needs. Nothing here touches the network.
//!
//! - [`metadata`] models ETHDebug artifacts: instructions, their source spans, live
//!   variable locations, and the `address:name:dir` contract specs used on the command
//!   line.
//! - [`source_map`] reads the legacy `srcmap` format, the fallback for compilers that
//!   predate ETHDebug.
//! - [`abi`] encodes calldata and parses function signatures, including tuples and
//!   arrays, and carries the keccak-256 implementation used to derive selectors.
//! - [`events`] decodes logs against event ABIs.
//!
//! Everything decoded here comes from files or from chain data, so it is untrusted:
//! offsets and lengths read out of an artifact or a log payload are validated rather
//! than trusted to be in range.

pub mod abi;
pub mod events;
pub mod metadata;
pub mod source_map;

pub use abi::{
    canonical_abi_input_type, encode_abi_arguments, encode_function_call, function_selector,
    keccak256, match_abi_types, match_single_type, parse_signature, parse_tuple_arg, AbiInput,
    FunctionSignature,
};
pub use events::{
    event_signature, event_topic, parse_event_abis, DecodedEvent, DecodedEventArg, EventAbi,
    EventParam, EventRegistry, EventRegistryEntry,
};
pub use metadata::{
    parse_ethdebug_spec, parse_multi_contract_spec, parse_single_contract_spec,
    parse_variable_locations, EthdebugInfo, EthdebugSpec, Instruction, SourceLocation,
    VariableLocation,
};
pub use source_map::{
    build_pc_to_instruction_map, is_legacy_compiler, parse_srcmap, SourceMapEntry, SourceMapInfo,
};
