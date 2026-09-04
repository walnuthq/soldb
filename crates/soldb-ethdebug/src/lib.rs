//! Loading and interpreting compiler-generated Solidity debug information.
//!
//! This is the metadata half of an ETHDebug-first debugger: it turns `solc` artifacts
//! into the program-counter, source-location, variable, and ABI lookups the rest of the
//! workspace needs. Nothing here touches the network.
//!
//! - [`metadata`] models ETHDebug artifacts: instructions, their source spans, live
//!   variable locations, and the `address:name:dir` contract specs used on the command
//!   line.
//! - [`source_map`] reads the legacy `srcmap` format for compiler and tooling
//!   interoperability when ETHDebug programs are unavailable.
//! - [`abi`] encodes calldata and parses function signatures, including tuples and
//!   arrays, and carries the keccak-256 implementation used to derive selectors.
//! - [`events`] decodes logs against event ABIs.
//!
//! Everything decoded here comes from files or from chain data, so it is untrusted:
//! offsets and lengths read out of an artifact or a log payload are validated rather
//! than trusted to be in range.

pub mod abi;
pub mod artifacts;
pub mod events;
pub mod metadata;
pub mod source_map;
pub mod storage_layout;

pub use abi::{
    canonical_abi_input_type, encode_abi_arguments, encode_function_call, function_selector,
    keccak256, match_abi_types, match_single_type, parse_signature, parse_tuple_arg, AbiInput,
    FunctionSignature,
};
pub use artifacts::{
    contract_name_from_program_path, ethdebug_resources_from_metadata, find_ethdebug_metadata,
    find_program_ethdebug, load_debug_program, load_debug_program_with_sources,
    load_storage_layout, read_debug_source, read_debug_source_from, read_json_file,
    source_candidates, DebugProgram,
};
pub use events::{
    event_signature, event_topic, parse_event_abis, DecodedEvent, DecodedEventArg, EventAbi,
    EventParam, EventRegistry, EventRegistryEntry,
};
pub use metadata::{
    parse_compilation_sources, parse_ethdebug_spec, parse_multi_contract_spec,
    parse_single_contract_spec, parse_variable_locations, read_compilation_source, EthdebugInfo,
    EthdebugSpec, FunctionExit, FunctionIdentity, Instruction, SourceLocation, VariableLocation,
};
pub use source_map::{
    build_pc_to_instruction_map, is_legacy_compiler, load_source_map_program,
    load_source_map_program_with_sources, parse_srcmap, SourceMapEntry, SourceMapEnvironment,
    SourceMapInfo, SourceMapProgram,
};
pub use storage_layout::{
    add_word, decode_value, element_place, mapping_slot, parse_word, word_hex, word_to_decimal,
    DecodedStorage, StorageEncoding, StorageLayout, StorageMember, StorageRef, StorageType,
    StorageVariable, Word,
};
