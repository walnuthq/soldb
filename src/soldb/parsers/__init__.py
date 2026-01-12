"""
Parsers module for soldb.

This module contains all parsers for debug information formats:
- ETHDebug (solc >= 0.8.29)
- Source maps (legacy solc)
- ABI utilities
- DWARF debug info
"""

from .ethdebug import (
    ETHDebugParser,
    ETHDebugInfo,
    SourceLocation as ETHDebugSourceLocation,
    Instruction,
    VariableLocation,
    MultiContractETHDebugParser,
    ContractDebugInfo,
    ExecutionContext,
    ETHDebugDirParser,
    ETHDebugSpec,
    SourceFileLoader,
    source_loader,
)
from .source_map import (
    SourceMapParser,
    SourceMapInfo,
    SourceMapEntry,
    SourceLocation as SrcMapSourceLocation,
    PCMapping,
    SourceMappingManager,
    load_debug_info,
)
from .abi import (
    match_abi_types,
    match_single_type,
    parse_signature,
    parse_tuple_arg,
)
from .dwarf import (
    DwarfParser,
    DwarfFunction,
    DwarfVariable,
    DwarfLineEntry,
    load_dwarf_info,
    HAS_ELFTOOLS,
)

__all__ = [
    # ETHDebug
    'ETHDebugParser',
    'ETHDebugInfo',
    'ETHDebugSourceLocation',
    'Instruction',
    'VariableLocation',
    'MultiContractETHDebugParser',
    'ContractDebugInfo',
    'ExecutionContext',
    'ETHDebugDirParser',
    'ETHDebugSpec',
    'SourceFileLoader',
    'source_loader',
    # Source maps
    'SourceMapParser',
    'SourceMapInfo',
    'SourceMapEntry',
    'SrcMapSourceLocation',
    'PCMapping',
    'SourceMappingManager',
    'load_debug_info',
    # ABI
    'match_abi_types',
    'match_single_type',
    'parse_signature',
    'parse_tuple_arg',
    # DWARF
    'DwarfParser',
    'DwarfFunction',
    'DwarfVariable',
    'DwarfLineEntry',
    'load_dwarf_info',
    'HAS_ELFTOOLS',
]
