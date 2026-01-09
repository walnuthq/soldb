"""
Source Map Parser for Legacy Solidity Compilers (<0.8.29)

Parses srcmap-runtime from combined.json output.
Format specification: https://docs.soliditylang.org/en/latest/internals/source_mappings.html

Each srcmap entry is `s:l:f:j:m` where:
- s = byte offset in source file
- l = length in bytes  
- f = source file index
- j = jump type (i=into function, o=out of function, -=regular)
- m = modifier depth

Entries are separated by `;`. Empty fields inherit from previous entry.
"""

import json
import os
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from pathlib import Path

from soldb.source_file_loader import source_loader


# EVM opcodes and their sizes (PUSH1-PUSH32 are multi-byte)
PUSH_OPCODES = {
    0x60: 1,  # PUSH1
    0x61: 2,  # PUSH2
    0x62: 3,  # PUSH3
    0x63: 4,  # PUSH4
    0x64: 5,  # PUSH5
    0x65: 6,  # PUSH6
    0x66: 7,  # PUSH7
    0x67: 8,  # PUSH8
    0x68: 9,  # PUSH9
    0x69: 10, # PUSH10
    0x6a: 11, # PUSH11
    0x6b: 12, # PUSH12
    0x6c: 13, # PUSH13
    0x6d: 14, # PUSH14
    0x6e: 15, # PUSH15
    0x6f: 16, # PUSH16
    0x70: 17, # PUSH17
    0x71: 18, # PUSH18
    0x72: 19, # PUSH19
    0x73: 20, # PUSH20
    0x74: 21, # PUSH21
    0x75: 22, # PUSH22
    0x76: 23, # PUSH23
    0x77: 24, # PUSH24
    0x78: 25, # PUSH25
    0x79: 26, # PUSH26
    0x7a: 27, # PUSH27
    0x7b: 28, # PUSH28
    0x7c: 29, # PUSH29
    0x7d: 30, # PUSH30
    0x7e: 31, # PUSH31
    0x7f: 32, # PUSH32
}


@dataclass
class SourceMapEntry:
    """Single source mapping entry."""
    offset: int      # s - byte offset in source file
    length: int      # l - length in bytes
    file_index: int  # f - source file index (-1 = no source)
    jump_type: str   # j - jump type (i/o/-)
    modifier_depth: int  # m - modifier depth
    
    def is_valid(self) -> bool:
        """Check if this entry points to valid source."""
        return self.file_index >= 0 and self.offset >= 0


@dataclass 
class SourceMapInfo:
    """Container for parsed source map information."""
    contract_name: str
    sources: List[str]  # List of source file paths by index
    bytecode: bytes
    srcmap_entries: List[SourceMapEntry]  # One per instruction
    pc_to_instruction_index: Dict[int, int]  # PC -> instruction index
    compiler_version: Optional[str] = None
    
    def get_source_entry_at_pc(self, pc: int) -> Optional[SourceMapEntry]:
        """Get source mapping entry for a specific PC."""
        instr_idx = self.pc_to_instruction_index.get(pc)
        if instr_idx is None or instr_idx >= len(self.srcmap_entries):
            return None
        return self.srcmap_entries[instr_idx]
    
    def get_source_info(self, pc: int) -> Optional[Tuple[str, int, int]]:
        """Get (source_file, offset, length) for PC."""
        entry = self.get_source_entry_at_pc(pc)
        if not entry or not entry.is_valid():
            return None
        if entry.file_index >= len(self.sources):
            return None
        return (self.sources[entry.file_index], entry.offset, entry.length)


class SourceMapParser:
    """Parser for srcmap-runtime from combined.json."""
    
    def __init__(self):
        self.source_map_info: Optional[SourceMapInfo] = None
        self.debug_dir: Optional[Path] = None
    
    def load_combined_json(
        self, 
        debug_dir: Union[str, Path], 
        contract_name: Optional[str] = None
    ) -> SourceMapInfo:
        """
        Load and parse combined.json file.
        
        Args:
            debug_dir: Directory containing combined.json
            contract_name: Optional contract name to filter by
            
        Returns:
            SourceMapInfo with parsed source mapping
        """
        debug_dir = Path(debug_dir)
        self.debug_dir = debug_dir
        
        combined_file = debug_dir / "combined.json"
        if not combined_file.exists():
            raise FileNotFoundError(f"combined.json not found in {debug_dir}")
        
        with open(combined_file) as f:
            data = json.load(f)
        
        contracts = data.get("contracts", {})
        source_list = data.get("sourceList", [])
        
        if not contracts:
            raise ValueError("No contracts found in combined.json")
        
        # Find target contract
        target_contract_key = None
        target_contract_data = None
        
        if contract_name:
            # First, try exact match with contract name (parts[1])
            for key, contract_data in contracts.items():
                # Key format is "SourceFile.sol:ContractName"
                parts = key.split(":")
                if len(parts) >= 2 and parts[1] == contract_name:
                    # Make sure it has bytecode (not an interface)
                    if contract_data.get("bin-runtime"):
                        target_contract_key = key
                        target_contract_data = contract_data
                        break
            
            # If not found, try to find contract with matching name in sourceList
            if not target_contract_data:
                # Check if contract_name matches a source file name
                for source_file in source_list:
                    source_stem = Path(source_file).stem
                    if contract_name.lower() == source_stem.lower():
                        # Look for contract with this source file
                        for key, contract_data in contracts.items():
                            parts = key.split(":")
                            if len(parts) >= 1 and parts[0] == source_file:
                                # Prefer contract with same name as source file
                                if len(parts) >= 2 and parts[1] == contract_name and contract_data.get("bin-runtime"):
                                    target_contract_key = key
                                    target_contract_data = contract_data
                                    break
                                # Or any contract from this source with bytecode
                                elif contract_data.get("bin-runtime") and not target_contract_data:
                                    target_contract_key = key
                                    target_contract_data = contract_data
        
        if not target_contract_data:
            # Use first contract with non-empty bytecode
            for key, contract_data in contracts.items():
                bin_runtime = contract_data.get("bin-runtime", "")
                if bin_runtime and len(bin_runtime) > 0:
                    target_contract_key = key
                    target_contract_data = contract_data
                    break
        
        if not target_contract_data:
            raise ValueError(f"No contract found with runtime bytecode in combined.json")
        
        # Extract data
        bin_runtime = target_contract_data.get("bin-runtime", "")
        srcmap_runtime = target_contract_data.get("srcmap-runtime", "")
        metadata_str = target_contract_data.get("metadata", "")
        
        if not bin_runtime:
            raise ValueError(f"No bin-runtime found for contract {target_contract_key}")
        
        if not srcmap_runtime:
            raise ValueError(f"No srcmap-runtime found for contract {target_contract_key}")
        
        # Parse compiler version from metadata
        compiler_version = None
        if metadata_str:
            try:
                metadata = json.loads(metadata_str)
                compiler_version = metadata.get("compiler", {}).get("version")
            except json.JSONDecodeError:
                pass
        
        # Convert hex bytecode to bytes
        bytecode = bytes.fromhex(bin_runtime)
        
        # Build PC to instruction index mapping
        pc_to_idx = self._build_pc_to_instruction_map(bytecode)
        
        # Parse source map entries
        entries = self._parse_srcmap(srcmap_runtime)
        
        # Extract contract name from key
        parts = target_contract_key.split(":")
        final_contract_name = parts[1] if len(parts) >= 2 else parts[0].replace(".sol", "")
        
        self.source_map_info = SourceMapInfo(
            contract_name=final_contract_name,
            sources=source_list,
            bytecode=bytecode,
            srcmap_entries=entries,
            pc_to_instruction_index=pc_to_idx,
            compiler_version=compiler_version
        )
        
        return self.source_map_info
    
    def _build_pc_to_instruction_map(self, bytecode: bytes) -> Dict[int, int]:
        """
        Build mapping from PC (bytecode offset) to instruction index.
        
        CRITICAL: PUSH opcodes are followed by N bytes of data.
        e.g., PUSH1 (0x60) is followed by 1 byte, PUSH32 (0x7f) by 32 bytes.
        These data bytes are NOT separate instructions.
        """
        pc_to_idx = {}
        pc = 0
        instr_idx = 0
        
        while pc < len(bytecode):
            pc_to_idx[pc] = instr_idx
            opcode = bytecode[pc]
            
            # Calculate instruction size
            if opcode in PUSH_OPCODES:
                # PUSH instructions: 1 byte opcode + N bytes data
                data_size = PUSH_OPCODES[opcode]
                pc += 1 + data_size
            else:
                # All other instructions are 1 byte
                pc += 1
            
            instr_idx += 1
        
        return pc_to_idx
    
    def _parse_srcmap(self, srcmap: str) -> List[SourceMapEntry]:
        """
        Parse srcmap string into list of SourceMapEntry.
        
        Format: "s:l:f:j:m;s:l:f:j:m;..."
        Empty fields inherit from previous entry.
        Missing trailing fields use defaults.
        """
        if not srcmap:
            return []
        
        entries = []
        
        # Default values
        prev_offset = 0
        prev_length = 0
        prev_file_index = -1
        prev_jump_type = "-"
        prev_modifier_depth = 0
        
        for part in srcmap.split(";"):
            if not part:
                # Empty entry - inherit all from previous
                entries.append(SourceMapEntry(
                    offset=prev_offset,
                    length=prev_length,
                    file_index=prev_file_index,
                    jump_type=prev_jump_type,
                    modifier_depth=prev_modifier_depth
                ))
                continue
            
            fields = part.split(":")
            
            # Parse each field, using previous value if empty
            offset = int(fields[0]) if len(fields) > 0 and fields[0] and fields[0].strip() else prev_offset
            length = int(fields[1]) if len(fields) > 1 and fields[1] and fields[1].strip() else prev_length
            file_index = int(fields[2]) if len(fields) > 2 and fields[2] and fields[2].strip() else prev_file_index
            jump_type = fields[3] if len(fields) > 3 and fields[3] and fields[3].strip() else prev_jump_type
            modifier_depth = int(fields[4]) if len(fields) > 4 and fields[4] and fields[4].strip() else prev_modifier_depth
            
            entry = SourceMapEntry(
                offset=offset,
                length=length,
                file_index=file_index,
                jump_type=jump_type,
                modifier_depth=modifier_depth
            )
            entries.append(entry)
            
            # Update previous values
            prev_offset = offset
            prev_length = length
            prev_file_index = file_index
            prev_jump_type = jump_type
            prev_modifier_depth = modifier_depth
        
        return entries
    
    def load_source_file(self, source_path: str) -> List[str]:
        """Load and cache source file lines using centralized loader."""
        return source_loader.load_source_file(source_path, self.debug_dir)
    
    def offset_to_line_col(self, source_path: str, offset: int) -> Tuple[int, int]:
        """Convert byte offset to line and column in source file."""
        lines = self.load_source_file(source_path)
        
        current_offset = 0
        for line_num, line in enumerate(lines, 1):
            line_len = len(line)
            if current_offset + line_len > offset:
                col = offset - current_offset + 1
                return (line_num, col)
            current_offset += line_len
        
        return (1, 1)
    
    def get_source_context(self, pc: int, context_lines: int = 2) -> Optional[Dict[str, Any]]:
        """Get source code context around a PC."""
        if not self.source_map_info:
            return None
        
        source_info = self.source_map_info.get_source_info(pc)
        if not source_info:
            return None
        
        source_path, offset, length = source_info
        lines = self.load_source_file(source_path)
        line_num, col = self.offset_to_line_col(source_path, offset)
        
        # Get current line content
        current_content = ""
        if 0 < line_num <= len(lines):
            current_content = lines[line_num - 1].rstrip()
        
        # Get context lines
        start_line = max(1, line_num - context_lines)
        end_line = min(len(lines), line_num + context_lines)
        
        context = {
            'file': source_path,
            'line': line_num,
            'column': col,
            'content': current_content,
            'context_lines': [],
            'lines': []
        }
        
        for i in range(start_line, end_line + 1):
            if i <= len(lines):
                context['context_lines'].append(lines[i-1].rstrip())
                context['lines'].append({
                    'number': i,
                    'content': lines[i-1].rstrip(),
                    'current': i == line_num
                })
        
        return context
    
    def get_source_mapping(self) -> Dict[int, Tuple[str, int, int]]:
        """Get PC to source line mapping."""
        if not self.source_map_info:
            return {}
        
        pc_to_source = {}
        unique_lines = set()
        
        for pc, instr_idx in self.source_map_info.pc_to_instruction_index.items():
            source_info = self.source_map_info.get_source_info(pc)
            if source_info:
                source_path, offset, length = source_info
                line, col = self.offset_to_line_col(source_path, offset)
                pc_to_source[pc] = (source_path, line, col)
                unique_lines.add((source_path, line))
        
        return pc_to_source
    
    @staticmethod
    def is_legacy_compiler(version: str) -> bool:
        """
        Check if compiler version is older than 0.8.29 (needs srcmap fallback).
        
        Args:
            version: Compiler version string like "0.8.26+commit.xxx"
        
        Returns:
            True if version < 0.8.29
        """
        if not version:
            return True
        
        # Extract major.minor.patch
        parts = version.split("+")[0].split(".")
        if len(parts) < 3:
            return True
        
        try:
            major = int(parts[0])
            minor = int(parts[1])
            patch = int(parts[2])
            
            # Compare with 0.8.29
            if major < 0:
                return True
            if major == 0:
                if minor < 8:
                    return True
                if minor == 8 and patch < 29:
                    return True
            return False
        except ValueError:
            return True


def load_debug_info(debug_dir: Union[str, Path], contract_name: Optional[str] = None):
    """
    Load debug info from directory, automatically selecting parser.
    
    First tries ETHDebug (for solc >= 0.8.29), then falls back to srcmap (legacy).
    
    Returns:
        Tuple of (parser_instance, debug_info) where parser_instance is either
        ETHDebugParser or SourceMapParser
    """
    debug_dir = Path(debug_dir)
    
    # Try ETHDebug first
    ethdebug_file = debug_dir / "ethdebug.json"
    if ethdebug_file.exists():
        from soldb.ethdebug_parser import ETHDebugParser
        parser = ETHDebugParser()
        info = parser.load_ethdebug_files(debug_dir, contract_name)
        return (parser, info)
    
    # Fallback to combined.json / srcmap
    combined_file = debug_dir / "combined.json"
    if combined_file.exists():
        parser = SourceMapParser()
        info = parser.load_combined_json(debug_dir, contract_name)
        return (parser, info)
    
    raise FileNotFoundError(
        f"No debug info found in {debug_dir}. "
        f"Expected ethdebug.json (solc >= 0.8.29) or combined.json (legacy solc)."
    )
