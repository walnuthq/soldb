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
from typing import Dict, List, Optional, Tuple, Any, Union, Set
from dataclasses import dataclass
from pathlib import Path

from .ethdebug import source_loader


# =============================================================================
# EVM Opcodes
# =============================================================================

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


# =============================================================================
# Data Classes
# =============================================================================

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


@dataclass
class SourceLocation:
    """Represents a source code location."""
    file_path: str
    line_number: int
    column: int
    content: str


@dataclass
class PCMapping:
    """Represents a mapping between PC and source location."""
    pc: int
    source_location: SourceLocation
    opcode: str


# =============================================================================
# Source Map Parser
# =============================================================================

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
            for key, contract_data in contracts.items():
                parts = key.split(":")
                if len(parts) >= 2 and parts[1] == contract_name:
                    if contract_data.get("bin-runtime"):
                        target_contract_key = key
                        target_contract_data = contract_data
                        break
            
            if not target_contract_data:
                for source_file in source_list:
                    source_stem = Path(source_file).stem
                    if contract_name.lower() == source_stem.lower():
                        for key, contract_data in contracts.items():
                            parts = key.split(":")
                            if len(parts) >= 1 and parts[0] == source_file:
                                if len(parts) >= 2 and parts[1] == contract_name and contract_data.get("bin-runtime"):
                                    target_contract_key = key
                                    target_contract_data = contract_data
                                    break
                                elif contract_data.get("bin-runtime") and not target_contract_data:
                                    target_contract_key = key
                                    target_contract_data = contract_data
        
        if not target_contract_data:
            for key, contract_data in contracts.items():
                bin_runtime = contract_data.get("bin-runtime", "")
                if bin_runtime and len(bin_runtime) > 0:
                    target_contract_key = key
                    target_contract_data = contract_data
                    break
        
        if not target_contract_data:
            raise ValueError(f"No contract found with runtime bytecode in combined.json")
        
        bin_runtime = target_contract_data.get("bin-runtime", "")
        srcmap_runtime = target_contract_data.get("srcmap-runtime", "")
        metadata_str = target_contract_data.get("metadata", "")
        
        if not bin_runtime:
            raise ValueError(f"No bin-runtime found for contract {target_contract_key}")
        
        if not srcmap_runtime:
            raise ValueError(f"No srcmap-runtime found for contract {target_contract_key}")
        
        compiler_version = None
        if metadata_str:
            try:
                metadata = json.loads(metadata_str)
                compiler_version = metadata.get("compiler", {}).get("version")
            except json.JSONDecodeError:
                pass
        
        bytecode = bytes.fromhex(bin_runtime)
        pc_to_idx = self._build_pc_to_instruction_map(bytecode)
        entries = self._parse_srcmap(srcmap_runtime)
        
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
        """
        pc_to_idx = {}
        pc = 0
        instr_idx = 0
        
        while pc < len(bytecode):
            pc_to_idx[pc] = instr_idx
            opcode = bytecode[pc]
            
            if opcode in PUSH_OPCODES:
                data_size = PUSH_OPCODES[opcode]
                pc += 1 + data_size
            else:
                pc += 1
            
            instr_idx += 1
        
        return pc_to_idx
    
    def _parse_srcmap(self, srcmap: str) -> List[SourceMapEntry]:
        """
        Parse srcmap string into list of SourceMapEntry.
        
        Format: "s:l:f:j:m;s:l:f:j:m;..."
        Empty fields inherit from previous entry.
        """
        if not srcmap:
            return []
        
        entries = []
        
        prev_offset = 0
        prev_length = 0
        prev_file_index = -1
        prev_jump_type = "-"
        prev_modifier_depth = 0
        
        for part in srcmap.split(";"):
            if not part:
                entries.append(SourceMapEntry(
                    offset=prev_offset,
                    length=prev_length,
                    file_index=prev_file_index,
                    jump_type=prev_jump_type,
                    modifier_depth=prev_modifier_depth
                ))
                continue
            
            fields = part.split(":")
            
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
            
            prev_offset = offset
            prev_length = length
            prev_file_index = file_index
            prev_jump_type = jump_type
            prev_modifier_depth = modifier_depth
        
        return entries
    
    def load_source_file(self, source_path: str) -> List[str]:
        """Load and cache source file lines using centralized loader."""
        return source_loader.load_source_file(source_path, str(self.debug_dir) if self.debug_dir else None)
    
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
        
        current_content = ""
        if 0 < line_num <= len(lines):
            current_content = lines[line_num - 1].rstrip()
        
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
        
        for pc, instr_idx in self.source_map_info.pc_to_instruction_index.items():
            source_info = self.source_map_info.get_source_info(pc)
            if source_info:
                source_path, offset, length = source_info
                line, col = self.offset_to_line_col(source_path, offset)
                pc_to_source[pc] = (source_path, line, col)
        
        return pc_to_source
    
    @staticmethod
    def is_legacy_compiler(version: str) -> bool:
        """Check if compiler version is older than 0.8.29 (needs srcmap fallback)."""
        if not version:
            return True
        
        parts = version.split("+")[0].split(".")
        if len(parts) < 3:
            return True
        
        try:
            major = int(parts[0])
            minor = int(parts[1])
            patch = int(parts[2])
            
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


# =============================================================================
# Source Mapping Manager
# =============================================================================

class SourceMappingManager:
    """Manages mappings between source code and EVM bytecode."""
    
    def __init__(self, ethdebug_parser=None, ethdebug_info=None):
        self.ethdebug_parser = ethdebug_parser
        self.ethdebug_info = ethdebug_info
        
        self._line_to_pcs_cache: Dict[str, Dict[int, Set[int]]] = {}
        self._line_to_steps_cache: Dict[str, Dict[int, List[int]]] = {}
        self._pc_to_source_cache: Dict[int, SourceLocation] = {}
        self._step_to_source_cache: Dict[int, SourceLocation] = {}
        
    def get_pcs_for_line(self, file_path: str, line_num: int) -> Set[int]:
        """Get all PCs that map to a specific line in a file."""
        if not self.ethdebug_info:
            return set()
        
        file_key = os.path.basename(file_path)
        if file_key in self._line_to_pcs_cache and line_num in self._line_to_pcs_cache[file_key]:
            return self._line_to_pcs_cache[file_key][line_num]
        
        pcs = set()
        for instruction in self.ethdebug_info.instructions:
            if instruction.source_location:
                source_file = self.ethdebug_info.sources.get(instruction.source_location.source_id)
                if source_file == file_path:
                    lines = self.ethdebug_parser.load_source_file(source_file)
                    if lines:
                        line_num_for_pc, col = self.ethdebug_parser.offset_to_line_col(
                            source_file, instruction.source_location.offset
                        )
                        if line_num_for_pc == line_num:
                            pcs.add(instruction.offset)
        
        if file_key not in self._line_to_pcs_cache:
            self._line_to_pcs_cache[file_key] = {}
        self._line_to_pcs_cache[file_key][line_num] = pcs
        
        return pcs
    
    def get_steps_for_line(self, file_path: str, line_num: int, trace_steps: List, 
                          contract_address: str = None, contract_address_getter=None) -> List[int]:
        """Get all steps that belong to a specific source line."""
        file_key = os.path.basename(file_path)
        cache_key = f"{line_num}:{contract_address}" if contract_address else str(line_num)
        
        if file_key in self._line_to_steps_cache and cache_key in self._line_to_steps_cache[file_key]:
            return self._line_to_steps_cache[file_key][cache_key]
        
        pcs = self.get_pcs_for_line(file_path, line_num)
        if not pcs:
            if file_key not in self._line_to_steps_cache:
                self._line_to_steps_cache[file_key] = {}
            self._line_to_steps_cache[file_key][cache_key] = []
            return []
        
        steps = []
        for step_idx, step in enumerate(trace_steps):
            if step.pc in pcs:
                if contract_address and contract_address_getter:
                    step_contract = contract_address_getter(step_idx)
                    if step_contract != contract_address:
                        continue
                
                steps.append(step_idx)
        
        if file_key not in self._line_to_steps_cache:
            self._line_to_steps_cache[file_key] = {}
        self._line_to_steps_cache[file_key][cache_key] = steps
        
        return steps
    
    def get_source_info_for_step(self, step_idx: int, trace_steps: List) -> Optional[Tuple[str, int]]:
        """Get source file and line for a given step."""
        if step_idx >= len(trace_steps):
            return None
        
        step = trace_steps[step_idx]
        
        if step_idx in self._step_to_source_cache:
            loc = self._step_to_source_cache[step_idx]
            return (loc.file_path, loc.line_number)
        
        if self.ethdebug_parser and self.ethdebug_info:
            context = self.ethdebug_parser.get_source_context(step.pc, context_lines=2)
            if context:
                file_path = context['file']
                line_num = context['line']
                
                self._step_to_source_cache[step_idx] = SourceLocation(
                    file_path=file_path,
                    line_number=line_num,
                    column=0,
                    content=context.get('content', '')
                )
                
                return (file_path, line_num)
        
        return None
    
    def get_source_info_for_pc(self, pc: int) -> Optional[SourceLocation]:
        """Get source location for a given PC."""
        if pc in self._pc_to_source_cache:
            return self._pc_to_source_cache[pc]
        
        if not self.ethdebug_info:
            return None
        
        for instruction in self.ethdebug_info.instructions:
            if instruction.offset == pc and instruction.source_location:
                source_file = self.ethdebug_info.sources.get(instruction.source_location.source_id)
                if source_file and self.ethdebug_parser:
                    lines = self.ethdebug_parser.load_source_file(source_file)
                    if lines:
                        line_num, col = self.ethdebug_parser.offset_to_line_col(
                            source_file, instruction.source_location.offset
                        )
                        content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                        
                        source_location = SourceLocation(
                            file_path=source_file,
                            line_number=line_num,
                            column=col,
                            content=content
                        )
                        
                        self._pc_to_source_cache[pc] = source_location
                        return source_location
        
        return None
    
    def get_line_content(self, file_path: str, line_num: int) -> Optional[str]:
        """Get the content of a specific line in a file."""
        if not self.ethdebug_parser:
            return None
        
        lines = self.ethdebug_parser.load_source_file(file_path)
        if lines and 1 <= line_num <= len(lines):
            return lines[line_num - 1].strip()
        
        return None
    
    def is_contract_declaration_line(self, file_path: str, line_num: int) -> bool:
        """Check if a line is a contract declaration."""
        content = self.get_line_content(file_path, line_num)
        if not content:
            return False
        
        return "contract" in content and "{" in content
    
    def is_function_return_line(self, file_path: str, line_num: int) -> bool:
        """Check if a line contains a function return statement."""
        content = self.get_line_content(file_path, line_num)
        if not content:
            return False
        
        return "return" in content and ";" in content
    
    def get_all_mappings_for_file(self, file_path: str) -> Dict[int, List[PCMapping]]:
        """Get all line to PC mappings for a file."""
        if not self.ethdebug_info:
            return {}
        
        mappings = {}
        for instruction in self.ethdebug_info.instructions:
            if instruction.source_location:
                source_file = self.ethdebug_info.sources.get(instruction.source_location.source_id)
                if source_file == file_path:
                    lines = self.ethdebug_parser.load_source_file(source_file)
                    if lines:
                        line_num, col = self.ethdebug_parser.offset_to_line_col(
                            source_file, instruction.source_location.offset
                        )
                        content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                        
                        if line_num not in mappings:
                            mappings[line_num] = []
                        
                        mappings[line_num].append(PCMapping(
                            pc=instruction.offset,
                            source_location=SourceLocation(
                                file_path=source_file,
                                line_number=line_num,
                                column=col,
                                content=content
                            ),
                            opcode=instruction.mnemonic
                        ))
        
        return mappings
    
    def find_next_available_line(self, file_path: str, current_line: int, trace_steps: List, max_lines_ahead: int = 20) -> Optional[Tuple[int, List[int]]]:
        """Find the next line after current_line that has actual PC/step mappings."""
        for line_num in range(current_line + 1, current_line + max_lines_ahead + 1):
            steps = self.get_steps_for_line(file_path, line_num, trace_steps)
            if steps:
                return (line_num, steps)
        
        return None
    
    def clear_cache(self):
        """Clear all cached mappings."""
        self._line_to_pcs_cache.clear()
        self._line_to_steps_cache.clear()
        self._pc_to_source_cache.clear()
        self._step_to_source_cache.clear()
    
    def get_cache_stats(self) -> Dict[str, int]:
        """Get statistics about cache usage."""
        return {
            "line_to_pcs_cache_entries": sum(len(file_mappings) for file_mappings in self._line_to_pcs_cache.values()),
            "line_to_steps_cache_entries": sum(len(file_mappings) for file_mappings in self._line_to_steps_cache.values()),
            "pc_to_source_cache_entries": len(self._pc_to_source_cache),
            "step_to_source_cache_entries": len(self._step_to_source_cache)
        }


# =============================================================================
# Utility Functions
# =============================================================================

def load_debug_info(debug_dir: Union[str, Path], contract_name: Optional[str] = None):
    """
    Load debug info from directory, automatically selecting parser.
    
    First tries ETHDebug (for solc >= 0.8.29), then falls back to srcmap (legacy).
    
    Returns:
        Tuple of (parser_instance, debug_info)
    """
    debug_dir = Path(debug_dir)
    
    # Try ETHDebug first
    ethdebug_file = debug_dir / "ethdebug.json"
    if ethdebug_file.exists():
        from .ethdebug import ETHDebugParser
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
