"""
Source Mapping Manager

This module provides a centralized way to manage mappings between Solidity source code
and EVM bytecode instructions (PCs) and execution steps.
"""

import os
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass


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


class SourceMappingManager:
    """Manages mappings between source code and EVM bytecode."""
    
    def __init__(self, ethdebug_parser=None, ethdebug_info=None):
        self.ethdebug_parser = ethdebug_parser
        self.ethdebug_info = ethdebug_info
        
        # Cache for mappings to avoid recomputation
        self._line_to_pcs_cache: Dict[str, Dict[int, Set[int]]] = {}
        self._line_to_steps_cache: Dict[str, Dict[int, List[int]]] = {}
        self._pc_to_source_cache: Dict[int, SourceLocation] = {}
        self._step_to_source_cache: Dict[int, SourceLocation] = {}
        
    def get_pcs_for_line(self, file_path: str, line_num: int) -> Set[int]:
        """Get all PCs that map to a specific line in a file."""
        if not self.ethdebug_info:
            return set()
        
        # Check cache first
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
        
        # Cache the result
        if file_key not in self._line_to_pcs_cache:
            self._line_to_pcs_cache[file_key] = {}
        self._line_to_pcs_cache[file_key][line_num] = pcs
        
        return pcs
    
    def get_steps_for_line(self, file_path: str, line_num: int, trace_steps: List, 
                          contract_address: str = None, contract_address_getter=None) -> List[int]:
        """Get all steps that belong to a specific source line, optionally filtered by contract."""
        file_key = os.path.basename(file_path)
        
        # Create cache key that includes contract_address if provided
        cache_key = f"{line_num}:{contract_address}" if contract_address else str(line_num)
        
        # Check cache first
        if file_key in self._line_to_steps_cache and cache_key in self._line_to_steps_cache[file_key]:
            return self._line_to_steps_cache[file_key][cache_key]
        
        # Get PCs for this line first
        pcs = self.get_pcs_for_line(file_path, line_num)
        if not pcs:
            # No PCs for this line, return empty list
            if file_key not in self._line_to_steps_cache:
                self._line_to_steps_cache[file_key] = {}
            self._line_to_steps_cache[file_key][cache_key] = []
            return []
        
        steps = []
        for step_idx, step in enumerate(trace_steps):
            if step.pc in pcs:
                # If contract_address is specified, filter by contract
                if contract_address and contract_address_getter:
                    step_contract = contract_address_getter(step_idx)
                    if step_contract != contract_address:
                        continue  # Skip steps from other contracts
                
                steps.append(step_idx)
        
        # Cache the result
        if file_key not in self._line_to_steps_cache:
            self._line_to_steps_cache[file_key] = {}
        self._line_to_steps_cache[file_key][cache_key] = steps
        
        return steps
    
    def get_source_info_for_step(self, step_idx: int, trace_steps: List) -> Optional[Tuple[str, int]]:
        """Get source file and line for a given step."""
        if step_idx >= len(trace_steps):
            return None
        
        step = trace_steps[step_idx]
        
        # Check cache first
        if step_idx in self._step_to_source_cache:
            loc = self._step_to_source_cache[step_idx]
            return (loc.file_path, loc.line_number)
        
        # Get source info using ethdebug parser
        if self.ethdebug_parser and self.ethdebug_info:
            context = self.ethdebug_parser.get_source_context(step.pc, context_lines=2)
            if context:
                file_path = context['file']
                line_num = context['line']
                
                # Cache the result
                self._step_to_source_cache[step_idx] = SourceLocation(
                    file_path=file_path,
                    line_number=line_num,
                    column=0,  # We don't have column info here
                    content=context.get('content', '')
                )
                
                return (file_path, line_num)
        
        return None
    
    def get_source_info_for_pc(self, pc: int) -> Optional[SourceLocation]:
        """Get source location for a given PC."""
        # Check cache first
        if pc in self._pc_to_source_cache:
            return self._pc_to_source_cache[pc]
        
        if not self.ethdebug_info:
            return None
        
        # Find instruction for this PC
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
                        
                        # Cache the result
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
    
    def debug_contract_line_mapping(self, file_path: str, line_num: int, trace_steps: List) -> Dict:
        """Debug function to show how steps are distributed across contracts for a specific line."""
        steps_for_line = self.get_steps_for_line(file_path, line_num, trace_steps)
        
        # Group steps by contract address
        contract_groups = {}
        for step_idx in steps_for_line:
            if step_idx < len(trace_steps):
                step = trace_steps[step_idx]
                # Extract contract address from step (assuming it's in step.address or step.to)
                contract_addr = getattr(step, 'address', None) or getattr(step, 'to', None) or 'unknown'
                
                if contract_addr not in contract_groups:
                    contract_groups[contract_addr] = []
                contract_groups[contract_addr].append(step_idx)
        
        print(f"\n=== DEBUG: Line {line_num} in {file_path} ===")
        print(f"Total steps: {len(steps_for_line)}")
        for contract, steps in contract_groups.items():
            print(f"  Contract {contract}: {len(steps)} steps → {steps[:10]}{'...' if len(steps) > 10 else ''}")
        print("=" * 50)
        
        return contract_groups
    
    def print_line_to_pc_mapping(self, file_path: str):
        """Print a mapping of line numbers to PCs for debugging."""
        mappings = self.get_all_mappings_for_file(file_path)
        
        print(f"\n{file_path} - Line to PC Mapping:")
        print("=" * 50)
        
        for line_num in sorted(mappings.keys()):
            pc_mappings = mappings[line_num]
            pcs = [mapping.pc for mapping in pc_mappings]
            opcodes = [mapping.opcode for mapping in pc_mappings]
            content = pc_mappings[0].source_location.content if pc_mappings else ""
            
            print(f"Line {line_num:2d}: PCs {pcs} | Opcodes: {opcodes}")
            if content:
                print(f"         Content: {content}")
            print()
    
    def find_next_available_line(self, file_path: str, current_line: int, trace_steps: List, max_lines_ahead: int = 20) -> Optional[Tuple[int, List[int]]]:
        """
        Find the next line after current_line that has actual PC/step mappings.
        Returns tuple of (line_number, steps) or None if no line found.
        """
        for line_num in range(current_line + 1, current_line + max_lines_ahead + 1):
            steps = self.get_steps_for_line(file_path, line_num, trace_steps)
            if steps:  # This line has actual execution steps
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
