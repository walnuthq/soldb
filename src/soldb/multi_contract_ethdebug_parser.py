"""
Multi-Contract ETHDebug Parser for Cross-Contract Debugging

Extends the ETHDebugParser to support loading and managing debug information
for multiple contracts in a single debugging session.
"""

import json
import os
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from pathlib import Path

from soldb.colors import warning

from .ethdebug_parser import ETHDebugParser, ETHDebugInfo, SourceLocation, Instruction, VariableLocation
from eth_utils import to_checksum_address


@dataclass
class ContractDebugInfo:
    """Container for contract-specific debug information."""
    address: str
    name: str
    debug_dir: Path
    ethdebug_info: ETHDebugInfo
    parser: ETHDebugParser


@dataclass
class ExecutionContext:
    """Represents the current execution context during cross-contract calls."""
    address: str
    debug_info: ETHDebugInfo
    pc_offset: int = 0  # For DELEGATECALL scenarios
    call_type: str = "CALL"  # CALL, DELEGATECALL, STATICCALL, etc.
    
    def __repr__(self):
        return f"ExecutionContext(address={self.address[:10]}..., call_type={self.call_type})"


class MultiContractETHDebugParser:
    """
    Enhanced ETHDebug parser that supports multiple contracts.
    
    This parser maintains a registry of contracts and their debug information,
    enabling seamless source-level debugging across contract boundaries.
    """
    
    def __init__(self):
        self.contracts: Dict[str, ContractDebugInfo] = {}  # address -> ContractDebugInfo
        self.contract_names: Dict[str, str] = {}  # address -> contract name
        self.execution_stack: List[ExecutionContext] = []  # Track execution context
        self.source_cache: Dict[str, List[str]] = {}  # Shared source cache
    
    def load_contract(self, address: str, debug_dir: Union[str, Path], 
                     contract_name: Optional[str] = None) -> ContractDebugInfo:
        """
        Load ETHDebug information for a specific contract.
        
        Args:
            address: The contract address (with or without 0x prefix)
            debug_dir: Path to the directory containing ETHDebug files
            contract_name: Optional contract name (auto-detected if not provided)
            
        Returns:
            ContractDebugInfo object containing the loaded debug information
        """
        # Normalize address
        if not address.startswith('0x'):
            address = '0x' + address
        address = to_checksum_address(address)
        
        debug_dir = Path(debug_dir)
        if not debug_dir.exists():
            raise FileNotFoundError(f"Debug directory not found: {debug_dir}")
        
        # Create a parser for this contract
        parser = ETHDebugParser()
        parser.source_cache = self.source_cache  # Share source cache
        parser.debug_dir = str(debug_dir)  # Set debug_dir for source loading
        
        # Load ETHDebug info
        ethdebug_info = parser.load_ethdebug_files(debug_dir, contract_name)

        # Use provided name or extract from ETHDebug info
        if not contract_name:
            contract_name = ethdebug_info.contract_name
        
        # Create contract debug info
        contract_info = ContractDebugInfo(
            address=address,
            name=contract_name,
            debug_dir=debug_dir,
            ethdebug_info=ethdebug_info,
            parser=parser
        )
        
        # Register the contract
        self.contracts[address] = contract_info
        self.contract_names[address] = contract_name
        
        return contract_info
    
    def load_from_deployment(self, deployment_file: Union[str, Path]) -> Dict[str, ContractDebugInfo]:
        # NOTE: This does not make sense because the contract that we want to debug is probably already deployed
        # and we do not have deployment.json for it.
        """
        Load contract debug information from a deployment.json file.
        
        Args:
            deployment_file: Path to deployment.json
            
        Returns:
            Dictionary mapping addresses to ContractDebugInfo objects
        """
        deployment_file = Path(deployment_file)
        if not deployment_file.exists():
            raise FileNotFoundError(f"Deployment file not found: {deployment_file}")
        
        with open(deployment_file) as f:
            deployment_data = json.load(f)
        
        loaded_contracts = {}
        
        # Handle single contract deployment format
        if 'address' in deployment_data and 'contract' in deployment_data:
            # Single contract format
            contract_name = deployment_data['contract']
            address = deployment_data['address']
            
            # The debug files should be in the same directory as deployment.json
            debug_dir = deployment_file.parent
            
            # Check if ethdebug is enabled
            if deployment_data.get('ethdebug', {}).get('enabled', False):
                try:
                    contract_debug_info = self.load_contract(address, debug_dir, contract_name)
                    loaded_contracts[address] = contract_debug_info
                except Exception as e:
                    print(warning(f"Warning: Failed to load debug info for {contract_name}: {e}"))
            else:
                print(warning(f"Warning: ETHDebug not enabled for {contract_name}"))
        
        # Also handle multi-contract format if present
        elif 'contracts' in deployment_data:
            # Multiple contracts format
            for contract_name, contract_info in deployment_data['contracts'].items():
                if isinstance(contract_info, dict) and 'address' in contract_info:
                    address = contract_info['address']
                    
                    # Look for debug directory
                    # Try standard locations relative to deployment file
                    base_dir = deployment_file.parent
                    debug_dirs = [
                        base_dir / f"debug_{contract_name.lower()}",
                        base_dir / "debug" / contract_name,
                        base_dir / contract_name / "debug",
                        base_dir  # Assume debug files are in same directory
                    ]
                    
                    debug_dir = None
                    for candidate in debug_dirs:
                        if candidate.exists() and (candidate / "ethdebug.json").exists():
                            debug_dir = candidate
                            break
                    
                    if debug_dir:
                        try:
                            contract_debug_info = self.load_contract(address, debug_dir, contract_name)
                            loaded_contracts[address] = contract_debug_info
                        except Exception as e:
                            print(warning("Warning: Failed to load debug info for {contract_name}: {e}"))
                    else:
                        print(f"Warning: No debug directory found for {contract_name}")
        
        return loaded_contracts
    
    def load_from_mapping_file(self, mapping_file: Union[str, Path]) -> Dict[str, ContractDebugInfo]:
        """
        Load contracts from a mapping file that specifies addresses and debug directories.
        
        Expected format:
        {
            "contracts": [
                {
                    "address": "0x...",
                    "name": "ContractName",
                    "debug_dir": "./path/to/debug"
                }
            ]
        }
        """
        mapping_file = Path(mapping_file)
        if not mapping_file.exists():
            raise FileNotFoundError(f"Mapping file not found: {mapping_file}")
        
        with open(mapping_file) as f:
            mapping_data = json.load(f)
        
        loaded_contracts = {}
        
        for contract in mapping_data.get('contracts', []):
            address = contract['address']
            name = contract.get('name', 'Unknown')
            debug_dir = Path(contract['debug_dir'])
            
            # Make path relative to mapping file if not absolute
            if not debug_dir.is_absolute():
                debug_dir = mapping_file.parent / debug_dir
            
            try:
                contract_debug_info = self.load_contract(address, debug_dir, name)
                loaded_contracts[address] = contract_debug_info
            except Exception as e:
                print(warning("Warning: Failed to load contract {name} at {address}: {e}"))
        
        return loaded_contracts
    
    def get_contract_at_address(self, address: str) -> Optional[ContractDebugInfo]:
        """Get contract debug info for a given address."""
        address = to_checksum_address(address)
        return self.contracts.get(address)
    
    def push_context(self, address: str, call_type: str = "CALL", pc_offset: int = 0):
        """Push a new execution context when entering a contract."""
        contract_info = self.get_contract_at_address(address)
        if contract_info:
            context = ExecutionContext(
                address=address,
                debug_info=contract_info.ethdebug_info,
                pc_offset=pc_offset,
                call_type=call_type
            )
            self.execution_stack.append(context)
            return context
        return None
    
    def pop_context(self) -> Optional[ExecutionContext]:
        """Pop execution context when returning from a contract."""
        if self.execution_stack:
            return self.execution_stack.pop()
        return None
    
    def get_current_context(self) -> Optional[ExecutionContext]:
        """Get the current execution context."""
        if self.execution_stack:
            return self.execution_stack[-1]
        return None
    
    def get_current_contract(self) -> Optional[ContractDebugInfo]:
        """Get the currently executing contract's debug info."""
        context = self.get_current_context()
        if context:
            return self.get_contract_at_address(context.address)
        return None
    
    def get_source_info_for_address(self, address: str, pc: int) -> Optional[Dict[str, Any]]:
        """Get source information for a specific address and PC."""
        contract_info = self.get_contract_at_address(address)
        if not contract_info:
            return None
        
        # Get source context from the contract's parser
        return contract_info.parser.get_source_context(pc)
    
    def format_call_stack(self) -> str:
        """Format the current call stack for display."""
        if not self.execution_stack:
            return "Call stack is empty"
        
        lines = ["Call Stack:"]
        lines.append("-" * 60)
        
        for i, context in enumerate(self.execution_stack):
            contract_name = self.contract_names.get(context.address, "Unknown")
            prefix = f"#{i} "
            
            # Get current instruction info if available
            contract_info = self.get_contract_at_address(context.address)
            if contract_info:
                # This would need the current PC from transaction tracer
                lines.append(f"{prefix}{contract_name} [{context.call_type}]")
                lines.append(f"   at: {context.address}")
            else:
                lines.append(f"{prefix}{context.address} [{context.call_type}]")
        
        lines.append("-" * 60)
        return "\n".join(lines)
    
    def get_all_loaded_contracts(self) -> List[Tuple[str, str]]:
        """Get list of all loaded contracts (address, name) pairs."""
        return [(addr, info.name) for addr, info in self.contracts.items()]
    
    def clear(self):
        """Clear all loaded contracts and reset state."""
        self.contracts.clear()
        self.contract_names.clear()
        self.execution_stack.clear()
        self.source_cache.clear()
    
    def __repr__(self):
        contract_list = ", ".join([f"{name}@{addr[:10]}..." 
                                  for addr, name in self.contract_names.items()])
        return f"MultiContractETHDebugParser(contracts=[{contract_list}])"