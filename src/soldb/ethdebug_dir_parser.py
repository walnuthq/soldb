"""
ETHDebug Directory Parser

Handles parsing and validation of ethdebug_dir paths.
"""

from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass
from pathlib import Path
import os

from soldb.colors import error, warning


@dataclass
class ETHDebugSpec:
    """Represents a parsed ethdebug directory specification."""
    address: Optional[str] = None
    name: Optional[str] = None
    path: str = ""
    
    def __post_init__(self):
        """Validate the parsed specification."""
        if self.address and not self.address.startswith('0x'):
            raise ValueError(f"Address must start with '0x': {self.address}")
        
        if not self.path:
            raise ValueError("Path cannot be empty")
        
        if not os.path.exists(self.path):
            raise ValueError(f"Path does not exist: {self.path}")


class ETHDebugDirParser:
    """Parser for ethdebug_dir paths."""
    
    @staticmethod
    def parse_single_contract(ethdebug_spec: str) -> ETHDebugSpec:
        """
        Parse single contract ethdebug specification.
        Expected format: 'address:name:path'
        
        Args:
            ethdebug_spec: The specification string
            
        Returns:
            ETHDebugSpec object with parsed components
            
        Raises:
            ValueError: If the format is invalid
        """
        if ':' not in ethdebug_spec or not ethdebug_spec.startswith('0x'):
            raise ValueError(f"Must use format 'address:name:path' (got: {ethdebug_spec})")
        
        parts = ethdebug_spec.split(':', 2)
        if len(parts) != 3:
            raise ValueError(f"Must use format 'address:name:path' (got: {ethdebug_spec})")
        
        address, name, path = parts
        
        # Normalize path
        path = os.path.normpath(path)
        
        return ETHDebugSpec(address=address, name=name, path=path)
    
    @staticmethod
    def parse_multi_contract(ethdebug_spec: str) -> ETHDebugSpec:
        """
        Parse multi-contract ethdebug specification.
        Expected format: 'address:path' or just 'path'
        
        Args:
            ethdebug_spec: The specification string
            
        Returns:
            ETHDebugSpec object with parsed components
            
        Raises:
            ValueError: If the format is invalid
        """
        if ':' in ethdebug_spec and ethdebug_spec.startswith('0x'):
            # Format: address:path
            parts = ethdebug_spec.split(':', 1)
            if len(parts) != 2:
                raise ValueError(f"Must use format 'address:path' (got: {ethdebug_spec})")
            
            address, path = parts
            path = os.path.normpath(path)
            
            return ETHDebugSpec(address=address, name=None, path=path)
        else:
            # Format: just path
            path = os.path.normpath(ethdebug_spec)
            return ETHDebugSpec(address=None, name=None, path=path)
    
    @staticmethod
    def parse_ethdebug_dirs(ethdebug_dirs: List[str]) -> List[ETHDebugSpec]:
        """
        Parse a list of ethdebug directory specifications.
        
        Args:
            ethdebug_dirs: List of ethdebug directory specifications in format 'address:name:path'
            
        Returns:
            List of ETHDebugSpec objects
            
        Raises:
            ValueError: If any specification is invalid
        """
        if not ethdebug_dirs:
            return []
        
        specs = []
        for ethdebug_spec in ethdebug_dirs:
            try:
                # Always use single contract parser since address:name:path is the only valid format
                spec = ETHDebugDirParser.parse_single_contract(ethdebug_spec)
                specs.append(spec)
            except ValueError as e:
                raise ValueError(f"Invalid ethdebug specification '{ethdebug_spec}': {e}")
        
        return specs
    
    @staticmethod
    def find_abi_file(spec: ETHDebugSpec, contract_name: Optional[str] = None) -> Optional[str]:
        """
        Find ABI file for the given specification.
        
        Args:
            spec: The ETHDebugSpec to find ABI for
            contract_name: Optional contract name to use for ABI file search
            
        Returns:
            Path to ABI file if found, None otherwise
        """
        ethdebug_dir = Path(spec.path)
        
        # Try contract-specific ABI file first
        if contract_name:
            abi_path = ethdebug_dir / f"{contract_name}.abi"
            if abi_path.exists():
                return str(abi_path)
        
        # Try any ABI file in the directory
        for abi_file in ethdebug_dir.glob("*.abi"):
            return str(abi_file)
        
        return None
