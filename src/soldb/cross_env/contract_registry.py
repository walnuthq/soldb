"""
Contract Registry for Cross-Environment Debugging

Manages registration and lookup of contracts across EVM and Stylus environments.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from pathlib import Path

from .protocol import ContractInfo, Environment


class ContractRegistry:
    """
    Registry for managing contracts across EVM and Stylus environments.

    Provides lookup functionality to determine which environment a contract
    belongs to and retrieve its debug information.
    """

    def __init__(self):
        # Address -> ContractInfo mapping (lowercase addresses)
        self._contracts: Dict[str, ContractInfo] = {}

        # Known Stylus contract addresses (for quick lookup)
        self._stylus_addresses: Set[str] = set()

        # Known EVM contract addresses
        self._evm_addresses: Set[str] = set()

    def _normalize_address(self, address: str) -> str:
        """Normalize address to lowercase without 0x prefix for consistent lookup."""
        addr = address.lower()
        if addr.startswith("0x"):
            addr = addr[2:]
        return addr

    def _format_address(self, address: str) -> str:
        """Format address with 0x prefix."""
        addr = self._normalize_address(address)
        return f"0x{addr}"

    def register(self, contract: ContractInfo) -> None:
        """Register a contract in the registry."""
        addr = self._normalize_address(contract.address)

        # Update the contract info with normalized address
        contract.address = self._format_address(contract.address)
        self._contracts[addr] = contract

        # Update environment-specific sets
        if contract.environment == Environment.STYLUS or contract.environment == "stylus":
            self._stylus_addresses.add(addr)
            self._evm_addresses.discard(addr)
        else:
            self._evm_addresses.add(addr)
            self._stylus_addresses.discard(addr)

    def unregister(self, address: str) -> Optional[ContractInfo]:
        """Remove a contract from the registry."""
        addr = self._normalize_address(address)
        contract = self._contracts.pop(addr, None)
        self._stylus_addresses.discard(addr)
        self._evm_addresses.discard(addr)
        return contract

    def get(self, address: str) -> Optional[ContractInfo]:
        """Get contract info by address."""
        addr = self._normalize_address(address)
        return self._contracts.get(addr)

    def is_stylus(self, address: str) -> bool:
        """Check if an address is a registered Stylus contract."""
        addr = self._normalize_address(address)
        return addr in self._stylus_addresses

    def is_evm(self, address: str) -> bool:
        """Check if an address is a registered EVM contract."""
        addr = self._normalize_address(address)
        return addr in self._evm_addresses

    def is_registered(self, address: str) -> bool:
        """Check if an address is registered in any environment."""
        addr = self._normalize_address(address)
        return addr in self._contracts

    def get_environment(self, address: str) -> Optional[str]:
        """Get the environment type for an address."""
        contract = self.get(address)
        if contract:
            return contract.environment
        return None

    def get_all_contracts(self) -> List[ContractInfo]:
        """Get all registered contracts."""
        return list(self._contracts.values())

    def get_stylus_contracts(self) -> List[ContractInfo]:
        """Get all registered Stylus contracts."""
        return [c for c in self._contracts.values()
                if c.environment == Environment.STYLUS or c.environment == "stylus"]

    def get_evm_contracts(self) -> List[ContractInfo]:
        """Get all registered EVM contracts."""
        return [c for c in self._contracts.values()
                if c.environment == Environment.EVM or c.environment == "evm"]

    def clear(self) -> None:
        """Clear all registered contracts."""
        self._contracts.clear()
        self._stylus_addresses.clear()
        self._evm_addresses.clear()

    def to_dict(self) -> Dict[str, Dict]:
        """Export registry as dictionary."""
        return {
            "contracts": {
                addr: info.to_dict()
                for addr, info in self._contracts.items()
            }
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "ContractRegistry":
        """Create registry from dictionary."""
        registry = cls()
        contracts = data.get("contracts", {})
        for addr, info in contracts.items():
            contract = ContractInfo.from_dict(info)
            registry.register(contract)
        return registry

    def save(self, path: str) -> None:
        """Save registry to JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "ContractRegistry":
        """Load registry from JSON file."""
        with open(path, "r") as f:
            data = json.load(f)
        return cls.from_dict(data)

    def load_from_file(self, path: str) -> int:
        """
        Load contracts from a JSON configuration file.

        Expected format:
        {
            "contracts": [
                {
                    "address": "0x...",
                    "environment": "evm|stylus",
                    "name": "ContractName",
                    "debug_dir": "...",  // for EVM
                    "lib_path": "..."    // for Stylus
                }
            ]
        }

        Returns the number of contracts loaded.
        """
        with open(path, "r") as f:
            data = json.load(f)

        count = 0
        contracts = data.get("contracts", [])

        # Handle both list and dict formats
        if isinstance(contracts, list):
            for item in contracts:
                contract = ContractInfo.from_dict(item)
                self.register(contract)
                count += 1
        elif isinstance(contracts, dict):
            for addr, info in contracts.items():
                info["address"] = info.get("address", addr)
                contract = ContractInfo.from_dict(info)
                self.register(contract)
                count += 1

        return count


# Stylus contract bytecode detection
# Stylus contracts have a specific bytecode pattern at deployment

STYLUS_BYTECODE_PREFIX = bytes.fromhex("ef0001")  # EIP-3540 EOF marker (potential)
STYLUS_MARKER_PATTERNS = [
    b"\x00asm",  # WASM magic number (if raw WASM)
    # Add more patterns as Stylus bytecode format is finalized
]


def detect_stylus_bytecode(bytecode: bytes) -> bool:
    """
    Attempt to detect if bytecode belongs to a Stylus contract.

    Note: This is heuristic-based and may need updates as Stylus evolves.
    Currently, the most reliable method is explicit registration.
    """
    if not bytecode or len(bytecode) < 4:
        return False

    # Check for known Stylus patterns
    for pattern in STYLUS_MARKER_PATTERNS:
        if pattern in bytecode[:100]:  # Check beginning of bytecode
            return True

    # Check for EOF prefix (potential future Stylus format)
    if bytecode[:3] == STYLUS_BYTECODE_PREFIX:
        return True

    return False
