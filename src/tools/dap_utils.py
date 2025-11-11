"""Utility functions for DAP server."""
import os
from typing import List


# Directories to exclude when searching for Solidity files
EXCLUDED_DIRS = {
    'node_modules', 'out', 'build', '.git', '__pycache__', '.venv', 'venv',
    'test', 'tests', 'script', 'scripts', 'artifacts', 'debug'
}


def find_sol_files(root_dir: str) -> List[str]:
    """Find all .sol files in the workspace, excluding common build and test directories.
    
    Args:
        root_dir: Root directory to search from
        
    Returns:
        List of paths to .sol files
    """
    sol_files = []
    
    def find_files(dir_path: str):
        try:
            for entry in os.listdir(dir_path):
                full_path = os.path.join(dir_path, entry)
                
                # Skip excluded directories
                if entry.startswith('.') or entry in EXCLUDED_DIRS:
                    continue
                
                if os.path.isdir(full_path):
                    find_files(full_path)
                elif os.path.isfile(full_path) and entry.endswith('.sol'):
                    sol_files.append(full_path)
        except PermissionError:
            pass
    
    find_files(root_dir)
    return sol_files


def ensure_0x_prefix(value: str) -> str:
    """Ensure a hex string has 0x prefix.
    
    Args:
        value: Hex string with or without 0x prefix
        
    Returns:
        Hex string with 0x prefix
    """
    if not value:
        return value
    if isinstance(value, str) and not value.startswith('0x'):
        return f'0x{value}'
    return value

