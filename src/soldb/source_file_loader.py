"""
Centralized source file loader to avoid duplicate loading and warnings.
"""

from typing import Dict, List, Optional
from pathlib import Path
import os

from soldb.colors import warning


class SourceFileLoader:
    """Centralized source file loader with global cache."""
    
    _instance = None
    _source_cache: Dict[str, List[str]] = {}
    _warning_shown: set = set()
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def load_source_file(self, source_path: str, debug_dir: Optional[str] = None) -> List[str]:
        """Load and cache source file lines globally."""
        if source_path not in self._source_cache:
            result = self._find_and_load_source_file(source_path, debug_dir)
            self._source_cache[source_path] = result
            
            # Show warning only if file was not found 
            if not result and source_path not in self._warning_shown:
                self._warning_shown.add(source_path)
                print(warning(f"Warning: Source file not found: {source_path}"))
        
        return self._source_cache[source_path]
    
    def _find_and_load_source_file(self, source_path: str, debug_dir: Optional[str] = None) -> List[str]:
        """Find and load a source file using simplified pattern."""
        # Try direct path first
        result = self._try_load_file(Path(source_path))
        if result:
            return result
        
        # Find root project directory (where out/ folder is generated)
        root_project_dir = self._find_root_project_directory()
        if root_project_dir:
            # Resolve source path relative to root project
            full_source_path = root_project_dir / source_path
            result = self._try_load_file(full_source_path)
            if result:
                return result
        
        # Try walking up the directory hierarchy from debug directory
        if debug_dir:
            current_dir = Path(debug_dir)
            filename = os.path.basename(source_path)
            
            # Try current debug directory and go up the hierarchy
            for _ in range(2):  # Limit to 2 levels up
                # Try current directory
                test_path = current_dir / source_path
                result = self._try_load_file(test_path)
                if result:
                    return result
                
                # Try just the filename in current directory
                test_path = current_dir / filename
                result = self._try_load_file(test_path)
                if result:
                    return result
                
                # Move up one directory
                parent = current_dir.parent
                if parent == current_dir:  # Reached root
                    break
                current_dir = parent
        
        # Not found
        return []
    
    def _find_root_project_directory(self) -> Optional[Path]:
        """Find the root project directory - assume out/ is in current directory."""
        current_dir = Path.cwd()
        out_dir = current_dir / "out"
        
        if out_dir.exists() and out_dir.is_dir():
            return current_dir
        
        return None
    
    def _try_load_file(self, file_path: Path) -> Optional[List[str]]:
        """Try to load a file and return its contents or None if failed."""
        if file_path.exists() and file_path.is_file():
            try:
                with open(file_path) as f:
                    return f.readlines()
            except (IsADirectoryError, PermissionError, UnicodeDecodeError) as e:
                print(warning(f"Warning: Cannot read source file {file_path}: {e}"))
        return None


# Global instance
source_loader = SourceFileLoader()
