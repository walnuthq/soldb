"""
Solidity compiler configuration management for ETHDebug support.
Manages compilation settings and paths for both optimized and debug builds.
"""

import os
import json
import subprocess
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from pathlib import Path


@dataclass
class CompilerConfig:
    """Configuration for Solidity compilation with ETHDebug support."""
    
    solc_path: str = "solc"
    debug_output_dir: str = "./out"
    contracts_dir: str = "./contracts"
    build_dir: str = "./build"
    
    # ETHDebug compilation flags
    ethdebug_flags: List[str] = None
    
    # Production compilation flags (optional)
    production_flags: List[str] = None
    
    def __post_init__(self):
        if self.ethdebug_flags is None:
            self.ethdebug_flags = [
                "--via-ir",
                "--debug-info", "ethdebug",
                "--ethdebug",
                "--ethdebug-runtime",
                "--bin",
                "--abi",
                #"--optimize",
                #"--optimize-runs", "200",
                "--overwrite"
            ]
        
        if self.production_flags is None:
            self.production_flags = [
                "--via-ir",
                "--optimize",
                "--optimize-runs", "200",
                "--bin",
                "--abi"
            ]
    
    def ensure_directories(self):
        """Create necessary directories if they don't exist."""
        Path(self.debug_output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.build_dir).mkdir(parents=True, exist_ok=True)
    
    def compile_with_ethdebug(self, contract_file: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Compile a Solidity contract with ETHDebug information.
        
        Args:
            contract_file: Path to the Solidity source file
            output_dir: Optional output directory (defaults to debug_output_dir)
            
        Returns:
            Dictionary containing compilation results and paths to generated files
        """
        if output_dir is None:
            output_dir = self.debug_output_dir
        
        self.ensure_directories()
        
        # Prepare compilation command
        cmd = [self.solc_path] + self.ethdebug_flags + ["-o", output_dir, contract_file]
        
        # Run compilation
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise CompilationError(f"Compilation failed:\n{result.stderr}")
        
        # Find generated files
        output_files = {
            "ethdebug": None,
            "contracts": {}
        }
        
        output_path = Path(output_dir)
        
        # Look for the main ethdebug.json file
        ethdebug_file = output_path / "ethdebug.json"
        if ethdebug_file.exists():
            output_files["ethdebug"] = str(ethdebug_file)
        
        # Find contract-specific files
        for file_path in output_path.iterdir():
            if file_path.suffix == ".bin":
                contract_name = file_path.stem
                contract_files = {
                    "bytecode": str(file_path),
                    "abi": str(output_path / f"{contract_name}.abi"),
                    "ethdebug": str(output_path / f"{contract_name}_ethdebug.json"),
                    "ethdebug_runtime": str(output_path / f"{contract_name}_ethdebug-runtime.json")
                }
                
                # Verify files exist
                for key, path in list(contract_files.items()):
                    if not Path(path).exists():
                        contract_files[key] = None
                
                output_files["contracts"][contract_name] = contract_files
        
        return {
            "success": True,
            "output_dir": output_dir,
            "files": output_files,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    
    def compile_for_production(self, contract_file: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Compile a Solidity contract for production (without debug info).
        
        Args:
            contract_file: Path to the Solidity source file
            output_dir: Optional output directory (defaults to build_dir)
            
        Returns:
            Dictionary containing compilation results
        """
        if output_dir is None:
            output_dir = self.build_dir
        
        self.ensure_directories()
        
        # Prepare compilation command
        cmd = [self.solc_path] + self.production_flags + ["-o", output_dir, contract_file]
        
        # Run compilation
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise CompilationError(f"Compilation failed:\n{result.stderr}")
        
        return {
            "success": True,
            "output_dir": output_dir,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    
    def verify_solc_version(self) -> Dict[str, Any]:
        """Verify solc version and ETHDebug support."""
        try:
            result = subprocess.run([self.solc_path, "--version"], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                return {"supported": False, "error": "Could not get solc version"}
            
            version_output = result.stdout
            
            # Extract version number
            import re
            version_match = re.search(r'Version: (\d+\.\d+\.\d+)', version_output)
            if not version_match:
                return {"supported": False, "error": "Could not parse version"}
            
            version_str = version_match.group(1)
            major, minor, patch = map(int, version_str.split('.'))
            
            # ETHDebug requires Solidity 0.8.29+
            if major > 0 or (major == 0 and minor > 8) or (major == 0 and minor == 8 and patch >= 29):
                return {
                    "supported": True,
                    "version": version_str,
                    "full_output": version_output
                }
            else:
                return {
                    "supported": False,
                    "version": version_str,
                    "error": f"Solidity {version_str} does not support ETHDebug (requires 0.8.29+)"
                }
            
        except Exception as e:
            return {"supported": False, "error": str(e)}
    
    @classmethod
    def from_soldb_config(cls, config_file: str = "soldb.config.yaml") -> "CompilerConfig":
        """Load configuration from soldb config file."""
        if not Path(config_file).exists():
            # Return default config if file doesn't exist
            return cls()
        
        import yaml
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
        
        debug_config = config_data.get('debug', {}).get('ethdebug', {})
        
        return cls(
            solc_path=debug_config.get('solc_path', 'solc'),
            debug_output_dir=debug_config.get('path', './out'),
            build_dir=config_data.get('build_dir', './build')
        )
    
    def save_to_soldb_config(self, config_file: str = "soldb.config.yaml"):
        """Save configuration to soldb config file."""
        import yaml
        
        config_data = {}
        if Path(config_file).exists():
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f) or {}
        
        # Ensure structure exists
        if 'debug' not in config_data:
            config_data['debug'] = {}
        if 'ethdebug' not in config_data['debug']:
            config_data['debug']['ethdebug'] = {}
        
        # Update ETHDebug configuration
        config_data['debug']['ethdebug'].update({
            'enabled': True,
            'path': self.debug_output_dir,
            'solc_path': self.solc_path,
            'fallback_to_heuristics': True,
            'compile_options': {
                'via_ir': True,
                'optimizer': True,
                'optimizer_runs': 200
            }
        })
        
        # Save build directory
        config_data['build_dir'] = self.build_dir
        
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)


class CompilationError(Exception):
    """Raised when compilation fails."""
    pass


def dual_compile(contract_file: str, config: Optional[CompilerConfig] = None) -> Dict[str, Any]:
    """
    Perform dual compilation: both production and debug builds.
    
    Args:
        contract_file: Path to the Solidity source file
        config: Optional compiler configuration
        
    Returns:
        Dictionary with both production and debug compilation results
    """
    if config is None:
        config = CompilerConfig()
    
    results = {
        "production": None,
        "debug": None
    }
    
    # Production build
    try:
        results["production"] = config.compile_for_production(contract_file)
    except CompilationError as e:
        results["production"] = {"success": False, "error": str(e)}
    
    # Debug build with ETHDebug
    try:
        results["debug"] = config.compile_with_ethdebug(contract_file)
    except CompilationError as e:
        results["debug"] = {"success": False, "error": str(e)}
    
    return results