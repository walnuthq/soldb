#!/usr/bin/env python3
"""
Command-line tool for compiling Solidity contracts with ETHDebug support.
Can be used standalone or integrated into the soldb workflow.
"""

import argparse
from logging import info
import sys
import json
from pathlib import Path
from typing import Optional

from .compiler_config import CompilerConfig, CompilationError, dual_compile


def main(args=None):
    parser = argparse.ArgumentParser(
        description="Compile Solidity contracts with ETHDebug support"
    )
    
    parser.add_argument(
        "contract_file",
        help="Path to the Solidity contract file"
    )
    
    parser.add_argument(
        "--solc", "--solc-path",
        default="solc",
        help="Path to the solc binary (default: solc)"
    )
    
    parser.add_argument(
        "--output-dir", "-o",
        default="./build/debug/ethdebug",
        help="Output directory for ETHDebug files (default: ./build/debug/ethdebug)"
    )
    
    parser.add_argument(
        "--dual-compile",
        action="store_true",
        help="Create both optimized production and debug builds"
    )
    
    parser.add_argument(
        "--production-dir",
        default="./build/contracts",
        help="Output directory for production build (default: ./build/contracts)"
    )
    
    parser.add_argument(
        "--verify-version",
        action="store_true",
        help="Verify solc version supports ETHDebug and exit"
    )
    
    parser.add_argument(
        "--save-config",
        action="store_true",
        help="Save configuration to soldb.config.yaml"
    )
    
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON"
    )
    
    args = parser.parse_args()
    
    # Create compiler configuration
    config = CompilerConfig(
        solc_path=args.solc,
        debug_output_dir=args.output_dir,
        build_dir=args.production_dir
    )
    
    # Verify version if requested
    if args.verify_version:
        version_info = config.verify_solc_version()
        if args.json:
            print(json.dumps(version_info, indent=2))
        else:
            if version_info["supported"]:
                print(f"✓ Solidity {version_info['version']} supports ETHDebug")
            else:
                print(f"✗ {version_info['error']}")
        return 0 if version_info["supported"] else 1  # changed from sys.exit

    # Verify contract file exists
    if not Path(args.contract_file).exists():
        print(f"Error: Contract file '{args.contract_file}' not found", file=sys.stderr)
        return 1
    
    # Save configuration if requested
    if args.save_config:
        try:
            config.save_to_soldb_config()
            if not args.json:
                print("✓ Configuration saved to soldb.config.yaml")
        except Exception as e:
            print(f"Error saving configuration: {e}", file=sys.stderr)
            return 1
    
    try:
        if args.dual_compile:
            # Perform dual compilation
            results = dual_compile(args.contract_file, config)
            
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                # Production build status
                if results["production"]["success"]:
                    print(f"✓ Production build created in {results['production']['output_dir']}")
                else:
                    print(f"✗ Production build failed: {results['production'].get('error', 'Unknown error')}")
                
                # Debug build status
                if results["debug"]["success"]:
                    print(f"✓ ETHDebug build created in {results['debug']['output_dir']}")
                    
                    # List generated files
                    if results["debug"]["files"]["ethdebug"]:
                        print("  - ethdebug.json")
                    
                    for contract_name, files in results["debug"]["files"]["contracts"].items():
                        print(f"\n  Contract: {contract_name}")
                        if files["bytecode"]:
                            print(f"    - {contract_name}.bin")
                        if files["abi"]:
                            print(f"    - {contract_name}.abi")
                        if files["ethdebug"]:
                            print(f"    - {contract_name}_ethdebug.json")
                        if files["ethdebug_runtime"]:
                            print(f"    - {contract_name}_ethdebug-runtime.json")
                else:
                    print(f"✗ ETHDebug build failed: {results['debug'].get('error', 'Unknown error')}")
                    return 1
        else:
            # ETHDebug compilation only
            result = config.compile_with_ethdebug(args.contract_file)
            
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"✓ ETHDebug compilation successful")
                print(f"Output directory: {result['output_dir']}")
                
                # List generated files
                if result["files"]["ethdebug"]:
                    print("\nGenerated files:")
                    print("  - ethdebug.json")
                
                for contract_name, files in result["files"]["contracts"].items():
                    print(f"\n  Contract: {contract_name}")
                    if files["bytecode"]:
                        print(f"    - {contract_name}.bin")
                    if files["abi"]:
                        print(f"    - {contract_name}.abi")
                    if files["ethdebug"]:
                        print(f"    - {contract_name}_ethdebug.json")
                    if files["ethdebug_runtime"]:
                        print(f"    - {contract_name}_ethdebug-runtime.json")
                
                # Show any warnings
                if result["stderr"]:
                    print("\nCompiler warnings:")
                    print(result["stderr"])
    
    except CompilationError as e:
        if args.json:
            print(json.dumps({"success": False, "error": str(e)}, indent=2))
        else:
            print(f"Compilation failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        if args.json:
            print(json.dumps({"success": False, "error": str(e)}, indent=2))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 1   

    return 0

def compile_ethdebug_run(
    contract_file: str,
    solc_path: str = "solc",
    debug_output_dir: str = "./build/debug/ethdebug",
    production_dir: str = "./build/contracts",
    dual: bool = False,
    verify_version: bool = False,
    save_config: bool = False,
    json_mode: bool = False
) -> dict:
    """
    Programmatic API. Returns result dict (same structure as CLI).
    Does NOT call sys.exit.
    """
    config = CompilerConfig(
        solc_path=solc_path,
        debug_output_dir=debug_output_dir,
        build_dir=production_dir
    )

    if verify_version:
        version_info = config.verify_solc_version()
        res = {"mode": "verify_version", **version_info}
        if not res.get("supported"):
            raise CompilationError(version_info.get("error", "Unsupported solc version"))
        print(info(f"solc {version_info['version']} OK (ETHDebug supported)"))
            
        

    if save_config:
        config.save_to_walnut_config()
        return {"mode": "save_config", "saved": True}

    if not Path(contract_file).exists():
        raise FileNotFoundError(f"Contract file '{contract_file}' not found")

    if dual:
        return dual_compile(contract_file, config)
    else:
        return config.compile_with_ethdebug(contract_file)


if __name__ == "__main__":
    import sys
    sys.exit(main())