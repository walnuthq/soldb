#!/usr/bin/env python3
"""
Command-line tool for compiling Solidity contracts with ETHDebug support.
Can be used standalone or integrated into the soldb workflow.
"""

import argparse
import sys
import json
from pathlib import Path
from typing import Optional

from .config import CompilerConfig, CompilationError, dual_compile


def main():
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
        default="./out",
        help="Output directory for ETHDebug files (default: ./out)"
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
    
    config = CompilerConfig(
        solc_path=args.solc,
        debug_output_dir=args.output_dir,
        build_dir=args.production_dir
    )
    
    if args.verify_version:
        version_info = config.verify_solc_version()
        if args.json:
            print(json.dumps(version_info, indent=2))
        else:
            if version_info["supported"]:
                print(f"✓ Solidity {version_info['version']} supports ETHDebug")
            else:
                print(f"✗ {version_info['error']}")
        sys.exit(0 if version_info["supported"] else 1)
    
    if not Path(args.contract_file).exists():
        print(f"Error: Contract file '{args.contract_file}' not found", file=sys.stderr)
        sys.exit(1)
    
    if args.save_config:
        try:
            config.save_to_soldb_config()
            if not args.json:
                print("✓ Configuration saved to soldb.config.yaml")
        except Exception as e:
            print(f"Error saving configuration: {e}", file=sys.stderr)
            sys.exit(1)
    
    try:
        if args.dual_compile:
            results = dual_compile(args.contract_file, config)
            
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                if results["production"]["success"]:
                    print(f"✓ Production build created in {results['production']['output_dir']}")
                else:
                    print(f"✗ Production build failed: {results['production'].get('error', 'Unknown error')}")
                
                if results["debug"]["success"]:
                    print(f"✓ ETHDebug build created in {results['debug']['output_dir']}")
                    
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
                    sys.exit(1)
        
        else:
            result = config.compile_with_ethdebug(args.contract_file)
            
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"✓ ETHDebug compilation successful")
                print(f"Output directory: {result['output_dir']}")
                
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
                
                if result["stderr"]:
                    print("\nCompiler warnings:")
                    print(result["stderr"])
    
    except CompilationError as e:
        if args.json:
            print(json.dumps({"success": False, "error": str(e)}, indent=2))
        else:
            print(f"Compilation failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        if args.json:
            print(json.dumps({"success": False, "error": str(e)}, indent=2))
        else:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def compile_ethdebug_run(
    contract_file: str,
    solc_path: str = "solc",
    debug_output_dir: str = "./out",
    production_dir: str = "./build/contracts",
    dual: bool = False,
    verify_version: bool = False,
    save_config: bool = False,
    json_mode: bool = False
) -> dict:
    """
    Runs ETHDebug compilation. Returns dict with compilation results.
    """
    from soldb.utils.colors import info
    
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
        config.save_to_soldb_config()
        return {"mode": "save_config", "saved": True}

    if not Path(contract_file).exists():
        raise FileNotFoundError(f"Contract file '{contract_file}' not found")

    if dual:
        return dual_compile(contract_file, config)
    else:
        return config.compile_with_ethdebug(contract_file)


if __name__ == "__main__":
    main()
