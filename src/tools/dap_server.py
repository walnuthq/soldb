#!/usr/bin/env python3
import json
import sys
import os
import subprocess
import shutil
import threading
import time

import io
from typing import Dict, Any, List, Optional
from pathlib import Path

from soldb.core.evm_repl import EVMDebugger
from soldb.core.transaction_tracer import TransactionTracer
from soldb.parsers.ethdebug import ETHDebugDirParser, ETHDebugInfo, MultiContractETHDebugParser
from eth_utils.address import is_address
from eth_utils import to_checksum_address
from .dap_utils import find_sol_files, ensure_0x_prefix

CRLF = b"\r\n"

class CaptureOutput:
    """Context manager to capture stdout from debugger."""
    def __init__(self, dap_server):
        self.dap_server = dap_server
        self.original_stdout = None
        self.captured_output = io.StringIO()
        
    def __enter__(self):
        self.original_stdout = sys.stdout
        sys.stdout = self.captured_output
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original stdout
        sys.stdout = self.original_stdout
        
        # Send captured output to VS Code
        output = self.captured_output.getvalue()
        if output:
            self.dap_server._send_output(output)
        
        self.captured_output.close()

class WalnutDAPServer:
    """Debug Adapter Protocol server for soldb (stdio version)"""
    
    def __init__(self):
        # DAP protocol state
        self._seq = 1
        self._initialized = False
        
        # Debugger state
        self.debugger: Optional[EVMDebugger] = None
        self.breakpoints: Dict[str, List[int]] = {}
        self.thread_id = 1
        
        # Monitoring state
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_stop_event = threading.Event()
        self._last_block_number: Optional[int] = None
        self._monitored_transactions: List[Dict[str, Any]] = []
        
        # Workspace and tracing state
        self._tracer: Optional[TransactionTracer] = None
        self._workspace_root: Optional[str] = None
        self._out_dir: Optional[str] = None
        self._rpc_url: Optional[str] = None

    def _capture_output(self):
        """Context manager to capture stdout and send as DAP output events."""
        return CaptureOutput(self)

    def _send_output(self, text: str):
        """Send output to VS Code via DAP output event."""
        self._event("output", {
            "output": text,
            "category": "stdout"
        })

    def _find_sol_files(self, root_dir: str) -> List[str]:
        """Find all .sol files in the workspace."""
        return find_sol_files(root_dir)
    
    def _find_project_root(self, start_path: str) -> Optional[str]:
        """Find the project root directory by looking for foundry.toml in subdirectories.
        Searches recursively in child directories. If not found, returns the original start_path.
        """
        start_path_resolved = Path(start_path).resolve()
        
        # First check if foundry.toml exists in the start directory itself
        foundry_toml = start_path_resolved / "foundry.toml"
        if foundry_toml.exists() and foundry_toml.is_file():
            return str(start_path_resolved)
        
        # Search in subdirectories (children)
        try:
            # Use rglob to search recursively in subdirectories
            for foundry_file in start_path_resolved.rglob("foundry.toml"):
                if foundry_file.is_file():
                    # Return the directory containing foundry.toml
                    return str(foundry_file.parent)
        except (PermissionError, OSError):
            # If we can't access some directories, continue
            pass
        
        # If not found, return the original start_path
        return str(start_path_resolved)

    def _monitor_transactions(self):
        """Monitor for all new transactions on the blockchain."""
        if not self._tracer:
            return
        
        try:
            w3 = self._tracer.w3
            
            # Get current block number
            current_block = w3.eth.block_number
            if self._last_block_number is None:
                self._last_block_number = current_block
                self._send_output(f"Monitoring transactions starting from block {current_block}\n")
                return
            
            # Check new blocks for transactions
            for block_num in range(self._last_block_number + 1, current_block + 1):
                try:
                    block = w3.eth.get_block(block_num, full_transactions=True)
                    for tx in block.transactions:
                        tx_hash = ensure_0x_prefix(tx.hash.hex())
                        # Print transaction hash to stdout
                        self._send_output(f"Transaction: {tx_hash}\n")
                        # Automatically handle/load the transaction
                        self._handle_transaction(tx_hash)
                except Exception as e:
                    self._send_output(f"Error checking block {block_num}: {e}\n")
            
            self._last_block_number = current_block
        except Exception as e:
            self._send_output(f"Error monitoring transactions: {e}\n")

    def _handle_transaction(self, tx_hash: str):
        """Handle a new transaction - trace it and check for breakpoints."""
        try:
            # Ensure tx_hash has 0x prefix
            tx_hash = ensure_0x_prefix(tx_hash)
            self._send_output(f"Transaction: {tx_hash}\n")
            
            # Get transaction details from blockchain
            if not self._tracer:
                return
            
            w3 = self._tracer.w3
            tx = w3.eth.get_transaction(tx_hash)
            
            # Extract contract address
            contract_address = tx.to
            if not contract_address:
                self._send_output(f"Warning: Transaction has no 'to' address (contract creation)\n")
                return
            
            # Normalize address to checksum format
            if isinstance(contract_address, str):
                try:
                    contract_address = to_checksum_address(contract_address)
                except Exception:
                    pass  # Keep original if conversion fails
            
            # Extract calldata (input data)
            if tx.input:
                if isinstance(tx.input, bytes):
                    calldata = "0x" + tx.input.hex()
                elif hasattr(tx.input, 'hex'):
                    calldata = tx.input.hex()
                else:
                    calldata = str(tx.input)
            else:
                calldata = "0x"
            
            # Extract entrypoint (function selector/name)
            entrypoint = None
            if calldata and len(calldata) >= 10:
                selector = calldata[:10]
                # Try to get function name from ABI if available
                if hasattr(self._tracer, 'function_signatures') and selector in self._tracer.function_signatures:
                    entrypoint = self._tracer.function_signatures[selector]['name']
                else:
                    # Use selector as entrypoint if function name not found
                    entrypoint = selector
            
            # Get transaction receipt to check status
            status = None
            try:
                receipt = w3.eth.get_transaction_receipt(tx_hash)
                # Status: 1 = success, 0 = failed/reverted
                status = receipt.status if hasattr(receipt, 'status') else (receipt.get('status') if isinstance(receipt, dict) else None)
            except Exception as e:
                # If receipt not available yet, status remains None
                self._send_output(f"Warning: Could not get receipt for {tx_hash}: {e}\n")
            
            # Store transaction info
            tx_info = {
                "tx_hash": tx_hash,
                "contract_address": contract_address,
                "calldata": calldata,
                "entrypoint": entrypoint or "unknown",
                "block_number": tx.blockNumber if hasattr(tx, 'blockNumber') else None,
                "from": tx['from'] if 'from' in tx else None,
                "value": str(tx.value) if hasattr(tx, 'value') else "0",
                "status": status
            }
            
            self._monitored_transactions.append(tx_info)
            
            # Send custom event to VS Code to notify about new monitored transaction
            self._event("transactionMonitored", {
                "txHash": tx_info["tx_hash"],
                "contractAddress": tx_info["contract_address"],
                "entrypoint": tx_info["entrypoint"],
                "blockNumber": tx_info.get("block_number"),
                "from": tx_info.get("from"),
                "value": tx_info.get("value", "0"),
                "status": tx_info.get("status")
            })
            
            # Check if we have breakpoints set
            has_breakpoints = any(len(lines) > 0 for lines in self.breakpoints.values())
            
            # Trace the transaction to entrypoint (even if no breakpoints)
            try:
                if has_breakpoints:
                    self._send_output(f"Getting breakpoints for transaction {tx_hash}...\n")
                else:
                    self._send_output(f"Tracing transaction {tx_hash} to decode entrypoint...\n")
                
                # Trace the transaction
                trace = self._tracer.trace_transaction(tx_hash)
                
                if not trace.debug_trace_available:
                    self._send_output(f"Warning: debug_traceTransaction not available for this transaction\n")
                    return
                
                # Load ethdebug files if not already loaded
                if not hasattr(self._tracer, 'multi_contract_parser') or not self._tracer.multi_contract_parser:
                    self._load_ethdebug_for_contract(contract_address)
                
                # Get contract-specific ethdebug_dir
                ethdebug_dir = self._out_dir  # Default fallback
                if hasattr(self, '_contract_ethdebug_dirs') and contract_address:
                    contract_ethdebug_dir = self._contract_ethdebug_dirs.get(contract_address.lower())
                    if contract_ethdebug_dir:
                        ethdebug_dir = contract_ethdebug_dir
                    else:
                        # Try to find it
                        found_dir, _ = self._find_contract_ethdebug_dir(contract_address)
                        if found_dir:
                            ethdebug_dir = found_dir
                            if not hasattr(self, '_contract_ethdebug_dirs'):
                                self._contract_ethdebug_dirs = {}
                            self._contract_ethdebug_dirs[contract_address.lower()] = found_dir
                
                # Check if debugger is initialized
                if not self.debugger:
                    # Initialize debugger if not already done
                    self.debugger = EVMDebugger(
                        contract_address=str(contract_address),
                        rpc_url=self._tracer.rpc_url,
                        ethdebug_dir=ethdebug_dir,
                        tracer=self._tracer,
                    )
                
                # Load trace into debugger temporarily
                self.debugger.current_trace = trace
                
                # Reload source_map for the contract after loading trace
                # This is important because source_map might not be loaded yet
                if (hasattr(self.debugger, 'tracer') and self.debugger.tracer and
                    hasattr(self.debugger.tracer, 'multi_contract_parser') and self.debugger.tracer.multi_contract_parser):
                    contract_info = self.debugger.tracer.multi_contract_parser.get_contract_at_address(contract_address)
                    if contract_info and hasattr(contract_info, 'parser') and contract_info.parser:
                        self.debugger.source_map = contract_info.parser.get_source_mapping()
                    else:
                        self.debugger.source_map = {}
                        
                else:
                    self.debugger.source_map = {}
                
                # Analyze function calls
                self.debugger.function_trace = self._tracer.analyze_function_calls(trace)
                
                # Update entrypoint with actual function name from function_trace if available
                if self.debugger.function_trace:
                    entry_function = None
                    if len(self.debugger.function_trace) > 1:
                        # Skip dispatcher, go to first actual function
                        entry_function = self.debugger.function_trace[1]
                    elif len(self.debugger.function_trace) > 0:
                        entry_function = self.debugger.function_trace[0]
                    
                    if entry_function and hasattr(entry_function, 'name') and entry_function.name:
                        # Extract just the function name (remove contract:: prefix if present)
                        function_name = entry_function.name
                        if '::' in function_name:
                            # Extract function name after ::
                            function_name = function_name.split('::')[-1]
                        # Only update if we have a meaningful function name (not dispatcher)
                        if function_name and function_name != "runtime_dispatcher" and function_name != "constructor":
                            tx_info["entrypoint"] = function_name
                            # Update in monitored_transactions list
                            for monitored_tx in self._monitored_transactions:
                                if monitored_tx["tx_hash"] == tx_hash:
                                    monitored_tx["entrypoint"] = function_name
                                    break
                            # Send updated transaction event to VS Code
                            self._event("transactionMonitored", {
                                "txHash": tx_info["tx_hash"],
                                "contractAddress": tx_info["contract_address"],
                                "entrypoint": tx_info["entrypoint"],
                                "blockNumber": tx_info.get("block_number"),
                                "from": tx_info.get("from"),
                                "value": tx_info.get("value", "0"),
                                "status": tx_info.get("status")
                            })
                
                # If no breakpoints, just return after decoding entrypoint
                if not has_breakpoints:
                    self._send_output(f"Transaction monitored: {tx_hash}\n")
                    return
                
                # Check each step for breakpoint hits
                breakpoint_hit = False
                breakpoint_step = None
                breakpoint_source = None
                breakpoint_line = None
                
                for step_idx, step in enumerate(trace.steps):
                    # Get source location for this step
                    source_info = None
                    
                    # Try to get source info from tracer
                    if (hasattr(self._tracer, 'ethdebug_parser') and self._tracer.ethdebug_parser and
                        hasattr(self._tracer, 'ethdebug_info') and self._tracer.ethdebug_info):
                        source_info = self._tracer.ethdebug_info.get_source_info(step.pc)
                    
                    if not source_info and hasattr(self._tracer, 'multi_contract_parser') and self._tracer.multi_contract_parser:
                        # Try multi-contract parser
                        contract_info = self._tracer.multi_contract_parser.get_contract_at_address(contract_address)
                        if contract_info and hasattr(contract_info, 'ethdebug_info') and contract_info.ethdebug_info:
                            source_info = contract_info.ethdebug_info.get_source_info(step.pc)
                    
                    if source_info:
                        source_path, offset, length = source_info
                        # Get line number from offset
                        if hasattr(self._tracer, 'ethdebug_parser') and self._tracer.ethdebug_parser:
                            line_num, col = self._tracer.ethdebug_parser.offset_to_line_col(source_path, offset)
                        else:
                            # Try from multi-contract parser
                            contract_info = self._tracer.multi_contract_parser.get_contract_at_address(contract_address) if hasattr(self._tracer, 'multi_contract_parser') else None
                            if contract_info and hasattr(contract_info, 'parser'):
                                line_num, col = contract_info.parser.offset_to_line_col(source_path, offset)
                            else:
                                continue  # Skip if we can't get line number
                        
                        # Get source file name (basename)
                        source_file_name = os.path.basename(source_path).replace('.sol', '')
                        
                        if source_file_name in self.breakpoints:
                            if line_num in self.breakpoints[source_file_name]:
                                # Breakpoint hit!
                                breakpoint_hit = True
                                breakpoint_step = step_idx
                                breakpoint_source = source_path
                                breakpoint_line = line_num
                                break
                
                if breakpoint_hit:
                    # Load transaction into debugger for debugging
                    self.debugger.current_step = breakpoint_step
                    
                    # Update contract_address from transaction if not set
                    if contract_address and (not self.debugger.contract_address or self.debugger.contract_address == "None"):
                        self.debugger.contract_address = contract_address
                    
                    # Re-register breakpoints after loading new transaction
                    # This is important because source_map might have changed
                    self._register_existing_breakpoints()
                    
                    # Normalize breakpoint_source path
                    normalized_breakpoint_source = breakpoint_source
                    if normalized_breakpoint_source.startswith('out/'):
                        normalized_breakpoint_source = normalized_breakpoint_source[4:]
                    elif normalized_breakpoint_source.startswith('./out/'):
                        normalized_breakpoint_source = normalized_breakpoint_source[6:]
                    
                    # Resolve absolute path using workspace_root
                    workspace_root = getattr(self, '_workspace_root', None) or getattr(self, 'workspace_root', None)
                    if not workspace_root and hasattr(self, '_out_dir') and self._out_dir:
                        workspace_root = os.path.dirname(self._out_dir)
                    
                    if os.path.isabs(normalized_breakpoint_source):
                        abs_breakpoint_source = normalized_breakpoint_source
                    elif workspace_root:
                        abs_breakpoint_source = os.path.normpath(os.path.join(workspace_root, normalized_breakpoint_source))
                        if not os.path.exists(abs_breakpoint_source):
                            abs_breakpoint_source = os.path.normpath(os.path.join(workspace_root, breakpoint_source))
                    else:
                        abs_breakpoint_source = os.path.abspath(normalized_breakpoint_source)
                    
                    self._send_output(f"Breakpoint hit at {os.path.basename(abs_breakpoint_source)}:{breakpoint_line} in transaction {tx_hash}\n")
                    # Send stopped event with breakpoint reason
                    self._event("stopped", {
                        "reason": "breakpoint",
                        "threadId": self.thread_id,
                        "description": f"Breakpoint hit in transaction {tx_hash}",
                        "source": {
                            "name": os.path.basename(abs_breakpoint_source),
                            "path": abs_breakpoint_source
                        },
                        "line": breakpoint_line
                    })
                    
                    self._send_output(f"Breakpoint hit at {os.path.basename(abs_breakpoint_source)}:{breakpoint_line} in transaction {tx_hash}\n")
                else:
                    # No breakpoint hit - just print transaction hash
                    self._send_output(f"Transaction monitored: {tx_hash}\n")
                    
            except Exception as e:
                # If tracing fails, just print transaction hash
                self._send_output(f"Error tracing transaction (printing hash only): {e}\n")
                self._send_output(f"Transaction monitored: {tx_hash}\n")
                
        except Exception as e:
            self._send_output(f"Error handling transaction {tx_hash}: {e}\n")

    def _find_contract_ethdebug_dir(self, contract_address: str, contract_name: str = None) -> tuple:
        """Find ethdebug directory for a contract by comparing deployed bytecode with compiled bytecode.
        Returns (ethdebug_dir, contract_name) tuple or (None, None) if not found.
        """
        if not self._out_dir or not os.path.exists(self._out_dir):
            return (None, None)
        
        ethdebug_dir = None
        found_name = contract_name
        
        # Get deployed bytecode from blockchain for comparison
        deployed_bytecode = None
        if contract_address and self._tracer and hasattr(self._tracer, 'w3'):
            try:
                deployed_bytecode = self._tracer.w3.eth.get_code(contract_address)
                if deployed_bytecode:
                    # Normalize to hex string
                    if isinstance(deployed_bytecode, bytes):
                        deployed_bytecode = deployed_bytecode.hex()
                    if not deployed_bytecode.startswith('0x'):
                        deployed_bytecode = '0x' + deployed_bytecode
                    # Remove 0x prefix for comparison (runtime bytecode)
                    deployed_bytecode = deployed_bytecode[2:] if deployed_bytecode.startswith('0x') else deployed_bytecode
            except Exception as e:
                self._send_output(f"Warning: Could not get deployed bytecode: {e}\n")
        
        # First, try to find contract by name in subfolder (preferred method)
        if contract_name:
            self._send_output(f"Trying to find contract {contract_name} in {self._out_dir}\n")
            contract_dir = os.path.join(self._out_dir, contract_name)
            # Check if contract subfolder exists and has ethdebug files
            if os.path.exists(contract_dir) and os.path.isdir(contract_dir):
                # Verify bytecode match if available
                if deployed_bytecode and self._verify_bytecode_match(contract_dir, contract_name, deployed_bytecode):
                    ethdebug_dir = contract_dir
                    found_name = contract_name
                else:
                    # Check for ethdebug files even if bytecode doesn't match
                    try:
                        ethdebug_files = [
                            f for f in os.listdir(contract_dir)
                            if f.endswith('_ethdebug.json') or f.endswith('_ethdebug-runtime.json') or f == 'ethdebug.json'
                        ]
                        if ethdebug_files and not deployed_bytecode:
                            # If we can't verify bytecode, use it anyway
                            ethdebug_dir = contract_dir
                            found_name = contract_name
                    except (OSError, PermissionError):
                        pass
        
        # If not found by name, try to find contract info from contracts.json
        if not ethdebug_dir:
            contracts_json_path = os.path.join(self._out_dir, "contracts.json")
            if os.path.exists(contracts_json_path):
                try:
                    with open(contracts_json_path, "r") as f:
                        contracts_data = json.load(f)
                        for contract in contracts_data.get('contracts', []):
                            if contract.get('address', '').lower() == contract_address.lower():
                                found_name = contract.get('name', '')
                                if found_name:
                                    contract_dir = os.path.join(self._out_dir, found_name)
                                    if os.path.exists(contract_dir) and os.path.isdir(contract_dir):
                                        # Verify bytecode match
                                        if deployed_bytecode and self._verify_bytecode_match(contract_dir, found_name, deployed_bytecode):
                                            ethdebug_dir = contract_dir
                                            break
                                        else:
                                            # Check for ethdebug files
                                            try:
                                                ethdebug_files = [
                                                    f for f in os.listdir(contract_dir)
                                                    if f.endswith('_ethdebug.json') or f.endswith('_ethdebug-runtime.json') or f == 'ethdebug.json'
                                                ]
                                                if ethdebug_files:
                                                    ethdebug_dir = contract_dir
                                                    break
                                            except (OSError, PermissionError):
                                                pass
                except (json.JSONDecodeError, IOError):
                    pass
        
        # If still not found, try to find by comparing bytecode with all contract folders
        if not ethdebug_dir and deployed_bytecode:
            try:
                for item in os.listdir(self._out_dir):
                    item_path = os.path.join(self._out_dir, item)
                    if os.path.isdir(item_path):
                        # Try to match bytecode
                        if self._verify_bytecode_match(item_path, item, deployed_bytecode):
                            ethdebug_dir = item_path
                            found_name = item
                            break
            except (OSError, PermissionError):
                pass
        
        # If still not found, try to find by scanning out/ directory for contract subfolders (fallback)
        if not ethdebug_dir:
            try:
                for item in os.listdir(self._out_dir):
                    item_path = os.path.join(self._out_dir, item)
                    if os.path.isdir(item_path):
                        # Check for ethdebug files in this folder
                        try:
                            ethdebug_files = [
                                f for f in os.listdir(item_path)
                                if f.endswith('_ethdebug.json') or f.endswith('_ethdebug-runtime.json') or f == 'ethdebug.json'
                            ]
                            if ethdebug_files:
                                ethdebug_dir = item_path
                                if not found_name:
                                    found_name = item
                                    # Don't break - continue to find better match
                        except (OSError, PermissionError):
                            continue
            except (OSError, PermissionError):
                pass
            
            # If still not found, check if out/ itself has ethdebug.json (fallback)
            if not ethdebug_dir and os.path.exists(os.path.join(self._out_dir, "ethdebug.json")):
                ethdebug_dir = self._out_dir
        
        return (ethdebug_dir, found_name)
    
    def _verify_bytecode_match(self, contract_dir: str, contract_name: str, deployed_bytecode: str) -> bool:
        """Verify if deployed bytecode matches compiled bytecode from contract folder.
        Returns True if bytecode matches, False otherwise.
        """
        try:
            # Look for .bin file in contract directory
            bin_file = os.path.join(contract_dir, f"{contract_name}.bin")
            if not os.path.exists(bin_file):
                return False
            
            # Read compiled bytecode
            with open(bin_file, 'r') as f:
                compiled_bytecode = f.read().strip()
            
            # Normalize bytecode (remove 0x prefix, whitespace)
            compiled_bytecode = compiled_bytecode.replace('0x', '').replace(' ', '').replace('\n', '')
            deployed_bytecode = deployed_bytecode.replace('0x', '').replace(' ', '').replace('\n', '')
            
            # Compare runtime bytecode (deployed bytecode is runtime, compiled .bin might be creation bytecode)
            # For runtime comparison, we need to extract runtime part from .bin if it contains creation bytecode
            # For now, simple comparison - if deployed matches end of compiled, it's likely a match
            if deployed_bytecode and compiled_bytecode:
                # Check if deployed bytecode is contained in compiled bytecode (runtime bytecode)
                if deployed_bytecode in compiled_bytecode:
                    return True
                # Or check if they match exactly (if .bin contains only runtime bytecode)
                if deployed_bytecode == compiled_bytecode:
                    return True
                # Or check if compiled bytecode ends with deployed bytecode (creation bytecode + runtime)
                if compiled_bytecode.endswith(deployed_bytecode):
                    return True
            
            return False
        except Exception as e:
            self._send_output(f"Warning: Error verifying bytecode match: {e}\n")
            return False
    
    def _update_contracts_json(self, contract_address: str, contract_name: str, debug_dir: str):
        """Create or update contracts.json file with contract information.
        
        Args:
            contract_address: The contract address (checksum format)
            contract_name: The contract name
            debug_dir: Absolute path to the debug directory
        """
        if not self._out_dir or not os.path.exists(self._out_dir):
            return
        
        contracts_json_path = os.path.join(self._out_dir, "contracts.json")
        
        # Normalize address to checksum format
        try:
            contract_address = to_checksum_address(contract_address)
        except Exception:
            pass  # Keep original if conversion fails
        
        # Calculate relative path from contracts.json location to debug_dir
        try:
            # If debug_dir is already relative, check if it's relative to out_dir
            if not os.path.isabs(debug_dir):
                # Already relative, use as-is but ensure ./ prefix
                relative_debug_dir = debug_dir if debug_dir.startswith('./') or debug_dir.startswith('../') else './' + debug_dir
            else:
                # Absolute path - convert to relative
                debug_dir_path = Path(debug_dir).resolve()
                out_dir_path = Path(self._out_dir).resolve()
                
                # Try to make path relative
                try:
                    relative_debug_dir = os.path.relpath(debug_dir_path, out_dir_path)
                    # Ensure it starts with ./ for consistency (unless it's ../)
                    if not relative_debug_dir.startswith('./') and not relative_debug_dir.startswith('../'):
                        relative_debug_dir = './' + relative_debug_dir
                except ValueError:
                    # If paths are on different drives (Windows), use absolute path
                    relative_debug_dir = str(debug_dir_path)
        except Exception:
            # Fallback to absolute path if relative path calculation fails
            relative_debug_dir = debug_dir
        
        # Load existing contracts.json if it exists
        contracts_data = {"contracts": []}
        if os.path.exists(contracts_json_path):
            try:
                with open(contracts_json_path, "r") as f:
                    contracts_data = json.load(f)
                    if not isinstance(contracts_data, dict) or "contracts" not in contracts_data:
                        contracts_data = {"contracts": []}
            except (json.JSONDecodeError, IOError) as e:
                self._send_output(f"Warning: Could not read existing contracts.json: {e}\n")
                contracts_data = {"contracts": []}
        
        # Check if contract already exists in the list
        contract_found = False
        for contract in contracts_data.get("contracts", []):
            if contract.get("address", "").lower() == contract_address.lower():
                # Update existing entry
                contract["name"] = contract_name
                contract["debug_dir"] = relative_debug_dir
                contract_found = True
                break
        
        # Add new contract if not found
        if not contract_found:
            contracts_data.setdefault("contracts", []).append({
                "address": contract_address,
                "name": contract_name,
                "debug_dir": relative_debug_dir
            })
        
        # Write updated contracts.json
        try:
            with open(contracts_json_path, "w") as f:
                json.dump(contracts_data, f, indent=2)
        except IOError as e:
            self._send_output(f"Warning: Could not write contracts.json: {e}\n")
    
    def _load_ethdebug_for_contract(self, contract_address: str, contract_name: str = None):
        """Load ethdebug files for a contract address from out/ directory.
        Looks for contract files in out/ContractName/ subfolder first.
        """
        if not self._out_dir or not os.path.exists(self._out_dir):
            self._send_output(f"Warning: out/ directory not found. Skipping ethdebug loading.\n")
            return
        
        ethdebug_dir = None
        found_name = None
        
        try:
            # Find contract ethdebug directory
            ethdebug_dir, found_name = self._find_contract_ethdebug_dir(contract_address, contract_name)
            
            if not ethdebug_dir:
                self._send_output(f"Warning: Could not find ethdebug directory for contract {contract_address}")
                if found_name:
                    self._send_output(f" (expected: {os.path.join(self._out_dir, found_name)})\n")
                else:
                    self._send_output(f"\n")
                return
            
            # Create multi-contract parser if it doesn't exist
            if not hasattr(self._tracer, 'multi_contract_parser') or not self._tracer.multi_contract_parser:
                multi_parser = MultiContractETHDebugParser()
                self._tracer.multi_contract_parser = multi_parser
            else:
                multi_parser = self._tracer.multi_contract_parser
            
            # Load contract into parser
            if found_name:
                multi_parser.load_contract(contract_address, ethdebug_dir, found_name)
            else:
                multi_parser.load_contract(contract_address, ethdebug_dir)
            
            # Set primary contract context
            primary_contract = multi_parser.get_contract_at_address(contract_address)
            if primary_contract:
                self._tracer.ethdebug_parser = primary_contract.parser
                self._tracer.ethdebug_parser.debug_dir = str(primary_contract.debug_dir)
                self._tracer.ethdebug_info = primary_contract.ethdebug_info
                
                # Load ABI
                abi_path = primary_contract.debug_dir / f"{primary_contract.name}.abi"
                if abi_path.exists():
                    self._tracer.load_abi(str(abi_path))
            else:
                self._send_output(f"Warning: Failed to load contract info from ethdebug directory\n")
            
            # Update contracts.json with the found contract information
            if ethdebug_dir and found_name:
                self._update_contracts_json(contract_address, found_name, ethdebug_dir)
            
            # Store ethdebug_dir for this contract (only if we successfully found it)
            if ethdebug_dir:
                if not hasattr(self, '_contract_ethdebug_dirs'):
                    self._contract_ethdebug_dirs = {}
                self._contract_ethdebug_dirs[contract_address.lower()] = ethdebug_dir
                
        except Exception as e:
            self._send_output(f"Error loading ethdebug files: {e}\n")
            import traceback
            self._send_output(f"Traceback: {traceback.format_exc()}\n")

    def _start_monitoring(self):
        """Start the transaction monitoring thread."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        
        self._monitor_stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def _monitor_loop(self):
        """Main loop for monitoring transactions."""
        while not self._monitor_stop_event.is_set():
            try:
                self._monitor_transactions()
                # Wait up to 1 second, but check stop event periodically
                if self._monitor_stop_event.wait(timeout=1):
                    break
            except Exception as e:
                self._send_output(f"Error in monitor loop: {e}\n")
                if self._monitor_stop_event.wait(timeout=5):
                    break

    def _stop_monitoring(self):
        """Stop the transaction monitoring thread."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_stop_event.set()
            self._monitor_thread.join(timeout=2)
            self._monitor_thread = None
    
    def _compile_contracts(self, project_root: str, output_dir: str):
        """Compile all Solidity files in the workspace to the output directory.
        Each contract gets its own subfolder in output_dir/ContractName/
        Only compiles files from src/ directory to avoid dependencies in lib/ and node_modules/
        
        Args:
            project_root: Foundry project root (where foundry.toml is located)
            output_dir: Output directory for compiled files
        """
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Get workspace root (original workspace, not foundry project root)
        workspace_root_abs = os.path.abspath(self._workspace_root) if self._workspace_root else os.path.abspath(project_root)
        
        # Get absolute path for project root
        project_root_abs = os.path.abspath(project_root)
        
        # Find src/ directory - try common locations first
        src_dir = None
        # Try project_root/src first
        candidate = os.path.join(project_root_abs, 'src')
        if os.path.exists(candidate) and os.path.isdir(candidate):
            src_dir = candidate
        else:
            # Try packages/blockchain/src (common in monorepos)
            candidate = os.path.join(project_root_abs, 'packages', 'blockchain', 'src')
            if os.path.exists(candidate) and os.path.isdir(candidate):
                src_dir = candidate
            else:
                # Try to find src directory in immediate subdirectories
                try:
                    for item in os.listdir(project_root_abs):
                        item_path = os.path.join(project_root_abs, item)
                        if os.path.isdir(item_path):
                            candidate = os.path.join(item_path, 'src')
                            if os.path.exists(candidate) and os.path.isdir(candidate):
                                src_dir = candidate
                                break
                except (OSError, PermissionError):
                    pass
        
        # Fallback: use project_root if src not found
        if not src_dir:
            src_dir = project_root_abs
            self._send_output(f"Warning: src/ directory not found, using project root: {project_root_abs}\n")
        
        # Show project root in message, not src directory
        self._send_output(f"Compiling Solidity files from: {project_root_abs}\n")
        
        # Find all .sol files only in src/ directory
        sol_files = self._find_sol_files(src_dir)
        
        if not sol_files:
            raise ValueError(f"No .sol files found in src directory: {src_dir}")
        
        # Use absolute paths for compilation
        absolute_files = [os.path.abspath(f) for f in sol_files]
        
        # Build compilation command with proper path handling
        # base-path should be workspace_root, not project_root
        cmd = [
            'solc',
            '--base-path', workspace_root_abs,
            '--allow-paths', '.',
            '--via-ir',
            '--debug-info', 'ethdebug',
            '--ethdebug',
            '--ethdebug-runtime',
            '--bin',
            '--abi',
            '--overwrite',
            '-o', output_dir
        ]
        
        # Add include paths for common directories (node_modules, lib)
        # Try to find them relative to src_dir parent (for monorepo structures)
        include_paths = []
        src_parent = os.path.dirname(src_dir) if src_dir != project_root_abs else project_root_abs
        
        # Try node_modules in src parent directory first (e.g., packages/blockchain/node_modules)
        node_modules_path = os.path.join(src_parent, 'node_modules')
        if not os.path.exists(node_modules_path) or not os.path.isdir(node_modules_path):
            # Fallback to project root
            node_modules_path = os.path.join(project_root_abs, 'node_modules')
        
        if os.path.exists(node_modules_path) and os.path.isdir(node_modules_path):
            include_paths.append('--include-path')
            include_paths.append(node_modules_path)
        
        # Try lib in src parent directory first (e.g., packages/blockchain/lib)
        lib_path = os.path.join(src_parent, 'lib')
        if not os.path.exists(lib_path) or not os.path.isdir(lib_path):
            # Fallback to project root
            lib_path = os.path.join(project_root_abs, 'lib')
        
        if os.path.exists(lib_path) and os.path.isdir(lib_path):
            include_paths.append('--include-path')
            include_paths.append(lib_path)
        
        cmd.extend(include_paths)
        cmd.extend(absolute_files)
        
        # Log the compilation command
        cmd_str = ' '.join(cmd)
        self._send_output(f"Running solc command:\n{cmd_str}\n\n")
        
        try:
            # Run compilation with cwd as workspace_root
            result = subprocess.run(
                cmd,
                cwd=project_root_abs,
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                error_msg = result.stderr or result.stdout or "Unknown compilation error"
                raise RuntimeError(f"Compilation failed:\n{error_msg}")
            
            # Show compilation output
            if result.stdout:
                self._send_output(result.stdout)
            if result.stderr:
                self._send_output(f"Compilation warnings:\n{result.stderr}")
            
            # Organize compiled files into contract-specific subfolders
            self._organize_compiled_files(output_dir)
            
            self._send_output(f"Successfully compiled {len(sol_files)} Solidity file(s) to {output_dir}\n")
            
        except FileNotFoundError:
            raise RuntimeError("solc not found. Please install solc and ensure it's in your PATH.")
        except subprocess.SubprocessError as e:
            raise RuntimeError(f"Compilation failed: {e}")
    
    def _organize_compiled_files(self, output_dir: str):
        """Organize compiled files into contract-specific subfolders.
        Moves ContractName_*.json, ContractName.bin, ContractName.abi into out/ContractName/
        """
        if not os.path.exists(output_dir):
            return
        
        # Find all contract files in output directory
        # Use a dict to map all possible contract names to their files
        contract_files = {}
        
        for filename in os.listdir(output_dir):
            file_path = os.path.join(output_dir, filename)
            
            # Skip directories
            if os.path.isdir(file_path):
                continue
            
            # Skip main ethdebug.json (we'll copy it later)
            if filename == "ethdebug.json":
                continue
            
            # Parse contract name from filename
            # Format: ContractName_ethdebug.json, ContractName_ethdebug-runtime.json, ContractName.bin, ContractName.abi
            contract_name = None
            
            # Check in order from most specific to least specific
            if filename.endswith('_ethdebug-runtime.json'):
                contract_name = filename[:-23]  # Remove '_ethdebug-runtime.json'
            elif filename.endswith('_ethdebug.json'):
                contract_name = filename[:-14]  # Remove '_ethdebug.json'
            elif filename.endswith('.bin'):
                contract_name = filename[:-4]  # Remove '.bin'
            elif filename.endswith('.abi'):
                contract_name = filename[:-4]  # Remove '.abi'
            
            if contract_name:
                if contract_name not in contract_files:
                    contract_files[contract_name] = []
                contract_files[contract_name].append(file_path)
        
        # Normalize contract names - merge similar names (handle cases like BuggyVaul vs BuggyVault)
        # Strategy: if one name is a prefix of another, merge them and use the longer name
        normalized_contracts = {}
        processed_names = set()
        
        for contract_name, files in contract_files.items():
            if contract_name in processed_names:
                continue
            
            # Find all similar names (one is prefix of another)
            similar_names = [contract_name]
            for other_name in contract_files.keys():
                if other_name != contract_name and other_name not in processed_names:
                    # Check if one is prefix of another
                    if contract_name.startswith(other_name) or other_name.startswith(contract_name):
                        similar_names.append(other_name)
            
            # Use the longest name as the normalized name
            normalized_name = max(similar_names, key=len)
            
            # Collect all files from similar names
            all_files = []
            for name in similar_names:
                all_files.extend(contract_files[name])
                processed_names.add(name)
            
            normalized_contracts[normalized_name] = all_files
        
        # Move files to contract-specific subfolders
        for contract_name, files in normalized_contracts.items():
            contract_dir = os.path.join(output_dir, contract_name)
            os.makedirs(contract_dir, exist_ok=True)
            
            for file_path in files:
                filename = os.path.basename(file_path)
                dest_path = os.path.join(contract_dir, filename)
                
                # Move file to contract subfolder
                try:
                    if os.path.exists(dest_path):
                        os.remove(dest_path)  # Remove existing file if any
                    os.rename(file_path, dest_path)
                except Exception as e:
                    self._send_output(f"Warning: Could not move {filename} to {contract_dir}: {e}\n")
        
        # Also copy ethdebug.json to each contract folder if it exists
        main_ethdebug = os.path.join(output_dir, "ethdebug.json")
        if os.path.exists(main_ethdebug):
            for contract_name in normalized_contracts.keys():
                contract_dir = os.path.join(output_dir, contract_name)
                dest_ethdebug = os.path.join(contract_dir, "ethdebug.json")
                try:
                    import shutil
                    shutil.copy2(main_ethdebug, dest_ethdebug)
                except Exception as e:
                    self._send_output(f"Warning: Could not copy ethdebug.json to {contract_dir}: {e}\n")

    # ---- DAP transport helpers ----
    def _send(self, msg: Dict[str, Any]):
        body = json.dumps(msg).encode("utf-8")
        header = f"Content-Length: {len(body)}".encode("utf-8") + CRLF + CRLF
        sys.stdout.buffer.write(header + body)
        sys.stdout.buffer.flush()

    def _event(self, event: str, body: Optional[Dict[str, Any]] = None):
        evt = {
            "type": "event",
            "seq": self._seq,
            "event": event,
            "body": body or {}
        }
        self._seq += 1
        self._send(evt)

    def _response(self, request: Dict[str, Any], success: bool = True, body: Optional[Dict[str, Any]] = None, message: Optional[str] = None):
        resp = {
            "type": "response",
            "seq": self._seq,
            "request_seq": request.get("seq"),
            "success": success,
            "command": request.get("command"),
        }
        if body is not None:
            resp["body"] = body
        if message and not success:
            resp["message"] = message
        self._seq += 1
        self._send(resp)

    def _read(self) -> Optional[Dict[str, Any]]:
        # Parse DAP headers from stdin
        content_length = None
        while True:
            line = sys.stdin.buffer.readline()
            if not line or line == b"\r\n":
                break
            k, _, v = line.partition(b":")
            if k.lower() == b"content-length":
                content_length = int(v.strip())
        if content_length is None:
            return None
        body = sys.stdin.buffer.read(content_length)
        return json.loads(body.decode("utf-8"))

    # ---- DAP request handlers ----
    def initialize(self, request):
        caps = {
            "supportsConfigurationDoneRequest": True,
            "supportsSetBreakpointsRequest": True,
            "supportsTerminateRequest": True,
            "supportsConditionalBreakpoints": True,
            "supportsRestartRequest": True,
        }
        self._response(request, True, {"capabilities": caps})
        self._event("initialized")
    def launch(self, request):
        try:
            args = request.get("arguments", {}) or {}
            
            # Get source file and workspace root
            source = args.get("source")
            workspace_root = args.get("workspaceRoot")
            
            # workspace detection
            if not workspace_root:
                if source:
                    workspace_root = os.path.dirname(source)
                else:
                    workspace_root = os.getcwd()
            
            # Change to workspace root
            os.chdir(workspace_root)
            
            # Enhanced path resolution with fallbacks
            def resolve_path(path_arg):
                if not path_arg:
                    return path_arg
                if os.path.isabs(path_arg):
                    return path_arg
                
                # Try workspace-relative first
                workspace_path = os.path.join(workspace_root, path_arg)
                if os.path.exists(workspace_path):
                    return workspace_path
                
                # Try current directory
                if os.path.exists(path_arg):
                    return os.path.abspath(path_arg)
                
                # Fallback to workspace-relative
                return workspace_path
            
            # Find project root (where foundry.toml is located) for out/ directory
            project_root = self._find_project_root(workspace_root)
            # Check if foundry.toml was actually found
            foundry_toml_path = Path(project_root) / "foundry.toml"
            if foundry_toml_path.exists() and foundry_toml_path.is_file():
                self._send_output(f"Found Foundry project root: {project_root}\n")
                out_dir = os.path.join(project_root, "out")
            else:
                # foundry.toml not found in subdirectories, using original workspace root
                self._send_output(f"Foundry project root not found in subdirectories, using workspace root: {workspace_root}\n")
                out_dir = os.path.join(workspace_root, "out")
            
            self._workspace_root = workspace_root
            self._out_dir = out_dir
            # Always compile - remove existing out/ folder if it exists to ensure fresh compilation
            if os.path.exists(out_dir):
                try:
                    shutil.rmtree(out_dir)
                except Exception as e:
                    self._send_output(f"Warning: Could not remove out/ directory: {e}\n")
            
            # Auto-compile contracts
            # Use project_root for compilation if found, otherwise use workspace_root
            compile_root = project_root if project_root else workspace_root
            self._send_output("Compiling Solidity contracts...\n")
            self._compile_contracts(compile_root, out_dir)
            
            # Auto-detect contracts.json if it exists
            contracts = resolve_path(args.get("contracts"))
            if not contracts:
                contracts_json_path = os.path.join(out_dir, "contracts.json")
                if os.path.exists(contracts_json_path):
                    contracts = contracts_json_path
            
            # Auto-detect ethdebug_dir from out/ directory
            ethdebug_dir = resolve_path(args.get("ethdebugDir"))

            rpc_url = args.get("rpc", "http://localhost:8545")
            block = args.get("block", None)
            from_addr = args.get("from_addr", "")
            function_signature = args.get("function", None)
            function_args = args.get("functionArgs", [])
            contract_address = args.get("contractAddress", "")
            
            # Store RPC URL for later use
            self._rpc_url = rpc_url
            
            # Store paths for later use in source requests
            self.source_file = source
            self.workspace_root = workspace_root
            contract_name = None
            abi_path = None
            # Create tracer
            try:
                tracer = TransactionTracer(rpc_url)
                self._tracer = tracer  # Store for monitoring
            except Exception as e:
                raise ValueError(f'Failed to create TransactionTracer: {e}')
            source_map = {}

            if contract_address:
                if not is_address(contract_address):
                    raise ValueError(f'Invalid contract address: {contract_address}')
        
            # Check if we have function_name and functionArgs for simulation
            # If not, we're in monitoring mode and should skip ethdebug loading
            is_monitoring_mode = not (function_signature and function_args)
            
            # Multi-contract mode detection (same as trace_command)
            # Only load ethdebug files if NOT in monitoring mode
            multi_contract_mode = False
            ethdebug_dirs = []
            if not is_monitoring_mode:
                if ethdebug_dir:
                    if isinstance(ethdebug_dir, list):
                        ethdebug_dirs = ethdebug_dir
                    else:
                        ethdebug_dirs = [ethdebug_dir]
                if args.get('multi_contract', False) or (ethdebug_dirs and len(ethdebug_dirs) > 1) or contracts:
                    multi_contract_mode = True

            if multi_contract_mode and not is_monitoring_mode:
                multi_parser = MultiContractETHDebugParser()
                # Load from contracts mapping file if provided
                if contracts:
                    try:
                        multi_parser.load_from_mapping_file(contracts)
                    except Exception as e:
                        self._send_output(f"Error loading contracts mapping file: {e}")
                        sys.exit(1)
                # Load from ethdebug directories
                if ethdebug_dirs:
                    try:
                        # Parse all ethdebug directories at once
                        specs = ETHDebugDirParser.parse_ethdebug_dirs(ethdebug_dirs)
                        
                        for spec in specs:
                            if spec.address and spec.name:
                                # Single contract format: address:name:path
                                multi_parser.load_contract(spec.address, spec.path, spec.name)
                            elif spec.address:
                                # Multi-contract format: address:path
                                multi_parser.load_contract(spec.address, spec.path)
                            else:
                                # Just path - try to load from deployment.json
                                deployment_file = Path(spec.path) / "deployment.json"
                                if deployment_file.exists():
                                    try:
                                        multi_parser.load_from_deployment(deployment_file)
                                    except Exception as e:
                                        self._send_output(f"Error loading deployment.json from {spec.path}: {e}\n")
                                        sys.exit(1)
                                else:
                                    # If no deployment.json, try to load directly from the directory
                                    # This handles the case where we auto-detected ethdebug_dir as just a path
                                    if contract_address:
                                        # Try to find contract name from files in the directory
                                        contract_name_from_files = None
                                        if os.path.exists(spec.path):
                                            for file in os.listdir(spec.path):
                                                if file.endswith('.abi') or file.endswith('.bin'):
                                                    contract_name_from_files = os.path.splitext(file)[0]
                                                    break
                                        if contract_name_from_files:
                                            multi_parser.load_contract(contract_address, spec.path, contract_name_from_files)
                                        else:
                                            multi_parser.load_contract(contract_address, spec.path)
                                    else:
                                        self._send_output("Warning: No deployment.json found and no contract address provided, skipping...\n")
                    except ValueError as e:
                        # If parsing fails, try to load directly if we have contract_address
                        if contract_address and ethdebug_dirs:
                            for ethdebug_path in ethdebug_dirs:
                                if os.path.exists(ethdebug_path):
                                    # Try to find contract name from files
                                    contract_name_from_files = None
                                    for file in os.listdir(ethdebug_path):
                                        if file.endswith('.abi') or file.endswith('.bin'):
                                            contract_name_from_files = os.path.splitext(file)[0]
                                            break
                                    if contract_name_from_files:
                                        multi_parser.load_contract(contract_address, ethdebug_path, contract_name_from_files)
                                    else:
                                        multi_parser.load_contract(contract_address, ethdebug_path)
                                    break
                        else:
                            self._send_output("Error parsing ethdebug directories\n")
                        sys.exit(1)
                tracer.multi_contract_parser = multi_parser

                # Set primary contract context for simulation (entrypoint contract)
                primary_contract = multi_parser.get_contract_at_address(contract_address)
                if primary_contract:
                    # We have debug info for the entrypoint contract
                    tracer.ethdebug_parser = primary_contract.parser
                    tracer.ethdebug_parser.debug_dir = str(primary_contract.debug_dir)  # Set debug_dir for source loading
                    tracer.ethdebug_info = primary_contract.ethdebug_info
                    source_map = primary_contract.parser.get_source_mapping()
                    # Load ABI for primary contract
                    abi_path = primary_contract.debug_dir / f"{primary_contract.name}.abi"
                    if abi_path.exists():
                        tracer.load_abi(str(abi_path))
                    else:
                        # Try to find any ABI file in the directory
                        for abi_file in Path(primary_contract.debug_dir).glob("*.abi"):
                            tracer.load_abi(str(abi_file))
                            break
                else:
                    # No debug info for entrypoint contract - simulate without source mapping
                    # This is similar to how trace command works
                    source_map = {}
                    if not getattr(args, 'raw', False) and not getattr(args, 'json', False):
                        self._send_output(f"Warning: No ETHDebug information for entrypoint contract {contract_address}\n")
                    
                    # Try to load ABI for entrypoint contract from common locations
                    if contract_address:
                        # Try to find ABI in current directory
                        for abi_file in Path(".").glob("*.abi"):
                            tracer.load_abi(str(abi_file))
                            break
                # Load ABIs for ALL contracts that might be called during simulation
                for addr, contract_info in multi_parser.contracts.items():
                    abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
                    if abi_path.exists():
                        tracer.load_abi(str(abi_path))
                        
            elif ethdebug_dirs and not multi_contract_mode and not is_monitoring_mode:
                # Single contract mode - parse address:name:path format (required)
                try:
                    specs = ETHDebugDirParser.parse_ethdebug_dirs(ethdebug_dirs)
                    if not specs:
                        self._send_output("No valid ethdebug directory specified\n")
                        sys.exit(1)
                    spec = specs[0]
                    address, name, ethdebug_dir = spec.address, spec.name, spec.path
                except ValueError as e:
                    self._send_output(f"Error: {e}")
                    sys.exit(1)
                
                # Check if the contract address matches the ETHDebug address
                if contract_address and contract_address.lower() != address.lower():
                    # Address doesn't match - simulate without source mapping for entrypoint
                    # This is similar to how trace command works
                    source_map = {}
                    if not getattr(args, 'raw', False) and not getattr(args, 'json', False):
                        self._send_output(f"Warning: Contract address {contract_address} does not match ETHDebug address {address}\n")
                        
                    
                    # Try to load ABI for entrypoint contract from common locations
                    if contract_address and ethdebug_dir:
                        # Try to find ABI in current directory
                        for abi_file in Path(ethdebug_dir).glob("*.abi"):
                            tracer.load_abi(str(abi_file))
                            break
                else:
                    source_map = {}
                
                # Create a multi-contract parser to handle additional contracts (same as trace command)
                multi_parser = MultiContractETHDebugParser()
                
                # Add the already loaded contract
                if tracer.ethdebug_info:
                    multi_parser.load_contract(address, ethdebug_dir, name)
                
                # Load ABIs for ALL contracts that might be called during simulation
                for addr, contract_info in multi_parser.contracts.items():
                    abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
                    if abi_path.exists():
                        tracer.load_abi(str(abi_path))
                
                # Set the multi-contract parser
                tracer.multi_contract_parser = multi_parser
            else:
                # No debug info provided - simulate without source code
                # Try to load ABI from common locations if available
                # TODO: Implement ABI loading from common locations
                pass

            # Only set ethdebug_dir and contract_name if NOT in monitoring mode
            if not is_monitoring_mode:
                if getattr(tracer, 'multi_contract_parser', None):
                    # In multi-contract mode, find the ethdebug_dir for the entrypoint contract
                    entrypoint_contract = tracer.multi_contract_parser.get_contract_at_address(contract_address)
                    if entrypoint_contract:
                        ethdebug_dir = str(entrypoint_contract.debug_dir)
                        contract_name = entrypoint_contract.name
                    else:
                        # Fallback to first ethdebug_dir if entrypoint not found - parse format
                        ethdebug_spec = ethdebug_dir[0] if isinstance(ethdebug_dir, list) else ethdebug_dir
                        try:
                            specs = ETHDebugDirParser.parse_ethdebug_dirs([ethdebug_spec])
                            if specs:
                                ethdebug_dir = specs[0].path
                                contract_name = specs[0].name
                            else:
                                ethdebug_dir = ethdebug_spec
                                contract_name = None
                        except ValueError:
                            # Fallback to old parsing for backward compatibility
                            if ':' in ethdebug_spec and ethdebug_spec.startswith('0x'):
                                parts = ethdebug_spec.split(':', 2)
                                if len(parts) >= 3:
                                    ethdebug_dir = parts[2]  # Extract path part
                                    contract_name = parts[1]  # Extract name part
                                elif len(parts) == 2:
                                    ethdebug_dir = parts[1]  # Extract path part
                                else:
                                    ethdebug_dir = ethdebug_spec
                            else:
                                ethdebug_dir = ethdebug_spec
                elif ethdebug_dir:
                    # Single contract mode - parse format
                    ethdebug_spec = ethdebug_dir[0] if isinstance(ethdebug_dir, list) else ethdebug_dir
                    try:
                        specs = ETHDebugDirParser.parse_ethdebug_dirs([ethdebug_spec])
                        if specs:
                            ethdebug_dir = specs[0].path
                            contract_name = specs[0].name
                        else:
                            ethdebug_dir = ethdebug_spec
                            contract_name = None
                    except ValueError:
                        # Fallback to old parsing for backward compatibility
                        if ':' in ethdebug_spec and ethdebug_spec.startswith('0x'):
                            parts = ethdebug_spec.split(':', 2)
                            if len(parts) >= 3:
                                ethdebug_dir = parts[2]  # Extract path part
                                contract_name = parts[1]  # Extract name part
                            elif len(parts) == 2:
                                ethdebug_dir = parts[1]  # Extract path part
                            else:
                                ethdebug_dir = ethdebug_spec
                        else:
                            ethdebug_dir = ethdebug_spec
    
            self._send_output("\nStarting debugger...\n")
            self.debugger = EVMDebugger(
                contract_address=str(contract_address) if contract_address else None,
                rpc_url=rpc_url,
                ethdebug_dir=ethdebug_dir,
                function_name=function_signature,
                function_args=function_args,
                abi_path=abi_path,
                from_addr=from_addr,
                block=block,
                tracer=tracer,
                contract_name=contract_name
            )

            # Check if we have function_name and functionArgs for simulation
            if function_signature and function_args:
                # Run simulation mode
                try:
                    # Check prerequisites before simulation
                    if not self.debugger.contract_address:
                        raise RuntimeError("No contract address available for simulation")
                    
                    # Capture stdout from the debugger simulation
                    with self._capture_output():
                        self.debugger._do_interactive()
                                        
                    if not self.debugger.current_trace:
                        raise RuntimeError("Simulation failed to generate trace - check function name and arguments")              
                    
                    # Find the actual function entry point (first function call after dispatcher)
                    entry_step = 0
                    if hasattr(self.debugger, 'function_trace') and len(self.debugger.function_trace) > 0:
                        # Look for the target function by name
                        target_function = None
                        for func in self.debugger.function_trace:
                            if func.name == self.debugger.function_name:
                                target_function = func
                                break
                        
                        if target_function:
                            entry_step = target_function.entry_step
                            self.debugger.current_function = target_function
                        elif len(self.debugger.function_trace) > 1:
                            # Skip dispatcher, go to first actual function
                            entry_step = self.debugger.function_trace[1].entry_step
                            self.debugger.current_function = self.debugger.function_trace[1]
                            self._send_output(f"Using first non-dispatcher function at step {entry_step}\n")
                        else:
                            # Use first function if only one exists
                            entry_step = self.debugger.function_trace[0].entry_step
                            self.debugger.current_function = self.debugger.function_trace[0]
                    else:
                        self._send_output("No function trace found, starting at step 0\n")
                        
                    # Set debugger to function entry point
                    self.debugger.current_step = entry_step

                except Exception as e:
                    self._send_output(f"Simulation failed: {e}")
                    raise RuntimeError(f"Failed to generate execution trace: {e}")
            else:
                # No function specified - enter monitoring mode
                # Contract address is optional - we monitor all transactions
                self._send_output(f"Waiting for transactions on RPC: {rpc_url}\n")
                
                # Start monitoring thread
                self._start_monitoring()
            
            # Don't register breakpoints here - wait for configurationDone
            # VS Code may send setBreakpoints requests after launch
            
            self._response(request, True, {})
            self._event("thread", {"reason": "started", "threadId": self.thread_id})
            
            # If we have a trace, stop at entry point, otherwise wait for transactions
            if self.debugger.current_trace:
                self._event("stopped", {"reason": "entry", "threadId": self.thread_id})
        except Exception as e:
            self._send_output(f"Launch failed with error: {e}")
            self._response(request, False, message=str(e))
            return

    def setBreakpoints(self, request):
        args = request.get("arguments", {}) or {}
        breakpoints = args.get("breakpoints", [])
        source = args.get("source", {})
        
        # Get source name - try multiple ways
        source_name = None
        source_path = None
        if isinstance(source, dict):
            source_name = source.get("name", "")
            source_path = source.get("path", "")
            # Extract base name without extension for compatibility
            if source_name:
                source_name = os.path.basename(source_name).split('.')[0]
            elif source_path:
                source_name = os.path.basename(source_path).split('.')[0]
        elif isinstance(source, str):
            source_name = os.path.basename(source).split('.')[0]
            source_path = source
        
        if not source_name:
            source_name = "unknown"
        
        lines = []
        functions = []
        # Separate line and function breakpoints
        for bp in breakpoints:
            if "line" in bp:
                lines.append(bp["line"])
            if "functions" in bp:
                functions.extend(bp["functions"])
        
        # Store breakpoints even if debugger is not initialized yet
        self.breakpoints[source_name] = lines[:]
        verified = []
        
        # Always verify breakpoints as valid (they will be registered when debugger is ready)
        for line in lines:
            verified.append({"verified": True, "line": line})
        
        for func_name in functions:
            verified.append({"verified": True, "functions": func_name})
        
        # If debugger is initialized, also register breakpoints in EVMDebugger
        if self.debugger:
            # Register line breakpoints in EVMDebugger
            for line in lines:
                try:
                    self.debugger.do_break(f"{source_name}:{line}")
                except Exception as e:
                    # Breakpoint will be registered when source map is available
                    self._send_output(f"Could not register breakpoint at {source_name}:{line} yet: {e}\n")

            # Register function name breakpoints in EVMDebugger
            for func_name in functions:
                try:
                    self.debugger.do_break(func_name)
                except Exception as e:
                    # Breakpoint will be registered when function trace is available
                    self._send_output(f"Could not register function breakpoint {func_name} yet: {e}\n")

        self._response(request, True, {"breakpoints": verified})

    def _register_existing_breakpoints(self):
        """Register all existing breakpoints in the debugger after initialization."""
        if not self.debugger:
            return
        
        # Register all stored breakpoints
        registered_count = 0
        for source_name, lines in self.breakpoints.items():
            if not lines:
                continue
            for line in lines:
                # Directly register breakpoints using source_map instead of do_break
                # This is more reliable and we can control to register only first PC per line
                if self.debugger.source_map:
                    # Find only the FIRST PC for this line (to avoid stopping multiple times on same line)
                    pc_found = None
                    for pc, source_info in self.debugger.source_map.items():
                        if isinstance(source_info, tuple) and len(source_info) >= 2:
                            src_line = source_info[1]
                            if src_line == line:
                                pc_found = pc
                                break  # Take only the first PC for this line
                    
                    if pc_found is not None:
                        self.debugger.breakpoints.add(pc_found)
                        registered_count += 1
                    else:
                        self._send_output(f"No PC found for line {line} in source_map\n")
                else:
                    # Fallback to do_break if source_map not available
                    try:
                        self.debugger.do_break(f"{source_name}:{line}")
                        registered_count += 1
                    except Exception as e:
                        self._send_output(f"Could not register {source_name}:{line}: {e}\n")
        
    def threads(self, request):
        self._response(request, True, {"threads": [{"id": self.thread_id, "name": "main"}]})

    def continue_(self, request):        
        # Run until end or breakpoint
        if not self.debugger or not self.debugger.current_trace:
            self._response(request, True, {})
            self._event("stopped", {"reason": "pause", "threadId": self.thread_id})
            return
        
        try:
            # Ensure breakpoints are registered before continue
            # This is important because breakpoints might have been lost or source_map might have changed
            if self.debugger.source_map and self.breakpoints:
                self._register_existing_breakpoints()
            
            # Store step before continue
            step_before = self.debugger.current_step
            total_steps = len(self.debugger.current_trace.steps)
            
            # Run continue - do_continue will stop at breakpoint or end
            self.debugger.do_continue("")
            
            # Check what happened after continue
            if self.debugger.current_step >= len(self.debugger.current_trace.steps) - 1:
                # Reached end of execution
                self._response(request, True, {"allThreadsContinued": False})
                self._event("exited", {"exitCode": 0})
                return
            
            # Check if we stopped at a breakpoint
            current_step = self.debugger.current_trace.steps[self.debugger.current_step]
            current_pc = current_step.pc
            is_breakpoint_hit = current_pc in self.debugger.breakpoints
            
            if is_breakpoint_hit:
                # Breakpoint hit - get source location
                source_info = None
                source_path = None
                line_num = 1
                
                # Try to get source info from tracer
                if (hasattr(self.debugger, 'tracer') and self.debugger.tracer and
                    hasattr(self.debugger.tracer, 'multi_contract_parser') and self.debugger.tracer.multi_contract_parser):
                    contract_info = self.debugger.tracer.multi_contract_parser.get_contract_at_address(self.debugger.contract_address)
                    if contract_info and hasattr(contract_info, 'ethdebug_info') and contract_info.ethdebug_info:
                        source_info = contract_info.ethdebug_info.get_source_info(current_step.pc)
                        if source_info:
                            source_path, offset, length = source_info
                            parser = getattr(contract_info, 'parser', None)
                            if parser:
                                line_num, col = parser.offset_to_line_col(source_path, offset)
                
                # Fallback to main parser
                if not source_info and (hasattr(self.debugger, 'tracer') and self.debugger.tracer and
                    hasattr(self.debugger.tracer, 'ethdebug_info') and self.debugger.tracer.ethdebug_info):
                    source_info = self.debugger.tracer.ethdebug_info.get_source_info(current_step.pc)
                    if source_info:
                        source_path, offset, length = source_info
                        if hasattr(self.debugger.tracer, 'ethdebug_parser') and self.debugger.tracer.ethdebug_parser:
                            line_num, col = self.debugger.tracer.ethdebug_parser.offset_to_line_col(source_path, offset)
                
                # Fallback to source_map if available
                if not source_info and hasattr(self.debugger, 'source_map') and self.debugger.source_map:
                    source_map_entry = self.debugger.source_map.get(current_step.pc)
                    if source_map_entry:
                        if isinstance(source_map_entry, tuple) and len(source_map_entry) >= 2:
                            line_num = source_map_entry[1]
                            # Try to find source file
                            if hasattr(self, 'source_file') and self.source_file:
                                source_path = self.source_file
                
                # Build stopped event with source location
                stopped_event = {
                    "reason": "breakpoint",
                    "threadId": self.thread_id,
                    "description": f"Breakpoint hit at PC {current_step.pc}"
                }
                
                if source_path:
                    # Normalize source_path - remove 'out/' prefix if present
                    normalized_source_path = source_path
                    if normalized_source_path.startswith('out/'):
                        normalized_source_path = normalized_source_path[4:]  # Remove 'out/' prefix
                    elif normalized_source_path.startswith('./out/'):
                        normalized_source_path = normalized_source_path[6:]  # Remove './out/' prefix
                    
                    # Resolve absolute path using workspace_root
                    workspace_root = getattr(self, '_workspace_root', None) or getattr(self, 'workspace_root', None)
                    if not workspace_root and hasattr(self, '_out_dir') and self._out_dir:
                        workspace_root = os.path.dirname(self._out_dir)
                    
                    if os.path.isabs(normalized_source_path):
                        abs_source_path = normalized_source_path
                    elif workspace_root:
                        abs_source_path = os.path.normpath(os.path.join(workspace_root, normalized_source_path))
                        # If file doesn't exist, try original path
                        if not os.path.exists(abs_source_path):
                            abs_source_path = os.path.normpath(os.path.join(workspace_root, source_path))
                    else:
                        abs_source_path = os.path.abspath(normalized_source_path)
                    
                    stopped_event["source"] = {
                        "name": os.path.basename(abs_source_path),
                        "path": abs_source_path
                    }
                    stopped_event["line"] = line_num
                
                self._response(request, True, {"allThreadsContinued": False})
                self._event("stopped", stopped_event)
                return
            else:
                # Stopped for some other reason (error, etc.) - still send stopped event
                self._response(request, True, {"allThreadsContinued": False})
                self._event("stopped", {"reason": "pause", "threadId": self.thread_id})
                return
            
        except Exception as e:
            self._send_output(f"Error during continue command: {e}\n")
            self._response(request, False, message=str(e))
            return

    def next(self, request):
        # Source-level step
        try:
            if self.debugger:
                self.debugger.do_next("")
                if self.debugger.current_step >= len(self.debugger.current_trace.steps):
                    self._response(request, True, {})
                    self._event("exited", {"exitCode": 0})
                    return
                new_step = self.debugger.current_trace.steps[self.debugger.current_step]
                # If we stepped into a CALL/DELEGATECALL/STATICCALL, step over it
                if new_step.op in ['CALL', 'DELEGATECALL', 'STATICCALL']:
                    self.debugger.do_next("")
                
            self._response(request, True, {})
            self._event("stopped", {"reason": "step", "threadId": self.thread_id})
        except Exception as e:
            self._response(request, False, message=str(e))

    def stepIn(self, request):
        # Step into function calls
        try:
            if self.debugger:
                while self.debugger.current_step < len(self.debugger.current_trace.steps) - 1:
                    self.debugger.current_step += 1
                    current_op = self.debugger.current_trace.steps[self.debugger.current_step].op
                    # Step in until we hit a CALL/DELEGATECALL/STATICCALL
                    if current_op in ["CALL", "DELEGATECALL", "STATICCALL"]:
                        break
                
                self.debugger.do_step("")
                
            self._response(request, True, {})
            self._event("stopped", {"reason": "step", "threadId": self.thread_id})
        except Exception as e:
            self._response(request, False, message=str(e))

    def stepOut(self, request):
        """Step out of current function - continue until we return to calling code"""
        try:
            if not self.debugger or not self.debugger.current_trace:
                self._response(request, False, message="No debugger or trace available")
                return

            old_step = self.debugger.current_step
            current_depth = None

            # Get current call depth
            if old_step < len(self.debugger.current_trace.steps):
                current_depth = self.debugger.current_trace.steps[old_step].depth

            if current_depth is None:
                return self.next(request)

            # Step until return
            while (self.debugger.current_step < len(self.debugger.current_trace.steps) - 1):

                self.debugger.current_step += 1
                step = self.debugger.current_trace.steps[self.debugger.current_step]

                # Check if we've returned to a higher level
                if step.depth < current_depth:
                    break

                if step.op == "RETURN":
                    # Call the method
                    self.debugger._handle_return_opcode(step)
                    # Check if we've returned to the target depth after handling
                    if self.debugger.current_step < len(self.debugger.current_trace.steps):
                        new_step = self.debugger.current_trace.steps[self.debugger.current_step]
                        if new_step.depth < current_depth:
                            break

                # Handle other exit opcodes
                if step.op in ["REVERT", "STOP"]:
                    if self.debugger.current_step < len(self.debugger.current_trace.steps) - 1:
                        self.debugger.current_step += 1
                        next_step = self.debugger.current_trace.steps[self.debugger.current_step]
                        if next_step.depth < current_depth:
                            break

            # Update current function
            if hasattr(self.debugger, '_update_current_function'):
                self.debugger._update_current_function()

            self._response(request, True, {})
            self._event("stopped", {"reason": "step", "threadId": self.thread_id})

        except Exception as e:
            self._send_output(f"Error in stepOut: {e}")
            self._response(request, False, message=str(e))

    def stackTrace(self, request):
        try:
            if not self.debugger or not self.debugger.current_trace:
                return self._response(request, True, {"stackFrames": []})

            stack_frames = []
            frame_id = 1
            
            # Build stack frames from function trace 
            current_frame = self._create_stack_frame(
                frame_id, 
                self.debugger.current_step, 
                self.debugger.contract_address,
                is_current=True
            )
            if current_frame:
                stack_frames.append(current_frame)
            
            self._response(request, True, {
                "stackFrames": stack_frames,
                "totalFrames": len(stack_frames)
            })
            
        except Exception as e:
            self._send_output(f"Error in stackTrace: {e}")
            # Return empty stack on error to avoid crashing
            self._response(request, True, {"stackFrames": []})

    def _create_stack_frame(self, frame_id, step_num, contract_address, is_current=False, call_type=None):
        """Create a stack frame for the given step and contract."""
        if not self.debugger or not self.debugger.current_trace or not self.debugger.current_trace.steps:
            return None
            
        if step_num >= len(self.debugger.current_trace.steps):
            return None
            
        step = self.debugger.current_trace.steps[step_num]
        pc = step.pc
        
        # Default frame name
        if is_current and hasattr(self.debugger, "current_function") and self.debugger.current_function:
            func_name = getattr(self.debugger.current_function, "name", None)
            name = func_name or f"pc:{pc}"
        else:
            name = f"{call_type or 'CALL'}@pc:{pc}"
        
        source = None
        line = 1
        col = 1
        
        # Try to resolve source location
        contract_info = None
        if (hasattr(self.debugger, 'tracer') and self.debugger.tracer and 
            hasattr(self.debugger.tracer, 'multi_contract_parser') and self.debugger.tracer.multi_contract_parser):
            # Try to find which contract this PC belongs to
            contract_info = self.debugger.tracer.multi_contract_parser.get_contract_at_address(contract_address)
        
        # Use contract-specific parser if found
        if contract_info and hasattr(contract_info, 'ethdebug_info'):
            parser = getattr(contract_info, 'parser', None)
            info_obj = contract_info.ethdebug_info
        else:
            # Fall back to main parser
            parser = None
            info_obj = None
            if hasattr(self.debugger, 'tracer') and self.debugger.tracer:
                parser = getattr(self.debugger.tracer, "ethdebug_parser", None)
                info_obj = getattr(self.debugger.tracer, "ethdebug_info", None)
        
        if info_obj and parser:
            si = info_obj.get_source_info(pc)
            if si:
                source_path, offset, _ = si
                l, c = parser.offset_to_line_col(source_path, offset)
                
                # Normalize source_path - remove 'out/' prefix if present
                normalized_source_path = source_path
                if normalized_source_path.startswith('out/'):
                    normalized_source_path = normalized_source_path[4:]  # Remove 'out/' prefix
                elif normalized_source_path.startswith('./out/'):
                    normalized_source_path = normalized_source_path[6:]  # Remove './out/' prefix
                
                # Resolve absolute path using workspace_root
                workspace_root = getattr(self, '_workspace_root', None) or getattr(self, 'workspace_root', None)
                if not workspace_root and hasattr(self, '_out_dir') and self._out_dir:
                    workspace_root = os.path.dirname(self._out_dir)
                
                if os.path.isabs(normalized_source_path):
                    abs_source_path = normalized_source_path
                elif workspace_root:
                    # Use workspace root to resolve path
                    abs_source_path = os.path.normpath(os.path.join(workspace_root, normalized_source_path))
                    # If file doesn't exist, try with original source_path
                    if not os.path.exists(abs_source_path):
                        abs_source_path = os.path.normpath(os.path.join(workspace_root, source_path))
                else:
                    # Fallback to contract's debug directory or source_file
                    if contract_info and hasattr(contract_info, 'debug_dir'):
                        base_dir = os.path.dirname(str(contract_info.debug_dir))
                        abs_source_path = os.path.normpath(os.path.join(base_dir, normalized_source_path))
                    elif hasattr(self, 'source_file') and self.source_file:
                        base_dir = os.path.dirname(self.source_file)
                        abs_source_path = os.path.normpath(os.path.join(base_dir, normalized_source_path))
                    else:
                        abs_source_path = os.path.abspath(normalized_source_path)
                
                # Check if file exists and try alternatives
                if not os.path.exists(abs_source_path):
                    alternatives = []
                    if workspace_root:
                        alternatives.extend([
                            os.path.join(workspace_root, normalized_source_path),
                            os.path.join(workspace_root, source_path)  # Try original path too
                        ])
                    if hasattr(self, 'source_file') and self.source_file:
                        alternatives.extend([
                            os.path.join(os.path.dirname(self.source_file), normalized_source_path),
                            os.path.join(os.path.dirname(self.source_file), os.path.basename(normalized_source_path))
                        ])
                    for alt in alternatives:
                        if os.path.exists(alt):
                            abs_source_path = alt
                            break
                source = {
                    "name": os.path.basename(abs_source_path),
                    "path": abs_source_path,
                    "sourceReference": 0
                }
                line, col = l, c
        
        # Fallback to main source file if no specific source found
        if not source and hasattr(self, 'source_file') and self.source_file:
            source = {
                "name": os.path.basename(self.source_file),
                "path": self.source_file,
                "sourceReference": 0
            }
        
        return {
            "id": frame_id,
            "name": name,
            "line": line,
            "column": col,
            "source": source or {},
        }



    def scopes(self, request):
        scopes = [
            {
                "name": "Parameters",
                "variablesReference": 1000,
                "expensive": False,
                "presentationHint": "Function Parameters",
                "expanded": True
            },
            {
                "name": "Stack",
                "variablesReference": 1001,
                "expensive": False
            },
            {
                "name": "Gas",
                "variablesReference": 1002,
                "expensive": False
            },
        ]
        self._response(request, True, {"scopes": scopes})

    def variables(self, request):
        ref = request.get("arguments", {}).get("variablesReference")
        vars_list: List[Dict[str, Any]] = []
        if not self.debugger or not self.debugger.current_trace:
            return self._response(request, True, {"variables": vars_list})

        if self.debugger.current_step >= len(self.debugger.current_trace.steps):
            return self._response(request, True, {"variables": vars_list})
        
        step = self.debugger.current_trace.steps[self.debugger.current_step]
                    
        if ref == 1001:
            # Stack
            for i, v in enumerate(step.stack):
                vars_list.append({"name": f"stack[{i}]", "value": hex(v) if isinstance(v, int) else str(v), "variablesReference": 0})

        elif ref == 1000:
            # Parameters
            if (self.debugger.current_function and self.debugger.current_function.args and
                (self.debugger.tracer.ethdebug_info or self.debugger.tracer.multi_contract_parser)):

                for param_name, param_value in self.debugger.current_function.args:
                    vars_list.append({"name": f"{param_name}", "value": str(param_value), "variablesReference": 0})
        elif ref == 1002:
            # Current step info
            vars_list.append({"name": "gas", "value": str(step.gas), "variablesReference": 0})
            vars_list.append({"name": "gasCost", "value": str(step.gas_cost), "variablesReference": 0})
        self._response(request, True, {"variables": vars_list})

    def evaluate(self, request):
        expr = request.get("arguments", {}).get("expression", "")
        result = "n/a"
        try:
            if expr.startswith("stack[") and expr.endswith("]") and self.debugger and self.debugger.current_trace:
                idx = int(expr[6:-1])
                if self.debugger.current_step >= len(self.debugger.current_trace.steps):
                    raise IndexError("Current step out of range")
                val = self.debugger.current_trace.steps[self.debugger.current_step].stack[idx]
                result = hex(val) if isinstance(val, int) else str(val)
            self._response(request, True, {"result": result, "variablesReference": 0})
        except Exception as e:
            self._response(request, False, message=str(e))

    def source(self, request):
        """Handle DAP 'source' request to load source file content"""
        try:
            args = request.get("arguments", {})
            source_ref = args.get("source", {})
            path = source_ref.get("path", "") if isinstance(source_ref, dict) else source_ref
            # Use the source file path from launch if available, otherwise use the requested path
            if hasattr(self, 'source_file') and self.source_file:
                source_path = self.source_file
            elif path:
                
                # Try to read the source file from the requested path
                if os.path.isabs(path):
                    # Absolute path
                    source_path = path
                else:
                    # Relative path - try to resolve from current working directory or debug info
                    if self.debugger and hasattr(self.debugger, 'tracer'):
                        # Try to get base path from debug info
                        if hasattr(self.debugger.tracer, 'ethdebug_parser') and self.debugger.tracer.ethdebug_parser:
                            base_dir = getattr(self.debugger.tracer.ethdebug_parser, 'debug_dir', os.getcwd())
                            if base_dir:
                                source_path = os.path.join(os.path.dirname(base_dir), path)
                            else:
                                source_path = os.path.join(os.getcwd(), path)
                        else:
                            source_path = os.path.join(os.getcwd(), path)
                    else:
                        source_path = os.path.join(os.getcwd(), path)
            else:
                self._response(request, False, message="No source path available")
                return
            
            # Read the file content
            if os.path.exists(source_path):
                with open(source_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self._response(request, True, {"content": content})
            else:
                self._response(request, False, message=f"Source file not found: {source_path}")
                
        except Exception as e:
            self._response(request, False, message=f"Error loading source: {str(e)}")

    def getMonitoredTransactions(self, request):
        """Get list of all monitored transactions."""
        try:
            transactions = []
            for tx in self._monitored_transactions:
                tx_hash = ensure_0x_prefix(tx.get("tx_hash", ""))
                transactions.append({
                    "txHash": tx_hash,
                    "contractAddress": tx.get("contract_address"),
                    "entrypoint": tx.get("entrypoint"),
                    "blockNumber": tx.get("block_number"),
                    "from": tx.get("from"),
                    "value": tx.get("value"),
                    "status": tx.get("status")
                })
            self._response(request, True, {
                "transactions": transactions,
                "rpcUrl": self._rpc_url or "unknown"
            })
        except Exception as e:
            self._response(request, False, message=str(e))

    def debugTransaction(self, request):
        """Handle 'debugTransaction' custom command - load a transaction for debugging and send event to VS Code."""
        try:
            args = request.get("arguments", {}) or {}
            tx_hash = args.get("txHash")
            if tx_hash:
                tx_hash = ensure_0x_prefix(tx_hash)
            
            # If no tx_hash provided, use the last monitored transaction
            if not tx_hash and self._monitored_transactions:
                tx_info = self._monitored_transactions[-1]
                tx_hash = ensure_0x_prefix(tx_info["tx_hash"])
            elif not tx_hash:
                self._response(request, False, message="No transaction hash provided and no monitored transactions available")
                return
            
            # Find transaction in monitored list
            tx_info = None
            for tx in self._monitored_transactions:
                if tx["tx_hash"] == tx_hash:
                    tx_info = tx
                    break
            
            if not tx_info:
                # Transaction not in monitored list, try to extract info from blockchain
                self._send_output(f"Transaction {tx_hash} not in monitored list, extracting from blockchain...\n")
                if not self._tracer:
                    self._response(request, False, message="Tracer not available")
                    return
                
                w3 = self._tracer.w3
                tx = w3.eth.get_transaction(tx_hash)
                contract_address = tx.to
                if not contract_address:
                    self._response(request, False, message="Transaction has no 'to' address (contract creation?)")
                    return
                
                # Normalize address to checksum format
                if isinstance(contract_address, str):
                    try:
                        contract_address = to_checksum_address(contract_address)
                    except Exception:
                        pass  # Keep original if conversion fails
                
                if tx.input:
                    if isinstance(tx.input, bytes):
                        calldata = "0x" + tx.input.hex()
                    elif hasattr(tx.input, 'hex'):
                        calldata = tx.input.hex()
                    else:
                        calldata = str(tx.input)
                else:
                    calldata = "0x"
                entrypoint = None
                if calldata and len(calldata) >= 10:
                    selector = calldata[:10]
                    if hasattr(self._tracer, 'function_signatures') and selector in self._tracer.function_signatures:
                        entrypoint = self._tracer.function_signatures[selector]['name']
                    else:
                        entrypoint = selector
                
                tx_info = {
                    "tx_hash": tx_hash,
                    "contract_address": contract_address,
                    "calldata": calldata,
                    "entrypoint": entrypoint or "unknown"
                }
            
            # Trace the transaction
            self._send_output(f"Tracing transaction {tx_hash}...\n")
            trace = self._tracer.trace_transaction(tx_hash)
            
            if not trace.debug_trace_available:
                self._response(request, False, message="debug_traceTransaction not available for this transaction")
                return
            
            # Load ethdebug files if not already loaded
            contract_address = tx_info["contract_address"]
            if not hasattr(self._tracer, 'multi_contract_parser') or not self._tracer.multi_contract_parser:
                self._load_ethdebug_for_contract(contract_address)
            
            # Load trace into debugger
            if not self.debugger:
                self._response(request, False, message="Debugger not initialized")
                return
            
            self.debugger.current_trace = trace
            self.debugger.current_step = 0
            
            # Update contract_address from transaction if not set
            if contract_address and (not self.debugger.contract_address or self.debugger.contract_address == "None"):
                self.debugger.contract_address = contract_address
            
            # Reload source_map for the contract after loading trace
            # This is important because source_map might not be loaded yet
            if (hasattr(self.debugger, 'tracer') and self.debugger.tracer and
                hasattr(self.debugger.tracer, 'multi_contract_parser') and self.debugger.tracer.multi_contract_parser):
                contract_info = self.debugger.tracer.multi_contract_parser.get_contract_at_address(contract_address)
                if contract_info and hasattr(contract_info, 'parser') and contract_info.parser:
                    self.debugger.source_map = contract_info.parser.get_source_mapping()
                    self._send_output(f"Loaded source_map with {len(self.debugger.source_map)} entries\n")
                else:
                    self._send_output(f"Warning: Could not load source_map for contract {contract_address}\n")
                    self.debugger.source_map = {}
            else:
                self._send_output(f"Warning: No multi_contract_parser available for source_map loading\n")
                self.debugger.source_map = {}
            
            # Analyze function calls
            self.debugger.function_trace = self._tracer.analyze_function_calls(trace)
            
            # Find entry point (first function call after dispatcher if available)
            entry_step = 0
            entry_function = None
            if len(self.debugger.function_trace) > 1:
                # Skip dispatcher, go to first actual function
                entry_step = self.debugger.function_trace[1].entry_step
                entry_function = self.debugger.function_trace[1]
                self.debugger.current_function = entry_function
            elif len(self.debugger.function_trace) > 0:
                entry_step = self.debugger.function_trace[0].entry_step
                entry_function = self.debugger.function_trace[0]
                self.debugger.current_function = entry_function
            
            # Update entrypoint with actual function name from function_trace if available
            if entry_function and hasattr(entry_function, 'name') and entry_function.name:
                # Extract just the function name (remove contract:: prefix if present)
                function_name = entry_function.name
                if '::' in function_name:
                    # Extract function name after ::
                    function_name = function_name.split('::')[-1]
                # Only update if we have a meaningful function name (not dispatcher)
                if function_name and function_name != "runtime_dispatcher" and function_name != "constructor":
                    tx_info["entrypoint"] = function_name
                    # Also update in monitored_transactions list if this transaction is there
                    for monitored_tx in self._monitored_transactions:
                        if monitored_tx["tx_hash"] == tx_hash:
                            monitored_tx["entrypoint"] = function_name
                            break
            
            # Re-register breakpoints after loading new transaction
            # This is important because source_map might have changed or breakpoints might have been lost
            self._register_existing_breakpoints()
            
            # Check if any breakpoints match steps in the trace
            # Start from entry_step and look for the first matching breakpoint
            breakpoint_step = None
            if self.debugger.breakpoints:
                # Search from entry_step onwards for a matching breakpoint
                for step_idx in range(entry_step, len(trace.steps)):
                    step = trace.steps[step_idx]
                    if step.pc in self.debugger.breakpoints:
                        breakpoint_step = step_idx
                        break
            
            # Set current_step to breakpoint if found, otherwise use entry_step
            if breakpoint_step is not None:
                self.debugger.current_step = breakpoint_step
                # Update current_function to match the breakpoint step
                if hasattr(self.debugger, '_update_current_function'):
                    self.debugger._update_current_function()
                stop_reason = "breakpoint"
                stop_description = f"Transaction {tx_hash} stopped at breakpoint"
            else:
                self.debugger.current_step = entry_step
                stop_reason = "entry"
                stop_description = f"Transaction {tx_hash} ready for debugging"
            
            # Send event to VS Code with transaction details
            self._event("transactionData", {
                "txHash": tx_info["tx_hash"],
                "contractAddress": tx_info["contract_address"],
                "calldata": tx_info["calldata"],
                "entrypoint": tx_info["entrypoint"],
                "blockNumber": tx_info.get("block_number"),
                "from": tx_info.get("from"),
                "value": tx_info.get("value", "0")
            })
            
            # Notify VS Code that we've stopped
            self._event("stopped", {
                "reason": stop_reason,
                "threadId": self.thread_id,
                "description": stop_description
            })
            
            self._response(request, True, {
                "txHash": tx_info["tx_hash"],
                "contractAddress": tx_info["contract_address"],
                "calldata": tx_info["calldata"],
                "entrypoint": tx_info["entrypoint"]
            })
            
        except Exception as e:
            self._send_output(f"Error in debugTransaction: {e}\n")
            self._response(request, False, message=str(e))

    # ---- Server loop ----
    def run(self):
        while True:
            msg = self._read()
            if msg is None:
                break
            if msg.get("type") != "request":
                continue
            cmd = msg.get("command")
            if cmd == "initialize":
                self.initialize(msg)
            elif cmd == "launch":
                self.launch(msg)
            elif cmd == "setBreakpoints":
                self.setBreakpoints(msg)
            elif cmd == "configurationDone":
                # VS Code sends this after all setBreakpoints requests are done
                # Now is the time to register any breakpoints that were set before debugger was ready
                if self.debugger:
                    self._register_existing_breakpoints()
                self._response(msg, True, {})
            elif cmd == "threads":
                self.threads(msg)
            elif cmd == "continue":
                self.continue_(msg)
            elif cmd == "next":
                self.next(msg)
            elif cmd == "stepIn":
                self.stepIn(msg)
            elif cmd == "stepOut":
                self.stepOut(msg)
            elif cmd == "stackTrace":
                self.stackTrace(msg)
            elif cmd == "scopes":
                self.scopes(msg)
            elif cmd == "variables":
                self.variables(msg)
            elif cmd == "evaluate":
                self.evaluate(msg)
            elif cmd == "source":
                self.source(msg)
            elif cmd == "debugTransaction":
                self.debugTransaction(msg)
            elif cmd == "getMonitoredTransactions":
                self.getMonitoredTransactions(msg)
            elif cmd == "disconnect" or cmd == "terminate":
                self._stop_monitoring()
                self._response(msg, True, {})
                break
            else:
                self._response(msg, False, message=f"Unsupported command: {cmd}")

def main():
    server = WalnutDAPServer()
    server.run()

if __name__ == "__main__":
    main()

