"""
JSON Serialization for SolDB trace output

Provides serialization of trace data into TypeScript-compatible JSON format
for web app consumption.
"""
import os
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import asdict
from eth_hash.auto import keccak
from web3 import Web3
from hexbytes import HexBytes
from .transaction_tracer import TransactionTrace, FunctionCall, TraceStep
from .ethdebug_parser import ETHDebugInfo, ETHDebugParser
from .multi_contract_ethdebug_parser import MultiContractETHDebugParser
from eth_utils import to_checksum_address


class TraceSerializer:
    """Serializes trace data to JSON format compatible with web app."""
    
    def __init__(self):
        self.logs = []  # Collect logs during trace processing
        self.log_position = 0
    
    def _convert_to_serializable(self, obj: Any) -> Any:
        """Convert non-serializable objects to JSON-serializable format."""
        if isinstance(obj, HexBytes):
            return obj.hex()
        elif isinstance(obj, bytes):
            return '0x' + obj.hex()
        elif isinstance(obj, dict):
            return {k: self._convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_to_serializable(item) for item in obj]
        elif isinstance(obj, tuple):
            return [self._convert_to_serializable(item) for item in obj]
        elif hasattr(obj, '__dict__'):
            # Handle custom objects by converting to dict
            return self._convert_to_serializable(obj.__dict__)
        else:
            return obj
    
    def extract_logs_from_trace(self, trace: TransactionTrace) -> List[Tuple[int, Dict[str, Any]]]:
        """Extract LOG events from the trace steps with their step indices."""
        logs = []
        log_position = 0
        
        for i, step in enumerate(trace.steps):
            if step.op in ['LOG0', 'LOG1', 'LOG2', 'LOG3', 'LOG4']:
                # LOG0, LOG1, LOG2, LOG3, LOG4
                num_topics = int(step.op[-1])
                
                # Get the data and topics from stack
                # Stack layout for LOGn: [offset, size, topic1, topic2, ..., topicN]
                # Note: Stack items are in reverse order (top of stack is index 0)
                if len(step.stack) >= 2 + num_topics:
                    # Memory offset and size are first two stack items
                    try:
                        offset = int(step.stack[0], 16) if isinstance(step.stack[0], str) else int(step.stack[0])
                        size = int(step.stack[1], 16) if isinstance(step.stack[1], str) else int(step.stack[1])
                        
                        # Validate and sanitize values
                        if offset < 0:
                            offset = 0
                        if size < 0:
                            size = 0
                        # Limit offset to prevent integer overflow
                        max_offset = 1024 * 1024 * 1024  # 1GB limit
                        if offset > max_offset:
                            offset = max_offset
                    except (ValueError, TypeError, OverflowError):
                        offset = 0
                        size = 0
                    
                    # Extract data from memory
                    data = "0x"
                    if size > 0:
                        # Limit size to prevent memory overflow (max 1MB)
                        max_size = 1024 * 1024  # 1MB limit
                        safe_size = min(size, max_size)
                        
                        if step.memory:
                            try:
                                # Memory is stored as hex string
                                # Check for integer overflow in calculations
                                if offset > (2**63 - 1) // 2:  # Prevent overflow in offset * 2
                                    offset = (2**63 - 1) // 2
                                start = offset * 2  # Each byte is 2 hex chars
                                end = start + (safe_size * 2)
                                # Ensure we don't go out of bounds
                                if end <= len(step.memory):
                                    memory_data = step.memory[start:end]
                                    # Ensure we only take the exact size requested
                                    if len(memory_data) > safe_size * 2:
                                        memory_data = memory_data[:safe_size * 2]
                                    data = "0x" + memory_data
                                else:
                                    # Use whatever memory is available up to size
                                    available_size = min(safe_size, (len(step.memory) - start) // 2)
                                    if available_size > 0:
                                        memory_data = step.memory[start:start + (available_size * 2)]
                                        data = "0x" + memory_data
                                    else:
                                        # No memory available, use zeros
                                        data = "0x" + "00" * safe_size
                            except:
                                # If memory extraction fails, use zeros
                                data = "0x" + "00" * safe_size
                        else:
                            # No memory available, use zeros
                            data = "0x" + "00" * safe_size
                    
                    # Extract topics from stack
                    # Stack layout for LOGn: [offset, size, topic1, topic2, ..., topicN]
                    topics = []
                    for j in range(num_topics):
                        if len(step.stack) > 2 + j:
                            topic = step.stack[2 + j]
                            # Convert to proper hex format
                            if isinstance(topic, int):
                                # Convert integer to 32-byte hex
                                try:
                                    # Limit extremely large integers to prevent overflow
                                    max_int = 2**256 - 1  # Max uint256
                                    safe_topic = min(topic, max_int)
                                    if safe_topic < 0:
                                        safe_topic = 0
                                    topic = '0x' + hex(safe_topic)[2:].zfill(64)
                                except (OverflowError, ValueError):
                                    # Fallback to zero if conversion fails
                                    topic = '0x' + '0' * 64
                            elif isinstance(topic, str):
                                # Remove 0x prefix if present
                                topic = topic[2:] if topic.startswith('0x') else topic
                                # Pad to 32 bytes (64 hex chars)
                                topic = '0x' + topic.zfill(64)
                            topics.append(topic)
                    
                    # Determine the contract address for this log
                    # This is the current contract being executed
                    contract_address = trace.to_addr
                    
                    # Only add valid logs (skip if topics look invalid)
                    # A valid event signature should be 32 bytes and look like a hash
                    is_valid_log = True
                    if num_topics > 0 and topics and len(topics) > 0:
                        # For LOG1+, check if first topic looks like an event signature
                        first_topic = topics[0]
                        # Skip if it's all zeros or a very small number
                        if (first_topic.startswith('0x00000000000000000000000000000000000000000000000000000000') or
                            first_topic == '0x' + '0' * 64):
                            # This looks like a small number padded to 32 bytes, not an event signature
                            is_valid_log = False
                    
                    if is_valid_log:
                        log = {
                            "address": contract_address,
                            "topics": topics,
                            "data": data,
                            "position": log_position
                        }
                        logs.append((i, log))  # Store with step index
                        log_position += 1
        
        return logs
    
    def encode_function_input(self, call: FunctionCall, trace: TransactionTrace) -> str:
        """Encode function input data from selector and arguments."""
        if call.depth == 1 and trace.input_data:
            # For the root call, use the transaction input data
            input_data = trace.input_data
            if isinstance(input_data, bytes):
                return '0x' + input_data.hex()
            elif isinstance(input_data, HexBytes):
                return input_data.hex()
            else:
                return str(input_data)
        
        if not call.selector:
            return "0x"
        
        # For internal calls, we need to build the encoded input
        # Start with the selector
        input_data = call.selector
        
        # Check if this is an internal call with unknown parameters
        if call.call_type == "internal" and call.args:
            has_unknown = any(param_value == '<unknown>' for _, param_value in call.args)
            if has_unknown:
                # For internal calls with unknown parameters, return only the selector
                return input_data if input_data.startswith('0x') else '0x' + input_data
        
        # Encode arguments if available
        if call.args:
            # Simple encoding - in reality, we'd use proper ABI encoding
            # For now, assume uint256 parameters (32 bytes each)
            for param_name, param_value in call.args:
                if isinstance(param_value, int):
                    # Encode as 32-byte hex value
                    try:
                        # Limit extremely large integers to prevent overflow
                        max_int = 2**256 - 1  # Max uint256
                        safe_value = min(param_value, max_int)
                        if safe_value < 0:
                            safe_value = 0
                        hex_value = hex(safe_value)[2:].zfill(64)
                        input_data += hex_value
                    except (OverflowError, ValueError):
                        # Fallback to zero if conversion fails
                        input_data += "0" * 64
                elif isinstance(param_value, str) and param_value.startswith('0x'):
                    # Already hex, just append (removing 0x prefix)
                    input_data += param_value[2:].zfill(64)
                else:
                    # Default to zero padding
                    input_data += "0" * 64
        
        return input_data if input_data.startswith('0x') else '0x' + input_data
    
    def get_function_signature_hash(self, function_name: str, param_types: List[str]) -> str:
        """Calculate the 4-byte function signature hash."""
        # Build the function signature
        signature = f"{function_name}({','.join(param_types)})"
        
        # Calculate keccak256 hash and take first 4 bytes
        selector_bytes = keccak(signature.encode())[:4]
        return '0x' + selector_bytes.hex()
    
    def convert_function_call_to_trace_call(
        self, 
        call: FunctionCall, 
        trace: TransactionTrace,
        logs_with_steps: List[Tuple[int, Dict[str, Any]]],
        all_calls: List[FunctionCall],
        multi_parser: Optional[MultiContractETHDebugParser] = None,
        tracer_instance = None,
        processed_ids: Optional[set] = None
    ) -> Dict[str, Any]:
        """Convert a FunctionCall to TraceCall format."""
        # Track processed calls to avoid duplicates
        if processed_ids is None:
            processed_ids = set()
        
        # Mark this call as processed
        processed_ids.add(call.call_id)
        
        trace_type = call.call_type.upper() if call.call_type else "INTERNALCALL"
        # Determine call type
        if trace_type == "EXTERNAL":
            trace_type = "CALL"
        elif trace_type == "INTERNAL":
            trace_type = "INTERNALCALL"
        elif trace_type == "STATICCALL":
            trace_type = "STATICCALL"  # Keep STATICCALL information
        elif trace_type == "DELEGATECALL":
            trace_type = "DELEGATECALL"  # Keep DELEGATECALL information
        elif trace_type in ["CREATE", "CREATE2"]:
            # Keep CREATE/CREATE2 as is
            pass
        elif trace_type == "ENTRY" and trace.contract_address:
            # For entry points that are contract creation, mark as CREATE
            trace_type = "CREATE"

         # Build input data with proper encoding
        input_data = self.encode_function_input(call, trace)
        
        # For internal functions without selectors, generate them
        if trace_type == "INTERNALCALL" and not call.selector:
            # Extract parameter types from args (simplified)
            param_types = ["uint256"] * len(call.args) if call.args else []
            call.selector = self.get_function_signature_hash(call.name, param_types)
            input_data = self.encode_function_input(call, trace)
        
        # For CREATE operations at the entry point, use transaction input data
        if trace_type in ["CREATE", "CREATE2"] and call.depth == 0:
            input_data = trace.input_data if trace.input_data else "0x"
        
        # Extract gas information
        # For the root call, get gas from first step
        if call.depth == 0 and trace.steps:
            gas = trace.steps[0].gas
        else:
            # For internal calls, try to get gas from the step where the call starts
            if call.entry_step is not None and call.entry_step < len(trace.steps):
                gas = trace.steps[call.entry_step].gas
            else:
                gas = None
        
        gas_used = call.gas_used if call.gas_used else None
        trace_call = {
            "type": trace_type,
            "input": input_data,
            "callId": call.call_id,
            "parentCallId": call.parent_call_id,
            "contractCallId": call.contract_call_id,
            "childrenCallIds": call.children_call_ids[:],
        }
        
        # Add decoded function information
        trace_call["functionName"] = call.name
        
        # Extract and format input parameters
        if call.args:
            argument_types = []
            argument_names = []
            argument_values = []
            
            # Try to get ABI information for proper types
            abi_item = None
            if tracer_instance and hasattr(tracer_instance, 'function_abis') and call.selector:
                abi_item = tracer_instance.function_abis.get(call.selector)
            
            for i, (param_name, param_value) in enumerate(call.args):
                # Get type from ABI if available
                if abi_item and 'inputs' in abi_item and i < len(abi_item['inputs']):
                    param_info = abi_item['inputs'][i]
                    param_type = param_info.get('type', 'uint256')
                    
                    # If it's a tuple (struct), expand the type to show components
                    if param_type == 'tuple' and 'components' in param_info:
                        # Build a detailed type string showing struct fields
                        field_types = []
                        for comp in param_info['components']:
                            field_name = comp.get('name', 'field')
                            field_type = comp.get('type', 'unknown')
                            field_types.append(f"{field_name}:{field_type}")
                        param_type = f"tuple({', '.join(field_types)})"
                else:
                    # Infer type from value
                    if isinstance(param_value, str) and param_value.startswith('0x') and len(param_value) == 42:
                        param_type = "address"
                    elif isinstance(param_value, str) and param_value not in ['<unknown>', 'None']:
                        param_type = "string"
                    else:
                        param_type = "uint256"
                
                argument_types.append(param_type)
                argument_names.append(param_name)
                argument_values.append(param_value)
            
            trace_call["inputs"] = {
                "argumentsType": argument_types,
                "argumentsName": argument_names,
                "argumentsDecodedValue": argument_values
            }
        else:
            # No arguments
            trace_call["inputs"] = {
                "argumentsType": [],
                "argumentsName": [],
                "argumentsDecodedValue": []
            }
        
        # TODO: Add outputs data when available
        trace_call["outputs"] = {
            "argumentsType": [],
            "argumentsName": [],
            "argumentsDecodedValue": []
        }
        if trace_type in ["CALL", "DELEGATECALL", "STATICCALL"]:
            if call.args:
                for k, v in call.args:
                    if k == "to":
                        trace_call["to"] = v
                        break
            if "to" not in trace_call and hasattr(call, 'contract_address'):
                trace_call["to"] = call.contract_address
            trace_call["from"] = trace.from_addr if call.depth == 0 else (
                call.contract_address if hasattr(call, 'contract_address') else None
            )
        elif trace_type == "INTERNALCALL":
            if hasattr(call, 'contract_address'):
                trace_call["contractAddress"] = call.contract_address
                # For internal calls, set 'to' to the contract address
                trace_call["to"] = call.contract_address
                # For internal calls, set 'from' to the contract address (same contract)
                trace_call["from"] = call.contract_address
        elif trace_type in ["CREATE", "CREATE2"]:
            # For CREATE/CREATE2, include the deployed contract address
            if hasattr(call, 'contract_address') and call.contract_address:
                trace_call["deployedContractAddress"] = call.contract_address
            # Set from address
            trace_call["from"] = trace.from_addr if call.depth == 0 else call.contract_address
        # Gas and gasUsed logic
        if call.entry_step is not None and call.entry_step < len(trace.steps):
            trace_call["gas"] = hex(trace.steps[call.entry_step].gas)
        if call.gas_used is not None:
            trace_call["gasUsed"] = hex(call.gas_used)
        
        call_logs = []
        for step_index, log in logs_with_steps:
            # Check if this log belongs to this function call
            if (call.entry_step is not None and step_index >= call.entry_step and
                (call.exit_step is None or step_index <= call.exit_step)):
                is_child_log = False
                for child_id in call.children_call_ids:
                    child = next((c for c in all_calls if c.call_id == child_id), None)
                    if child and child.entry_step is not None and child.entry_step <= step_index <= (child.exit_step or step_index):
                        is_child_log = True
                        break
                if not is_child_log:
                    call_logs.append(log)
        if call_logs:
            trace_call["logs"] = call_logs
        # Recursively add children by call_id
        child_calls = []
        for child_id in call.children_call_ids:
            child = next((c for c in all_calls if c.call_id == child_id), None)
            if child and child.call_id not in processed_ids:
                child_calls.append(self.convert_function_call_to_trace_call(
                    child, trace, logs_with_steps, all_calls, multi_parser, tracer_instance, processed_ids
                ))
        
        if child_calls:
            trace_call["calls"] = child_calls
        for field in ["to", "from", "contractAddress", "input", "output"]:
            if field in trace_call and isinstance(trace_call[field], str):
                if not trace_call[field].startswith("0x"):
                    trace_call[field] = "0x" + trace_call[field]
                trace_call[field] = trace_call[field].lower()
        
        # Ensure 'to' and 'from' are always present in trace_call
        if "to" not in trace_call or not trace_call["to"]:
            if hasattr(call, 'contract_address') and call.contract_address:
                trace_call["to"] = call.contract_address
            else:
                trace_call["to"] = trace.to_addr
        if "from" not in trace_call or not trace_call["from"]:
            if call.depth == 0:
                trace_call["from"] = trace.from_addr
            elif hasattr(call, 'contract_address') and call.contract_address:
                trace_call["from"] = call.contract_address
            else:
                trace_call["from"] = trace.to_addr

        # Normalize addresses to checksum format for 'to', 'from', 'contractAddress'
        for addr_field in ["to", "from", "contractAddress"]:
            if addr_field in trace_call and trace_call[addr_field]:
                try:
                    # Only normalize if it looks like an address
                    val = trace_call[addr_field]
                    if isinstance(val, str) and val.startswith("0x") and len(val) == 42:
                        trace_call[addr_field] = to_checksum_address(val)
                except Exception:
                    pass
        # Add function name
        trace_call["function_name"] = call.name
        
        # Add isRevertedFrame if this frame caused the revert
        if hasattr(call, 'caused_revert') and call.caused_revert:
            trace_call["isRevertedFrame"] = True
        
        # Add isVerified field for all call types
        # For entry points, check if debug info is available
        if call.call_type == "entry":
            # Entry point is verified if we have debug info for the contract
            has_debug_info = False
            if multi_parser and call.contract_address:
                target_contract = multi_parser.get_contract_at_address(call.contract_address)
                has_debug_info = target_contract is not None and target_contract.ethdebug_info is not None
            elif tracer_instance and hasattr(tracer_instance, 'ethdebug_info'):
                has_debug_info = tracer_instance.ethdebug_info is not None
            trace_call["isVerified"] = has_debug_info
        elif multi_parser and call.contract_address:
            target_contract = multi_parser.get_contract_at_address(call.contract_address)
            trace_call["isVerified"] = target_contract is not None
        else:
            trace_call["isVerified"] = False

        return trace_call
    
    def extract_internal_function_abi(
        self, 
        function_calls: List[FunctionCall],
        tracer_instance = None
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Extract internal function signatures and create ABI entries for each contract."""
        abis_by_contract = {}
        internal_functions_by_contract = {}
        
        # First, get the existing ABIs from the tracer if available
        if tracer_instance and hasattr(tracer_instance, 'function_abis'):
            # Get existing external function ABIs
            for selector, abi_item in tracer_instance.function_abis.items():
                # This is an external function from the loaded ABI
                contract_addr = tracer_instance.to_addr if hasattr(tracer_instance, 'to_addr') else None
                if contract_addr:
                    checksum_addr = to_checksum_address(contract_addr)
                    if checksum_addr not in abis_by_contract:
                        abis_by_contract[checksum_addr] = []
                    abis_by_contract[checksum_addr].append(abi_item)
        
        # Extract internal functions from the function calls
        for call in function_calls:
            if call.call_type == "internal" and call.name not in ["runtime_dispatcher", "constructor"]:
                # Determine which contract this internal function belongs to
                # For now, assume it belongs to the main contract
                contract_addr = tracer_instance.to_addr if tracer_instance and hasattr(tracer_instance, 'to_addr') else "0x0"
                checksum_addr = to_checksum_address(contract_addr)
                
                if checksum_addr not in internal_functions_by_contract:
                    internal_functions_by_contract[checksum_addr] = {}
                
                # Skip if we already have this function
                if call.name in internal_functions_by_contract[checksum_addr]:
                    continue
                
                # Build ABI entry for internal function
                inputs = []
                if call.args:
                    for param_name, param_value in call.args:
                        # Infer type from value (simplified)
                        param_type = "uint256"  # Default to uint256
                        if isinstance(param_value, str) and param_value.startswith('0x') and len(param_value) == 42:
                            param_type = "address"
                        
                        inputs.append({
                            "internalType": param_type,
                            "name": param_name,
                            "type": param_type
                        })
                
                internal_abi = {
                    "inputs": inputs,
                    "name": call.name,
                    "outputs": [],  # We don't have return type info yet
                    "stateMutability": "nonpayable",  # Default assumption
                    "type": "function"
                }
                
                internal_functions_by_contract[checksum_addr][call.name] = internal_abi
        
        # Merge internal functions into the contract ABIs
        for checksum_addr, internal_funcs in internal_functions_by_contract.items():
            if checksum_addr not in abis_by_contract:
                abis_by_contract[checksum_addr] = []
            # Check for duplicates before adding
            existing_names = {func.get('name') for func in abis_by_contract[checksum_addr]}
            for func_name, func_abi in internal_funcs.items():
                if func_name not in existing_names:
                    abis_by_contract[checksum_addr].append(func_abi)
        
        return abis_by_contract
    
    def build_steps_array(
        self, 
        trace: TransactionTrace, 
        function_calls: List[FunctionCall],
        multi_parser: Optional[MultiContractETHDebugParser] = None,
        ethdebug_info: Optional[ETHDebugInfo] = None
    ) -> List[Dict[str, Any]]:
        """Build the steps array mapping PC to trace call index."""
        steps = []
        
        # Build mapping from call object to its callId
        # traceCallIndex should directly correspond to callId
        call_id_map = {}
        for call in function_calls:
            call_id_map[id(call)] = call.call_id
        
        # Map each step to its corresponding call ID
        for i, step in enumerate(trace.steps):
            # Find the deepest call that contains this step
            containing_call = None
            deepest_depth = -1
            
            for call in function_calls:
                if (call.entry_step is not None and call.entry_step <= i and 
                    (call.exit_step is None or i <= call.exit_step) and
                    call.depth > deepest_depth):
                    containing_call = call
                    deepest_depth = call.depth
            
            # Get the callId for this call, default to 0 (root call)
            call_id = call_id_map.get(id(containing_call), 0) if containing_call else 0
            
            # Detect unverified contract calls
            if step.op in ["CALL", "DELEGATECALL", "STATICCALL"]:
                # Extract target contract address from stack
                target_contract = None
                if len(step.stack) >= 2:
                    # For CALL: stack[-2] is the target address
                    # For DELEGATECALL/STATICCALL: stack[-2] is also the target address
                    raw_address = step.stack[-2]
                    if raw_address.startswith('0x'):
                        raw_address = raw_address[2:]
                    target_contract = "0x" + raw_address.zfill(40)
                
                # Find the callId for the target contract in the trace
                target_call_id = None
                has_debug_info = False
                if target_contract:
                    # Check if we have debug info for this target contract
                    if multi_parser:
                        target_contract_obj = multi_parser.get_contract_at_address(target_contract)
                        has_debug_info = target_contract_obj is not None and target_contract_obj.ethdebug_info is not None
                    elif ethdebug_info:
                        # For single contract mode, check if this is the main contract
                        has_debug_info = True  
                    else:
                        has_debug_info = False
                
                # Mark as unverified contract call only if we don't have debug info
                step_info = {
                    "pc": step.pc,
                    "traceCallIndex": call_id, 
                    "stepIndex": i,
                    "targetContract": target_contract
                }
                
                # Only add debug_info: False if we don't have debug info
                if not has_debug_info:
                    step_info["debugInfo"] = False
            else:
                # For regular steps, check if we have debug info for the target contract
                step_info = {
                    "pc": step.pc,
                    "traceCallIndex": call_id,
                    "stepIndex": i  
                }
            
            steps.append(step_info)
        
        # Sort steps by the entry_step of their containing call
        # This ensures steps are ordered by execution sequence
        steps.sort(key=lambda step: function_calls[step["traceCallIndex"]].entry_step 
                  if step["traceCallIndex"] < len(function_calls) and 
                     function_calls[step["traceCallIndex"]].entry_step is not None 
                  else float('inf'))
        
        # Remove the temporary stepIndex field
        for step in steps:
            step.pop("stepIndex", None)
        
        return steps

    def build_contracts_mapping(
        self,
        trace: TransactionTrace,
        ethdebug_info: Optional[ETHDebugInfo],
        multi_parser: Optional[MultiContractETHDebugParser],
        abis: Dict[str, List[Dict[str, Any]]],
        tracer_instance = None
    ) -> Dict[str, Dict[str, Any]]:
        """Build the contracts mapping with PC to source mappings and sources."""
        contracts = {}
        
        if multi_parser:
            # Multi-contract mode
            for address, contract_info in multi_parser.contracts.items():
                abi = []
                abi_path = contract_info.debug_dir / f"{contract_info.name}.abi"
                if os.path.exists(abi_path):
                    with open(abi_path) as f:
                        try:
                            abi = json.load(f)
                        except Exception:
                            abi = []
                checksum_addr = to_checksum_address(address)
                contract_data = self._build_single_contract_data(
                    address,
                    contract_info.parser,
                    contract_info.ethdebug_info,
                    abi
                )
                if contract_data:
                    contracts[address] = contract_data
        elif ethdebug_info and tracer_instance:
            # Single contract mode
            address = trace.to_addr
            if address:
                checksum_addr = to_checksum_address(address)
                contract_data = self._build_single_contract_data(
                    address,
                    tracer_instance.ethdebug_parser,
                    ethdebug_info,
                    abis.get(checksum_addr, [])
                )
                if contract_data:
                    contracts[address] = contract_data
        
        return contracts
    
    def _build_single_contract_data(
        self,
        address: str,
        parser: ETHDebugParser,
        ethdebug_info: ETHDebugInfo,
        abi: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Build debug data for a single contract."""
        if not ethdebug_info:
            return None
        
        # Build PC to source mappings in 's:l:f' format
        pc_to_source_mappings = {}
        for instruction in ethdebug_info.instructions:
            if instruction.source_location:
                loc = instruction.source_location
                # Format: 'start:length:fileId'
                mapping = f"{loc.offset}:{loc.length}:{loc.source_id}"
                pc_to_source_mappings[instruction.offset] = mapping
        
        # Collect source files
        sources = {}
        for source_id, source_path in ethdebug_info.sources.items():
            # Load the actual source content
            source_lines = parser.load_source_file(source_path)
            if source_lines:
                sources[source_id] = "".join(source_lines)
            else:
                sources[source_id] = f"// Source file not found: {source_path}"
        
        return {
            "pcToSourceMappings": pc_to_source_mappings,
            "sources": sources,
            "abi": abi
        }
    
    def serialize_trace(
        self,
        trace: TransactionTrace,
        function_calls: List[FunctionCall],
        ethdebug_info: Optional[ETHDebugInfo] = None,
        multi_parser: Optional[MultiContractETHDebugParser] = None,
        tracer_instance = None
    ) -> Dict[str, Any]:
        """Serialize trace data to JSON format for web app."""
        # Extract logs from trace with their step indices
        logs_with_steps = self.extract_logs_from_trace(trace)

        # Always use the dispatcher (depth 0, call_type 'entry') as the root call
        root_calls = [call for call in function_calls if call.depth == 0 and call.call_type == "entry"]
        if not root_calls:
            # Fallback: if no dispatcher, use the first call
            root_calls = function_calls[:1]

        # Track which calls have been processed
        processed_ids = set()
        
        # Convert the root call and build the call tree recursively
        root_trace_call = self.convert_function_call_to_trace_call(
            root_calls[0], trace, logs_with_steps, function_calls, multi_parser, tracer_instance, processed_ids
        )
        
        # Check for any remaining unprocessed calls
        # This should not happen if parent-child relationships are correct
        unprocessed_calls = []
        for call in function_calls:
            if call.call_id not in processed_ids:
                # Skip these - they should have been processed as children
                # This indicates a bug in parent-child relationship tracking
                pass
        # Ensure root call has proper from/to addresses and gas info
        root_trace_call["from"] = trace.from_addr
        root_trace_call["to"] = trace.to_addr
        root_trace_call["gas"] = trace.steps[0].gas if trace.steps else 0
        root_trace_call["gasUsed"] = trace.gas_used
        # Handle input data - for root call, always use the full transaction input data
        if isinstance(trace.input_data, bytes):
            root_trace_call["input"] = '0x' + trace.input_data.hex()
        elif hasattr(trace.input_data, 'hex'):
            root_trace_call["input"] = trace.input_data.hex()
        else:
            root_trace_call["input"] = trace.input_data
        # Handle output
        if isinstance(trace.output, bytes):
            root_trace_call["output"] = '0x' + trace.output.hex()
        elif hasattr(trace.output, 'hex'):
            root_trace_call["output"] = trace.output.hex()
        else:
            root_trace_call["output"] = trace.output or "0x"

        # Build ABIs mapping
        abis = self.extract_internal_function_abi(function_calls, tracer_instance)

        # Build the response - always build steps if we have trace steps
        if trace.steps:
            # Build step-by-step response (with or without debug info)
            steps = self.build_steps_array(trace, function_calls, multi_parser, ethdebug_info)
            
            if ethdebug_info or multi_parser:
                # Full debugging response with contracts mapping
                contracts = self.build_contracts_mapping(
                    trace, ethdebug_info, multi_parser, abis, tracer_instance
                )
                response = {
                    "status": "success" if trace.success else "reverted",
                    "traceCall": root_trace_call,
                    "steps": steps,
                    "contracts": contracts
                }
            else:
                # Basic response with steps but no contracts mapping
                response = {
                    "status": "success" if trace.success else "reverted",
                    "traceCall": root_trace_call,
                    "steps": steps,
                    "abis": abis
                }
        else:
            # Basic response without steps
            response = {
                "status": "success" if trace.success else "reverted",
                "traceCall": root_trace_call,
                "abis": abis
            }
        
        # Add contract deployment info if this is a creation transaction
        if trace.contract_address:
            response["isContractCreation"] = True
            response["deployedContractAddress"] = trace.contract_address
        
        # Add error message if transaction reverted
        if not trace.success and trace.error:
            response["error"] = trace.error
        
        # Convert any non-serializable objects
        return self._convert_to_serializable(response)