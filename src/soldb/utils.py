    

from .transaction_tracer import TransactionTrace, TransactionTracer
from typing import Dict, Any
from eth_abi.abi import decode
from .colors import *
import requests


def print_contracts_in_transaction(tracer: TransactionTracer,trace: TransactionTrace):
        """Prints the contracts involved in a transaction trace."""
        print(f"Looking for contracts in transaction: {info(trace.tx_hash)} on {info(tracer.rpc_url)}..")
        print(f"\n{bold('Contracts detected in transaction:')}")
        print(dim("-" * 80))

        call_count = 0
        for i, step in enumerate(trace.steps):
            if step.op in ["CALL", "DELEGATECALL", "STATICCALL"]:
                call_count += 1
                
                # Extract call information
                if len(step.stack) >= 6:
                    required_stack_size = 7 if step.op == "CALL" else 6
                    if len(step.stack) >= required_stack_size:
                        to_addr = tracer.extract_address_from_stack(step.stack[-2])
                        calldata = tracer.extract_calldata_from_step(step)

                        # Try to identify target contract
                        target_name = "Unknown"
                        if tracer.multi_contract_parser:
                            target_contract = tracer.multi_contract_parser.get_contract_at_address(to_addr)
                            if target_contract:
                                target_name = target_contract.name
                        
                        # Try to decode function
                        func_name = "Unknown"
                        if calldata and len(calldata) >= 10:
                            selector = calldata[:10]
                            if hasattr(tracer, 'function_signatures'):
                                func_info = tracer.function_signatures.get(selector)
                                if func_info:
                                    func_name = func_info['name']

                        print(f"Contract Address: {address(to_addr)}",end="")
                        if target_name != "Unknown":
                            print(f" ({info(target_name)})")
                        if func_name != "Unknown":
                            print(f"Entry Function: {info(func_name)}")
                            print(f"Gas: {gas_value(step.gas)}",end="")

                        print(f"\n{dim('-' * 80)}")

        if call_count == 0:
            print(f"{warning('No contract calls detected in this transaction.')}")
            print(f"Please verify:")
            print(f"  {dim('-')} {'The transaction hash is correct'}")
            print(f"  {dim('-')} {'The RPC URL is correct'}")

def decode_event_log(tracer,log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Decode an event log using ABI information."""
        decoded_log = {
            'address': log_entry.get('address'),
            'topics': log_entry.get('topics', []),
            'data': log_entry.get('data', '0x'),
            'decoded': None
        }
        
        topics = log_entry.get('topics', [])
        if not topics:
            return decoded_log
        
        # First topic is the event signature hash
        # Handle both bytes and string formats
        first_topic = topics[0]
        if isinstance(first_topic, bytes):
            event_hash = '0x' + first_topic.hex()
        elif isinstance(first_topic, str):
            event_hash = first_topic
            if not event_hash.startswith('0x'):
                event_hash = '0x' + event_hash
        else:
            # Fallback - convert to string
            event_hash = str(first_topic)
            if not event_hash.startswith('0x'):
                event_hash = '0x' + event_hash
        
        # Look up event ABI
        if event_hash in tracer.event_abis:
            try:
                event_abi = tracer.event_abis[event_hash]
                event_signature = tracer.event_signatures[event_hash]
                
                # Separate indexed and non-indexed parameters
                indexed_inputs = [inp for inp in event_abi['inputs'] if inp.get('indexed', False)]
                non_indexed_inputs = [inp for inp in event_abi['inputs'] if not inp.get('indexed', False)]
                
                decoded_values = {}
                
                # Decode indexed parameters from topics (skip first topic which is event signature)
                indexed_topics = topics[1:]
                for i, (topic, inp) in enumerate(zip(indexed_topics, indexed_inputs)):
                    if i < len(indexed_topics):
                        param_name = inp['name']
                        param_type = inp['type']
                        
                        # Convert topic to bytes for decoding
                        if isinstance(topic, bytes):
                            topic_bytes = topic
                        elif isinstance(topic, str):
                            topic_bytes = bytes.fromhex(topic[2:] if topic.startswith('0x') else topic)
                        else:
                            # Handle HexBytes or other types
                            topic_bytes = bytes(topic)
                        
                        # Decode based on type
                        if param_type in ['address']:
                            # Address is in the last 20 bytes
                            decoded_values[param_name] = '0x' + topic_bytes[-20:].hex()
                        elif param_type.startswith('uint') or param_type.startswith('int'):
                            # Integer types
                            decoded_values[param_name] = int.from_bytes(topic_bytes, 'big')
                        elif param_type == 'bool':
                            decoded_values[param_name] = topic_bytes[-1] != 0
                        elif param_type.startswith('bytes'):
                            if param_type == 'bytes':
                                # Dynamic bytes
                                decoded_values[param_name] = topic
                            else:
                                # Fixed bytes
                                decoded_values[param_name] = topic
                        else:
                            # For other types, just show the raw topic
                            decoded_values[param_name] = topic
                
                # Decode non-indexed parameters from data
                if non_indexed_inputs and log_entry.get('data', '0x') != '0x':
                    data_hex = log_entry['data']
                    
                    # Handle different data formats
                    if isinstance(data_hex, bytes):
                        data_hex = data_hex.hex()
                    elif isinstance(data_hex, str):
                        if data_hex.startswith('0x'):
                            data_hex = data_hex[2:]
                    else:
                        # Handle HexBytes or other types
                        data_hex = bytes(data_hex).hex()
                    
                    if data_hex:
                        data_bytes = bytes.fromhex(data_hex)
                        param_types = [inp['type'] for inp in non_indexed_inputs]
                        
                        try:
                            decoded_data = decode(param_types, data_bytes)
                            for inp, value in zip(non_indexed_inputs, decoded_data):
                                decoded_values[inp['name']] = value
                        except Exception as e:
                            # If decoding fails, add raw data
                            for inp in non_indexed_inputs:
                                decoded_values[inp['name']] = f"decode_error: {str(e)}"
                
                decoded_log['decoded'] = {
                    'event': event_abi['name'],
                    'signature': event_signature,
                    'args': decoded_values
                }
                
            except Exception as e:
                decoded_log['decoded'] = {
                    'error': f"Failed to decode event: {str(e)}"
                }
        else:
            # Unknown event - dynamically determine parameter count from data length
            try:
                data_hex = log_entry["data"][2:].hex() if log_entry["data"].hex().startswith("0x") else log_entry["data"].hex()

                if data_hex and len(data_hex) >= 64:  # At least one uint256 (64 hex chars = 32 bytes)
                    data_bytes = bytes.fromhex(data_hex)
                    data_length = len(data_bytes)

                # Try to lookup event signature from 4byte.directory
                    text_signature = None
                    event_name = "Unknown"
                    try:
                        r = requests.get(f"https://www.4byte.directory/api/v1/event-signatures/?hex_signature={event_hash}")
                        response_data = r.json()
                        
                        # Parse text_signature from response
                        if 'results' in response_data and response_data['results']:
                            text_signature = response_data['results'][0].get('text_signature', 'Unknown')
                            
                        elif 'text_signature' in response_data:
                            # Alternative response format
                            text_signature = response_data['text_signature']
                            if isinstance(text_signature, list) and text_signature:
                                text_signature = text_signature[0]
                    except:
                        # If 4byte lookup fails, keep as Unknown
                        pass
                    
                    # Calculate number of uint256 parameters (each is 32 bytes)
                    if data_length % 32 == 0:
                        param_count = data_length // 32
                        if text_signature is not None:
                            event_name = text_signature.split('(')[0]
                            text_signature = text_signature.split('(')[1].replace(')','')
                            text_signature = list(text_signature.split(','))
                            params = text_signature
                        else:
                            params = ["uint256"] * param_count
                        # Instead of decoding, just split into 32-byte hex chunks and strip leading zeros
                        hex_params = []
                        for i in range(0, len(data_bytes), 32):
                            chunk = data_bytes[i:i+32]
                            # Convert to hex and strip leading zeros
                            hex_value = chunk.hex().lstrip('0')
                            # If all zeros, keep one zero
                            if not hex_value:
                                hex_value = '0'
                            hex_params.append(f"0x{hex_value}")
                        
                        # Use hex values as display data
                        if len(hex_params) == 1:
                            display_data = hex_params[0]  # Single hex value
                        else:
                            display_data = hex_params  # List of hex values
                        
                        decoded_log['decoded'] = {
                            'event': 'Unknown',
                            'signature': event_hash,
                            'raw_topics': topics[0].hex(),
                            'param_count': param_count,
                            'data': display_data,
                            'event_name': event_name
                        }
                        
                    else:
                        # Data length not divisible by 32, might be mixed types or strings
                        decoded_log['decoded'] = {
                            'event': 'Unknown',
                            'signature': event_hash,
                            'raw_topics': topics[0].hex(),
                            'data': log_entry["data"].hex(),
                        }
                else:
                    decoded_log['decoded'] = {
                        'event': 'Unknown',
                        'signature': event_hash,
                        'raw_topics': topics[0].hex(),
                        'data': log_entry["data"].hex()
                    }
            except Exception:
                decoded_log['decoded'] = {
                    'event': 'Unknown',
                    'signature': event_hash,
                    'raw_topics': topics[0].hex(),
                    'data': log_entry["data"].hex()
                }
        
        return decoded_log

def print_contracts_events(tracer, receipt):
    print("")
    print(f"Events emitted in Transaction:")
    print(dim("-" * 80))
    
    # Get logs from transaction receipt
    receipt_logs = receipt['logs'] if receipt and 'logs' in receipt else []
    
    decoded_logs = []

    # Process all receipt logs
    for i, log in enumerate(receipt_logs):
        decoded_log = decode_event_log(tracer, log)
        decoded_logs.append(decoded_log)

    if not decoded_logs:
        print(dim("No events emitted"))
    else:
        for i, log in enumerate(decoded_logs):
            if log['decoded']:
                
                if 'error' in log['decoded']:
                    print(f"  {error(log['decoded']['error'])}")
                elif log['decoded']['event'] == 'Unknown':
                    print(f"{warning(f'Event #{i+1}:')} Contract Address: {(log['address'])}")
                    if log['decoded']['event_name'] != "Unknown":
                        print(f"    topic: {f'{address(log['decoded']['event_name'])}'}")
                    else:
                        print(f"    topic: {f'{log['decoded']['signature']}'}")
                    print(f"    data: {cyan(log['decoded']['data'])}")
                else:
                    print(f"{success(f'Event #{i+1}: ')}", end="")
                    if tracer.multi_contract_parser:
                        contract_name = tracer.multi_contract_parser.get_contract_at_address(log['address']).name
                        print(f"{info(contract_name)}::", end="")
                    print(f"{function_name(log['decoded']['signature'])}")
                    for arg_name, arg_value in log['decoded']['args'].items():    
                        value_str = yellow(str(arg_value))
                        print(f"    {arg_name}: {value_str}")
            else:
                print("  No decoded information available")
            print(dim("-" * 80))