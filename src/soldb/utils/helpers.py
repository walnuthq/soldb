"""
Miscellaneous helper functions for soldb.
"""

from typing import Dict, Any, List
from eth_abi.abi import decode
import requests

from .colors import (
    info, warning, error, success, dim, cyan, yellow, 
    bold, address, gas_value, function_name
)


def format_error_json(message: str, error_type: str, **extra_fields) -> dict:
    """
    Format a uniform error JSON structure for all soldb errors.
    
    Args:
        message: The main error message
        error_type: Type of error (e.g., "InsufficientFunds", "ConnectionError")
        **extra_fields: Additional fields to include in the error object
    
    Returns:
        dict: Uniform error JSON structure with soldbFailed and error fields
    """
    error_obj = {
        "message": message,
        "type": error_type
    }
    error_obj.update(extra_fields)
    
    return {
        "soldbFailed": message,
        "error": error_obj
    }


def print_contracts_in_transaction(tracer, trace):
    """Prints the contracts involved in a transaction trace."""
    print(f"Looking for contracts in transaction: {info(trace.tx_hash)} on {info(tracer.rpc_url)}..")
    print(f"\n{bold('Contracts detected in transaction:')}")
    print(dim("-" * 80))

    call_count = 0
    for i, step in enumerate(trace.steps):
        if step.op in ["CALL", "DELEGATECALL", "STATICCALL"]:
            call_count += 1
            
            if len(step.stack) >= 6:
                required_stack_size = 7 if step.op == "CALL" else 6
                if len(step.stack) >= required_stack_size:
                    to_addr = tracer.extract_address_from_stack(step.stack[-2])
                    calldata = tracer.extract_calldata_from_step(step)

                    target_name = "Unknown"
                    if tracer.multi_contract_parser:
                        target_contract = tracer.multi_contract_parser.get_contract_at_address(to_addr)
                        if target_contract:
                            target_name = target_contract.name
                    
                    func_name = "Unknown"
                    if calldata and len(calldata) >= 10:
                        selector = calldata[:10]
                        if hasattr(tracer, 'function_signatures'):
                            func_info = tracer.function_signatures.get(selector)
                            if func_info:
                                func_name = func_info['name']

                    print(f"Contract Address: {address(to_addr)}", end="")
                    if target_name != "Unknown":
                        print(f" ({info(target_name)})")
                    if func_name != "Unknown":
                        print(f"Entry Function: {info(func_name)}")
                        print(f"Gas: {gas_value(step.gas)}", end="")

                    print(f"\n{dim('-' * 80)}")

    if call_count == 0:
        print(f"{warning('No contract calls detected in this transaction.')}")
        print(f"Please verify:")
        print(f"  {dim('-')} {'The transaction hash is correct'}")
        print(f"  {dim('-')} {'The RPC URL is correct'}")


def decode_event_log(tracer, log_entry: Dict[str, Any]) -> Dict[str, Any]:
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
    
    first_topic = topics[0]
    if isinstance(first_topic, bytes):
        event_hash = '0x' + first_topic.hex()
    elif isinstance(first_topic, str):
        event_hash = first_topic
        if not event_hash.startswith('0x'):
            event_hash = '0x' + event_hash
    else:
        event_hash = str(first_topic)
        if not event_hash.startswith('0x'):
            event_hash = '0x' + event_hash
    
    if event_hash in tracer.event_abis:
        try:
            event_abi = tracer.event_abis[event_hash]
            event_signature = tracer.event_signatures[event_hash]
            
            indexed_inputs = [inp for inp in event_abi['inputs'] if inp.get('indexed', False)]
            non_indexed_inputs = [inp for inp in event_abi['inputs'] if not inp.get('indexed', False)]
            
            decoded_values = {}
            
            indexed_topics = topics[1:]
            for i, (topic, inp) in enumerate(zip(indexed_topics, indexed_inputs)):
                if i < len(indexed_topics):
                    param_name = inp['name']
                    param_type = inp['type']
                    
                    if isinstance(topic, bytes):
                        topic_bytes = topic
                    elif isinstance(topic, str):
                        topic_bytes = bytes.fromhex(topic[2:] if topic.startswith('0x') else topic)
                    else:
                        topic_bytes = bytes(topic)
                    
                    if param_type in ['address']:
                        decoded_value = '0x' + topic_bytes[-20:].hex()
                    elif param_type.startswith('uint') or param_type.startswith('int'):
                        decoded_value = int.from_bytes(topic_bytes, 'big')
                    elif param_type == 'bool':
                        decoded_value = topic_bytes[-1] != 0
                    else:
                        decoded_value = topic
                    
                    decoded_values[param_name] = {
                        'type': param_type,
                        'value': decoded_value
                    }
            
            if non_indexed_inputs and log_entry.get('data', '0x') != '0x':
                data_hex = log_entry['data']
                
                if isinstance(data_hex, bytes):
                    data_hex = data_hex.hex()
                elif isinstance(data_hex, str):
                    if data_hex.startswith('0x'):
                        data_hex = data_hex[2:]
                else:
                    data_hex = bytes(data_hex).hex()
                
                if data_hex:
                    data_bytes = bytes.fromhex(data_hex)
                    param_types = [inp['type'] for inp in non_indexed_inputs]
                    
                    try:
                        decoded_data = decode(param_types, data_bytes)
                        for inp, value in zip(non_indexed_inputs, decoded_data):
                            decoded_values[inp['name']] = {
                                'type': inp['type'],
                                'value': value
                            }
                    except Exception as e:
                        for inp in non_indexed_inputs:
                            decoded_values[inp['name']] = {
                                'type': inp['type'],
                                'value': f"decode_error: {str(e)}"
                            }
            
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
        try:
            data_hex = log_entry["data"][2:].hex() if log_entry["data"].hex().startswith("0x") else log_entry["data"].hex()

            if data_hex and len(data_hex) >= 64:
                data_bytes = bytes.fromhex(data_hex)
                data_length = len(data_bytes)

                text_signature = None
                event_name = "Unknown"
                try:
                    r = requests.get(f"https://www.4byte.directory/api/v1/event-signatures/?hex_signature={event_hash}")
                    response_data = r.json()
                    
                    if 'results' in response_data and response_data['results']:
                        text_signature = response_data['results'][0].get('text_signature', 'Unknown')
                    elif 'text_signature' in response_data:
                        text_signature = response_data['text_signature']
                        if isinstance(text_signature, list) and text_signature:
                            text_signature = text_signature[0]
                except:
                    pass
                
                if data_length % 32 == 0:
                    param_count = data_length // 32
                    if text_signature is not None:
                        event_name = text_signature.split('(')[0]
                        text_signature = text_signature.split('(')[1].replace(')','')
                        text_signature = list(text_signature.split(','))
                        params = text_signature
                    else:
                        params = ["uint256"] * param_count
                    
                    hex_params = []
                    for i in range(0, len(data_bytes), 32):
                        chunk = data_bytes[i:i+32]
                        hex_value = chunk.hex().lstrip('0')
                        if not hex_value:
                            hex_value = '0'
                        hex_params.append(f"0x{hex_value}")
                    
                    if len(hex_params) == 1:
                        display_data = hex_params[0]
                    else:
                        display_data = hex_params
                    
                    decoded_log['decoded'] = {
                        'event': 'Unknown',
                        'signature': event_hash,
                        'raw_topics': topics[0].hex(),
                        'param_count': param_count,
                        'data': display_data,
                        'event_name': event_name
                    }
                else:
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


def print_contracts_events(tracer, receipt, json_output=False):
    """Print or return events from a transaction receipt."""
    if json_output:
        return serialize_events_to_json(tracer, receipt)
    
    print("")
    print(f"Events emitted in Transaction:")
    print(dim("-" * 80))
    
    receipt_logs = receipt['logs'] if receipt and 'logs' in receipt else []
    decoded_logs = []

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
                    contract_name = ""
                    if tracer.multi_contract_parser:
                        contract_info = tracer.multi_contract_parser.get_contract_at_address(log['address'])
                        if contract_info:
                            contract_name = contract_info.name
                    
                    print(f"{warning(f'Event #{i+1}:')} Contract Address: {(log['address'])}")
                    if contract_name:
                        print(f"    Contract: {info(contract_name)}")
                    if log['decoded']['event_name'] != "Unknown":
                        print(f"    topic: {address(log['decoded']['event_name'])}")
                    else:
                        print(f"    topic: {log['decoded']['signature']}")
                    print(f"    data: {cyan(log['decoded']['data'])}")
                else:
                    print(f"{success(f'Event #{i+1}: ')}", end="")
                    contract_name = ""
                    if tracer.multi_contract_parser:
                        contract_info = tracer.multi_contract_parser.get_contract_at_address(log['address'])
                        if contract_info:
                            contract_name = contract_info.name
                            print(f"{info(contract_name)}::", end="")
                    print(f"{function_name(log['decoded']['signature'])}")
                    for arg_name, arg_info in log['decoded']['args'].items():
                        if isinstance(arg_info, dict) and 'type' in arg_info and 'value' in arg_info:
                            arg_type = arg_info['type']
                            arg_value = arg_info['value']
                        
                        value_str = yellow(str(arg_value))
                        type_str = dim(f"({arg_type})")
                        print(f"    {arg_name}: {value_str} {type_str}")
            else:
                print("  No decoded information available")
            print(dim("-" * 80))


def _convert_hexbytes_to_string(obj):
    """Convert HexBytes and other non-serializable objects to strings."""
    if isinstance(obj, str):
        return obj  
    
    if hasattr(obj, 'hex'):
        hex_str = obj.hex()
        return hex_str if hex_str.startswith('0x') else '0x' + hex_str
    elif isinstance(obj, bytes):
        return '0x' + obj.hex()
    
    if isinstance(obj, list):
        return [_convert_hexbytes_to_string(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: _convert_hexbytes_to_string(value) for key, value in obj.items()}
    elif isinstance(obj, tuple):
        return tuple(_convert_hexbytes_to_string(item) for item in obj)
    
    if hasattr(obj, '__dict__'):
        return _convert_hexbytes_to_string(obj.__dict__)
    elif hasattr(obj, '_asdict'):
        return _convert_hexbytes_to_string(obj._asdict())
    elif hasattr(obj, '_fields'):
        return {field: _convert_hexbytes_to_string(getattr(obj, field)) 
                for field in obj._fields}
    
    if hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
        try:
            return [_convert_hexbytes_to_string(item) for item in obj]
        except (TypeError, AttributeError):
            pass
    
    return obj


def serialize_events_to_json(tracer, receipt) -> Dict[str, Any]:
    """Serialize events to JSON format."""
    receipt_logs = receipt['logs'] if receipt and 'logs' in receipt else []
    
    events = []
    
    for i, log in enumerate(receipt_logs):
        decoded_log = decode_event_log(tracer, log)
        
        event_data = {
            "index": i,
            "address": decoded_log['address'],
            "topics": decoded_log['topics'],
            "data": decoded_log['data']
        }
        
        if decoded_log['decoded'] and 'args' in decoded_log['decoded']:
            event_data["datas"] = []
            
            for arg_name, arg_info in decoded_log['decoded']['args'].items():
                if isinstance(arg_info, dict) and 'type' in arg_info and 'value' in arg_info:
                    arg_type = arg_info['type']
                    arg_value = arg_info['value']
                else:
                    arg_type = "unknown"
                    arg_value = arg_info
                
                if isinstance(arg_value, bytes) and arg_type == 'string':
                    value = arg_value.decode('utf-8').rstrip('\x00')
                elif isinstance(arg_value, (str, int, bool)):
                    value = arg_value
                else:
                    value = f"0x{str(arg_value)}"
                
                event_data["datas"].append({
                    "name": arg_name,
                    "type": arg_type,
                    "value": value
                })
        else:
            raw_data = decoded_log['data']
            if isinstance(raw_data, bytes):
                raw_data = raw_data.hex()
            elif isinstance(raw_data, str) and not raw_data.startswith('0x'):
                raw_data = '0x' + raw_data
            
            if raw_data and raw_data != '0x':
                data_hex = raw_data[2:] if raw_data.startswith('0x') else raw_data
                if len(data_hex) >= 64:
                    datas = []
                    for i in range(0, len(data_hex), 64):
                        chunk = data_hex[i:i+64]
                        if len(chunk) == 64:
                            datas.append({
                                "name": None,
                                "type": "hex",
                                "value": f"0x{chunk}"
                            })
                    event_data["datas"] = datas
                else:
                    event_data["datas"] = [{
                        "name": None,
                        "type": "hex", 
                        "value": raw_data
                    }]
            else:
                event_data["datas"] = []
        
        if decoded_log['decoded']:
            if 'error' in decoded_log['decoded']:
                event_data["error"] = decoded_log['decoded']['error']
            elif decoded_log['decoded']['event'] == 'Unknown':
                event_data["event"] = ""
                event_data["signature"] = decoded_log['decoded']['signature']
                if 'event_name' in decoded_log['decoded'] and decoded_log['decoded']['event_name'] != "Unknown":
                    event_data["event_name"] = decoded_log['decoded']['event_name']
                
                if tracer.multi_contract_parser:
                    contract_info = tracer.multi_contract_parser.get_contract_at_address(log['address'])
                    if contract_info:
                        event_data["contract_name"] = contract_info.name
            else:
                event_data["event"] = decoded_log['decoded']['event']
                event_data["signature"] = decoded_log['decoded']['signature']
                if tracer.multi_contract_parser:
                    contract_info = tracer.multi_contract_parser.get_contract_at_address(log['address'])
                    if contract_info:
                        event_data["contract_name"] = contract_info.name
        
        events.append(event_data)
    
    result = {
        "transaction_hash": receipt.get('transactionHash'),
        "events": events,
        "total_events": len(events)
    }
    
    return _convert_hexbytes_to_string(result)


def format_exception_message(e: Exception) -> str:
    """
    Extract a clean, user-friendly error message from any exception.
    """
    if hasattr(e, 'args') and e.args:
        first_arg = e.args[0]
        
        if isinstance(first_arg, dict):
            return first_arg.get('message', str(e))
        elif isinstance(first_arg, str):
            return first_arg
        else:
            return str(first_arg)
    
    return str(e)
