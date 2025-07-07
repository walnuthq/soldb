"""
ABI/type parsing and matching utilities for SolDB.
"""
import re
import ast
from typing import Any, List, Tuple, Dict

def match_abi_types(parsed_types: List[str], abi_types: List[str]) -> bool:
    """Recursively match parsed signature types with ABI types."""
    if len(parsed_types) != len(abi_types):
        return False
    for parsed_type, abi_type in zip(parsed_types, abi_types):
        if not match_single_type(parsed_type, abi_type):
            return False
    return True

def match_single_type(parsed_type: str, abi_type: str) -> bool:
    """Match a single parsed type with ABI type."""
    # Handle basic types
    if parsed_type == abi_type:
        return True
    # Handle tuple types
    if parsed_type.startswith('(') and parsed_type.endswith(')') and abi_type == 'tuple':
        return True
    # Handle array types
    if parsed_type.endswith('[]') and abi_type.endswith('[]'):
        # Remove array brackets and compare base types
        parsed_base = parsed_type[:-2]
        abi_base = abi_type[:-2]
        return match_single_type(parsed_base, abi_base)
    # Handle nested tuples - basic matching
    if '(' in parsed_type and abi_type == 'tuple':
        return True
    return False

def parse_signature(signature: str) -> Tuple[str, List[str]]:
    """Parse a function signature like 'foo(uint256,(string,uint256))' into name and argument types."""
    match = re.match(r'(\w+)\((.*)\)', signature)
    if not match:
        return "", []
    name = match.group(1)
    args = match.group(2)
    def split_args(s):
        args, depth, current = [], 0, ''
        for c in s:
            if c == ',' and depth == 0:
                args.append(current)
                current = ''
            else:
                if c == '(': depth += 1
                elif c == ')': depth -= 1
                current += c
        if current:
            args.append(current)
        return [a.strip() for a in args if a.strip()]
    arg_types = split_args(args)
    return name, arg_types

def parse_tuple_arg(val: Any, abi_input: Dict) -> Tuple:
    """Recursively parse a tuple argument according to ABI input definition."""
    if not isinstance(val, (list, tuple)):
        raise ValueError("Tuple argument must be a tuple or list")
    result = []
    for i, component in enumerate(abi_input['components']):
        comp_type = component['type']
        comp_val = val[i]
        if comp_type == 'tuple':
            result.append(parse_tuple_arg(comp_val, component))
        elif comp_type.endswith('[]') and comp_type.startswith('tuple'):
            # Array of tuples/structs
            result.append([parse_tuple_arg(x, component) for x in comp_val])
        else:
            result.append(comp_val)
    return tuple(result)
