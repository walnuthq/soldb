# -*- Python -*-

import os
import platform
import subprocess
import sys

import lit.formats

# Configuration file for the 'lit' test runner.

# name: The name of this test suite.
config.name = 'soldb'

# testFormat: The test format to use to interpret tests.
config.test_format = lit.formats.ShTest(True)

# suffixes: A list of file extensions to treat as test files.
config.suffixes = ['.test']

# test_source_root: The root path where tests are located.
config.test_source_root = os.path.dirname(__file__)

# test_exec_root: The root path where tests should be run.
config.test_exec_root = os.path.join(config.test_source_root, 'Output')

# Substitutions
import shutil

# Find soldb
if hasattr(config, 'soldb') and config.soldb:
    soldb_path = config.soldb
else:
    soldb_path = shutil.which('soldb')
    if not soldb_path and hasattr(config, 'soldb_dir'):
        # Try to find it in the virtual environment
        venv_path = os.path.join(config.soldb_dir, 'MyEnv', 'bin', 'soldb')
        if os.path.exists(venv_path):
            soldb_path = venv_path

if soldb_path:
    config.substitutions.append(('%soldb', soldb_path))
else:
    config.substitutions.append(('%soldb', 'soldb'))

# RPC and chain configuration
config.substitutions.append(('%{rpc_url}', getattr(config, 'rpc_url', 'http://localhost:8547')))
config.substitutions.append(('%{sepolia_rpc_url}', getattr(config, 'sepolia_rpc_url', '')))
config.substitutions.append(('%{chain_id}', getattr(config, 'chain_id', '412346')))
config.substitutions.append(('%{private_key}', getattr(config, 'private_key', '')))

# Contract addresses and transaction hashes
if hasattr(config, 'test_contracts'):
    for key, value in config.test_contracts.items():
        config.substitutions.append(('%{' + key + '}', value))

# Solc path
if hasattr(config, 'solc_path'):
    config.substitutions.append(('%{solc_path}', config.solc_path))
else:
    config.substitutions.append(('%{solc_path}', 'solc'))

# Test directories
config.substitutions.append(('%S', config.test_source_root))
config.substitutions.append(('%p', config.test_source_root))
config.substitutions.append(('%{inputs}', os.path.join(config.test_source_root, 'Inputs')))

# Project root directory (parent of test directory)
project_root = os.path.dirname(config.test_source_root)
config.substitutions.append(('%{project_root}', project_root))

# Platform-specific features
if platform.system() == 'Darwin':
    config.available_features.add('darwin')
elif platform.system() == 'Linux':
    config.available_features.add('linux')

# Check if soldb is available
def check_soldb():
    try:
        if soldb_path:
            subprocess.run([soldb_path, '--help'], check=True, capture_output=True)
            return True
    except:
        pass
    return False

if check_soldb():
    config.available_features.add('soldb')

# Check if Sepolia RPC is configured
if hasattr(config, 'sepolia_rpc_url') and config.sepolia_rpc_url:
    config.available_features.add('sepolia-rpc')

# Check if Stylus bridge is configured and available
if hasattr(config, 'stylus_config') and config.stylus_config:
    stylus_cfg = config.stylus_config
    # Add Stylus-related substitutions
    config.substitutions.append(('%{stylus_rpc_url}', stylus_cfg.get('rpc_url', 'http://localhost:8547')))
    config.substitutions.append(('%{stylus_bridge_url}', stylus_cfg.get('bridge_url', 'http://127.0.0.1:8765')))
    config.substitutions.append(('%{stylus_test_tx}', stylus_cfg.get('test_tx', '')))
    config.substitutions.append(('%{stylus_caller_address}', stylus_cfg.get('caller_address', '')))
    config.substitutions.append(('%{stylus_counter_address}', stylus_cfg.get('counter_address', '')))
    config.substitutions.append(('%{stylus_debug_dir}', stylus_cfg.get('debug_dir', '')))
    config.substitutions.append(('%{stylus_contracts_json}', stylus_cfg.get('contracts_json', '')))

    # Check if bridge is actually running
    def check_stylus_bridge():
        try:
            import urllib.request
            bridge_url = stylus_cfg.get('bridge_url', 'http://127.0.0.1:8765')
            urllib.request.urlopen(bridge_url, timeout=2)
            return True
        except Exception as e:
            return False

    if check_stylus_bridge():
        config.available_features.add('stylus-bridge')

# Add 'not' command
not_path = shutil.which('not')
if not not_path:
    # Try common locations
    for path in ['/usr/local/opt/llvm/bin', '/opt/homebrew/opt/llvm/bin', '/usr/bin']:
        candidate = os.path.join(path, 'not')
        if os.path.exists(candidate):
            not_path = candidate
            break
if not_path:
    config.substitutions.append(('not', not_path))

# Find and add FileCheck
filecheck_path = None
for path in ['/usr/local/opt/llvm/bin', '/opt/homebrew/opt/llvm/bin', '/usr/bin']:
    candidate = os.path.join(path, 'FileCheck')
    if os.path.exists(candidate):
        filecheck_path = candidate
        break

if filecheck_path:
    config.substitutions.append(('FileCheck', filecheck_path))
else:
    # Try to find FileCheck in PATH
    filecheck_path = shutil.which('FileCheck')
    if filecheck_path:
        config.substitutions.append(('FileCheck', filecheck_path))
    else:
        # If FileCheck is not found, tests will fail but we'll let lit report it
        config.substitutions.append(('FileCheck', 'FileCheck'))

# Environment variables
if not hasattr(config, 'soldb') or not config.soldb:
    config.environment['PYTHONPATH'] = os.pathsep.join(sys.path)
elif 'venv' in config.soldb or 'MyEnv' in config.soldb:
    # Using venv - don't set PYTHONPATH, let venv handle it
    pass
else:
    config.environment['PYTHONPATH'] = os.pathsep.join(sys.path)