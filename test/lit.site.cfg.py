import sys
import os
import shutil

# Get the test directory and project directory dynamically
script_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(script_dir)

config.soldb_dir = project_dir

# Find soldb dynamically
if shutil.which('soldb'):
    config.soldb = shutil.which('soldb')
elif os.path.exists(os.path.join(project_dir, 'MyEnv', 'bin', 'soldb')):
    config.soldb = os.path.join(project_dir, 'MyEnv', 'bin', 'soldb')
else:
    config.soldb = "soldb"
config.rpc_url = "http://localhost:8545"
config.chain_id = "1"
config.private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
config.test_contracts = {
    "contract_address": "0x0dcd1bf9a1b36ce34237eeafef220932846bcd82",
    "deploy_tx": "0xc4111cd3dd62e1a55587054da11649cc2a838a01e153feb73085991a4130ee1c",
    "test_tx": "0x37946602f5b59ebb3d970d6efd7cc22b1dc2d1ad9e742604e5abe6d6a1f4f2e6",
    "ethdebug_dir": os.path.join(project_dir, "examples", "out")
}
# Determine solc path dynamically
solc_path = os.environ.get('SOLC_PATH')
if not solc_path:
    # Try to find solc in PATH
    solc_path = shutil.which('solc')
if not solc_path:
    # Fallback to a default
    solc_path = 'solc'
config.solc_path = solc_path

# Load the main config
lit_config.load_config(config, os.path.join(script_dir, "lit.cfg.py"))
