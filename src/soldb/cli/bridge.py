"""
Bridge command implementation.

This module handles running the SolDB cross-environment bridge server,
which coordinates tracing between EVM and non-EVM environments like Stylus.
"""

from soldb.cross_env.bridge_server import run_bridge_server
from soldb.utils.colors import info

def bridge_command(args) -> int:
    """
    Execute the bridge command.
    
    Args:
        args: Parsed command arguments
        
    Returns:
        Exit code (0 for success, non-zero for error)
    """
    host = getattr(args, 'host', '127.0.0.1')
    port = getattr(args, 'port', 8765)
    config_file = getattr(args, 'config_file', None)
    verbose = not getattr(args, 'quiet', False)
    json_mode = getattr(args, 'json', False)
    
    if not json_mode:
        print(info(f"Starting SolDB Cross-Environment Bridge on {host}:{port}..."))
    
    try:
        run_bridge_server(
            host=host,
            port=port,
            verbose=verbose,
            config_file=config_file
        )
        return 0
    except KeyboardInterrupt:
        if not json_mode:
            print("\nBridge server stopped.")
        return 0
    except Exception as e:
        print(f"Error starting bridge server: {e}")
        return 1
