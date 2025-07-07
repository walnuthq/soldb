#!/usr/bin/env python3
"""
Setup script for soldb that can be called as soldb-setup
"""

import subprocess
import sys
import os
from pathlib import Path


def main():
    """Run the setup script from the package."""
    # Find the setup script in the package
    package_dir = Path(__file__).parent.parent.parent
    setup_script = package_dir / "setup-soldb.sh"
    
    if not setup_script.exists():
        # Try to find it in the installed package data
        import pkg_resources
        try:
            setup_script = pkg_resources.resource_filename('soldb', '../../setup-soldb.sh')
        except:
            print("Error: Could not find setup-soldb.sh")
            print("Please run from the source directory or reinstall the package")
            return 1
    
    # Run the setup script
    try:
        subprocess.run(["/bin/bash", str(setup_script)], check=True)
        return 0
    except subprocess.CalledProcessError as e:
        print(f"Setup failed with error: {e}")
        return 1
    except FileNotFoundError:
        print("Error: bash not found. Please ensure bash is installed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
