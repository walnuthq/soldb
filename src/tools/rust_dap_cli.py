"""
Python console-script shim for the Rust soldb-dap-server binary.

The Python package only keeps the installed debug-adapter entrypoint; all DAP
behavior lives in the Rust binary.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    """Run the Rust DAP server with the original command-line arguments."""
    binary = _find_rust_dap_server()
    if binary is None:
        sys.stderr.write(
            "Rust soldb-dap-server binary not found. Build it with "
            "`cargo build --bin soldb-dap-server`, or set SOLDB_DAP_RUST_BIN.\n"
        )
        return 127

    completed = subprocess.run([str(binary), *sys.argv[1:]], check=False)
    return completed.returncode


def _find_rust_dap_server() -> Path | None:
    override = os.environ.get("SOLDB_DAP_RUST_BIN")
    if override:
        path = Path(override)
        if path.exists() and os.access(path, os.X_OK):
            return path

    repo_root = _repo_root()
    candidates = [
        repo_root / "target" / "debug" / "soldb-dap-server",
        repo_root / "target" / "release" / "soldb-dap-server",
    ]
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate

    return None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


if __name__ == "__main__":
    raise SystemExit(main())
