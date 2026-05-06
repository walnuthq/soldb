"""
Python console-script shim for the Rust soldb binary.

The Python package still exposes importable compatibility modules while the
user-facing CLI migrates to Rust. This module keeps `pip install -e .`
workflows usable by dispatching `soldb` to the Rust binary.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    """Run the Rust soldb binary with the original command-line arguments."""
    binary = _find_rust_soldb()
    if binary is None:
        sys.stderr.write(
            "Rust soldb binary not found. Build it with `cargo build --bin soldb`, "
            "or set SOLDB_RUST_BIN.\n"
        )
        return 127

    completed = subprocess.run([str(binary), *sys.argv[1:]], check=False)
    return completed.returncode


def _find_rust_soldb() -> Path | None:
    override = os.environ.get("SOLDB_RUST_BIN")
    if override:
        path = Path(override)
        if path.exists() and os.access(path, os.X_OK):
            return path

    repo_root = _repo_root()
    candidates = [
        repo_root / "target" / "debug" / "soldb",
        repo_root / "target" / "release" / "soldb",
    ]
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate

    return None


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


if __name__ == "__main__":
    raise SystemExit(main())
