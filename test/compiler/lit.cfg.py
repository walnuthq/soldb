"""Shared compiler-backed tests using the ordinary node-free lit shell format."""

import os
import shlex
import shutil
from pathlib import Path

import lit.formats

config.name = "soldb-compiler"
config.test_format = lit.formats.ShTest(execute_external=False)
config.suffixes = [".test"]
config.test_source_root = str(Path(__file__).resolve().parent)
config.excludes = ["__pycache__"]
root = Path(config.test_source_root).parents[1]
optimization = lit_config.params.get("optimization", "gas")
if optimization not in ("none", "gas", "size"):
    lit_config.fatal("optimization must be none, gas, or size")
compiler = lit_config.params.get("compiler", "both")
if compiler not in ("solc", "solar", "both"):
    lit_config.fatal("compiler must be solc, solar, or both")
config.test_exec_root = str(
    Path(lit_config.params.get("output", root / "target/compiler-lit")).resolve()
    / compiler / optimization
)
config.environment["NO_COLOR"] = "1"


def require_tool(name, value):
    path = shutil.which(str(value))
    if path is None:
        lit_config.fatal(f"{name} is required; could not find {value}")
    return shlex.quote(path)


# Unlike the live-node suite, missing prerequisites must fail configuration.
soldb = require_tool("soldb", os.environ.get("SOLDB_BIN", root / "target/debug/soldb"))
filecheck = require_tool("FileCheck", os.environ.get("FILECHECK", "FileCheck"))
require_tool("jq", "jq")
solc_optimization = {
    "none": "",
    "gas": "--optimize --optimize-runs 200",
    "size": "--optimize --optimize-runs 1",
}[optimization]
config.substitutions = [("%soldb", soldb), ("FileCheck", filecheck)]
if compiler in ("solar", "both"):
    solar = require_tool("Solar (set SOLAR)", os.environ.get("SOLAR", "solar"))
    config.substitutions.append(("%solar", f"{solar} --evm-version=cancun -O{optimization}"))
    config.available_features.add("compiler-solar")
if compiler in ("solc", "both"):
    solc = require_tool("solc (set SOLC_PATH)", os.environ.get("SOLC_PATH", "solc"))
    config.substitutions.append(("%solc", f"{solc} --evm-version=cancun {solc_optimization}"))
    config.available_features.add("compiler-solc")
if compiler == "both":
    config.available_features.add("compiler-diff")
config.available_features.add("soldb")
config.available_features.add(f"optimization-{optimization}")
