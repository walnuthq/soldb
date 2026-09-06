"""Node-free Solar compatibility tests using the ordinary lit shell format."""

import os
import shlex
import shutil
import sys
from pathlib import Path

import lit.formats

config.name = "soldb-solar"
config.test_format = lit.formats.ShTest(execute_external=False)
config.suffixes = [".test"]
config.test_source_root = str(Path(__file__).resolve().parent)
config.excludes = ["__pycache__"]
root = Path(config.test_source_root).parents[1]
optimization = lit_config.params.get("optimization", "gas")
if optimization not in ("none", "gas", "size"):
    lit_config.fatal("optimization must be none, gas, or size")
config.test_exec_root = str(
    Path(lit_config.params.get("output", root / "target/solar-lit")).resolve() / optimization
)
config.environment["NO_COLOR"] = "1"


def require_tool(name, value):
    path = shutil.which(str(value))
    if path is None:
        lit_config.fatal(f"{name} is required; could not find {value}")
    return shlex.quote(path)


# Unlike the live-node suite, missing prerequisites must fail configuration.
solar = require_tool("Solar (set SOLAR)", os.environ.get("SOLAR", "solar"))
solc = require_tool("solc (set SOLC_PATH)", os.environ.get("SOLC_PATH", "solc"))
soldb = require_tool("soldb", os.environ.get("SOLDB_BIN", root / "target/debug/soldb"))
filecheck = require_tool("FileCheck", os.environ.get("FILECHECK", "FileCheck"))
require_tool("jq", "jq")
prepare = shlex.join([sys.executable, str(Path(config.test_source_root) / "prepare.py")])
config.substitutions = [
    ("%prepare", f"{prepare} --solar {solar} --solc {solc}"),
    ("%optimization", optimization),
    ("%soldb", soldb),
    ("FileCheck", filecheck),
]
config.available_features.add("soldb")
