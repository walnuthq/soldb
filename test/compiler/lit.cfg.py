"""Shared compiler-backed tests using the ordinary node-free lit shell format."""

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
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

# Tests that need a compiler release gate on it with `REQUIRES: solc-at-least-<version>`;
# every version listed here becomes such a feature when the selected solc is at least
# that new. A development build such as `0.8.38-develop.2026.9.17` counts as its
# leading `major.minor.patch`.
SOLC_VERSION_GATES = ("0.8.38",)


def require_tool(name, value):
    path = shutil.which(str(value))
    if path is None:
        lit_config.fatal(f"{name} is required; could not find {value}")
    return path


def solc_version(path):
    """The leading `major.minor.patch` of `solc --version`, ignoring a prerelease suffix."""
    output = subprocess.run([path, "--version"], capture_output=True, text=True, check=False)
    match = re.search(r"Version: (\d+)\.(\d+)\.(\d+)", output.stdout)
    if match is None:
        lit_config.fatal(f"could not read the solc version from {path}")
    return tuple(int(part) for part in match.groups())


def solc_emits_program_context(path):
    """Whether the compiler lists the state variables in the program-level context of a
    program, which a version alone does not say: it arrives on develop after the type and
    pointer tables do. Tests that read it gate on `solc-ethdebug-program-context`."""
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "Probe.sol"
        source.write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity >=0.8.0;\ncontract Probe { uint256 x; }\n"
        )
        result = subprocess.run(
            [
                path, "--evm-version=cancun", "--via-ir", "--debug-info", "ethdebug",
                "--experimental", "--ethdebug-program-runtime", "-o", directory, str(source),
            ],
            capture_output=True, text=True, check=False, cwd=directory,
        )
        program = Path(directory) / "Probe_ethdebug-runtime.json"
        if result.returncode != 0 or not program.is_file():
            return False
        try:
            variables = json.loads(program.read_text())["context"]["variables"]
        except (ValueError, KeyError, TypeError):
            return False
        return any(variable.get("identifier") == "x" for variable in variables)


# Unlike the live-node suite, missing prerequisites must fail configuration.
soldb = require_tool("soldb", os.environ.get("SOLDB_BIN", root / "target/debug/soldb"))
filecheck = require_tool("FileCheck", os.environ.get("FILECHECK", "FileCheck"))
require_tool("jq", "jq")
solc_optimization = {
    "none": "",
    "gas": "--optimize --optimize-runs 200",
    "size": "--optimize --optimize-runs 1",
}[optimization]
config.substitutions = [("%soldb", shlex.quote(soldb)), ("FileCheck", shlex.quote(filecheck))]

# `verdict.jq` judges a debug-diff or profile report: debugger invariants fail
# the test, attribution the optimizer dropped is reported. solc 0.8.36 is the
# pinned oracle, so its reports are always strict; Solar is a moving target, so
# its optimized builds only report what they kept. `%verdict-cross` judges a
# solc-versus-Solar comparison, where the candidate alone may have lost stops.
verdict = f"jq -er -f {shlex.quote(str(Path(config.test_source_root) / 'verdict.jq'))}"
solar_strict = "true" if optimization == "none" else "false"
config.substitutions.extend(
    [
        ("%verdict-solc", f"{verdict} --arg strict true --arg asymmetric false"),
        ("%verdict-solar", f"{verdict} --arg strict {solar_strict} --arg asymmetric false"),
        ("%verdict-cross", f"{verdict} --arg strict {solar_strict} --arg asymmetric true"),
    ]
)
if compiler in ("solar", "both"):
    solar = require_tool("Solar (set SOLAR)", os.environ.get("SOLAR", "solar"))
    config.substitutions.append(
        ("%solar", f"{shlex.quote(solar)} --evm-version=cancun -O{optimization}")
    )
    config.available_features.add("compiler-solar")
if compiler in ("solc", "both"):
    solc = require_tool("solc (set SOLC_PATH)", os.environ.get("SOLC_PATH", "solc"))
    config.substitutions.append(
        ("%solc", f"{shlex.quote(solc)} --evm-version=cancun {solc_optimization}")
    )
    config.available_features.add("compiler-solc")
    version = solc_version(solc)
    lit_config.note(f"solc {'.'.join(str(part) for part in version)} at {solc}")
    for gate in SOLC_VERSION_GATES:
        if version >= tuple(int(part) for part in gate.split(".")):
            config.available_features.add(f"solc-at-least-{gate}")
    if solc_emits_program_context(solc):
        config.available_features.add("solc-ethdebug-program-context")
        lit_config.note("solc lists the state variables in the program-level context")
if compiler == "both":
    config.available_features.add("compiler-diff")
config.available_features.add("soldb")
config.available_features.add(f"optimization-{optimization}")
