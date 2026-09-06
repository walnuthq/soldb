"""Prepare compiler artifacts for the Solar lit tests; assertions live in .test files."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def run(command, directory, name, *, input_text=None):
    command = [str(arg) for arg in command]
    write_json(directory / f"{name}.command.json", command)
    result = subprocess.run(
        command,
        input=input_text,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=180,
        cwd=ROOT,
    )
    (directory / f"{name}.stdout").write_text(result.stdout, encoding="utf-8")
    (directory / f"{name}.stderr").write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"{name} exited {result.returncode}: {result.stderr or result.stdout}")
    return result


def compile_source(binary, source, contract, mode, directory, ethdebug):
    selections = [
        "abi",
        "evm.bytecode.object",
        "evm.deployedBytecode.object",
        "evm.bytecode.sourceMap",
        "evm.deployedBytecode.sourceMap",
    ]
    if ethdebug:
        selections += [
            "evm.bytecode.ethdebug",
            "evm.deployedBytecode.ethdebug",
            "ethdebug.resources",
        ]
    request = {
        "language": "Solidity",
        "sources": {source.name: {"content": source.read_bytes().decode("utf-8")}},
        "settings": {
            "evmVersion": "cancun",
            "optimizer": {"enabled": mode != "none", "runs": 1 if mode == "size" else 200},
            "outputSelection": {"*": {"*": selections}},
        },
    }
    write_json(directory / "input.json", request)
    result = run([binary, "--standard-json"], directory, "compile", input_text=json.dumps(request))
    # solc can prefix its JSON with an informational SMT message.
    output = json.loads(result.stdout[result.stdout.index("{") :])
    write_json(directory / "output.json", output)
    errors = [e for e in output.get("errors", []) if e.get("severity") == "error"]
    if errors:
        raise RuntimeError("\n".join(e.get("formattedMessage", e["message"]) for e in errors))
    artifact = output["contracts"][source.name][contract]
    if not artifact["evm"]["bytecode"]["object"]:
        raise ValueError("compiler emitted no creation bytecode")
    return output


def write_artifacts(output, source, contract, directory, ethdebug):
    directory.mkdir(parents=True, exist_ok=True)
    artifact = output["contracts"][source.name][contract]
    evm = artifact["evm"]
    (directory / source.name).write_bytes(source.read_bytes())
    (directory / f"{contract}.bin").write_text(evm["bytecode"]["object"], encoding="utf-8")
    write_json(directory / f"{contract}.abi", artifact["abi"])
    if ethdebug:
        write_json(directory / "ethdebug_resources.json", output["ethdebug"]["resources"])
        write_json(directory / f"{contract}_ethdebug.json", evm["bytecode"]["ethdebug"])
        write_json(
            directory / f"{contract}_ethdebug-runtime.json", evm["deployedBytecode"]["ethdebug"]
        )
    else:
        sources = sorted(output["sources"], key=lambda name: output["sources"][name]["id"])
        if any(output["sources"][name]["id"] != i for i, name in enumerate(sources)):
            raise ValueError("source IDs must be dense for the combined JSON adapter")
        write_json(
            directory / "combined.json",
            {
                "sourceList": sources,
                "contracts": {
                    f"{source.name}:{contract}": {
                        "bin": evm["bytecode"]["object"],
                        "bin-runtime": evm["deployedBytecode"]["object"],
                        "srcmap": evm["bytecode"]["sourceMap"],
                        "srcmap-runtime": evm["deployedBytecode"]["sourceMap"],
                    }
                },
            },
        )
    return directory


def checkpoint_lines(source):
    checkpoints = {}
    for line, text in enumerate(source.read_bytes().decode("utf-8").splitlines(), 1):
        if "// debug-check:" in text:
            name = text.split("// debug-check:", 1)[1].strip()
            if not name or name in checkpoints:
                raise ValueError(f"invalid or duplicate checkpoint at {source}:{line}")
            checkpoints[name] = {"source": source.name, "line": line}
    return checkpoints


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("contract")
    parser.add_argument("--solar", default=os.environ.get("SOLAR", "solar"))
    parser.add_argument("--solc", default=os.environ.get("SOLC_PATH", "solc"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--optimization", choices=["none", "gas", "size"], required=True)
    parser.add_argument("--checkpoints", nargs="+", required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    try:
        checkpoints = checkpoint_lines(args.source)
        write_json(args.output / "checkpoints.json", [checkpoints[key] for key in args.checkpoints])
        for name, binary in [("solar", args.solar), ("solc", args.solc)]:
            directory = args.output / name
            run([binary, "--version"], directory, "version")
            output = compile_source(
                binary, args.source, args.contract, args.optimization, directory, name == "solar"
            )
            write_artifacts(output, args.source, args.contract, directory, False)
            if name == "solar":
                write_artifacts(output, args.source, args.contract, args.output / "ethdebug", True)
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
