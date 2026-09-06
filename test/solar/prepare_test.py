"""Unit tests for the compiler artifact adapter used by lit."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import prepare


class AdapterTests(unittest.TestCase):
    def test_compile_preserves_source_bytes_and_requests_both_formats(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "Example.sol"
            source.write_bytes("// café\r\ncontract Example {}\r\n".encode())
            response = {
                "contracts": {
                    source.name: {
                        "Example": {
                            "evm": {"bytecode": {"object": "00"}},
                        }
                    }
                }
            }
            result = subprocess.CompletedProcess([], 0, json.dumps(response), "")
            with patch.object(prepare, "run", return_value=result) as command:
                prepare.compile_source("solar", source, "Example", "gas", directory, True)
            request = json.loads(command.call_args.kwargs["input_text"])
            self.assertEqual(
                request["sources"][source.name]["content"].encode(), source.read_bytes()
            )
            flags = request["settings"]["outputSelection"]["*"]["*"]
            self.assertIn("evm.bytecode.ethdebug", flags)
            self.assertIn("ethdebug.resources", flags)
            self.assertIn("evm.deployedBytecode.sourceMap", flags)

    def test_compiler_diagnostics_are_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "Bad.sol"
            source.write_text("contract Bad {}")
            response = {"errors": [{"severity": "error", "message": "unsupported"}]}
            result = subprocess.CompletedProcess([], 0, json.dumps(response), "")
            with (
                patch.object(prepare, "run", return_value=result),
                self.assertRaisesRegex(RuntimeError, "unsupported"),
            ):
                prepare.compile_source("solar", source, "Bad", "none", directory, True)
            self.assertEqual(json.loads((directory / "output.json").read_text()), response)

    def test_duplicate_checkpoints_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "C.sol"
            source.write_bytes(b"// debug-check: one\r\n// debug-check: one\r\n")
            with self.assertRaisesRegex(ValueError, "duplicate checkpoint"):
                prepare.checkpoint_lines(source)

    def test_artifact_formats_preserve_bytecode_and_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "C.sol"
            source.write_bytes("// café\r\ncontract C {}\r\n".encode())
            output = {
                "sources": {"C.sol": {"id": 0}},
                "ethdebug": {"resources": {"compilation": {"id": "test"}}},
                "contracts": {
                    "C.sol": {
                        "C": {
                            "abi": [],
                            "evm": {
                                "bytecode": {
                                    "object": "6000",
                                    "sourceMap": "1:2:0",
                                    "ethdebug": {"environment": "create"},
                                },
                                "deployedBytecode": {
                                    "object": "00",
                                    "sourceMap": "3:4:0",
                                    "ethdebug": {"environment": "call"},
                                },
                            },
                        }
                    }
                },
            }
            for name, ethdebug in [("ethdebug", True), ("legacy", False)]:
                artifacts = prepare.write_artifacts(output, source, "C", directory / name, ethdebug)
                self.assertEqual((artifacts / "C.sol").read_bytes(), source.read_bytes())
                self.assertEqual((artifacts / "C.bin").read_text(), "6000")
            legacy = json.loads((directory / "legacy/combined.json").read_text())
            self.assertEqual(legacy["contracts"]["C.sol:C"]["srcmap-runtime"], "3:4:0")
            resources = json.loads((directory / "ethdebug/ethdebug_resources.json").read_text())
            self.assertEqual(resources, output["ethdebug"]["resources"])
            output["sources"]["C.sol"]["id"] = 2
            with self.assertRaisesRegex(ValueError, "source IDs must be dense"):
                prepare.write_artifacts(output, source, "C", directory / "sparse", False)

    def test_failed_commands_keep_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaises(RuntimeError):
                prepare.run(
                    [sys.executable, "-c", "print('failure details'); exit(2)"], directory, "failed"
                )
            self.assertEqual((directory / "failed.stdout").read_text(), "failure details\n")
            self.assertTrue((directory / "failed.command.json").is_file())


if __name__ == "__main__":
    unittest.main()
