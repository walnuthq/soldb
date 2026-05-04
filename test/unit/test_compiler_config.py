"""Unit tests for soldb.compiler.config — direct method coverage.

These tests exercise CompilerConfig and dual_compile against a stubbed
subprocess so that no real solc invocation is required.
"""

import subprocess
from typing import Any, Dict, List

import pytest

from soldb.compiler.config import (
    CompilationError,
    CompilerConfig,
    dual_compile,
)


class FakeCompletedProcess:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _stub_subprocess(monkeypatch, recorded: List[list], response: FakeCompletedProcess):
    def fake_run(cmd, capture_output=False, text=False):
        recorded.append(list(cmd))
        return response

    monkeypatch.setattr(subprocess, "run", fake_run)


def test_post_init_sets_default_flag_lists():
    cfg = CompilerConfig()
    assert "--ethdebug" in cfg.ethdebug_flags
    assert "--via-ir" in cfg.production_flags
    # Custom flag lists must be respected and not overwritten.
    custom = CompilerConfig(ethdebug_flags=["--x"], production_flags=["--y"])
    assert custom.ethdebug_flags == ["--x"]
    assert custom.production_flags == ["--y"]


def test_ensure_directories_creates_paths(tmp_path):
    cfg = CompilerConfig(
        debug_output_dir=str(tmp_path / "out"),
        build_dir=str(tmp_path / "build"),
    )
    cfg.ensure_directories()
    assert (tmp_path / "out").is_dir()
    assert (tmp_path / "build").is_dir()


def test_compile_with_ethdebug_collects_generated_files(monkeypatch, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    # Simulate solc artifacts: one ethdebug.json plus a contract C with all sidecars.
    (out / "ethdebug.json").write_text("{}")
    (out / "C.bin").write_text("60806040")
    (out / "C.abi").write_text("[]")
    (out / "C_ethdebug.json").write_text("{}")
    (out / "C_ethdebug-runtime.json").write_text("{}")
    # Plus one contract D missing its abi/ethdebug companions.
    (out / "D.bin").write_text("60806040")

    recorded: List[list] = []
    _stub_subprocess(monkeypatch, recorded, FakeCompletedProcess(stdout="ok"))

    cfg = CompilerConfig(debug_output_dir=str(out))
    result = cfg.compile_with_ethdebug("Counter.sol")

    assert result["success"] is True
    assert result["files"]["ethdebug"] == str(out / "ethdebug.json")
    assert set(result["files"]["contracts"].keys()) == {"C", "D"}
    assert result["files"]["contracts"]["C"]["abi"] == str(out / "C.abi")
    # Missing companion files are reported as None instead of bogus paths.
    assert result["files"]["contracts"]["D"]["abi"] is None
    assert result["files"]["contracts"]["D"]["ethdebug"] is None
    # The recorded command must include the source path and the -o flag.
    assert recorded[0][-1] == "Counter.sol"
    assert "-o" in recorded[0]


def test_compile_with_ethdebug_raises_on_failure(monkeypatch, tmp_path):
    recorded: List[list] = []
    _stub_subprocess(
        monkeypatch, recorded,
        FakeCompletedProcess(returncode=1, stderr="boom"),
    )
    cfg = CompilerConfig(debug_output_dir=str(tmp_path))
    with pytest.raises(CompilationError) as excinfo:
        cfg.compile_with_ethdebug("Bad.sol")
    assert "boom" in str(excinfo.value)


def test_compile_for_production_returns_metadata(monkeypatch, tmp_path):
    recorded: List[list] = []
    _stub_subprocess(
        monkeypatch, recorded,
        FakeCompletedProcess(stdout="prod-ok", stderr=""),
    )
    cfg = CompilerConfig(build_dir=str(tmp_path / "build"))
    result = cfg.compile_for_production("Counter.sol")
    assert result["success"] is True
    assert result["output_dir"] == str(tmp_path / "build")
    assert result["stdout"] == "prod-ok"


def test_compile_for_production_raises_on_failure(monkeypatch, tmp_path):
    recorded: List[list] = []
    _stub_subprocess(
        monkeypatch, recorded,
        FakeCompletedProcess(returncode=2, stderr="prod-fail"),
    )
    cfg = CompilerConfig(build_dir=str(tmp_path))
    with pytest.raises(CompilationError):
        cfg.compile_for_production("Bad.sol")


@pytest.mark.parametrize(
    "version_line,expected_supported",
    [
        ("Version: 0.8.31+commit.abcd", True),
        ("Version: 0.8.29+commit.abcd", True),
        ("Version: 0.8.28+commit.abcd", False),
        ("Version: 0.7.6+commit.abcd", False),
    ],
)
def test_verify_solc_version_branches(monkeypatch, version_line, expected_supported):
    _stub_subprocess(
        monkeypatch, [],
        FakeCompletedProcess(stdout=f"solc, the solidity compiler\n{version_line}\n"),
    )
    info = CompilerConfig().verify_solc_version()
    assert info["supported"] is expected_supported
    if expected_supported:
        assert info["version"] in version_line
    else:
        assert "error" in info


def test_verify_solc_version_handles_missing_version(monkeypatch):
    _stub_subprocess(monkeypatch, [], FakeCompletedProcess(stdout="no version here"))
    info = CompilerConfig().verify_solc_version()
    assert info == {"supported": False, "error": "Could not parse version"}


def test_verify_solc_version_handles_nonzero_exit(monkeypatch):
    _stub_subprocess(monkeypatch, [], FakeCompletedProcess(returncode=127))
    info = CompilerConfig().verify_solc_version()
    assert info["supported"] is False
    assert "Could not get solc version" in info["error"]


def test_verify_solc_version_handles_subprocess_exception(monkeypatch):
    def boom(*a, **kw):
        raise FileNotFoundError("no such binary")

    monkeypatch.setattr(subprocess, "run", boom)
    info = CompilerConfig().verify_solc_version()
    assert info["supported"] is False
    assert "no such binary" in info["error"]


def test_from_soldb_config_returns_default_when_missing(tmp_path):
    cfg = CompilerConfig.from_soldb_config(str(tmp_path / "missing.yaml"))
    assert cfg.solc_path == "solc"
    assert cfg.debug_output_dir == "./out"


def test_from_soldb_config_reads_values(tmp_path):
    yaml = pytest.importorskip("yaml")
    config_file = tmp_path / "soldb.config.yaml"
    config_file.write_text(
        yaml.dump(
            {
                "build_dir": "./prod-out",
                "debug": {
                    "ethdebug": {
                        "solc_path": "/usr/local/bin/solc",
                        "path": "./debug-out",
                    }
                },
            }
        )
    )
    cfg = CompilerConfig.from_soldb_config(str(config_file))
    assert cfg.solc_path == "/usr/local/bin/solc"
    assert cfg.debug_output_dir == "./debug-out"
    assert cfg.build_dir == "./prod-out"


def test_save_to_soldb_config_round_trips(tmp_path):
    yaml = pytest.importorskip("yaml")
    config_file = tmp_path / "soldb.config.yaml"
    cfg = CompilerConfig(
        solc_path="/opt/solc",
        debug_output_dir="./out",
        build_dir="./build",
    )
    cfg.save_to_soldb_config(str(config_file))
    raw: Dict[str, Any] = yaml.safe_load(config_file.read_text())
    assert raw["debug"]["ethdebug"]["enabled"] is True
    assert raw["debug"]["ethdebug"]["solc_path"] == "/opt/solc"
    assert raw["debug"]["ethdebug"]["path"] == "./out"
    assert raw["build_dir"] == "./build"

    # Saving again merges with existing data instead of clobbering siblings.
    raw["debug"]["other"] = "preserved"
    config_file.write_text(yaml.dump(raw))
    cfg.save_to_soldb_config(str(config_file))
    merged = yaml.safe_load(config_file.read_text())
    assert merged["debug"]["other"] == "preserved"


def test_dual_compile_records_both_results(monkeypatch, tmp_path):
    calls = []

    def fake_prod(self, contract_file, output_dir=None):
        calls.append(("prod", contract_file))
        return {"success": True, "output_dir": "build"}

    def fake_debug(self, contract_file, output_dir=None):
        calls.append(("debug", contract_file))
        return {"success": True, "output_dir": "debug"}

    monkeypatch.setattr(CompilerConfig, "compile_for_production", fake_prod)
    monkeypatch.setattr(CompilerConfig, "compile_with_ethdebug", fake_debug)

    result = dual_compile("Counter.sol")
    assert result["production"]["success"] is True
    assert result["debug"]["success"] is True
    assert calls == [("prod", "Counter.sol"), ("debug", "Counter.sol")]


def test_dual_compile_captures_both_failures(monkeypatch):
    def raise_prod(self, contract_file, output_dir=None):
        raise CompilationError("prod failed")

    def raise_debug(self, contract_file, output_dir=None):
        raise CompilationError("debug failed")

    monkeypatch.setattr(CompilerConfig, "compile_for_production", raise_prod)
    monkeypatch.setattr(CompilerConfig, "compile_with_ethdebug", raise_debug)

    result = dual_compile("Counter.sol", CompilerConfig())
    assert result["production"] == {"success": False, "error": "prod failed"}
    assert result["debug"] == {"success": False, "error": "debug failed"}
