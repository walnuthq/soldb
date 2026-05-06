"""Unit tests for soldb.compiler.ethdebug.compile_ethdebug_run helper."""

import pytest

from soldb.compiler import ethdebug as compiler_ethdebug
from soldb.compiler.config import CompilationError, CompilerConfig


def test_compile_ethdebug_run_default_invokes_single_compile(monkeypatch, tmp_path):
    contract = tmp_path / "C.sol"
    contract.write_text("contract C {}")

    captured = {}

    def fake_compile(self, path):
        captured["path"] = path
        captured["debug_dir"] = self.debug_output_dir
        captured["solc"] = self.solc_path
        return {"success": True, "output_dir": str(tmp_path / "out")}

    monkeypatch.setattr(CompilerConfig, "compile_with_ethdebug", fake_compile)

    result = compiler_ethdebug.compile_ethdebug_run(
        str(contract),
        solc_path="/opt/solc",
        debug_output_dir=str(tmp_path / "out"),
    )
    assert result["success"] is True
    assert captured["path"] == str(contract)
    assert captured["solc"] == "/opt/solc"


def test_compile_ethdebug_run_dual_invokes_dual_compile(monkeypatch, tmp_path):
    contract = tmp_path / "C.sol"
    contract.write_text("contract C {}")

    seen = {}

    def fake_dual(path, config):
        seen["path"] = path
        seen["build_dir"] = config.build_dir
        return {"production": {"success": True}, "debug": {"success": True}}

    monkeypatch.setattr(compiler_ethdebug, "dual_compile", fake_dual)

    result = compiler_ethdebug.compile_ethdebug_run(
        str(contract),
        production_dir=str(tmp_path / "prod"),
        dual=True,
    )
    assert result == {"production": {"success": True}, "debug": {"success": True}}
    assert seen["path"] == str(contract)
    assert seen["build_dir"] == str(tmp_path / "prod")


def test_compile_ethdebug_run_save_config_short_circuits(monkeypatch, tmp_path):
    captured = {}

    def fake_save(self):
        captured["saved"] = True

    def boom(*a, **kw):
        raise AssertionError("compile must not run when only saving config")

    monkeypatch.setattr(CompilerConfig, "save_to_soldb_config", fake_save)
    monkeypatch.setattr(CompilerConfig, "compile_with_ethdebug", boom)
    monkeypatch.setattr(compiler_ethdebug, "dual_compile", boom)

    # The contract file does not need to exist when save_config short-circuits
    # before the existence check.
    result = compiler_ethdebug.compile_ethdebug_run(
        "missing.sol", save_config=True,
    )
    assert result == {"mode": "save_config", "saved": True}
    assert captured == {"saved": True}


def test_compile_ethdebug_run_verify_version_supported_continues(
    monkeypatch, tmp_path, capsys
):
    contract = tmp_path / "C.sol"
    contract.write_text("contract C {}")

    monkeypatch.setattr(
        CompilerConfig, "verify_solc_version",
        lambda self: {"supported": True, "version": "0.8.31"},
    )
    monkeypatch.setattr(
        CompilerConfig, "compile_with_ethdebug",
        lambda self, path: {"success": True, "output_dir": "out"},
    )

    result = compiler_ethdebug.compile_ethdebug_run(
        str(contract), verify_version=True,
    )
    assert result["success"] is True
    # The supported branch prints a status line via the info() helper.
    assert "0.8.31" in capsys.readouterr().out


def test_compile_ethdebug_run_verify_version_unsupported_raises(monkeypatch, tmp_path):
    contract = tmp_path / "C.sol"
    contract.write_text("contract C {}")

    monkeypatch.setattr(
        CompilerConfig, "verify_solc_version",
        lambda self: {"supported": False, "error": "too old"},
    )

    with pytest.raises(CompilationError, match="too old"):
        compiler_ethdebug.compile_ethdebug_run(
            str(contract), verify_version=True,
        )


def test_compile_ethdebug_run_verify_version_unsupported_default_message(
    monkeypatch, tmp_path
):
    contract = tmp_path / "C.sol"
    contract.write_text("contract C {}")

    # Even with no explicit error key the helper falls back to a sensible string.
    monkeypatch.setattr(
        CompilerConfig, "verify_solc_version",
        lambda self: {"supported": False},
    )
    with pytest.raises(CompilationError, match="Unsupported solc version"):
        compiler_ethdebug.compile_ethdebug_run(
            str(contract), verify_version=True,
        )


def test_compile_ethdebug_run_missing_file_raises():
    with pytest.raises(FileNotFoundError, match="not found"):
        compiler_ethdebug.compile_ethdebug_run("/tmp/does-not-exist-soldb.sol")


def test_compile_ethdebug_run_passes_debug_output_dir_to_config(monkeypatch, tmp_path):
    contract = tmp_path / "C.sol"
    contract.write_text("contract C {}")

    captured = {}

    def fake_compile(self, path):
        captured["debug_output_dir"] = self.debug_output_dir
        return {"success": True}

    monkeypatch.setattr(CompilerConfig, "compile_with_ethdebug", fake_compile)
    compiler_ethdebug.compile_ethdebug_run(
        str(contract), debug_output_dir=str(tmp_path / "custom-out"),
    )
    assert captured["debug_output_dir"] == str(tmp_path / "custom-out")
