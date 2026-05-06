"""Tests for the Python console-script shim that dispatches to Rust."""

from types import SimpleNamespace

from soldb import rust_cli


def test_rust_cli_uses_env_override(monkeypatch, tmp_path):
    binary = tmp_path / "soldb"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    calls = []

    monkeypatch.setenv("SOLDB_RUST_BIN", str(binary))
    monkeypatch.setattr(rust_cli.sys, "argv", ["soldb", "--version"])
    monkeypatch.setattr(
        rust_cli.subprocess,
        "run",
        lambda args, check: calls.append((args, check)) or SimpleNamespace(returncode=3),
    )

    assert rust_cli.main() == 3
    assert calls == [([str(binary), "--version"], False)]


def test_rust_cli_reports_missing_binary(monkeypatch, capsys):
    monkeypatch.delenv("SOLDB_RUST_BIN", raising=False)
    monkeypatch.setattr(rust_cli, "_repo_root", lambda: rust_cli.Path("/missing"))

    assert rust_cli.main() == 127
    assert "Rust soldb binary not found" in capsys.readouterr().err
