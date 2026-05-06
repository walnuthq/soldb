"""Unit tests for soldb.cli.bridge."""

from types import SimpleNamespace

from soldb.cli import bridge as bridge_cli


def _args(**overrides):
    defaults = dict(host="0.0.0.0", port=8765, config_file=None, quiet=False, json=False)
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_bridge_command_runs_server_and_returns_zero(monkeypatch, capsys):
    captured = {}

    def fake_run(host, port, verbose, config_file):
        captured["host"] = host
        captured["port"] = port
        captured["verbose"] = verbose
        captured["config_file"] = config_file

    monkeypatch.setattr(bridge_cli, "run_bridge_server", fake_run)
    code = bridge_cli.bridge_command(
        _args(host="127.0.0.1", port=9000, config_file="cfg.json", quiet=False)
    )
    assert code == 0
    assert captured == {
        "host": "127.0.0.1",
        "port": 9000,
        # quiet=False maps to verbose=True for the server.
        "verbose": True,
        "config_file": "cfg.json",
    }
    assert "Starting SolDB Cross-Environment Bridge on 127.0.0.1:9000" in capsys.readouterr().out


def test_bridge_command_quiet_maps_to_non_verbose(monkeypatch):
    captured = {}

    def fake_run(host, port, verbose, config_file):
        captured["verbose"] = verbose

    monkeypatch.setattr(bridge_cli, "run_bridge_server", fake_run)
    bridge_cli.bridge_command(_args(quiet=True))
    assert captured["verbose"] is False


def test_bridge_command_json_mode_suppresses_startup_message(monkeypatch, capsys):
    monkeypatch.setattr(bridge_cli, "run_bridge_server", lambda **kwargs: None)
    bridge_cli.bridge_command(_args(json=True))
    assert capsys.readouterr().out == ""


def test_bridge_command_keyboard_interrupt_returns_zero(monkeypatch, capsys):
    def interrupt(**kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(bridge_cli, "run_bridge_server", interrupt)
    assert bridge_cli.bridge_command(_args()) == 0
    assert "Bridge server stopped." in capsys.readouterr().out


def test_bridge_command_keyboard_interrupt_silent_in_json_mode(monkeypatch, capsys):
    def interrupt(**kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(bridge_cli, "run_bridge_server", interrupt)
    assert bridge_cli.bridge_command(_args(json=True)) == 0
    assert capsys.readouterr().out == ""


def test_bridge_command_unexpected_exception_returns_one(monkeypatch, capsys):
    def boom(**kwargs):
        raise RuntimeError("port in use")

    monkeypatch.setattr(bridge_cli, "run_bridge_server", boom)
    assert bridge_cli.bridge_command(_args()) == 1
    assert "Error starting bridge server: port in use" in capsys.readouterr().out


def test_bridge_command_uses_attribute_defaults_when_args_missing(monkeypatch):
    captured = {}

    def fake_run(host, port, verbose, config_file):
        captured["host"] = host
        captured["port"] = port
        captured["config_file"] = config_file
        captured["verbose"] = verbose

    monkeypatch.setattr(bridge_cli, "run_bridge_server", fake_run)
    # An argparse Namespace that lacks every optional attribute exercises the
    # `getattr(args, ..., default)` fallbacks.
    bridge_cli.bridge_command(SimpleNamespace())
    assert captured == {
        "host": "127.0.0.1",
        "port": 8765,
        "config_file": None,
        "verbose": True,
    }
