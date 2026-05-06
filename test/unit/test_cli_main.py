"""Unit tests for soldb.cli.main argument parsing and dispatch."""

import sys

import pytest

# Importing soldb.cli runs `from .main import main`, which rebinds the name
# `soldb.cli.main` to the function. Pull the actual module out of sys.modules.
import soldb.cli.main  # noqa: F401  (registers the submodule)
cli_main = sys.modules["soldb.cli.main"]


@pytest.fixture
def stub_subcommands(monkeypatch):
    """Replace every subcommand entry point with a recorder."""
    recorded = []

    def recorder(label):
        def fn(args):
            recorded.append((label, args))
            return 0
        return fn

    monkeypatch.setattr(cli_main, "trace_command", recorder("trace"))
    monkeypatch.setattr(cli_main, "simulate_command", recorder("simulate"))
    monkeypatch.setattr(cli_main, "list_events_command", recorder("list-events"))
    monkeypatch.setattr(cli_main, "list_contracts_command", recorder("list-contracts"))
    monkeypatch.setattr(cli_main, "bridge_command", recorder("bridge"))
    return recorded


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["soldb", *argv])
    return cli_main.main()


def test_main_routes_to_bridge(monkeypatch, stub_subcommands):
    assert _run_main(monkeypatch, ["bridge", "--port", "9000", "--host", "0.0.0.0"]) == 0
    assert stub_subcommands[0][0] == "bridge"
    args = stub_subcommands[0][1]
    assert args.host == "0.0.0.0"
    assert args.port == 9000
    assert args.config_file is None
    assert args.quiet is False
    assert args.json is False


def test_main_routes_to_list_contracts(monkeypatch, stub_subcommands):
    _run_main(monkeypatch, ["list-contracts", "0xabc", "--rpc-url", "http://r"])
    label, args = stub_subcommands[0]
    assert label == "list-contracts"
    assert args.tx_hash == "0xabc"
    assert args.rpc_url == "http://r"
    assert args.ethdebug_dir is None
    assert args.multi_contract is False


def test_main_routes_to_list_events(monkeypatch, stub_subcommands):
    _run_main(
        monkeypatch,
        ["list-events", "0xdead", "--rpc-url", "http://r", "--json-events", "-e", "out"],
    )
    label, args = stub_subcommands[0]
    assert label == "list-events"
    assert args.tx_hash == "0xdead"
    assert args.json_events is True
    assert args.ethdebug_dir == ["out"]


def test_main_routes_to_trace(monkeypatch, stub_subcommands):
    _run_main(
        monkeypatch,
        ["trace", "0xtx", "--rpc", "http://x", "--max-steps", "0", "-i", "--raw"],
    )
    label, args = stub_subcommands[0]
    assert label == "trace"
    assert args.tx_hash == "0xtx"
    assert args.rpc == "http://x"
    assert args.max_steps == 0
    assert args.interactive is True
    assert args.raw is True


def test_main_routes_to_simulate(monkeypatch, stub_subcommands):
    _run_main(
        monkeypatch,
        [
            "simulate",
            "--from", "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
            "increment(uint256)", "1",
            "--value", "0",
            "--block", "100",
        ],
    )
    label, args = stub_subcommands[0]
    assert label == "simulate"
    assert args.from_addr == "0x1111111111111111111111111111111111111111"
    assert args.contract_address == "0x2222222222222222222222222222222222222222"
    assert args.function_signature == "increment(uint256)"
    assert args.function_args == ["1"]
    assert args.block == 100
    # Defaults that should survive parsing.
    assert args.solc_path == "solc"
    assert args.fork_port == 8545


def test_main_returns_zero_when_subcommand_returns_none(monkeypatch, stub_subcommands):
    # The dispatcher just returns whatever the handler returns, including None
    # if a handler ever decides not to return an explicit code.
    monkeypatch.setattr(cli_main, "bridge_command", lambda args: None)
    assert _run_main(monkeypatch, ["bridge"]) is None


def test_main_requires_a_subcommand(monkeypatch, stub_subcommands):
    monkeypatch.setattr(sys, "argv", ["soldb"])
    with pytest.raises(SystemExit):
        cli_main.main()


def test_main_version_flag_exits_with_zero(monkeypatch, stub_subcommands, capsys):
    monkeypatch.setattr(sys, "argv", ["soldb", "--version"])
    with pytest.raises(SystemExit) as excinfo:
        cli_main.main()
    assert excinfo.value.code == 0
    assert "0.1.0" in capsys.readouterr().out
