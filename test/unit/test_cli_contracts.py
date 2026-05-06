"""Unit tests for soldb.cli.contracts."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from soldb.cli import contracts as contracts_cli


def _args(**overrides):
    defaults = dict(
        tx_hash="0xtx",
        rpc_url="http://localhost:8545",
        ethdebug_dir=None,
        contracts=None,
        multi_contract=False,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class FakeTracer:
    """Stand-in for TransactionTracer used by the CLI."""

    def __init__(self, rpc_url, *, trace_value=None, trace_error=None):
        self.rpc_url = rpc_url
        self._trace_value = trace_value
        self._trace_error = trace_error
        self.loaded_abis = []
        self.multi_contract_parser = None

    def trace_transaction(self, tx_hash):
        if self._trace_error is not None:
            raise self._trace_error
        return self._trace_value

    def load_abi(self, path):
        self.loaded_abis.append(path)


def test_list_contracts_command_returns_one_on_tracer_failure(monkeypatch, capsys):
    def boom(rpc_url):
        raise RuntimeError("dial tcp")

    monkeypatch.setattr(contracts_cli, "TransactionTracer", boom)
    assert contracts_cli.list_contracts_command(_args()) == 1
    assert "dial tcp" in capsys.readouterr().out


def test_list_contracts_command_returns_one_when_trace_raises(monkeypatch, capsys):
    tracer = FakeTracer("http://r", trace_error=ValueError("missing tx"))
    monkeypatch.setattr(contracts_cli, "TransactionTracer", lambda url: tracer)
    monkeypatch.setattr(contracts_cli, "_print_contracts_in_transaction", lambda *_: None)
    assert contracts_cli.list_contracts_command(_args()) == 1
    assert "missing tx" in capsys.readouterr().out


def test_list_contracts_command_happy_path(monkeypatch):
    tracer = FakeTracer("http://r", trace_value="TRACE-OBJ")
    monkeypatch.setattr(contracts_cli, "TransactionTracer", lambda url: tracer)
    captured = {}

    def fake_print(t, trace):
        captured["tracer"] = t
        captured["trace"] = trace

    monkeypatch.setattr(contracts_cli, "_print_contracts_in_transaction", fake_print)
    assert contracts_cli.list_contracts_command(_args()) == 0
    assert captured == {"tracer": tracer, "trace": "TRACE-OBJ"}


def test_load_contracts_debug_info_skips_when_not_multi_contract():
    tracer = FakeTracer("http://r")
    contracts_cli._load_contracts_debug_info(tracer, _args())
    # Single-contract mode never touches the tracer's parser slot.
    assert tracer.multi_contract_parser is None


def test_load_contracts_debug_info_loads_mapping_file(monkeypatch, tmp_path):
    mapping = tmp_path / "contracts.json"
    mapping.write_text("{}")

    captured = {}

    class FakeParser:
        def __init__(self):
            self.contracts = {}

        def load_from_mapping_file(self, path):
            captured["mapping"] = path

    monkeypatch.setattr(contracts_cli, "MultiContractETHDebugParser", FakeParser)
    tracer = FakeTracer("http://r")
    contracts_cli._load_contracts_debug_info(
        tracer, _args(multi_contract=True, contracts=str(mapping))
    )
    assert captured["mapping"] == str(mapping)
    assert isinstance(tracer.multi_contract_parser, FakeParser)


def test_load_contracts_debug_info_exits_on_mapping_failure(monkeypatch, capsys):
    class FakeParser:
        contracts = {}

        def load_from_mapping_file(self, path):
            raise RuntimeError("malformed mapping")

    monkeypatch.setattr(contracts_cli, "MultiContractETHDebugParser", FakeParser)
    with pytest.raises(SystemExit) as excinfo:
        contracts_cli._load_contracts_debug_info(
            FakeTracer("http://r"),
            _args(multi_contract=True, contracts="m.json"),
        )
    assert excinfo.value.code == 1
    assert "malformed mapping" in capsys.readouterr().out


def test_load_contracts_debug_info_exits_on_invalid_dir_spec(monkeypatch, capsys):
    class FakeParser:
        contracts = {}

    def fake_parse(dirs):
        raise ValueError("bad spec")

    monkeypatch.setattr(contracts_cli, "MultiContractETHDebugParser", FakeParser)
    monkeypatch.setattr(
        contracts_cli.ETHDebugDirParser, "parse_ethdebug_dirs",
        staticmethod(fake_parse),
    )
    with pytest.raises(SystemExit) as excinfo:
        contracts_cli._load_contracts_debug_info(
            FakeTracer("http://r"),
            _args(multi_contract=True, ethdebug_dir=["bogus"]),
        )
    assert excinfo.value.code == 1
    assert "bad spec" in capsys.readouterr().err


def test_load_contracts_debug_info_loads_abis_for_each_format(monkeypatch, tmp_path):
    abi_dir = tmp_path / "with_abi"
    abi_dir.mkdir()
    (abi_dir / "Counter.abi").write_text("[]")

    json_dir = tmp_path / "with_json"
    json_dir.mkdir()
    (json_dir / "Token.json").write_text("[]")

    nothing_dir = tmp_path / "with_nothing"
    nothing_dir.mkdir()

    class FakeParser:
        def __init__(self):
            self.contracts = {
                "0x1": SimpleNamespace(name="Counter", debug_dir=abi_dir),
                "0x2": SimpleNamespace(name="Token", debug_dir=json_dir),
                "0x3": SimpleNamespace(name="Missing", debug_dir=nothing_dir),
            }

    monkeypatch.setattr(contracts_cli, "MultiContractETHDebugParser", FakeParser)
    monkeypatch.setattr(
        contracts_cli.ETHDebugDirParser, "parse_ethdebug_dirs",
        staticmethod(lambda dirs: []),
    )

    tracer = FakeTracer("http://r")
    contracts_cli._load_contracts_debug_info(tracer, _args(multi_contract=True))

    assert str(abi_dir / "Counter.abi") in tracer.loaded_abis
    assert str(json_dir / "Token.json") in tracer.loaded_abis
    # Missing files are silently skipped.
    assert all("Missing" not in p for p in tracer.loaded_abis)


def test_load_contract_from_spec_dispatches_by_fields():
    calls = []

    class FakeParser:
        def load_contract(self, address, path, name=None):
            calls.append(("load", address, path, name))

        def load_from_deployment(self, file):
            calls.append(("deploy", str(file)))

    parser = FakeParser()
    contracts_cli._load_contract_from_spec(
        parser, SimpleNamespace(address="0x1", name="C", path="p"),
    )
    contracts_cli._load_contract_from_spec(
        parser, SimpleNamespace(address="0x2", name=None, path="p"),
    )
    assert ("load", "0x1", "p", "C") in calls
    assert ("load", "0x2", "p", None) in calls


def test_load_contract_from_spec_uses_deployment_json(tmp_path, monkeypatch):
    deploy_dir = tmp_path / "d"
    deploy_dir.mkdir()
    (deploy_dir / "deployment.json").write_text("{}")

    captured = {}

    class FakeParser:
        def load_from_deployment(self, file):
            captured["file"] = Path(file)

    contracts_cli._load_contract_from_spec(
        FakeParser(), SimpleNamespace(address=None, name=None, path=str(deploy_dir)),
    )
    assert captured["file"] == deploy_dir / "deployment.json"


def test_load_contract_from_spec_warns_when_no_deployment(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()

    class FakeParser:
        def load_from_deployment(self, file):  # pragma: no cover - shouldn't be called
            raise AssertionError("should not be called")

    contracts_cli._load_contract_from_spec(
        FakeParser(), SimpleNamespace(address=None, name=None, path=str(empty)),
    )
    assert "No deployment.json" in capsys.readouterr().err


def test_load_contract_from_spec_handles_missing_file_with_compiler_info(monkeypatch, capsys):
    class FakeParser:
        def load_contract(self, address, path, name=None):
            raise FileNotFoundError("debug file missing")

    # Force the optional compiler-info enrichment to add a tag to the message.
    from soldb.parsers import ethdebug as ethdebug_mod

    monkeypatch.setattr(
        ethdebug_mod.ETHDebugParser, "_get_compiler_info",
        staticmethod(lambda path: "0.8.31"),
    )
    with pytest.raises(SystemExit) as excinfo:
        contracts_cli._load_contract_from_spec(
            FakeParser(), SimpleNamespace(address="0xaaa", name="Foo", path="ignored"),
        )
    assert excinfo.value.code == 1
    out = capsys.readouterr().out
    assert "Error loading contract Foo: debug file missing" in out
    assert "compiler: 0.8.31" in out


def test_load_contract_from_spec_swallows_compiler_info_failure(monkeypatch, capsys):
    class FakeParser:
        def load_contract(self, address, path, name=None):
            raise FileNotFoundError("nope")

    from soldb.parsers import ethdebug as ethdebug_mod

    def boom(path):
        raise RuntimeError("compiler probe failed")

    monkeypatch.setattr(
        ethdebug_mod.ETHDebugParser, "_get_compiler_info", staticmethod(boom)
    )
    with pytest.raises(SystemExit):
        contracts_cli._load_contract_from_spec(
            FakeParser(), SimpleNamespace(address="0xbbb", name=None, path="x"),
        )
    # Falling through the inner try/except still surfaces the original FileNotFoundError text.
    assert "Error loading contract 0xbbb: nope" in capsys.readouterr().out


def test_print_contracts_in_transaction_delegates_to_helpers(monkeypatch):
    captured = {}

    def fake_print(tracer, trace):
        captured["args"] = (tracer, trace)

    import soldb.utils.helpers as helpers_mod
    monkeypatch.setattr(helpers_mod, "print_contracts_in_transaction", fake_print)
    contracts_cli._print_contracts_in_transaction("TRACER", "TRACE")
    assert captured["args"] == ("TRACER", "TRACE")
