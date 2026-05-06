"""Unit tests for soldb.cli.events."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from soldb.cli import events as events_cli


def _args(**overrides):
    defaults = dict(
        tx_hash="0xtx",
        rpc_url="http://localhost:8545",
        ethdebug_dir=None,
        contracts=None,
        multi_contract=False,
        json_events=False,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class FakeReceiptApi:
    def __init__(self, receipt=None, error=None):
        self._receipt = receipt
        self._error = error

    def get_transaction_receipt(self, tx_hash):
        if self._error is not None:
            raise self._error
        return self._receipt


class FakeTracer:
    """Stand-in for TransactionTracer used by the CLI."""

    def __init__(self, rpc_url, *, receipt=None, receipt_error=None):
        self.rpc_url = rpc_url
        self.w3 = SimpleNamespace(eth=FakeReceiptApi(receipt, receipt_error))
        self.loaded_abis = []
        self.multi_contract_parser = None

    def load_abi(self, path):
        self.loaded_abis.append(path)


def test_list_events_command_returns_one_on_tracer_failure(monkeypatch, capsys):
    def boom(rpc_url):
        raise RuntimeError("dial tcp")

    monkeypatch.setattr(events_cli, "TransactionTracer", boom)
    assert events_cli.list_events_command(_args()) == 1
    assert "dial tcp" in capsys.readouterr().out


def test_list_events_command_returns_one_on_receipt_error_text(monkeypatch, capsys):
    tracer = FakeTracer("http://r", receipt_error=RuntimeError("rpc down"))
    monkeypatch.setattr(events_cli, "TransactionTracer", lambda url: tracer)
    monkeypatch.setattr(events_cli, "_print_events", lambda *_: None)
    assert events_cli.list_events_command(_args()) == 1
    out = capsys.readouterr().out
    assert "rpc down" in out


def test_list_events_command_returns_one_on_receipt_error_json(monkeypatch, capsys):
    tracer = FakeTracer("http://r", receipt_error=RuntimeError("rpc down"))
    monkeypatch.setattr(events_cli, "TransactionTracer", lambda url: tracer)
    monkeypatch.setattr(events_cli, "_print_events", lambda *_: None)
    assert events_cli.list_events_command(_args(json_events=True)) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"] is True
    assert payload["type"] == "TransactionReceiptError"
    assert "rpc down" in payload["message"]


def test_list_events_command_happy_path(monkeypatch):
    tracer = FakeTracer("http://r", receipt={"logs": []})
    monkeypatch.setattr(events_cli, "TransactionTracer", lambda url: tracer)
    captured = {}

    def fake_print(t, receipt, json_mode):
        captured["tracer"] = t
        captured["receipt"] = receipt
        captured["json_mode"] = json_mode

    monkeypatch.setattr(events_cli, "_print_events", fake_print)
    assert events_cli.list_events_command(_args(json_events=True)) == 0
    assert captured == {
        "tracer": tracer,
        "receipt": {"logs": []},
        "json_mode": True,
    }


def test_load_events_debug_info_skips_when_not_multi_contract():
    tracer = FakeTracer("http://r")
    events_cli._load_events_debug_info(tracer, _args())
    assert tracer.multi_contract_parser is None


def test_load_events_debug_info_loads_mapping_file(monkeypatch, tmp_path):
    mapping = tmp_path / "contracts.json"
    mapping.write_text("{}")

    captured = {}

    class FakeParser:
        def __init__(self):
            self.contracts = {}

        def load_from_mapping_file(self, path):
            captured["mapping"] = path

    monkeypatch.setattr(events_cli, "MultiContractETHDebugParser", FakeParser)
    tracer = FakeTracer("http://r")
    events_cli._load_events_debug_info(
        tracer, _args(multi_contract=True, contracts=str(mapping))
    )
    assert captured["mapping"] == str(mapping)
    assert isinstance(tracer.multi_contract_parser, FakeParser)


def test_load_events_debug_info_exits_on_mapping_failure(monkeypatch, capsys):
    class FakeParser:
        contracts = {}

        def load_from_mapping_file(self, path):
            raise RuntimeError("malformed mapping")

    monkeypatch.setattr(events_cli, "MultiContractETHDebugParser", FakeParser)
    with pytest.raises(SystemExit) as excinfo:
        events_cli._load_events_debug_info(
            FakeTracer("http://r"),
            _args(multi_contract=True, contracts="m.json"),
        )
    assert excinfo.value.code == 1
    assert "malformed mapping" in capsys.readouterr().out


def test_load_events_debug_info_exits_on_invalid_dir_spec(monkeypatch, capsys):
    class FakeParser:
        contracts = {}

    def fake_parse(dirs):
        raise ValueError("bad spec")

    monkeypatch.setattr(events_cli, "MultiContractETHDebugParser", FakeParser)
    monkeypatch.setattr(
        events_cli.ETHDebugDirParser, "parse_ethdebug_dirs",
        staticmethod(fake_parse),
    )
    with pytest.raises(SystemExit) as excinfo:
        events_cli._load_events_debug_info(
            FakeTracer("http://r"),
            _args(multi_contract=True, ethdebug_dir=["bogus"]),
        )
    assert excinfo.value.code == 1
    assert "bad spec" in capsys.readouterr().err


def test_load_events_debug_info_loads_abis_for_each_format(monkeypatch, tmp_path):
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

    monkeypatch.setattr(events_cli, "MultiContractETHDebugParser", FakeParser)
    monkeypatch.setattr(
        events_cli.ETHDebugDirParser, "parse_ethdebug_dirs",
        staticmethod(lambda dirs: []),
    )

    tracer = FakeTracer("http://r")
    events_cli._load_events_debug_info(tracer, _args(multi_contract=True))

    assert str(abi_dir / "Counter.abi") in tracer.loaded_abis
    assert str(json_dir / "Token.json") in tracer.loaded_abis
    assert all("Missing" not in p for p in tracer.loaded_abis)


def test_load_contract_from_spec_dispatches_by_fields():
    calls = []

    class FakeParser:
        def load_contract(self, address, path, name=None):
            calls.append(("load", address, path, name))

    parser = FakeParser()
    events_cli._load_contract_from_spec(
        parser, SimpleNamespace(address="0x1", name="C", path="p"),
    )
    events_cli._load_contract_from_spec(
        parser, SimpleNamespace(address="0x2", name=None, path="p"),
    )
    assert calls == [("load", "0x1", "p", "C"), ("load", "0x2", "p", None)]


def test_load_contract_from_spec_uses_deployment_json(tmp_path):
    deploy_dir = tmp_path / "d"
    deploy_dir.mkdir()
    (deploy_dir / "deployment.json").write_text("{}")

    captured = {}

    class FakeParser:
        def load_from_deployment(self, file):
            captured["file"] = Path(file)

    events_cli._load_contract_from_spec(
        FakeParser(), SimpleNamespace(address=None, name=None, path=str(deploy_dir)),
    )
    assert captured["file"] == deploy_dir / "deployment.json"


def test_load_contract_from_spec_warns_when_no_deployment(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()

    class FakeParser:
        pass

    events_cli._load_contract_from_spec(
        FakeParser(), SimpleNamespace(address=None, name=None, path=str(empty)),
    )
    assert "No deployment.json" in capsys.readouterr().err


def test_load_contract_from_spec_exits_when_deployment_load_fails(tmp_path, capsys):
    deploy_dir = tmp_path / "d"
    deploy_dir.mkdir()
    (deploy_dir / "deployment.json").write_text("{}")

    class FakeParser:
        def load_from_deployment(self, file):
            raise RuntimeError("bad json")

    with pytest.raises(SystemExit) as excinfo:
        events_cli._load_contract_from_spec(
            FakeParser(), SimpleNamespace(address=None, name=None, path=str(deploy_dir)),
        )
    assert excinfo.value.code == 1
    assert "bad json" in capsys.readouterr().err


def test_print_events_text_mode(monkeypatch):
    captured = {}
    import soldb.utils.helpers as helpers_mod

    def fake_print(tracer, receipt):
        captured["called_text"] = (tracer, receipt)

    monkeypatch.setattr(helpers_mod, "print_contracts_events", fake_print)
    events_cli._print_events("TRACER", "RECEIPT", json_mode=False)
    assert captured["called_text"] == ("TRACER", "RECEIPT")


def test_print_events_json_mode(monkeypatch, capsys):
    import soldb.utils.helpers as helpers_mod

    def fake_print(tracer, receipt, json_output):
        assert json_output is True
        return {"events": [], "total_events": 0}

    monkeypatch.setattr(helpers_mod, "print_contracts_events", fake_print)
    events_cli._print_events("TRACER", "RECEIPT", json_mode=True)
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"events": [], "total_events": 0}
