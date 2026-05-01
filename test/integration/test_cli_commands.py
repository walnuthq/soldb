import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from soldb.cli import trace, events, contracts, simulate
from soldb.core.transaction_tracer import FunctionCall, TraceStep, TransactionTrace


ADDR = "0x00000000000000000000000000000000000000aa"
OTHER_ADDR = "0x00000000000000000000000000000000000000bb"
FROM_ADDR = "0x0000000000000000000000000000000000000001"


def _extract_json(text):
    """Extract first JSON object from text that may contain non-JSON lines."""
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        return json.loads(match.group())
    raise ValueError(f"No JSON found in: {text}")


def make_trace(**overrides):
    defaults = dict(
        tx_hash="0xtx",
        from_addr=FROM_ADDR,
        to_addr=ADDR,
        value=0,
        input_data="0x",
        gas_used=123,
        output="0x",
        steps=[TraceStep(0, "PUSH1", 100, 1, 0, ["0x1"])],
        success=True,
    )
    defaults.update(overrides)
    return TransactionTrace(**defaults)


class FakeTracer:
    def __init__(self, rpc_url=None, quiet_mode=False):
        self.rpc_url = rpc_url
        self.quiet_mode = quiet_mode
        self.multi_contract_parser = None
        self.ethdebug_info = None
        self.ethdebug_parser = None
        self.srcmap_parser = None
        self.srcmap_info = None
        self.function_abis = {}
        self.w3 = SimpleNamespace(
            eth=SimpleNamespace(
                get_transaction_receipt=lambda tx: {"logs": []},
            ),
            to_wei=lambda v, unit: int(float(v) * 10**18),
        )
        self._abi_loaded = []
        self._trace = make_trace()

    def trace_transaction(self, tx_hash):
        return self._trace

    def analyze_function_calls(self, t):
        return [FunctionCall("f", "0x12345678", 0, 0, 1, 0, [], contract_address=ADDR)]

    def print_function_trace(self, t, calls):
        print("function trace")

    def print_trace(self, t, source_map, max_steps=None):
        print("raw trace")

    def load_abi(self, path):
        self._abi_loaded.append(path)

    def load_debug_info(self, debug_file):
        return {"mapping": True}

    def load_debug_info_auto(self, ethdebug_dir, name):
        return {"auto": True}

    def setup_stylus_bridge(self, url):
        return True

    def register_stylus_contract(self, address, name, lib_path):
        pass

    def simulate_call_trace(self, contract, from_addr, calldata, block, tx_index, value):
        return self._trace

    def snapshot_state(self):
        pass

    def is_contract_deployed(self, address):
        return address == ADDR


# ---------------------------------------------------------------------------
# trace.py
# ---------------------------------------------------------------------------


class TestTraceCommand:
    def _base_args(self, **kw):
        defaults = dict(
            rpc="http://rpc",
            tx_hash="0xtx",
            json=False,
            cross_env_bridge=None,
            stylus_contracts=None,
            interactive=False,
            raw=False,
            max_steps=10,
            ethdebug_dir=None,
            contracts=None,
            multi_contract=False,
            debug_info_from_zasm_file=None,
        )
        defaults.update(kw)
        return SimpleNamespace(**defaults)

    def test_connection_error(self, monkeypatch, capsys):
        def boom(*a, **kw):
            raise ConnectionError("offline")
        monkeypatch.setattr(trace, "TransactionTracer", boom)
        assert trace.trace_command(self._base_args()) == 1
        assert "offline" in capsys.readouterr().out

    def test_connection_error_json(self, monkeypatch, capsys):
        def boom(*a, **kw):
            raise ConnectionError("offline")
        monkeypatch.setattr(trace, "TransactionTracer", boom)
        assert trace.trace_command(self._base_args(json=True)) == 1
        out = _extract_json(capsys.readouterr().out)
        assert out["type"] == "ConnectionError"

    def test_trace_transaction_error(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.trace_transaction = lambda tx: (_ for _ in ()).throw(ValueError("bad tx"))
        monkeypatch.setattr(trace, "TransactionTracer", lambda *a, **kw: ft)
        assert trace.trace_command(self._base_args()) == 1
        assert "bad tx" in capsys.readouterr().out

    def test_trace_transaction_error_json(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.trace_transaction = lambda tx: (_ for _ in ()).throw(ValueError("bad tx"))
        monkeypatch.setattr(trace, "TransactionTracer", lambda *a, **kw: ft)
        assert trace.trace_command(self._base_args(json=True)) == 1
        out = _extract_json(capsys.readouterr().out)
        assert out["type"] == "TransactionError"

    def test_debug_trace_unavailable_text(self, monkeypatch, capsys):
        t = make_trace()
        t.debug_trace_available = False
        t.error = "method not found"
        ft = FakeTracer()
        ft._trace = t
        monkeypatch.setattr(trace, "TransactionTracer", lambda *a, **kw: ft)
        assert trace.trace_command(self._base_args()) == 1
        out = capsys.readouterr().out
        assert "debug_traceTransaction not available" in out
        assert "method not found" in out

    def test_debug_trace_unavailable_json(self, monkeypatch, capsys):
        t = make_trace()
        t.debug_trace_available = False
        t.error = None
        ft = FakeTracer()
        ft._trace = t
        monkeypatch.setattr(trace, "TransactionTracer", lambda *a, **kw: ft)
        assert trace.trace_command(self._base_args(json=True)) == 1
        out = _extract_json(capsys.readouterr().out)
        assert "DebugTraceUnavailable" in out["type"]

    def test_json_output(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(trace, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            trace, "_load_debug_info",
            lambda tracer, t, args, jm: ({}, None),
        )
        monkeypatch.setattr(
            trace.TraceSerializer, "serialize_trace",
            lambda self, *a, **kw: {"trace": "data"},
        )
        assert trace.trace_command(self._base_args(json=True)) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["trace"] == "data"

    def test_raw_output(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(trace, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            trace, "_load_debug_info",
            lambda tracer, t, args, jm: ({}, None),
        )
        assert trace.trace_command(self._base_args(raw=True)) == 0
        assert "raw trace" in capsys.readouterr().out

    def test_stylus_bridge_setup(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(trace, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            trace, "_load_debug_info",
            lambda tracer, t, args, jm: ({}, None),
        )
        args = self._base_args(cross_env_bridge="http://bridge:8765")
        assert trace.trace_command(args) == 0

    def test_extract_error_detail_non_string(self):
        assert trace._extract_error_detail(42) == "42"
        assert trace._extract_error_detail(None) is None

    def test_extract_error_detail_dict_string(self):
        assert trace._extract_error_detail("{'message': 'oops'}") == "oops"

    def test_extract_error_detail_plain(self):
        assert trace._extract_error_detail("plain error") == "plain error"

    def test_find_debug_file_for_trace_no_to_addr(self, monkeypatch, tmp_path):
        t = make_trace(to_addr=None)
        import os
        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            debug_dir = tmp_path / "debug"
            debug_dir.mkdir()
            (debug_dir / "deployment.json").write_text(
                json.dumps({"transaction": "0xtx"})
            )
            (debug_dir / "Contract.zasm").write_text("zasm data")
            result = trace._find_debug_file_for_trace(t, "0xtx")
            assert result is not None and result.endswith(".zasm")
        finally:
            os.chdir(old_cwd)

    def test_find_debug_file_for_trace_with_to_addr(self, monkeypatch):
        t = make_trace()
        # The function does `from soldb.cli.common import find_debug_file` inside
        from soldb.cli import common
        monkeypatch.setattr(common, "find_debug_file", lambda addr: "/path/to/debug")
        result = trace._find_debug_file_for_trace(t, "0xtx")
        assert result == "/path/to/debug"

    def test_load_debug_info_with_zasm_file(self, monkeypatch):
        ft = FakeTracer()
        args = self._base_args(debug_info_from_zasm_file="/tmp/test.zasm")
        source_map, debug_file = trace._load_debug_info(ft, make_trace(), args, False)
        assert debug_file == "/tmp/test.zasm"
        assert source_map == {"mapping": True}

    def test_get_entrypoint_ethdebug_dir_from_multi_parser(self):
        contract = SimpleNamespace(debug_dir=Path("/dbg"))
        multi = SimpleNamespace(
            get_contract_at_address=lambda addr: contract
        )
        ft = FakeTracer()
        ft.multi_contract_parser = multi
        t = make_trace()
        args = SimpleNamespace(ethdebug_dir=None)
        result = trace._get_entrypoint_ethdebug_dir(ft, t, args)
        assert result == "/dbg"

    def test_get_entrypoint_ethdebug_dir_from_args(self, monkeypatch):
        ft = FakeTracer()
        t = make_trace()
        spec = SimpleNamespace(address=ADDR, name="Token", path="/out")
        monkeypatch.setattr(
            trace.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [spec],
        )
        args = SimpleNamespace(ethdebug_dir=["/out"])
        result = trace._get_entrypoint_ethdebug_dir(ft, t, args)
        assert result == "/out"

    def test_get_entrypoint_ethdebug_dir_parse_error(self, monkeypatch):
        ft = FakeTracer()
        t = make_trace()
        monkeypatch.setattr(
            trace.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: (_ for _ in ()).throw(ValueError("bad")),
        )
        args = SimpleNamespace(ethdebug_dir=["0xaa:Token:out"])
        result = trace._get_entrypoint_ethdebug_dir(ft, t, args)
        assert result == "out"

    def test_get_entrypoint_contract_name_from_multi(self):
        contract = SimpleNamespace(name="Token", debug_dir=Path("/dbg"))
        multi = SimpleNamespace(
            get_contract_at_address=lambda addr: contract
        )
        ft = FakeTracer()
        ft.multi_contract_parser = multi
        t = make_trace()
        args = SimpleNamespace(ethdebug_dir=None)
        result = trace._get_entrypoint_contract_name(ft, t, args)
        assert result == "Token"

    def test_get_entrypoint_contract_name_from_args(self, monkeypatch):
        ft = FakeTracer()
        t = make_trace()
        spec = SimpleNamespace(address=ADDR, name="Token", path="/out")
        monkeypatch.setattr(
            trace.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [spec],
        )
        args = SimpleNamespace(ethdebug_dir=["/out"])
        result = trace._get_entrypoint_contract_name(ft, t, args)
        assert result == "Token"


# ---------------------------------------------------------------------------
# events.py
# ---------------------------------------------------------------------------


class TestEventsCommand:
    def _base_args(self, **kw):
        defaults = dict(
            rpc_url="http://rpc",
            tx_hash="0xtx",
            json_events=False,
            ethdebug_dir=None,
            contracts=None,
            multi_contract=False,
        )
        defaults.update(kw)
        return SimpleNamespace(**defaults)

    def test_connection_error(self, monkeypatch, capsys):
        def boom(*a, **kw):
            raise ConnectionError("down")
        monkeypatch.setattr(events, "TransactionTracer", boom)
        assert events.list_events_command(self._base_args()) == 1
        assert "down" in capsys.readouterr().out

    def test_receipt_error_text(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.w3.eth.get_transaction_receipt = lambda tx: (_ for _ in ()).throw(
            ValueError("no receipt")
        )
        monkeypatch.setattr(events, "TransactionTracer", lambda *a, **kw: ft)
        assert events.list_events_command(self._base_args()) == 1
        assert "no receipt" in capsys.readouterr().out

    def test_receipt_error_json(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.w3.eth.get_transaction_receipt = lambda tx: (_ for _ in ()).throw(
            ValueError("no receipt")
        )
        monkeypatch.setattr(events, "TransactionTracer", lambda *a, **kw: ft)
        assert events.list_events_command(self._base_args(json_events=True)) == 1
        out = _extract_json(capsys.readouterr().out)
        assert "TransactionReceiptError" in out["type"]

    def test_print_events_text(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(events, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            events, "_print_events",
            lambda tracer, receipt, jm: print("decoded events"),
        )
        assert events.list_events_command(self._base_args()) == 0
        assert "decoded events" in capsys.readouterr().out

    def test_print_events_json(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(events, "TransactionTracer", lambda *a, **kw: ft)

        def fake_print_events(tracer, receipt, json_mode):
            from soldb.utils.helpers import print_contracts_events
            # Just exercise the json path
            if json_mode:
                print(json.dumps({"events": []}))
            else:
                print("events")

        monkeypatch.setattr(events, "_print_events", fake_print_events)
        assert events.list_events_command(self._base_args(json_events=True)) == 0

    def test_load_events_debug_info_non_multi(self, monkeypatch):
        ft = FakeTracer()
        # Should return early without loading anything
        events._load_events_debug_info(ft, self._base_args())
        assert ft.multi_contract_parser is None

    def test_load_events_debug_info_multi_with_ethdebug(self, monkeypatch):
        ft = FakeTracer()

        class FakeMultiParser:
            def __init__(self):
                self.contracts = {}

        monkeypatch.setattr(events, "MultiContractETHDebugParser", FakeMultiParser)
        spec = SimpleNamespace(address=ADDR, name="Token", path="/out")
        monkeypatch.setattr(
            events.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [spec],
        )
        monkeypatch.setattr(
            events, "_load_contract_from_spec",
            lambda mp, s: None,
        )
        args = self._base_args(
            multi_contract=True,
            ethdebug_dir=["/out"],
        )
        events._load_events_debug_info(ft, args)
        assert ft.multi_contract_parser is not None

    def test_load_contract_from_spec_address_and_name(self, monkeypatch):
        loaded = []

        class FakeMP:
            def load_contract(self, *a):
                loaded.append(a)

        spec = SimpleNamespace(address=ADDR, name="Token", path="/out")
        events._load_contract_from_spec(FakeMP(), spec)
        assert loaded == [(ADDR, "/out", "Token")]

    def test_load_contract_from_spec_address_only(self, monkeypatch):
        loaded = []

        class FakeMP:
            def load_contract(self, *a):
                loaded.append(a)

        spec = SimpleNamespace(address=ADDR, name=None, path="/out")
        events._load_contract_from_spec(FakeMP(), spec)
        assert loaded == [(ADDR, "/out")]

    def test_load_contract_from_spec_no_address_with_deployment(self, monkeypatch, tmp_path):
        loaded = []

        class FakeMP:
            def load_from_deployment(self, path):
                loaded.append(str(path))

        dep = tmp_path / "deployment.json"
        dep.write_text("{}")
        spec = SimpleNamespace(address=None, name=None, path=str(tmp_path))
        events._load_contract_from_spec(FakeMP(), spec)
        assert len(loaded) == 1

    def test_load_contract_from_spec_no_deployment(self, monkeypatch, tmp_path, capsys):
        class FakeMP:
            pass

        spec = SimpleNamespace(address=None, name=None, path=str(tmp_path))
        events._load_contract_from_spec(FakeMP(), spec)
        # Should print warning to stderr
        # (sys.stderr.write in actual code)


# ---------------------------------------------------------------------------
# contracts.py
# ---------------------------------------------------------------------------


class TestContractsCommand:
    def _base_args(self, **kw):
        defaults = dict(
            rpc_url="http://rpc",
            tx_hash="0xtx",
            ethdebug_dir=None,
            contracts=None,
            multi_contract=False,
        )
        defaults.update(kw)
        return SimpleNamespace(**defaults)

    def test_connection_error(self, monkeypatch, capsys):
        def boom(*a, **kw):
            raise ConnectionError("offline")
        monkeypatch.setattr(contracts, "TransactionTracer", boom)
        assert contracts.list_contracts_command(self._base_args()) == 1
        assert "offline" in capsys.readouterr().out

    def test_trace_error(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.trace_transaction = lambda tx: (_ for _ in ()).throw(ValueError("bad"))
        monkeypatch.setattr(contracts, "TransactionTracer", lambda *a, **kw: ft)
        assert contracts.list_contracts_command(self._base_args()) == 1
        assert "bad" in capsys.readouterr().out

    def test_success_non_multi(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(contracts, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            contracts, "_print_contracts_in_transaction",
            lambda tracer, t: print("contracts list"),
        )
        assert contracts.list_contracts_command(self._base_args()) == 0
        assert "contracts list" in capsys.readouterr().out

    def test_load_contracts_debug_info_non_multi(self, monkeypatch):
        ft = FakeTracer()
        contracts._load_contracts_debug_info(ft, self._base_args())
        assert ft.multi_contract_parser is None

    def test_load_contracts_debug_info_multi(self, monkeypatch, tmp_path):
        ft = FakeTracer()

        class FakeMultiParser:
            def __init__(self):
                self.contracts = {}

        monkeypatch.setattr(contracts, "MultiContractETHDebugParser", FakeMultiParser)
        spec = SimpleNamespace(address=ADDR, name="Token", path="/out")
        monkeypatch.setattr(
            contracts.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [spec],
        )

        loaded = []

        def fake_load(mp, s):
            loaded.append(s)

        monkeypatch.setattr(contracts, "_load_contract_from_spec", fake_load)

        args = self._base_args(multi_contract=True, ethdebug_dir=["/out"])
        contracts._load_contracts_debug_info(ft, args)
        assert ft.multi_contract_parser is not None
        assert len(loaded) == 1

    def test_load_contract_from_spec_with_address_name(self, monkeypatch):
        loaded = []

        class FakeMP:
            def load_contract(self, *a):
                loaded.append(a)

        spec = SimpleNamespace(address=ADDR, name="Token", path="/out")
        contracts._load_contract_from_spec(FakeMP(), spec)
        assert loaded == [(ADDR, "/out", "Token")]

    def test_load_contract_from_spec_address_only(self, monkeypatch):
        loaded = []

        class FakeMP:
            def load_contract(self, *a):
                loaded.append(a)

        spec = SimpleNamespace(address=ADDR, name=None, path="/out")
        contracts._load_contract_from_spec(FakeMP(), spec)
        assert loaded == [(ADDR, "/out")]

    def test_load_contract_from_spec_deployment_file(self, monkeypatch, tmp_path):
        loaded = []

        class FakeMP:
            def load_from_deployment(self, path):
                loaded.append(str(path))

        dep = tmp_path / "deployment.json"
        dep.write_text("{}")
        spec = SimpleNamespace(address=None, name=None, path=str(tmp_path))
        contracts._load_contract_from_spec(FakeMP(), spec)
        assert len(loaded) == 1

    def test_load_contract_from_spec_file_not_found(self, monkeypatch, tmp_path):
        class FakeMP:
            def load_contract(self, *a):
                raise FileNotFoundError("missing ethdebug")

        monkeypatch.setattr(
            "soldb.parsers.ethdebug.ETHDebugParser._get_compiler_info",
            lambda path: None,
        )
        spec = SimpleNamespace(address=ADDR, name="Token", path=str(tmp_path))
        with pytest.raises(SystemExit):
            contracts._load_contract_from_spec(FakeMP(), spec)

    def test_load_contract_from_spec_with_compiler_info(self, monkeypatch, tmp_path, capsys):
        class FakeMP:
            def load_contract(self, *a):
                raise FileNotFoundError("missing ethdebug")

        monkeypatch.setattr(
            "soldb.parsers.ethdebug.ETHDebugParser._get_compiler_info",
            lambda path: "solc 0.8.16",
        )
        spec = SimpleNamespace(address=ADDR, name="Token", path=str(tmp_path))
        with pytest.raises(SystemExit):
            contracts._load_contract_from_spec(FakeMP(), spec)
        out = capsys.readouterr().out
        assert "solc 0.8.16" in out


# ---------------------------------------------------------------------------
# simulate.py
# ---------------------------------------------------------------------------


class TestSimulateCommand:
    def _base_args(self, **kw):
        defaults = dict(
            rpc_url="http://rpc",
            from_addr=FROM_ADDR,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["7"],
            raw_data=None,
            value=0,
            interactive=False,
            cross_env_bridge=None,
            stylus_contracts=None,
            ethdebug_dir=None,
            contracts=None,
            multi_contract=False,
            json=False,
            raw=False,
            max_steps=10,
            block=None,
            tx_index=None,
        )
        defaults.update(kw)
        return SimpleNamespace(**defaults)

    def test_connection_error_text(self, monkeypatch, capsys):
        def boom(*a, **kw):
            raise ConnectionError("down")
        monkeypatch.setattr(simulate, "TransactionTracer", boom)
        assert simulate.simulate_command(self._base_args()) == 1
        assert "down" in capsys.readouterr().out

    def test_connection_error_json(self, monkeypatch, capsys):
        def boom(*a, **kw):
            raise ConnectionError("down")
        monkeypatch.setattr(simulate, "TransactionTracer", boom)
        assert simulate.simulate_command(self._base_args(json=True)) == 1
        out = _extract_json(capsys.readouterr().out)
        assert out["type"] == "ConnectionError"

    def test_invalid_value_text(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(simulate, "TransactionTracer", lambda *a, **kw: ft)
        assert simulate.simulate_command(self._base_args(value="bad_value")) == 1
        assert "Invalid value" in capsys.readouterr().out

    def test_invalid_value_json(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(simulate, "TransactionTracer", lambda *a, **kw: ft)
        assert simulate.simulate_command(self._base_args(value="bad_value", json=True)) == 1
        out = _extract_json(capsys.readouterr().out)
        assert "InvalidValue" in out["type"]

    def test_invalid_contract_address(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(simulate, "TransactionTracer", lambda *a, **kw: ft)
        assert simulate.simulate_command(self._base_args(contract_address="bad")) == 1
        assert "Contract not found" in capsys.readouterr().out

    def test_normalize_addresses(self):
        args = SimpleNamespace(
            from_addr="0x0000000000000000000000000000000000000001",
            contract_address=ADDR,
        )
        result = simulate._normalize_addresses(args)
        # Should be checksummed
        assert result.from_addr.startswith("0x")
        assert result.contract_address.startswith("0x")

    def test_parse_value_zero(self):
        ft = FakeTracer()
        assert simulate._parse_value(SimpleNamespace(value=0), ft, False) == 0

    def test_parse_value_ether(self):
        ft = FakeTracer()
        result = simulate._parse_value(SimpleNamespace(value="1ether"), ft, False)
        assert result == 10**18

    def test_parse_value_wei(self):
        ft = FakeTracer()
        result = simulate._parse_value(SimpleNamespace(value="1000"), ft, False)
        assert result == 1000

    def test_simulate_with_raw_data_success(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(simulate, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            simulate, "_load_debug_info_for_simulate",
            lambda tracer, args, jm: {},
        )
        args = self._base_args(
            raw_data="0x12345678",
            function_signature=None,
            function_args=[],
        )
        assert simulate.simulate_command(args) == 0

    def test_simulate_with_raw_data_error(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.simulate_call_trace = lambda *a: (_ for _ in ()).throw(RuntimeError("fail"))
        result = simulate._simulate_with_raw_data(
            ft,
            self._base_args(raw_data="0x12345678"),
            {}, 0, False,
        )
        assert result == 1
        assert "fail" in capsys.readouterr().out

    def test_simulate_with_raw_data_error_json(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.simulate_call_trace = lambda *a: (_ for _ in ()).throw(RuntimeError("fail"))
        result = simulate._simulate_with_raw_data(
            ft,
            self._base_args(raw_data="0x12345678"),
            {}, 0, True,
        )
        assert result == 1
        out = _extract_json(capsys.readouterr().out)
        assert "SimulationError" in out["type"]

    def test_simulate_with_function_no_signature(self, capsys):
        ft = FakeTracer()
        result = simulate._simulate_with_function(ft, SimpleNamespace(function_signature=None), {}, 0, False)
        assert result == 1
        assert "function_signature is required" in capsys.readouterr().out

    def test_simulate_with_function_no_abi_warning(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.function_abis = {}
        monkeypatch.setattr(simulate, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            simulate, "_load_debug_info_for_simulate",
            lambda tracer, args, jm: {},
        )
        args = self._base_args()
        assert simulate.simulate_command(args) == 0
        out = capsys.readouterr().out
        assert "No ABI files found" in out

    def test_simulate_with_function_abi_mismatch(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.function_abis = {
            "0x1": {"name": "get", "inputs": []},
        }
        monkeypatch.setattr(simulate, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            simulate, "_load_debug_info_for_simulate",
            lambda tracer, args, jm: {},
        )
        args = self._base_args()
        assert simulate.simulate_command(args) == 0
        out = capsys.readouterr().out
        assert "not found in ABI" in out

    def test_simulate_wrong_arg_count(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.function_abis = {}
        monkeypatch.setattr(simulate, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            simulate, "_load_debug_info_for_simulate",
            lambda tracer, args, jm: {},
        )
        args = self._base_args(function_args=[])  # expects 1, got 0
        assert simulate.simulate_command(args) == 1

    def test_simulate_parse_int_error(self, monkeypatch, capsys):
        """Passing a non-integer for uint256 raises ValueError during arg parsing."""
        ft = FakeTracer()
        ft.function_abis = {}
        monkeypatch.setattr(simulate, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            simulate, "_load_debug_info_for_simulate",
            lambda tracer, args, jm: {},
        )
        # ValueError from int("not_a_number", 0) propagates
        args = self._base_args(function_args=["not_a_number"])
        with pytest.raises(ValueError):
            simulate.simulate_command(args)

    def test_simulate_execution_error_json(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.function_abis = {}
        ft.simulate_call_trace = lambda *a: (_ for _ in ()).throw(RuntimeError("boom"))
        result = simulate._simulate_with_function(
            ft,
            self._base_args(json=True),
            {}, 0, True,
        )
        assert result == 1
        out = _extract_json(capsys.readouterr().out)
        assert "SimulationError" in out["type"]

    def test_output_trace_json(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(
            simulate.TraceSerializer, "serialize_trace",
            lambda self, *a, **kw: {"result": "ok"},
        )
        args = self._base_args(contract_address=ADDR)
        result = simulate._output_trace(ft, make_trace(), args, {}, True)
        assert result == 0
        out = json.loads(capsys.readouterr().out)
        assert out["result"] == "ok"

    def test_output_trace_raw(self, monkeypatch, capsys):
        ft = FakeTracer()
        args = self._base_args(raw=True, max_steps=5)
        result = simulate._output_trace(ft, make_trace(), args, {}, False)
        assert result == 0
        assert "raw trace" in capsys.readouterr().out

    def test_output_trace_function(self, monkeypatch, capsys):
        ft = FakeTracer()
        args = self._base_args()
        result = simulate._output_trace(ft, make_trace(), args, {}, False)
        assert result == 0
        assert "function trace" in capsys.readouterr().out

    def test_load_debug_info_no_dirs(self, monkeypatch):
        ft = FakeTracer()
        args = self._base_args()
        result = simulate._load_debug_info_for_simulate(ft, args, False)
        assert result == {}

    def test_parse_single_arg_simple_types(self):
        assert simulate._parse_single_arg_simple("42", "uint256") == 42
        assert simulate._parse_single_arg_simple("0xff", "uint8") == 255
        assert simulate._parse_single_arg_simple(ADDR, "address") == ADDR
        assert simulate._parse_single_arg_simple("0xab", "bytes2") == bytes.fromhex("ab")
        assert simulate._parse_single_arg_simple("ab", "bytes2") == bytes.fromhex("ab")
        assert simulate._parse_single_arg_simple("hello", "string") == "hello"
        assert simulate._parse_single_arg_simple("true", "bool") is True
        assert simulate._parse_single_arg_simple("false", "bool") is False
        assert simulate._parse_single_arg_simple("1", "bool") is True
        assert simulate._parse_single_arg_simple("0", "bool") is False

    def test_parse_single_arg_with_abi(self):
        abi_input = {"type": "uint256", "name": "x"}
        assert simulate._parse_single_arg("42", "uint256", abi_input) == 42
        assert simulate._parse_single_arg(ADDR, "address", abi_input) == ADDR
        assert simulate._parse_single_arg("0xab", "bytes2", abi_input) == bytes.fromhex("ab")

    def test_parse_single_arg_tuple(self):
        abi_input = {
            "type": "tuple",
            "name": "t",
            "components": [
                {"type": "uint256", "name": "a"},
            ],
        }
        result = simulate._parse_single_arg("[42]", "tuple", abi_input)
        assert result is not None

    def test_parse_single_arg_tuple_error(self, capsys):
        abi_input = {"type": "tuple", "name": "t"}
        result = simulate._parse_single_arg("not_valid", "tuple", abi_input)
        assert result is None

    def test_encode_calldata_success(self):
        result = simulate._encode_calldata("set", ["uint256"], [42])
        assert result.startswith("0x")
        assert len(result) > 10

    def test_encode_calldata_failure(self, capsys):
        result = simulate._encode_calldata("set", ["uint256"], ["bad"])
        assert result is None
        assert "Error encoding" in capsys.readouterr().out

    def test_find_abi_item_tuple_conversion(self):
        ft = FakeTracer()
        ft.function_abis = {
            "0x1": {
                "name": "foo",
                "inputs": [{"type": "tuple", "name": "t"}],
            }
        }
        result = simulate._find_abi_item(ft, "foo", ["(uint256,bool)"])
        assert result is not None
        assert result["name"] == "foo"

    def test_interactive_mode_no_contract(self, capsys):
        result = simulate._interactive_mode(
            SimpleNamespace(contract_address=None), FakeTracer()
        )
        assert result == 1

    def test_interactive_mode_invalid_contract(self, capsys):
        args = SimpleNamespace(
            contract_address="not_valid",
            function_signature="f()",
        )
        result = simulate._interactive_mode(args, FakeTracer())
        assert result == 1
        assert "Contract not found" in capsys.readouterr().out

    def test_interactive_mode_address_no_ethdebug(self, capsys):
        args = SimpleNamespace(
            contract_address=ADDR,
            function_signature="f()",
            function_args=[],
            interactive=True,
            ethdebug_dir=None,
            contracts=None,
        )
        result = simulate._interactive_mode(args, FakeTracer())
        assert result == 1
        assert "ethdebug-dir is required" in capsys.readouterr().out

    def test_interactive_mode_no_function(self, capsys):
        args = SimpleNamespace(
            contract_address=ADDR,
            function_signature=None,
        )
        result = simulate._interactive_mode(args, FakeTracer())
        assert result == 1
        assert "function signature is required" in capsys.readouterr().out

    def test_get_ethdebug_dir_for_interactive_multi(self):
        contract = SimpleNamespace(debug_dir=Path("/dbg"), name="Token")
        multi = SimpleNamespace(
            get_contract_at_address=lambda addr: contract
        )
        ft = FakeTracer()
        ft.multi_contract_parser = multi
        args = SimpleNamespace(
            contract_address=ADDR,
            ethdebug_dir=None,
        )
        d, n = simulate._get_ethdebug_dir_for_interactive(ft, args)
        assert d == "/dbg"
        assert n == "Token"

    def test_get_ethdebug_dir_for_interactive_parsed(self, monkeypatch):
        ft = FakeTracer()
        spec = SimpleNamespace(address=ADDR, name="Token", path="/out")
        monkeypatch.setattr(
            simulate.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [spec],
        )
        args = SimpleNamespace(
            contract_address=ADDR,
            ethdebug_dir=["/out"],
        )
        d, n = simulate._get_ethdebug_dir_for_interactive(ft, args)
        assert d == "/out"
        assert n == "Token"

    def test_get_ethdebug_dir_for_interactive_parse_error(self, monkeypatch):
        ft = FakeTracer()
        monkeypatch.setattr(
            simulate.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: (_ for _ in ()).throw(ValueError("bad")),
        )
        args = SimpleNamespace(
            contract_address=ADDR,
            ethdebug_dir=["0xaa:Token:out"],
        )
        d, n = simulate._get_ethdebug_dir_for_interactive(ft, args)
        assert d == "out"
        assert n == "Token"

    def test_get_ethdebug_dir_for_interactive_two_parts(self, monkeypatch):
        ft = FakeTracer()
        monkeypatch.setattr(
            simulate.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: (_ for _ in ()).throw(ValueError("bad")),
        )
        args = SimpleNamespace(
            contract_address=ADDR,
            ethdebug_dir=["0xaa:out"],
        )
        d, n = simulate._get_ethdebug_dir_for_interactive(ft, args)
        assert d == "out"
        assert n is None

    def test_setup_auto_deploy_error(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "soldb.core.auto_deploy.AutoDeployDebugger.__init__",
            lambda self, **kw: (_ for _ in ()).throw(RuntimeError("compile failed")),
        )
        args = self._base_args(
            contract_address="/tmp/Token.sol",
            solc_path="solc",
            dual_compile=False,
            keep_build=False,
            output_dir="./out",
            production_dir="./build",
            save_config=False,
            verify_version=False,
            no_cache=False,
            cache_dir=".cache",
            fork_url=None,
            fork_block=None,
            no_snapshot=False,
            keep_fork=False,
            reuse_fork=False,
            fork_port=8545,
        )
        result = simulate._setup_auto_deploy(args)
        assert result == (None, None, None, None)

    def test_load_abi_for_contract_with_name(self, tmp_path):
        ft = FakeTracer()
        ft.ethdebug_info = SimpleNamespace(contract_name="Token")
        abi = tmp_path / "Token.abi"
        abi.write_text("[]")
        simulate._load_abi_for_contract(ft, str(tmp_path))
        assert str(abi) in ft._abi_loaded

    def test_load_abi_for_contract_no_name(self, tmp_path):
        ft = FakeTracer()
        ft.ethdebug_info = None
        ft.srcmap_info = None
        abi = tmp_path / "Contract.abi"
        abi.write_text("[]")
        simulate._load_abi_for_contract(ft, str(tmp_path))
        assert len(ft._abi_loaded) == 1

    def test_try_load_abi_from_common_locations(self, monkeypatch, tmp_path):
        import os
        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            (tmp_path / "Token.abi").write_text("[]")
            ft = FakeTracer()
            simulate._try_load_abi_from_common_locations(ft, ADDR)
            assert len(ft._abi_loaded) == 1
        finally:
            os.chdir(old_cwd)

    def test_stylus_bridge_with_contracts(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(simulate, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            simulate, "_load_debug_info_for_simulate",
            lambda tracer, args, jm: {},
        )

        # Mock ContractRegistry
        class FakeContract:
            address = ADDR
            name = "StylusToken"
            lib_path = "/lib.so"

        class FakeRegistry:
            def load_from_file(self, path):
                return 1
            def get_stylus_contracts(self):
                return [FakeContract()]

        monkeypatch.setattr(
            "soldb.cross_env.contract_registry.ContractRegistry",
            FakeRegistry,
        )

        args = self._base_args(
            cross_env_bridge="http://bridge:8765",
            stylus_contracts="/contracts.json",
        )
        assert simulate.simulate_command(args) == 0
        out = capsys.readouterr().out
        assert "STYLUS" in out


# ---------------------------------------------------------------------------
# trace.py — additional coverage for multi/single contract loading
# ---------------------------------------------------------------------------


class TestTraceMultiContractLoading:
    def _base_args(self, **kw):
        defaults = dict(
            rpc="http://rpc", tx_hash="0xtx", json=False,
            cross_env_bridge=None, stylus_contracts=None,
            interactive=False, raw=False, max_steps=10,
            ethdebug_dir=None, contracts=None, multi_contract=False,
            debug_info_from_zasm_file=None,
        )
        defaults.update(kw)
        return SimpleNamespace(**defaults)

    def test_load_multi_contract_debug_info(self, monkeypatch):
        ft = FakeTracer()
        t = make_trace()

        parser_obj = SimpleNamespace(get_source_mapping=lambda: {"src": True})
        abi_dir = Path("/fake")
        contract = SimpleNamespace(
            parser=SimpleNamespace(), srcmap_parser=None,
            ethdebug_info="info", srcmap_info=None,
            debug_dir=abi_dir, name="Token",
            get_parser=lambda: parser_obj,
        )
        fake_multi = SimpleNamespace(
            get_contract_at_address=lambda addr: contract,
            contracts={ADDR: contract},
        )
        monkeypatch.setattr(
            trace, "load_multi_contract_parser",
            lambda dirs, cf, jm: (fake_multi, []),
        )
        monkeypatch.setattr(
            trace, "load_abi_files", lambda tracer, mp: None,
        )
        args = self._base_args(multi_contract=True, ethdebug_dir=["/out"])
        result = trace._load_multi_contract_debug_info(ft, t, args, False)
        assert result == {"src": True}

    def test_load_multi_contract_with_errors(self, monkeypatch, capsys):
        ft = FakeTracer()
        t = make_trace()
        monkeypatch.setattr(
            trace, "load_multi_contract_parser",
            lambda dirs, cf, jm: (None, ["Error: bad contract"]),
        )
        args = self._base_args(multi_contract=True, ethdebug_dir=["/out"])
        result = trace._load_multi_contract_debug_info(ft, t, args, False)
        assert result is None

    def test_load_single_contract_debug_info(self, monkeypatch, tmp_path):
        ft = FakeTracer()
        ft.ethdebug_info = SimpleNamespace(contract_name="Token")
        t = make_trace()
        spec = SimpleNamespace(address=ADDR, name="Token", path=str(tmp_path))
        monkeypatch.setattr(
            trace.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [spec],
        )
        monkeypatch.setattr(
            trace.ETHDebugDirParser, "find_abi_file",
            lambda s, cn: str(tmp_path / "Token.abi"),
        )
        (tmp_path / "Token.abi").write_text("[]")

        class FakeMulti:
            def __init__(self):
                self.contracts = {}
            def load_contract(self, *a):
                pass

        monkeypatch.setattr(trace, "MultiContractETHDebugParser", FakeMulti)
        monkeypatch.setattr(trace, "load_abi_files", lambda t, mp: None)

        args = self._base_args(
            ethdebug_dir=[str(tmp_path)], interactive=False,
        )
        result = trace._load_single_contract_debug_info(ft, t, args, False)
        assert result == {"auto": True}

    def test_load_single_contract_file_not_found(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.load_debug_info_auto = lambda *a: (_ for _ in ()).throw(
            FileNotFoundError("missing ethdebug")
        )
        t = make_trace()
        spec = SimpleNamespace(address=ADDR, name="Token", path="/fake")
        monkeypatch.setattr(
            trace.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [spec],
        )
        monkeypatch.setattr(
            "soldb.parsers.ethdebug.ETHDebugParser._get_compiler_info",
            lambda path: "solc 0.8.31",
        )

        args = self._base_args(ethdebug_dir=["/fake"], interactive=False)
        result = trace._load_single_contract_debug_info(ft, t, args, False)
        assert result is None
        assert "missing ethdebug" in capsys.readouterr().out

    def test_load_debug_info_multi_mode(self, monkeypatch):
        ft = FakeTracer()
        t = make_trace()
        monkeypatch.setattr(
            trace, "_load_multi_contract_debug_info",
            lambda tracer, t, args, jm: {"multi": True},
        )
        args = self._base_args(multi_contract=True, ethdebug_dir=["/out"])
        source_map, debug_file = trace._load_debug_info(ft, t, args, False)
        assert source_map == {"multi": True}

    def test_load_debug_info_multi_mode_returns_none(self, monkeypatch):
        ft = FakeTracer()
        t = make_trace()
        monkeypatch.setattr(
            trace, "_load_multi_contract_debug_info",
            lambda tracer, t, args, jm: None,
        )
        args = self._base_args(multi_contract=True, ethdebug_dir=["/out"])
        source_map, debug_file = trace._load_debug_info(ft, t, args, False)
        assert source_map is None

    def test_load_debug_info_single_dir(self, monkeypatch):
        ft = FakeTracer()
        t = make_trace()
        monkeypatch.setattr(
            trace, "_load_single_contract_debug_info",
            lambda tracer, t, args, jm: {"single": True},
        )
        args = self._base_args(ethdebug_dir=["/out"])
        source_map, debug_file = trace._load_debug_info(ft, t, args, False)
        assert source_map == {"single": True}

    def test_stylus_bridge_with_contracts(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(trace, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            trace, "_load_debug_info",
            lambda tracer, t, args, jm: ({}, None),
        )

        class FakeContract:
            address = ADDR
            name = "StylusToken"
            lib_path = "/lib.so"

        class FakeRegistry:
            def load_from_file(self, path):
                return 1
            def get_stylus_contracts(self):
                return [FakeContract()]

        monkeypatch.setattr(
            "soldb.cross_env.contract_registry.ContractRegistry",
            FakeRegistry,
        )

        args = self._base_args(
            cross_env_bridge="http://bridge:8765",
            stylus_contracts="/contracts.json",
        )
        assert trace.trace_command(args) == 0
        out = capsys.readouterr().out
        assert "STYLUS" in out

    def test_stylus_bridge_load_failure(self, monkeypatch, capsys):
        ft = FakeTracer()
        monkeypatch.setattr(trace, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            trace, "_load_debug_info",
            lambda tracer, t, args, jm: ({}, None),
        )

        monkeypatch.setattr(
            "soldb.cross_env.contract_registry.ContractRegistry",
            lambda: (_ for _ in ()).throw(RuntimeError("bad registry")),
        )

        args = self._base_args(
            cross_env_bridge="http://bridge:8765",
            stylus_contracts="/contracts.json",
        )
        assert trace.trace_command(args) == 0
        out = capsys.readouterr().out
        assert "Failed to load" in out


# ---------------------------------------------------------------------------
# common.py — additional coverage
# ---------------------------------------------------------------------------

from soldb.cli import common


class TestCommonAdditional:
    def test_load_multi_contract_parser_mapping_error(self, monkeypatch):
        class BadParser:
            contracts = {}
            def load_from_mapping_file(self, path):
                raise RuntimeError("bad file")
        monkeypatch.setattr(common, "MultiContractETHDebugParser", BadParser)
        parser, errors = common.load_multi_contract_parser([], contracts_file="/bad")
        assert len(errors) == 1
        assert "bad file" in errors[0]

    def test_load_multi_contract_parser_mapping_success(self, monkeypatch, tmp_path):
        class FakeParser:
            contracts = {}
            loaded_files = []
            def load_from_mapping_file(self, path):
                self.loaded_files.append(path)
        monkeypatch.setattr(common, "MultiContractETHDebugParser", lambda: FakeParser())
        parser, errors = common.load_multi_contract_parser([], contracts_file="/ok.json")
        assert errors == []
        assert parser.loaded_files == ["/ok.json"]

    def test_load_multi_contract_parser_file_not_found_with_compiler(self, monkeypatch, tmp_path):
        class FakeParser:
            contracts = {}
            def load_contract(self, *a):
                raise FileNotFoundError("missing files")
        monkeypatch.setattr(common, "MultiContractETHDebugParser", lambda: FakeParser())
        spec = SimpleNamespace(address=ADDR, name="Token", path=str(tmp_path))
        monkeypatch.setattr(
            common.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [spec],
        )
        monkeypatch.setattr(
            "soldb.parsers.ethdebug.ETHDebugParser._get_compiler_info",
            lambda path: "solc 0.8.31",
        )
        parser, errors = common.load_multi_contract_parser([str(tmp_path)])
        assert len(errors) == 1
        assert "solc 0.8.31" in errors[0]

    def test_load_multi_contract_parser_file_not_found(self, monkeypatch, tmp_path):
        class FakeParser:
            contracts = {}
            def load_contract(self, *a):
                raise FileNotFoundError("no ethdebug")
        monkeypatch.setattr(common, "MultiContractETHDebugParser", lambda: FakeParser())
        spec = SimpleNamespace(address=ADDR, name="Token", path=str(tmp_path))
        monkeypatch.setattr(
            common.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [spec],
        )
        monkeypatch.setattr(
            "soldb.parsers.ethdebug.ETHDebugParser._get_compiler_info",
            lambda path: None,
        )
        parser, errors = common.load_multi_contract_parser([str(tmp_path)])
        assert len(errors) == 1
        assert "no ethdebug" in errors[0]

    def test_load_multi_contract_parser_unexpected_error(self, monkeypatch, tmp_path):
        class FakeParser:
            contracts = {}
            def load_contract(self, *a):
                raise RuntimeError("unexpected")
        monkeypatch.setattr(common, "MultiContractETHDebugParser", lambda: FakeParser())
        spec = SimpleNamespace(address=ADDR, name="Token", path=str(tmp_path))
        monkeypatch.setattr(
            common.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [spec],
        )
        parser, errors = common.load_multi_contract_parser([str(tmp_path)])
        assert len(errors) == 1
        assert "Unexpected" in errors[0]

    def test_load_multi_contract_parser_parse_error(self, monkeypatch):
        monkeypatch.setattr(
            common.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: (_ for _ in ()).throw(ValueError("bad format")),
        )
        parser, errors = common.load_multi_contract_parser(["/bad"])
        assert len(errors) == 1
        assert "bad format" in errors[0]

    def test_load_contract_from_spec_no_address_deployment(self, monkeypatch, tmp_path):
        loaded = []
        class FakeMP:
            def load_from_deployment(self, path):
                loaded.append(str(path))
        dep = tmp_path / "deployment.json"
        dep.write_text("{}")
        spec = SimpleNamespace(address=None, name=None, path=str(tmp_path))
        common._load_contract_from_spec(FakeMP(), spec)
        assert len(loaded) == 1

    def test_load_contract_from_spec_no_deployment(self, tmp_path):
        class FakeMP:
            pass
        spec = SimpleNamespace(address=None, name=None, path=str(tmp_path))
        # Should not raise, just log warning
        common._load_contract_from_spec(FakeMP(), spec)

    def test_load_abi_json_fallback(self, tmp_path):
        loaded = []
        tracer = SimpleNamespace(load_abi=lambda path: loaded.append(path))
        json_abi = tmp_path / "Token.json"
        json_abi.write_text("[]")
        class FakeMP:
            contracts = {ADDR: SimpleNamespace(debug_dir=tmp_path, name="Token")}
        common.load_abi_files(tracer, FakeMP())
        assert len(loaded) == 1
        assert loaded[0].endswith("Token.json")

    def test_validate_contract_address_json_not_found(self, capsys):
        tracer = SimpleNamespace(is_contract_deployed=lambda addr: False)
        result = common.validate_contract_address(ADDR, tracer, json_mode=True)
        assert result is False

    def test_validate_contract_address_text_not_found(self, capsys):
        tracer = SimpleNamespace(is_contract_deployed=lambda addr: False)
        result = common.validate_contract_address(ADDR, tracer, json_mode=False)
        assert result is False
        out = capsys.readouterr().out
        assert "Please verify" in out
        assert "deployed" in out

    def test_validate_contract_address_invalid_json(self, capsys):
        tracer = SimpleNamespace(is_contract_deployed=lambda addr: False)
        result = common.validate_contract_address("bad", tracer, json_mode=True)
        assert result is False

    def test_handle_command_error_json(self, capsys):
        result = common.handle_command_error(ValueError("oops"), json_mode=True)
        assert result == 1

    def test_find_debug_file_no_debug_dir(self, monkeypatch, tmp_path):
        import os
        old = os.getcwd()
        try:
            os.chdir(tmp_path)
            # No debug/ dir, no .zasm files
            result = common.find_debug_file(ADDR)
            assert result is None
        finally:
            os.chdir(old)

    def test_find_debug_file_debug_dir_no_match(self, monkeypatch, tmp_path):
        import os
        old = os.getcwd()
        try:
            os.chdir(tmp_path)
            debug = tmp_path / "debug"
            debug.mkdir()
            (debug / "deployment.json").write_text(json.dumps({"address": OTHER_ADDR}))
            # No .runtime.zasm file — no match
            result = common.find_debug_file(ADDR)
            assert result is None
        finally:
            os.chdir(old)

    def test_find_debug_file_fallback_glob(self, monkeypatch, tmp_path):
        import os
        old = os.getcwd()
        try:
            os.chdir(tmp_path)
            # No debug/ dir, but a .runtime.zasm in subdirectory
            sub = tmp_path / "sub"
            sub.mkdir()
            (sub / "Token.runtime.zasm").write_text("zasm data")
            result = common.find_debug_file(ADDR)
            assert result is not None and result.endswith(".runtime.zasm")
        finally:
            os.chdir(old)

    def test_get_ethdebug_dirs_non_list(self):
        args = SimpleNamespace(ethdebug_dir="/single/path")
        result = common.get_ethdebug_dirs(args)
        assert result == ["/single/path"]

    def test_get_ethdebug_dirs_none(self):
        args = SimpleNamespace(ethdebug_dir=None)
        result = common.get_ethdebug_dirs(args)
        assert result == []

    def test_is_multi_contract_contracts_file(self):
        args = SimpleNamespace(
            ethdebug_dir=None, multi_contract=False,
            contracts="/mapping.json",
        )
        assert common.is_multi_contract_mode(args) is True

    def test_normalize_address_no_prefix(self):
        result = common.normalize_address("0000000000000000000000000000000000000001")
        assert result.startswith("0x")

    def test_normalize_address_empty(self):
        with pytest.raises(ValueError):
            common.normalize_address("")

    def test_parse_value_arg_empty(self):
        assert common.parse_value_arg("", None) == 0

    def test_parse_value_arg_int(self):
        assert common.parse_value_arg("42", None) == 42


# ---------------------------------------------------------------------------
# simulate.py — additional coverage for loading paths
# ---------------------------------------------------------------------------


class TestSimulateLoadingPaths:
    def test_load_debug_info_multi_contract(self, monkeypatch):
        ft = FakeTracer()

        class FakeMulti:
            contracts = {}
            def load_from_mapping_file(self, path):
                pass
            def get_contract_at_address(self, addr):
                return None

        monkeypatch.setattr(simulate, "MultiContractETHDebugParser", FakeMulti)
        monkeypatch.setattr(simulate, "load_abi_files", lambda t, mp: None)
        monkeypatch.setattr(
            simulate.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [],
        )

        args = SimpleNamespace(
            contract_address=ADDR, ethdebug_dir=["/out"],
            contracts="/mapping.json", multi_contract=True,
            raw=False, json=False,
        )
        result = simulate._load_debug_info_for_simulate(ft, args, False)
        assert isinstance(result, dict)

    def test_load_debug_info_single_ethdebug(self, monkeypatch, tmp_path):
        ft = FakeTracer()
        ft.ethdebug_info = SimpleNamespace(contract_name="Token")
        ft.srcmap_info = None

        spec = SimpleNamespace(address=ADDR, name="Token", path=str(tmp_path))
        monkeypatch.setattr(
            simulate.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [spec],
        )
        monkeypatch.setattr(
            simulate.ETHDebugDirParser, "find_abi_file",
            lambda s, cn: str(tmp_path / "Token.abi"),
        )
        (tmp_path / "Token.abi").write_text("[]")

        class FakeMulti:
            contracts = {}
            def load_contract(self, *a):
                pass

        monkeypatch.setattr(simulate, "MultiContractETHDebugParser", FakeMulti)
        monkeypatch.setattr(simulate, "load_abi_files", lambda t, mp: None)

        args = SimpleNamespace(
            contract_address=ADDR, ethdebug_dir=[str(tmp_path)],
            contracts=None, multi_contract=False,
            raw=False, json=False, interactive=False,
        )
        result = simulate._load_debug_info_for_simulate(ft, args, False)
        assert result == {"auto": True}

    def test_load_debug_info_single_address_mismatch(self, monkeypatch, tmp_path, capsys):
        ft = FakeTracer()
        ft.ethdebug_info = None
        ft.srcmap_info = None

        spec = SimpleNamespace(address=OTHER_ADDR, name="Token", path=str(tmp_path))
        monkeypatch.setattr(
            simulate.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [spec],
        )

        class FakeMulti:
            contracts = {}
            def load_contract(self, *a):
                pass

        monkeypatch.setattr(simulate, "MultiContractETHDebugParser", FakeMulti)
        monkeypatch.setattr(simulate, "load_abi_files", lambda t, mp: None)

        args = SimpleNamespace(
            contract_address=ADDR, ethdebug_dir=[str(tmp_path)],
            contracts=None, multi_contract=False,
            raw=False, json=False, interactive=False,
        )
        result = simulate._load_debug_info_for_simulate(ft, args, False)
        out = capsys.readouterr().out
        assert "does not match" in out

    def test_simulate_with_function_abi_match(self, monkeypatch, capsys):
        ft = FakeTracer()
        ft.function_abis = {
            "0x12345678": {
                "name": "set",
                "inputs": [{"name": "x", "type": "uint256"}],
            }
        }
        monkeypatch.setattr(simulate, "TransactionTracer", lambda *a, **kw: ft)
        monkeypatch.setattr(
            simulate, "_load_debug_info_for_simulate",
            lambda tracer, args, jm: {},
        )

        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM_ADDR,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["42"],
            raw_data=None, value=0, interactive=False,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=None, contracts=None, multi_contract=False,
            json=False, raw=False, max_steps=10,
            block=None, tx_index=None,
        )
        assert simulate.simulate_command(args) == 0

    def test_parse_function_args_with_abi(self):
        abi_item = {
            "name": "set",
            "inputs": [
                {"name": "x", "type": "uint256"},
                {"name": "addr", "type": "address"},
            ],
        }
        args = SimpleNamespace(
            function_args=["42", ADDR],
            function_signature="set(uint256,address)",
        )
        result = simulate._parse_function_args(args, ["uint256", "address"], abi_item, True)
        assert result == [42, ADDR]

    def test_parse_function_args_wrong_count_abi(self, capsys):
        abi_item = {
            "name": "set",
            "inputs": [{"name": "x", "type": "uint256"}],
        }
        args = SimpleNamespace(
            function_args=["42", "extra"],
            function_signature="set(uint256)",
        )
        result = simulate._parse_function_args(args, ["uint256"], abi_item, True)
        assert result is None

    def test_parse_function_args_no_abi_wrong_count(self, capsys):
        args = SimpleNamespace(
            function_args=[],
            function_signature="set(uint256)",
        )
        result = simulate._parse_function_args(args, ["uint256"], None, False)
        assert result is None

    def test_parse_single_arg_int_types(self):
        assert simulate._parse_single_arg("42", "int256", {}) == 42
        assert simulate._parse_single_arg("0x1a", "uint8", {}) == 26

    def test_parse_single_arg_string_fallback(self):
        assert simulate._parse_single_arg("hello", "string", {}) == "hello"

    def test_load_abi_for_contract_srcmap(self, tmp_path):
        ft = FakeTracer()
        ft.ethdebug_info = None
        ft.srcmap_info = SimpleNamespace(contract_name="Token")
        abi = tmp_path / "Token.abi"
        abi.write_text("[]")
        simulate._load_abi_for_contract(ft, str(tmp_path))
        assert str(abi) in ft._abi_loaded


# ---------------------------------------------------------------------------
# events.py — additional coverage for multi-contract + ABI loading
# ---------------------------------------------------------------------------


class TestEventsAdditional:
    def _base_args(self, **kw):
        defaults = dict(
            rpc_url="http://rpc", tx_hash="0xtx", json_events=False,
            ethdebug_dir=None, contracts=None, multi_contract=False,
        )
        defaults.update(kw)
        return SimpleNamespace(**defaults)

    def test_load_events_multi_with_contracts_file(self, monkeypatch, tmp_path):
        ft = FakeTracer()

        class FakeMultiParser:
            def __init__(self):
                self.contracts = {}
                self.loaded_mapping = None
            def load_from_mapping_file(self, path):
                self.loaded_mapping = path

        monkeypatch.setattr(events, "MultiContractETHDebugParser", FakeMultiParser)
        args = self._base_args(
            multi_contract=True,
            contracts="/mapping.json",
        )
        events._load_events_debug_info(ft, args)
        assert ft.multi_contract_parser is not None
        assert ft.multi_contract_parser.loaded_mapping == "/mapping.json"

    def test_load_events_multi_abi_loading(self, monkeypatch, tmp_path):
        ft = FakeTracer()
        abi_file = tmp_path / "Token.abi"
        abi_file.write_text("[]")
        json_abi = tmp_path / "Other.json"
        json_abi.write_text("[]")

        class FakeMultiParser:
            def __init__(self):
                self.contracts = {
                    ADDR: SimpleNamespace(debug_dir=tmp_path, name="Token"),
                    OTHER_ADDR: SimpleNamespace(debug_dir=tmp_path, name="Other"),
                }

        monkeypatch.setattr(events, "MultiContractETHDebugParser", FakeMultiParser)
        monkeypatch.setattr(
            events.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [],
        )
        args = self._base_args(multi_contract=True, ethdebug_dir=[])
        events._load_events_debug_info(ft, args)
        assert len(ft._abi_loaded) == 2

    def test_print_events_text(self, monkeypatch, capsys):
        ft = FakeTracer()
        receipt = {"logs": []}
        monkeypatch.setattr(
            "soldb.utils.helpers.print_contracts_events",
            lambda tracer, receipt, **kw: print("decoded"),
        )
        events._print_events(ft, receipt, False)
        assert "decoded" in capsys.readouterr().out

    def test_print_events_json(self, monkeypatch, capsys):
        ft = FakeTracer()
        receipt = {"logs": []}
        monkeypatch.setattr(
            "soldb.utils.helpers.print_contracts_events",
            lambda tracer, receipt, **kw: {"events": []} if kw.get("json_output") else None,
        )
        events._print_events(ft, receipt, True)
        out = capsys.readouterr().out
        assert "events" in out

    def test_load_events_mapping_error(self, monkeypatch):
        ft = FakeTracer()

        class FakeMultiParser:
            def __init__(self):
                self.contracts = {}
            def load_from_mapping_file(self, path):
                raise RuntimeError("bad mapping")

        monkeypatch.setattr(events, "MultiContractETHDebugParser", FakeMultiParser)
        args = self._base_args(multi_contract=True, contracts="/bad.json")
        with pytest.raises(SystemExit):
            events._load_events_debug_info(ft, args)

    def test_load_events_parse_error(self, monkeypatch):
        ft = FakeTracer()

        class FakeMultiParser:
            def __init__(self):
                self.contracts = {}

        monkeypatch.setattr(events, "MultiContractETHDebugParser", FakeMultiParser)
        monkeypatch.setattr(
            events.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: (_ for _ in ()).throw(ValueError("bad")),
        )
        args = self._base_args(multi_contract=True, ethdebug_dir=["/bad"])
        with pytest.raises(SystemExit):
            events._load_events_debug_info(ft, args)

    def test_load_events_abi_json_fallback(self, monkeypatch, tmp_path):
        ft = FakeTracer()
        (tmp_path / "Token.json").write_text("[]")

        class FakeMultiParser:
            def __init__(self):
                self.contracts = {
                    ADDR: SimpleNamespace(debug_dir=tmp_path, name="Token"),
                }

        monkeypatch.setattr(events, "MultiContractETHDebugParser", FakeMultiParser)
        monkeypatch.setattr(
            events.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [],
        )
        args = self._base_args(multi_contract=True, ethdebug_dir=[])
        events._load_events_debug_info(ft, args)
        assert len(ft._abi_loaded) == 1

    def test_load_contract_from_spec_deployment_error(self, monkeypatch, tmp_path):
        class FakeMP:
            def load_from_deployment(self, path):
                raise RuntimeError("bad deployment")
        dep = tmp_path / "deployment.json"
        dep.write_text("{}")
        spec = SimpleNamespace(address=None, name=None, path=str(tmp_path))
        with pytest.raises(SystemExit):
            events._load_contract_from_spec(FakeMP(), spec)


# ---------------------------------------------------------------------------
# contracts.py ��� additional coverage for multi-contract + ABI loading
# ---------------------------------------------------------------------------


class TestContractsAdditional:
    def _base_args(self, **kw):
        defaults = dict(
            rpc_url="http://rpc", tx_hash="0xtx",
            ethdebug_dir=None, contracts=None, multi_contract=False,
        )
        defaults.update(kw)
        return SimpleNamespace(**defaults)

    def test_load_contracts_multi_with_contracts_file(self, monkeypatch, tmp_path):
        ft = FakeTracer()

        class FakeMultiParser:
            def __init__(self):
                self.contracts = {}
                self.loaded_mapping = None
            def load_from_mapping_file(self, path):
                self.loaded_mapping = path

        monkeypatch.setattr(contracts, "MultiContractETHDebugParser", FakeMultiParser)
        monkeypatch.setattr(
            contracts.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [],
        )
        args = self._base_args(multi_contract=True, contracts="/mapping.json")
        contracts._load_contracts_debug_info(ft, args)
        assert ft.multi_contract_parser is not None
        assert ft.multi_contract_parser.loaded_mapping == "/mapping.json"

    def test_load_contracts_multi_abi_loading(self, monkeypatch, tmp_path):
        ft = FakeTracer()
        (tmp_path / "Token.abi").write_text("[]")

        class FakeMultiParser:
            def __init__(self):
                self.contracts = {
                    ADDR: SimpleNamespace(debug_dir=tmp_path, name="Token"),
                }

        monkeypatch.setattr(contracts, "MultiContractETHDebugParser", FakeMultiParser)
        monkeypatch.setattr(
            contracts.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [],
        )
        args = self._base_args(multi_contract=True, ethdebug_dir=[])
        contracts._load_contracts_debug_info(ft, args)
        assert len(ft._abi_loaded) == 1

    def test_load_contract_no_deployment_warning(self, tmp_path, capsys):
        class FakeMP:
            pass
        spec = SimpleNamespace(address=None, name=None, path=str(tmp_path))
        contracts._load_contract_from_spec(FakeMP(), spec)
        # No crash, just warning to stderr

    def test_print_contracts_in_transaction(self, monkeypatch, capsys):
        ft = FakeTracer()
        t = make_trace()
        monkeypatch.setattr(
            "soldb.utils.helpers.print_contracts_in_transaction",
            lambda tracer, trace: print("contracts printed"),
        )
        contracts._print_contracts_in_transaction(ft, t)
        assert "contracts printed" in capsys.readouterr().out

    def test_load_contracts_mapping_error(self, monkeypatch):
        ft = FakeTracer()

        class FakeMultiParser:
            def __init__(self):
                self.contracts = {}
            def load_from_mapping_file(self, path):
                raise RuntimeError("bad mapping")

        monkeypatch.setattr(contracts, "MultiContractETHDebugParser", FakeMultiParser)
        args = self._base_args(multi_contract=True, contracts="/bad.json")
        with pytest.raises(SystemExit):
            contracts._load_contracts_debug_info(ft, args)

    def test_load_contracts_parse_error(self, monkeypatch):
        ft = FakeTracer()

        class FakeMultiParser:
            def __init__(self):
                self.contracts = {}

        monkeypatch.setattr(contracts, "MultiContractETHDebugParser", FakeMultiParser)
        monkeypatch.setattr(
            contracts.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: (_ for _ in ()).throw(ValueError("bad spec")),
        )
        args = self._base_args(multi_contract=True, ethdebug_dir=["/bad"])
        with pytest.raises(SystemExit):
            contracts._load_contracts_debug_info(ft, args)

    def test_load_contracts_abi_json_fallback(self, monkeypatch, tmp_path):
        ft = FakeTracer()
        (tmp_path / "Token.json").write_text("[]")

        class FakeMultiParser:
            def __init__(self):
                self.contracts = {
                    ADDR: SimpleNamespace(debug_dir=tmp_path, name="Token"),
                }

        monkeypatch.setattr(contracts, "MultiContractETHDebugParser", FakeMultiParser)
        monkeypatch.setattr(
            contracts.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [],
        )
        args = self._base_args(multi_contract=True, ethdebug_dir=[])
        contracts._load_contracts_debug_info(ft, args)
        assert len(ft._abi_loaded) == 1
        assert ft._abi_loaded[0].endswith("Token.json")