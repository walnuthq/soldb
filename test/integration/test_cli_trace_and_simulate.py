"""Integration tests that exercise full CLI flows end-to-end with mock RPC."""

import json
from types import SimpleNamespace

import pytest

from soldb.cli import trace as trace_mod, simulate as simulate_mod, events as events_mod, contracts as contracts_mod
from soldb.core.transaction_tracer import TraceStep, TransactionTrace, TransactionTracer
from soldb.parsers.ethdebug import ETHDebugParser, MultiContractETHDebugParser
from soldb.core.serializer import TraceSerializer

ADDR = "0x00000000000000000000000000000000000000aa"
OTHER = "0x00000000000000000000000000000000000000bb"
FROM = "0x0000000000000000000000000000000000000001"


def _rich_trace(tracer, input_data=None, success=True, error=None, with_call=False, with_log=False):
    """Build a rich trace with various opcodes."""
    set_sel = None
    for sel, item in tracer.function_abis.items():
        if item["name"] == "set":
            set_sel = sel
            break

    if input_data is None:
        input_data = (set_sel or "0x12345678") + f"{42:064x}"

    steps = [
        TraceStep(0, "PUSH1", 100000, 1, 0, ["0x2a"]),
        TraceStep(5, "JUMPDEST", 99000, 1, 0, ["0x2a"]),
        TraceStep(10, "SLOAD", 98000, 1, 0, ["0x00"], storage={"0x0": f"{0:064x}"}),
        TraceStep(15, "SSTORE", 97000, 1, 0, ["0x2a", "0x00"]),
    ]

    if with_log:
        event_topic = list(tracer.event_signatures.keys())[0] if tracer.event_signatures else "0x" + "ee" * 32
        steps.append(
            TraceStep(20, "LOG1", 96000, 1, 0,
                      ["0x00", "0x20", event_topic],
                      memory=f"{42:064x}")
        )

    if with_call:
        steps.append(
            TraceStep(25, "CALL", 95000, 2, 0,
                      ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "cc" * 20, "0x1000"],
                      memory="70a08231" + "0" * 64)
        )
        steps.append(TraceStep(30, "PUSH1", 90000, 1, 1, []))
        steps.append(TraceStep(35, "RETURN", 85000, 1, 0, ["0x0", "0x20"],
                                memory=f"{100:064x}"))

    if not success:
        steps.append(TraceStep(40, "REVERT", 80000, 1, 0, []))
    else:
        steps.append(TraceStep(40, "STOP", 80000, 1, 0, []))

    return TransactionTrace(
        tx_hash="0xintegration",
        from_addr=FROM,
        to_addr=ADDR,
        value=0,
        input_data=input_data,
        gas_used=20000,
        output="0x" + f"{42:064x}" if success else "0x",
        steps=steps,
        success=success,
        error=error,
    )


class TestIntegrationTraceCommand:
    """Full trace_command flow with real ETHDebug parsing."""

    def test_trace_text_output(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer, with_log=True)

        # Patch TransactionTracer to return our tracer
        monkeypatch.setattr(trace_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        args = SimpleNamespace(
            rpc="http://rpc", tx_hash="0xintegration",
            json=False, cross_env_bridge=None, stylus_contracts=None,
            interactive=False, raw=False, max_steps=50,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            debug_info_from_zasm_file=None,
        )
        result = trace_mod.trace_command(args)
        assert result == 0
        out = capsys.readouterr().out
        assert "Function Call Trace" in out
        assert "0xintegration" in out

    def test_trace_json_output(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer, with_call=True)

        monkeypatch.setattr(trace_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        args = SimpleNamespace(
            rpc="http://rpc", tx_hash="0xintegration",
            json=True, cross_env_bridge=None, stylus_contracts=None,
            interactive=False, raw=False, max_steps=50,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            debug_info_from_zasm_file=None,
        )
        result = trace_mod.trace_command(args)
        assert result == 0
        raw_out = capsys.readouterr().out
        # Extract JSON from output
        json_start = raw_out.index("{")
        json_data = json.loads(raw_out[json_start:])
        assert json_data["status"] == "success"
        assert "traceCall" in json_data
        assert "contracts" in json_data

    def test_trace_raw_output(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer)

        monkeypatch.setattr(trace_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        args = SimpleNamespace(
            rpc="http://rpc", tx_hash="0xintegration",
            json=False, cross_env_bridge=None, stylus_contracts=None,
            interactive=False, raw=True, max_steps=10,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            debug_info_from_zasm_file=None,
        )
        result = trace_mod.trace_command(args)
        assert result == 0
        out = capsys.readouterr().out
        assert "PUSH1" in out
        assert "SSTORE" in out

    def test_trace_reverted(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer, success=False, error="insufficient balance")

        monkeypatch.setattr(trace_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        args = SimpleNamespace(
            rpc="http://rpc", tx_hash="0xintegration",
            json=False, cross_env_bridge=None, stylus_contracts=None,
            interactive=False, raw=False, max_steps=50,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            debug_info_from_zasm_file=None,
        )
        result = trace_mod.trace_command(args)
        assert result == 0
        out = capsys.readouterr().out
        assert "REVERTED" in out

    def test_trace_multi_contract(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        # Set up two contracts
        a_dir = tmp_path / "a"
        a_dir.mkdir()
        write_ethdebug_project(a_dir, "TokenA")
        b_dir = tmp_path / "b"
        b_dir.mkdir()
        write_ethdebug_project(b_dir, "TokenB")

        tracer = build_tracer(a_dir, "TokenA")
        tracer.load_abi(str(b_dir / "TokenB.abi"))
        trace = _rich_trace(tracer, with_call=True)

        # Set up multi-contract parser
        multi = MultiContractETHDebugParser()
        multi.load_contract(ADDR, str(a_dir), "TokenA")
        multi.load_contract(OTHER, str(b_dir), "TokenB")
        tracer.multi_contract_parser = multi

        monkeypatch.setattr(trace_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        args = SimpleNamespace(
            rpc="http://rpc", tx_hash="0xintegration",
            json=True, cross_env_bridge=None, stylus_contracts=None,
            interactive=False, raw=False, max_steps=50,
            ethdebug_dir=[f"{ADDR}:TokenA:{a_dir}", f"{OTHER}:TokenB:{b_dir}"],
            contracts=None, multi_contract=True,
            debug_info_from_zasm_file=None,
        )
        result = trace_mod.trace_command(args)
        assert result == 0


class TestIntegrationSimulateCommand:
    """Full simulate_command flow."""

    def test_simulate_with_function(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer)

        monkeypatch.setattr(simulate_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "simulate_call_trace",
                            lambda *a, **kw: trace)

        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["42"],
            raw_data=None, value=0,
            interactive=False,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            json=False, raw=False, max_steps=50,
            block=None, tx_index=None,
        )
        result = simulate_mod.simulate_command(args)
        assert result == 0
        out = capsys.readouterr().out
        assert "Function Call Trace" in out

    def test_simulate_json(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer, with_log=True)

        monkeypatch.setattr(simulate_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "simulate_call_trace",
                            lambda *a, **kw: trace)

        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["42"],
            raw_data=None, value="1000",
            interactive=False,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            json=True, raw=False, max_steps=50,
            block=None, tx_index=None,
        )
        result = simulate_mod.simulate_command(args)
        assert result == 0
        raw_out = capsys.readouterr().out
        json_start = raw_out.index("{")
        json_data = json.loads(raw_out[json_start:])
        assert json_data["status"] == "success"
        assert "contracts" in json_data

    def test_simulate_raw_data(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer)

        monkeypatch.setattr(simulate_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "simulate_call_trace",
                            lambda *a, **kw: trace)

        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM,
            contract_address=ADDR,
            function_signature=None, function_args=[],
            raw_data="0x12345678",
            value=0, interactive=False,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            json=False, raw=True, max_steps=5,
            block=None, tx_index=None,
        )
        result = simulate_mod.simulate_command(args)
        assert result == 0


class TestIntegrationEventsContracts:
    """Integration test for list-events and list-contracts commands."""

    def test_list_events(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)

        monkeypatch.setattr(events_mod, "TransactionTracer", lambda *a, **kw: tracer)
        tracer.w3 = SimpleNamespace(
            eth=SimpleNamespace(
                get_transaction_receipt=lambda tx: {"logs": [], "status": 1}
            ),
        )
        monkeypatch.setattr(
            events_mod, "_print_events",
            lambda t, r, jm: print("events ok"),
        )

        args = SimpleNamespace(
            rpc_url="http://rpc", tx_hash="0xintegration",
            json_events=False,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=True,
        )
        result = events_mod.list_events_command(args)
        assert result == 0

    def test_list_contracts(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer)

        monkeypatch.setattr(contracts_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)
        monkeypatch.setattr(
            contracts_mod, "_print_contracts_in_transaction",
            lambda t, tr: print("contracts ok"),
        )

        args = SimpleNamespace(
            rpc_url="http://rpc", tx_hash="0xintegration",
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=True,
        )
        result = contracts_mod.list_contracts_command(args)
        assert result == 0


class TestIntegrationTraceInteractive:
    """Test interactive mode entry in trace command."""

    def test_trace_interactive_mode(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer, with_call=True)

        monkeypatch.setattr(trace_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        # Mock EVMDebugger to avoid real REPL
        import cmd
        debugger_created = []

        class MockDebugger:
            def __init__(self, **kw):
                debugger_created.append(kw)
                self.current_trace = None
                self.current_step = 0
                self.function_trace = []
                self.current_function = None
                self.tracer = tracer

            def do_run(self, tx):
                pass

            def cmdloop(self):
                pass

        monkeypatch.setattr(trace_mod, "EVMDebugger", MockDebugger)

        args = SimpleNamespace(
            rpc="http://rpc", tx_hash="0xinteractive",
            json=False, cross_env_bridge=None, stylus_contracts=None,
            interactive=True, raw=False, max_steps=50,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            debug_info_from_zasm_file=None,
        )
        result = trace_mod.trace_command(args)
        assert result == 0
        assert len(debugger_created) == 1


class TestIntegrationSimulateMultiContract:
    """Simulate with multi-contract and various debug info loading paths."""

    def test_simulate_multi_contract_json(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        a_dir = tmp_path / "a"
        a_dir.mkdir()
        write_ethdebug_project(a_dir, "TokenA")
        b_dir = tmp_path / "b"
        b_dir.mkdir()
        write_ethdebug_project(b_dir, "TokenB")

        tracer = build_tracer(a_dir, "TokenA")
        tracer.load_abi(str(b_dir / "TokenB.abi"))
        trace = _rich_trace(tracer, with_call=True, with_log=True)

        multi = MultiContractETHDebugParser()
        multi.load_contract(ADDR, str(a_dir), "TokenA")
        multi.load_contract(OTHER, str(b_dir), "TokenB")
        tracer.multi_contract_parser = multi

        monkeypatch.setattr(simulate_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "simulate_call_trace", lambda *a, **kw: trace)

        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["42"],
            raw_data=None, value=0,
            interactive=False,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=[f"{ADDR}:TokenA:{a_dir}", f"{OTHER}:TokenB:{b_dir}"],
            contracts=None, multi_contract=True,
            json=True, raw=False, max_steps=50,
            block=None, tx_index=None,
        )
        result = simulate_mod.simulate_command(args)
        assert result == 0

    def test_simulate_reverted_json(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer, success=False, error="out of gas")

        monkeypatch.setattr(simulate_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "simulate_call_trace", lambda *a, **kw: trace)

        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["42"],
            raw_data=None, value=0,
            interactive=False,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            json=True, raw=False, max_steps=50,
            block=None, tx_index=None,
        )
        result = simulate_mod.simulate_command(args)
        assert result == 0
        raw_out = capsys.readouterr().out
        json_start = raw_out.index("{")
        json_data = json.loads(raw_out[json_start:])
        assert json_data["status"] == "reverted"


class TestIntegrationTraceLoadingPaths:
    """Integration tests that exercise trace.py debug info loading branches."""

    def test_trace_single_contract_with_srcmap(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        """Exercise _load_single_contract_debug_info with srcmap fallback."""
        from soldb.parsers.source_map import SourceMapParser

        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer)

        # Simulate srcmap-only mode
        tracer.ethdebug_info = None
        srcmap_info = SimpleNamespace(contract_name="Counter", get_source_info=lambda pc: None)
        tracer.srcmap_info = srcmap_info
        tracer.srcmap_parser = SimpleNamespace(
            get_source_context=lambda pc, context_lines=2: {"file": "Counter.sol", "line": 3},
        )

        monkeypatch.setattr(trace_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)
        monkeypatch.setattr(tracer, "load_debug_info_auto",
                            lambda d, n=None: {"mapping": True})

        args = SimpleNamespace(
            rpc="http://rpc", tx_hash="0xsrcmap",
            json=False, cross_env_bridge=None, stylus_contracts=None,
            interactive=False, raw=False, max_steps=50,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            debug_info_from_zasm_file=None,
        )
        result = trace_mod.trace_command(args)
        assert result == 0

    def test_trace_multi_contract_primary_not_found(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        """Multi-contract mode where primary contract has no debug info."""
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer)

        # Multi parser that doesn't find the primary contract
        multi = MultiContractETHDebugParser()
        multi.load_contract(OTHER, str(tmp_path), "Counter")  # loaded at OTHER, not ADDR

        monkeypatch.setattr(trace_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)
        monkeypatch.setattr(
            trace_mod, "load_multi_contract_parser",
            lambda dirs, cf, jm: (multi, []),
        )
        monkeypatch.setattr(trace_mod, "load_abi_files", lambda t, mp: None)

        args = SimpleNamespace(
            rpc="http://rpc", tx_hash="0xmulti",
            json=False, cross_env_bridge=None, stylus_contracts=None,
            interactive=False, raw=False, max_steps=50,
            ethdebug_dir=[f"{OTHER}:Counter:{tmp_path}"],
            contracts=None, multi_contract=True,
            debug_info_from_zasm_file=None,
        )
        result = trace_mod.trace_command(args)
        assert result == 0

    def test_trace_interactive_keyboard_interrupt(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer)

        monkeypatch.setattr(trace_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        class MockDebugger:
            def __init__(self, **kw):
                self.current_trace = None
                self.current_step = 0
                self.function_trace = []
                self.current_function = None
                self.tracer = tracer
            def do_run(self, tx):
                pass
            def cmdloop(self):
                raise KeyboardInterrupt()

        monkeypatch.setattr(trace_mod, "EVMDebugger", MockDebugger)

        args = SimpleNamespace(
            rpc="http://rpc", tx_hash="0xinterrupt",
            json=False, cross_env_bridge=None, stylus_contracts=None,
            interactive=True, raw=False, max_steps=50,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            debug_info_from_zasm_file=None,
        )
        result = trace_mod.trace_command(args)
        assert result == 0
        assert "Interrupted" in capsys.readouterr().out


class TestIntegrationSimulateNoDebugInfo:
    """Simulate command paths without debug info."""

    def test_simulate_no_ethdebug_no_abi(self, monkeypatch, tmp_path, capsys):
        """Simulate with no debug info — exercises _try_load_abi_from_common_locations."""
        from web3 import Web3
        bare_tracer = TransactionTracer.__new__(TransactionTracer)
        bare_tracer.rpc_url = "http://rpc"
        bare_tracer.quiet_mode = True
        bare_tracer.w3 = Web3()
        bare_tracer.multi_contract_parser = None
        bare_tracer.stylus_bridge = None
        bare_tracer._stylus_traces = {}
        bare_tracer.missing_mappings_warned = False
        bare_tracer.function_signatures = {}
        bare_tracer.function_abis = {}
        bare_tracer.function_abis_by_name = {}
        bare_tracer.function_params = {}
        bare_tracer.event_signatures = {}
        bare_tracer.event_abis = {}
        bare_tracer.ethdebug_info = None
        bare_tracer.ethdebug_parser = ETHDebugParser()
        bare_tracer.srcmap_info = None
        bare_tracer.srcmap_parser = None
        bare_tracer.source_maps = {}
        bare_tracer.contracts = {}
        bare_tracer.to_addr = ADDR

        steps = [TraceStep(i, "PUSH1", 100 - i, 1, 0, []) for i in range(5)]
        trace = TransactionTrace(
            tx_hash="0xbare", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0x12345678" + "0" * 64,
            gas_used=50, output="0x", steps=steps, success=True,
        )

        monkeypatch.setattr(simulate_mod, "TransactionTracer", lambda *a, **kw: bare_tracer)
        monkeypatch.setattr(bare_tracer, "simulate_call_trace", lambda *a, **kw: trace)

        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["42"],
            raw_data=None, value=0,
            interactive=False,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=None, contracts=None, multi_contract=False,
            json=False, raw=False, max_steps=50,
            block=None, tx_index=None,
        )
        result = simulate_mod.simulate_command(args)
        assert result == 0

    def test_simulate_with_value_ether(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer)

        monkeypatch.setattr(simulate_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "simulate_call_trace", lambda *a, **kw: trace)

        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["42"],
            raw_data=None, value="0.5ether",
            interactive=False,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            json=False, raw=False, max_steps=50,
            block=None, tx_index=None,
        )
        result = simulate_mod.simulate_command(args)
        assert result == 0


class TestIntegrationSimulateLoadMulti:
    """Exercise simulate multi-contract debug info loading paths."""

    def test_simulate_multi_with_primary_no_debug(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        """Multi-contract where primary contract has no debug info — shows warning."""
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer)

        # Multi parser without the primary contract
        multi = MultiContractETHDebugParser()
        multi.load_contract(OTHER, str(tmp_path), "Counter")

        monkeypatch.setattr(simulate_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "simulate_call_trace", lambda *a, **kw: trace)
        monkeypatch.setattr(simulate_mod, "MultiContractETHDebugParser", lambda: multi)
        monkeypatch.setattr(simulate_mod, "load_abi_files", lambda t, mp: None)
        monkeypatch.setattr(
            simulate_mod.ETHDebugDirParser, "parse_ethdebug_dirs",
            lambda dirs: [],
        )

        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["42"],
            raw_data=None, value=0,
            interactive=False,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=[f"{OTHER}:Counter:{tmp_path}"],
            contracts=None, multi_contract=True,
            json=False, raw=False, max_steps=50,
            block=None, tx_index=None,
        )
        result = simulate_mod.simulate_command(args)
        assert result == 0
        out = capsys.readouterr().out
        assert "Warning" in out or "No ETHDebug" in out

    def test_simulate_single_ethdebug_address_match(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        """Single ethdebug dir with matching address."""
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer)

        monkeypatch.setattr(simulate_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "simulate_call_trace", lambda *a, **kw: trace)

        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["42"],
            raw_data=None, value=0,
            interactive=False,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=[f"{ADDR}:Counter:{tmp_path}"],
            contracts=None, multi_contract=False,
            json=False, raw=False, max_steps=50,
            block=None, tx_index=None,
        )
        result = simulate_mod.simulate_command(args)
        assert result == 0


class TestIntegrationSimulateContractsFile:
    """Exercise simulate multi-contract with contracts mapping file."""

    def test_simulate_with_contracts_json(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer)

        # Create contracts mapping file
        mapping = {ADDR: {"name": "Counter", "path": str(tmp_path)}}
        mapping_file = tmp_path / "contracts.json"
        mapping_file.write_text(json.dumps(mapping))

        monkeypatch.setattr(simulate_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "simulate_call_trace", lambda *a, **kw: trace)

        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["42"],
            raw_data=None, value=0,
            interactive=False,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=None,
            contracts=str(mapping_file),
            multi_contract=True,
            json=False, raw=False, max_steps=50,
            block=None, tx_index=None,
        )
        result = simulate_mod.simulate_command(args)
        assert result == 0


class TestIntegrationTraceWithContractsFile:
    """Trace with contracts mapping file."""

    def test_trace_with_contracts_json(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer, with_call=True, with_log=True)

        mapping = {ADDR: {"name": "Counter", "path": str(tmp_path)}}
        mapping_file = tmp_path / "contracts.json"
        mapping_file.write_text(json.dumps(mapping))

        monkeypatch.setattr(trace_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        args = SimpleNamespace(
            rpc="http://rpc", tx_hash="0xcontracts",
            json=False, cross_env_bridge=None, stylus_contracts=None,
            interactive=False, raw=False, max_steps=50,
            ethdebug_dir=None,
            contracts=str(mapping_file),
            multi_contract=True,
            debug_info_from_zasm_file=None,
        )
        result = trace_mod.trace_command(args)
        assert result == 0

    def test_events_with_contracts_json(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)

        mapping = {ADDR: {"name": "Counter", "path": str(tmp_path)}}
        mapping_file = tmp_path / "contracts.json"
        mapping_file.write_text(json.dumps(mapping))

        monkeypatch.setattr(events_mod, "TransactionTracer", lambda *a, **kw: tracer)
        tracer.w3 = SimpleNamespace(
            eth=SimpleNamespace(
                get_transaction_receipt=lambda tx: {"logs": [], "status": 1}
            ),
        )
        monkeypatch.setattr(events_mod, "_print_events", lambda t, r, jm: print("ok"))

        args = SimpleNamespace(
            rpc_url="http://rpc", tx_hash="0xevents",
            json_events=False,
            ethdebug_dir=None,
            contracts=str(mapping_file),
            multi_contract=True,
        )
        result = events_mod.list_events_command(args)
        assert result == 0

    def test_contracts_with_contracts_json(self, monkeypatch, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _rich_trace(tracer)

        mapping = {ADDR: {"name": "Counter", "path": str(tmp_path)}}
        mapping_file = tmp_path / "contracts.json"
        mapping_file.write_text(json.dumps(mapping))

        monkeypatch.setattr(contracts_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)
        monkeypatch.setattr(contracts_mod, "_print_contracts_in_transaction", lambda t, tr: print("ok"))

        args = SimpleNamespace(
            rpc_url="http://rpc", tx_hash="0xcontracts",
            ethdebug_dir=None,
            contracts=str(mapping_file),
            multi_contract=True,
        )
        result = contracts_mod.list_contracts_command(args)
        assert result == 0


class TestIntegrationAnalyzeAndSerialize:
    """Full analyze + serialize pipeline with realistic multi-opcode trace."""

    def test_full_pipeline_with_all_opcodes(self, tmp_path, capsys, write_ethdebug_project, build_tracer):
        write_ethdebug_project(tmp_path)
        tracer = build_tracer(tmp_path)

        # Build a trace that exercises many branch paths in analyze_function_calls
        set_sel = None
        for sel, item in tracer.function_abis.items():
            if item["name"] == "set":
                set_sel = sel
                break

        event_topic = list(tracer.event_signatures.keys())[0] if tracer.event_signatures else "0x" + "ee" * 32

        steps = [
            # Entry
            TraceStep(0, "PUSH1", 100000, 1, 0, ["0x2a"]),
            # JUMPDEST (internal call detection)
            TraceStep(5, "JUMPDEST", 99000, 1, 0, ["0x2a"]),
            # Storage operations
            TraceStep(10, "SLOAD", 98000, 1, 0, ["0x00"], storage={"0x0": "0" * 64}),
            TraceStep(15, "SSTORE", 97000, 1, 0, ["0x2a", "0x00"]),
            # CALL to external contract
            TraceStep(25, "CALL", 95000, 2, 0,
                      ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "cc" * 20, "0x5000"],
                      memory="70a08231" + "0" * 64),
            # Inside called contract (depth 1)
            TraceStep(30, "PUSH1", 90000, 1, 1, ["0x64"]),
            TraceStep(35, "RETURN", 85000, 1, 1, ["0x0", "0x20"], memory="0" * 64),
            # Back to main (depth 0)
            TraceStep(40, "PUSH1", 80000, 1, 0, ["0x01"]),
            # LOG event
            TraceStep(45, "LOG1", 75000, 1, 0,
                      ["0x00", "0x20", event_topic],
                      memory=f"{42:064x}"),
            # STATICCALL
            TraceStep(50, "STATICCALL", 70000, 2, 0,
                      ["0x0", "0x04", "0x00", "0x0", "0x" + "dd" * 20, "0x3000"],
                      memory="18160ddd"),
            TraceStep(55, "PUSH1", 65000, 1, 1, []),
            TraceStep(60, "STOP", 60000, 1, 0, []),
            # End
            TraceStep(65, "STOP", 55000, 1, 0, []),
        ]

        calldata = (set_sel or "0x12345678") + f"{42:064x}"
        trace = TransactionTrace(
            tx_hash="0xfull", from_addr=FROM, to_addr=ADDR,
            value=1000, input_data=calldata,
            gas_used=45000, output=f"0x{1:064x}",
            steps=steps, success=True,
        )

        # Analyze
        calls = tracer.analyze_function_calls(trace)
        assert len(calls) >= 2

        # Should have various call types
        call_types = {c.call_type for c in calls}
        assert "entry" in call_types

        # Print function trace
        tracer.print_function_trace(trace, calls)
        out = capsys.readouterr().out
        assert "Function Call Trace" in out
        assert "0xfull" in out

        # Print raw trace
        source_map = tracer.ethdebug_parser.get_source_mapping()
        tracer.print_trace(trace, source_map, max_steps=0)
        out2 = capsys.readouterr().out
        assert "all" in out2
        assert "CALL" in out2
        assert "SSTORE" in out2

        # Serialize
        serializer = TraceSerializer()
        result = serializer.serialize_trace(
            trace, calls,
            ethdebug_info=tracer.ethdebug_info,
            tracer_instance=tracer,
        )
        assert result["status"] == "success"
        assert "traceCall" in result
        assert "contracts" in result
        assert len(result["steps"]) == len(steps)

        # Extract logs
        logs = serializer.extract_logs_from_trace(trace)
        assert len(logs) >= 1
