"""Integration tests exercising the EVMDebugger through realistic debugging sessions."""

import json
from types import SimpleNamespace

import pytest

from soldb.core.evm_repl import EVMDebugger
from soldb.core.transaction_tracer import (
    TraceStep, TransactionTrace,
)
from soldb.parsers.ethdebug import MultiContractETHDebugParser

ADDR = "0x00000000000000000000000000000000000000aa"
OTHER = "0x00000000000000000000000000000000000000bb"
FROM = "0x0000000000000000000000000000000000000001"


def _write_project(tmp_path, name="Counter"):
    """Write a complete ETHDebug project with rich source and variables."""
    source = (
        f"// SPDX-License-Identifier: MIT\n"
        f"pragma solidity ^0.8.0;\n"
        f"contract {name} {{\n"
        f"    uint256 public count;\n"
        f"    event Incremented(uint256 newValue);\n"
        f"    function increment(uint256 amount) public {{\n"
        f"        count += amount;\n"
        f"    }}\n"
        f"    function get() public view returns (uint256) {{\n"
        f"        return count;\n"
        f"    }}\n"
        f"}}\n"
    )
    (tmp_path / f"{name}.sol").write_text(source)

    fn_inc = source.index("function increment")
    fn_get = source.index("function get")
    body_inc = source.index("count += amount")

    (tmp_path / "ethdebug.json").write_text(json.dumps({
        "compilation": {
            "compiler": {"version": "0.8.31"},
            "sources": [{"id": 0, "path": f"{name}.sol"}],
        }
    }))

    (tmp_path / f"{name}_ethdebug-runtime.json").write_text(json.dumps({
        "instructions": [
            {"offset": 0, "operation": {"mnemonic": "PUSH1", "arguments": ["0x01"]},
             "context": {"code": {"source": {"id": 0}, "range": {"offset": fn_inc, "length": 10}},
                          "variables": [
                              {"name": "amount", "type": "uint256",
                               "location": {"type": "stack", "offset": 0},
                               "scope": {"start": 0, "end": 100}},
                          ]}},
            {"offset": 5, "operation": {"mnemonic": "SLOAD"},
             "context": {"code": {"source": {"id": 0}, "range": {"offset": body_inc, "length": 10}},
                          "variables": [
                              {"name": "count", "type": "uint256",
                               "location": {"type": "storage", "offset": 0},
                               "scope": {"start": 0, "end": 100}},
                          ]}},
            {"offset": 10, "operation": {"mnemonic": "ADD"},
             "context": {"code": {"source": {"id": 0}, "range": {"offset": body_inc, "length": 10}}}},
            {"offset": 15, "operation": {"mnemonic": "SSTORE"},
             "context": {"code": {"source": {"id": 0}, "range": {"offset": body_inc, "length": 10}}}},
            {"offset": 20, "operation": {"mnemonic": "STOP"},
             "context": {"code": {"source": {"id": 0}, "range": {"offset": fn_inc, "length": 10}}}},
            {"offset": 50, "operation": {"mnemonic": "SLOAD"},
             "context": {"code": {"source": {"id": 0}, "range": {"offset": fn_get, "length": 10}}}},
            {"offset": 55, "operation": {"mnemonic": "RETURN"},
             "context": {"code": {"source": {"id": 0}, "range": {"offset": fn_get, "length": 10}}}},
        ],
    }))

    (tmp_path / f"{name}.abi").write_text(json.dumps([
        {"type": "function", "name": "increment",
         "inputs": [{"name": "amount", "type": "uint256"}], "outputs": []},
        {"type": "function", "name": "get",
         "inputs": [], "outputs": [{"name": "", "type": "uint256"}]},
        {"type": "event", "name": "Incremented",
         "inputs": [{"name": "newValue", "type": "uint256", "indexed": False}]},
    ]))

    return fn_inc, fn_get, body_inc


def _make_trace(tracer, with_call=False, success=True, num_steps=60):
    """Build a synthetic trace with enough steps for analyze_function_calls heuristics."""
    inc_sel = None
    for sel, item in tracer.function_abis.items():
        if item["name"] == "increment":
            inc_sel = sel
            break

    steps = []
    for i in range(num_steps):
        if i == 0:
            steps.append(TraceStep(0, "PUSH1", 100000, 1, 0, [f"0x{42:064x}"]))
        elif i == 5:
            steps.append(TraceStep(5, "SLOAD", 99000, 1, 0, ["0x00"],
                                   storage={"0x0": f"{10:064x}"}))
        elif i == 10:
            steps.append(TraceStep(10, "ADD", 98000, 1, 0, ["0x2a", "0x0a"]))
        elif i == 15:
            steps.append(TraceStep(15, "SSTORE", 97000, 1, 0, ["0x34", "0x00"]))
        elif i == 20:
            steps.append(TraceStep(20, "STOP", 96000, 1, 0, []))
        elif with_call and i == 25:
            steps.append(TraceStep(25, "CALL", 95000, 2, 0,
                                   ["0x0", "0x0", "0x04", "0x00", "0x0",
                                    "0x" + "cc" * 20, "0x1000"],
                                   memory="70a08231" + "0" * 64))
        elif with_call and i == 26:
            steps.append(TraceStep(30, "PUSH1", 90000, 1, 1, []))
        elif with_call and i == 27:
            steps.append(TraceStep(35, "RETURN", 85000, 1, 0, ["0x0", "0x20"],
                                   memory="0" * 64))
        elif i == 40:
            steps.append(TraceStep(40, "JUMPDEST", 80000, 1, 0, [f"0x{42:064x}"]))
        else:
            steps.append(TraceStep(i, "PUSH1", 100000 - i * 100, 1, 0, ["0x01"]))

    calldata = (inc_sel or "0x12345678") + f"{42:064x}"
    return TransactionTrace(
        tx_hash="0xsession", from_addr=FROM, to_addr=ADDR,
        value=0, input_data=calldata, gas_used=50000,
        output="0x", steps=steps, success=success,
        error=None if success else "reverted",
    )


class TestDebuggerInitWithETHDebug:
    """Test EVMDebugger __init__ with real ETHDebug data."""

    def test_init_with_ethdebug_dir(self, tmp_path, capsys, build_tracer):
        _write_project(tmp_path)
        tracer = build_tracer(tmp_path)

        debugger = EVMDebugger(
            contract_address=ADDR,
            ethdebug_dir=f"{ADDR}:Counter:{tmp_path}",
            abi_path=str(tmp_path / "Counter.abi"),
            tracer=tracer,
        )
        assert debugger.contract_address == ADDR
        assert "Counter.sol" in debugger.source_lines
        assert debugger.source_map  # Should have loaded source mappings

    def test_init_with_multi_contract(self, tmp_path, capsys, build_tracer):
        _write_project(tmp_path)

        multi = MultiContractETHDebugParser()
        multi.load_contract(ADDR, str(tmp_path), "Counter")

        tracer = build_tracer(tmp_path)
        tracer.multi_contract_parser = multi

        debugger = EVMDebugger(
            contract_address=ADDR,
            tracer=tracer,
        )
        # Should have loaded from multi-contract parser
        assert debugger.tracer.ethdebug_info is not None
        out = capsys.readouterr().out
        assert "Contract found" in out


class TestDebuggerRunAndAnalyze:
    """Test do_run with real trace analysis."""

    def test_run_loads_trace(self, tmp_path, capsys, monkeypatch, build_tracer):
        _write_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _make_trace(tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        debugger = EVMDebugger(
            contract_address=ADDR,
            ethdebug_dir=f"{ADDR}:Counter:{tmp_path}",
            tracer=tracer,
        )
        debugger.do_run("0xsession")
        assert debugger.init is True
        assert debugger.current_trace is not None
        assert len(debugger.function_trace) >= 1
        out = capsys.readouterr().out
        assert "Transaction loaded" in out

    def test_interactive_simulation(self, tmp_path, capsys, monkeypatch, build_tracer):
        _write_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _make_trace(tracer)
        monkeypatch.setattr(tracer, "simulate_call_trace", lambda **kw: trace)

        debugger = EVMDebugger(
            contract_address=ADDR,
            ethdebug_dir=f"{ADDR}:Counter:{tmp_path}",
            tracer=tracer,
            function_name="increment(uint256)",
            function_args=["42"],
            from_addr=FROM,
        )
        # _encode_function_call uses w3.eth.contract(...).build_transaction() which
        # requires a chain_id from the provider — bypass it for offline testing.
        monkeypatch.setattr(
            debugger, "_encode_function_call",
            lambda fn, args: "0x12345678" + f"{42:064x}",
        )
        debugger._do_interactive()
        assert debugger.init is True
        out = capsys.readouterr().out
        assert "Simulation complete" in out


class TestDebuggerStepping:
    """Test stepping through a trace with real debug info."""

    def _make_debugger(self, tmp_path, monkeypatch, build_tracer):
        _write_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _make_trace(tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        debugger = EVMDebugger(
            contract_address=ADDR,
            ethdebug_dir=f"{ADDR}:Counter:{tmp_path}",
            tracer=tracer,
        )
        debugger.do_run("0xsession")
        return debugger

    def test_nexti_advances(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        capsys.readouterr()  # clear init output
        initial = d.current_step
        d.do_nexti("")
        assert d.current_step == initial + 1

    def test_continue_to_breakpoint(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        capsys.readouterr()
        d.breakpoints = {15}  # Break at SSTORE
        d.current_step = 0
        d.do_continue("")
        out = capsys.readouterr().out
        assert "Breakpoint" in out

    def test_continue_to_end(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        capsys.readouterr()
        d.breakpoints = set()
        d.current_step = 0
        d.do_continue("")
        out = capsys.readouterr().out
        assert "completed" in out.lower() or "Execution" in out

    def test_info_commands(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        capsys.readouterr()
        d.do_info("")
        d.do_info("memory")
        d.do_info("storage")
        d.do_info("gas")
        d.do_where("")
        d.do_disasm("")
        out = capsys.readouterr().out
        assert len(out) > 0

    def test_print_variable(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        capsys.readouterr()
        d.do_print("")  # Print all
        d.do_print("amount")  # Named variable
        d.do_print("stack[0]")  # Stack access
        out = capsys.readouterr().out
        assert len(out) > 0

    def test_list_source(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        capsys.readouterr()
        d.do_list("")
        out = capsys.readouterr().out
        # Should show source code from Counter.sol
        assert len(out) > 0

    def test_vars_command(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        capsys.readouterr()
        d.do_vars("")
        out = capsys.readouterr().out
        assert len(out) > 0

    def test_breakpoint_set_clear(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        capsys.readouterr()
        d.do_break("0x5")
        assert 5 in d.breakpoints
        d.do_break("")  # List breakpoints
        d.do_clear("0x5")
        assert 5 not in d.breakpoints
        out = capsys.readouterr().out
        assert "PC 5" in out

    def test_goto_step(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        capsys.readouterr()
        d.do_goto("5")
        assert d.current_step == 5
        d.do_goto("0")
        assert d.current_step == 0

    def test_mode_switch(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        d.do_mode("asm")
        assert d.display_mode == "asm"
        d.do_mode("source")
        assert d.display_mode == "source"

    def test_watch_expressions(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        capsys.readouterr()
        d.do_watch("amount")
        assert len(d.watch_expressions) == 1
        d.do_watch("stack[0]")
        assert len(d.watch_expressions) == 2
        d.do_watch("clear")
        assert len(d.watch_expressions) == 0

    def test_debug_ethdebug_command(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        capsys.readouterr()
        d.do_debug_ethdebug("0x0")
        out = capsys.readouterr().out
        assert "ETHDebug" in out

    def test_snapshot_revert(self, tmp_path, capsys, monkeypatch, build_tracer):
        d = self._make_debugger(tmp_path, monkeypatch, build_tracer)
        d.tracer.snapshot_state = lambda: "snap-1"
        d.tracer.revert_state = lambda target=None: True
        d.do_snapshot("")
        d.do_revert("")


class TestDebuggerWithCallOpcodes:
    """Test debugger behavior with CALL opcodes in trace."""

    def test_next_stops_at_call(self, tmp_path, capsys, monkeypatch, build_tracer):
        _write_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _make_trace(tracer, with_call=True)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        debugger = EVMDebugger(
            contract_address=ADDR,
            ethdebug_dir=f"{ADDR}:Counter:{tmp_path}",
            tracer=tracer,
        )
        debugger.do_run("0xsession")
        capsys.readouterr()

        # Step until we hit the CALL
        for _ in range(30):
            if debugger.current_step >= len(debugger.current_trace.steps) - 1:
                break
            step = debugger.current_trace.steps[debugger.current_step]
            if step.op in ["CALL", "DELEGATECALL", "STATICCALL"]:
                break
            debugger.do_nexti("")

    def test_filter_commands(self, tmp_path, capsys, monkeypatch, build_tracer):
        _write_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _make_trace(tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        debugger = EVMDebugger(
            contract_address=ADDR,
            ethdebug_dir=f"{ADDR}:Counter:{tmp_path}",
            tracer=tracer,
        )
        debugger.do_run("0xsession")
        capsys.readouterr()

        debugger.do_filter("")
        debugger.do_filter("hide-temps")
        debugger.do_filter("show-temps")
        debugger.do_filter("show-type uint256")
        debugger.do_filter("hide-type address")
        debugger.do_filter("show-location stack")
        debugger.do_filter("clear-filters")
        out = capsys.readouterr().out
        assert len(out) > 0

    def test_history_command(self, tmp_path, capsys, monkeypatch, build_tracer):
        _write_project(tmp_path)
        tracer = build_tracer(tmp_path)
        trace = _make_trace(tracer)
        monkeypatch.setattr(tracer, "trace_transaction", lambda tx: trace)

        debugger = EVMDebugger(
            contract_address=ADDR,
            ethdebug_dir=f"{ADDR}:Counter:{tmp_path}",
            tracer=tracer,
        )
        debugger.do_run("0xsession")
        capsys.readouterr()

        # Add some variable history
        debugger.variable_history = {
            "amount": [(0, 42, "uint256", "stack[0]"), (5, 42, "uint256", "stack[0]")],
        }
        debugger.do_history("")
        debugger.do_history("amount")
        debugger.do_history("missing")
        out = capsys.readouterr().out
        assert "amount" in out
