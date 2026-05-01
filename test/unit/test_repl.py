"""Additional tests for evm_repl.py uncovered paths: main(), cmdloop, _get_source_info_for_step."""

import sys
from types import SimpleNamespace

import pytest

import soldb.core.evm_repl as repl_module
from soldb.core.evm_repl import EVMDebugger
from soldb.core.transaction_tracer import FunctionCall, TraceStep, TransactionTrace

ADDR = "0x00000000000000000000000000000000000000aa"


def _trace():
    return TransactionTrace(
        tx_hash="0xtx",
        from_addr="0x0000000000000000000000000000000000000001",
        to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
        steps=[
            TraceStep(0, "PUSH1", 100, 1, 0, ["0x01"]),
            TraceStep(10, "PUSH1", 90, 2, 0, []),
            TraceStep(20, "STOP", 80, 1, 0, []),
        ],
        success=True,
    )


class FakeParser:
    def get_source_context(self, pc, context_lines=2):
        return {"file": "C.sol", "line": pc + 1, "content": f"line {pc + 1}"}

    def offset_to_line_col(self, source_path, offset):
        return offset + 10, 0

    def load_source_file(self, source_path):
        return ["line 1\n", "line 2\n"]

    def get_source_mapping(self):
        return {0: ("C.sol", 1), 10: ("C.sol", 2)}


class FakeTracer:
    def __init__(self):
        self.function_abis_by_name = {}
        self.function_signatures = {}
        self.function_abis = {}
        self.ethdebug_info = None
        self.ethdebug_parser = None
        self.srcmap_info = None
        self.srcmap_parser = None
        self.multi_contract_parser = None
        self.w3 = SimpleNamespace(eth=SimpleNamespace())

    def trace_transaction(self, tx_hash):
        return _trace()

    def analyze_function_calls(self, trace):
        return [FunctionCall("f", "", 0, 2, 10, 0, [], contract_address=ADDR, call_id=0)]

    def extract_address_from_stack(self, value):
        if isinstance(value, str) and value.startswith("0x"):
            return value[-40:]
        return "0x" + "00" * 20

    def extract_calldata_from_step(self, step):
        return "0x"

    def decode_function_parameters(self, selector, calldata):
        return []


def _make_debugger():
    debugger = EVMDebugger(tracer=FakeTracer())
    debugger.current_trace = _trace()
    debugger.function_trace = debugger.tracer.analyze_function_calls(debugger.current_trace)
    debugger.current_function = debugger.function_trace[0]
    debugger.current_step = 0
    debugger.contract_address = ADDR
    debugger.source_map = {0: ("C.sol", 1), 10: ("C.sol", 2), 20: ("C.sol", 3)}
    debugger.source_lines = {"C.sol": ["line 1\n", "line 2\n", "line 3\n"]}
    return debugger


class TestGetSourceInfoForStep:
    def test_with_ethdebug_info(self):
        debugger = _make_debugger()
        debugger.tracer.ethdebug_info = SimpleNamespace()
        debugger.tracer.ethdebug_parser = FakeParser()
        step = debugger.current_trace.steps[0]
        result = debugger._get_source_info_for_step(0)
        assert result == ("C.sol", 1)

    def test_with_ethdebug_no_context(self):
        debugger = _make_debugger()
        debugger.tracer.ethdebug_info = SimpleNamespace()
        debugger.tracer.ethdebug_parser = SimpleNamespace(
            get_source_context=lambda pc, context_lines=2: None
        )
        result = debugger._get_source_info_for_step(0)
        assert result is None

    def test_with_srcmap_info(self):
        debugger = _make_debugger()
        debugger.tracer.ethdebug_info = None
        debugger.tracer.srcmap_info = SimpleNamespace(
            get_source_info=lambda pc: ("Token.sol", 42, 5)
        )
        debugger.tracer.srcmap_parser = SimpleNamespace(
            offset_to_line_col=lambda src, offset: (7, 0)
        )
        result = debugger._get_source_info_for_step(0)
        assert result == ("Token.sol", 7)

    def test_with_srcmap_no_source_info(self):
        debugger = _make_debugger()
        debugger.tracer.ethdebug_info = None
        debugger.tracer.srcmap_info = SimpleNamespace(
            get_source_info=lambda pc: None
        )
        debugger.tracer.srcmap_parser = SimpleNamespace()
        result = debugger._get_source_info_for_step(0)
        assert result is None

    def test_with_source_map_dict(self):
        debugger = _make_debugger()
        debugger.tracer.ethdebug_info = None
        debugger.tracer.srcmap_info = None
        debugger.tracer.srcmap_parser = None
        result = debugger._get_source_info_for_step(0)
        assert result == ("C.sol", 1)

    def test_with_source_map_miss(self):
        debugger = _make_debugger()
        debugger.tracer.ethdebug_info = None
        debugger.tracer.srcmap_info = None
        debugger.tracer.srcmap_parser = None
        debugger.source_map = {}
        result = debugger._get_source_info_for_step(0)
        assert result is None

    def test_no_source_info_at_all(self):
        debugger = _make_debugger()
        debugger.tracer.ethdebug_info = None
        debugger.tracer.srcmap_info = None
        debugger.tracer.srcmap_parser = None
        debugger.source_map = None
        result = debugger._get_source_info_for_step(0)
        assert result is None


class TestCmdloop:
    def test_cmdloop_init_with_trace(self, monkeypatch):
        import cmd
        debugger = _make_debugger()
        debugger.init = True
        shown = []
        monkeypatch.setattr(debugger, "_show_current_state", lambda: shown.append(True))
        monkeypatch.setattr(cmd.Cmd, "cmdloop", lambda self, intro="": None)
        debugger.cmdloop(intro="Welcome")
        assert len(shown) == 1

    def test_cmdloop_not_init(self, monkeypatch):
        import cmd
        debugger = _make_debugger()
        debugger.init = False
        called = []
        monkeypatch.setattr(cmd.Cmd, "cmdloop", lambda self, intro="": called.append(intro))
        debugger.cmdloop()
        assert len(called) == 1

    def test_cmdloop_init_no_trace(self, monkeypatch):
        import cmd
        debugger = _make_debugger()
        debugger.init = True
        debugger.current_trace = None
        shown = []
        monkeypatch.setattr(debugger, "_show_current_state", lambda: shown.append(True))
        monkeypatch.setattr(cmd.Cmd, "cmdloop", lambda self, intro="": None)
        debugger.cmdloop()
        assert len(shown) == 0


class TestMain:
    def test_main_with_tx(self, monkeypatch):
        calls = []
        monkeypatch.setattr(
            sys, "argv", ["evm-repl", "--contract", ADDR, "--tx", "0xtx"]
        )

        class FakeDebugger:
            def __init__(self, **kw):
                self.kw = kw

            def do_run(self, tx):
                calls.append(("run", tx))

            def cmdloop(self):
                calls.append("cmdloop")

        monkeypatch.setattr(repl_module, "EVMDebugger", FakeDebugger)
        repl_module.main()
        assert ("run", "0xtx") in calls
        assert "cmdloop" in calls

    def test_main_no_tx(self, monkeypatch):
        calls = []
        monkeypatch.setattr(sys, "argv", ["evm-repl", "--contract", ADDR])

        class FakeDebugger:
            def __init__(self, **kw):
                pass

            def do_run(self, tx):
                calls.append("run")

            def cmdloop(self):
                calls.append("cmdloop")

        monkeypatch.setattr(repl_module, "EVMDebugger", FakeDebugger)
        repl_module.main()
        assert "run" not in calls
        assert "cmdloop" in calls

    def test_main_keyboard_interrupt(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["evm-repl"])

        class FakeDebugger:
            def __init__(self, **kw):
                pass
            def cmdloop(self):
                raise KeyboardInterrupt()

        monkeypatch.setattr(repl_module, "EVMDebugger", FakeDebugger)
        result = repl_module.main()
        assert result == 0
        assert "Interrupted" in capsys.readouterr().out


class TestDoNextCallSkip:
    """Test do_next behavior when hitting CALL opcode (lines 579-639)."""

    def test_next_skips_call_opcode(self, capsys):
        debugger = _make_debugger()
        # Build trace: PUSH, CALL, PUSH (return), STOP
        debugger.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 1000, 1, 0, ["0x01"]),  # line 1
                TraceStep(10, "CALL", 900, 2, 0,
                          ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "bb" * 20, "0x0"],
                          memory="12345678"),
                TraceStep(20, "PUSH1", 800, 1, 1, ["0x01"]),  # inside called contract
                TraceStep(30, "RETURN", 700, 1, 0, ["0x0", "0x0"]),  # back
                TraceStep(40, "STOP", 600, 1, 0, []),
            ],
            success=True,
        )
        debugger.source_map = {
            0: ("C.sol", 1), 10: ("C.sol", 2), 20: ("D.sol", 1),
            30: ("C.sol", 3), 40: ("C.sol", 4),
        }
        debugger.source_lines = {
            "C.sol": ["line 1\n", "line 2\n", "line 3\n", "line 4\n"],
            "D.sol": ["line 1\n"],
        }
        debugger.function_trace = [
            FunctionCall("f", "", 0, 4, 100, 0, [],
                         contract_address=ADDR, call_id=0),
        ]
        debugger.current_function = debugger.function_trace[0]
        debugger.current_step = 0

        # First next: moves to CALL opcode (step 1)
        debugger.do_next("")
        assert debugger.on_call_opcode is True

        # Second next: should skip the call and land after it
        debugger.do_next("")
        assert debugger.on_call_opcode is False
        assert debugger.current_step >= 3  # Should have skipped call internals

    def test_next_at_return_opcode(self, capsys):
        debugger = _make_debugger()
        debugger.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 100, 1, 0, []),
                TraceStep(10, "RETURN", 90, 1, 0, ["0x0", "0x02"], memory="aabb"),
                TraceStep(20, "STOP", 80, 1, 0, []),
            ],
            success=True,
        )
        debugger.source_map = {0: ("C.sol", 1), 10: ("C.sol", 2), 20: ("C.sol", 3)}
        debugger.source_lines = {"C.sol": ["l1\n", "l2\n", "l3\n"]}
        debugger.function_trace = [
            FunctionCall("f", "", 0, 2, 100, 0, [],
                         contract_address=ADDR, call_id=0),
        ]
        debugger.current_function = debugger.function_trace[0]
        debugger.current_step = 0

        debugger.do_next("")
        debugger.do_next("")
        # Should reach end
        assert debugger.current_step >= 2


class TestDoStep:
    def test_step_into_with_multi_contract(self, capsys):
        debugger = _make_debugger()
        debugger.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 1000, 1, 0, ["0x01"]),
                TraceStep(10, "CALL", 900, 2, 0,
                          ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "bb" * 20, "0x0"],
                          memory="12345678"),
                TraceStep(20, "PUSH1", 800, 1, 1, ["0x01"]),
                TraceStep(30, "STOP", 700, 1, 0, []),
            ],
            success=True,
        )
        debugger.source_map = {0: ("C.sol", 1), 10: ("C.sol", 2), 20: ("D.sol", 1), 30: ("C.sol", 3)}
        debugger.source_lines = {"C.sol": ["l1\n", "l2\n", "l3\n"], "D.sol": ["l1\n"]}
        debugger.function_trace = [
            FunctionCall("f", "", 0, 3, 100, 0, [],
                         contract_address=ADDR, call_id=0),
            FunctionCall("g", "", 2, 2, 50, 1, [],
                         contract_address="0x" + "bb" * 20, call_id=1),
        ]
        debugger.current_function = debugger.function_trace[0]
        debugger.current_step = 0

        # Move to CALL
        debugger.do_next("")
        assert debugger.on_call_opcode is True

        # Step into requires multi-contract parser with target contract
        target = SimpleNamespace(
            name="Target", ethdebug_info=SimpleNamespace(sources={0: "D.sol"}),
            parser=FakeParser(), srcmap_info=None, srcmap_parser=None,
            get_parser=lambda: FakeParser(),
        )
        debugger.tracer.multi_contract_parser = SimpleNamespace(
            get_contract_at_address=lambda addr: target
        )
        debugger.do_step("")
        assert debugger.current_step >= 2


class TestDoNextSourceMapping:
    """Test do_next with source map (lines 886-964)."""

    def test_next_no_source_map(self, capsys):
        d = _make_debugger()
        d.source_map = None
        d.tracer.ethdebug_info = None
        d.tracer.srcmap_info = None
        d.do_next("")
        out = capsys.readouterr().out
        assert "No source mapping" in out

    def test_next_no_source_info_at_step(self, capsys):
        d = _make_debugger()
        d.tracer.ethdebug_info = None
        d.tracer.srcmap_info = None
        d.source_map = {}  # empty = no mapping for any PC
        d.do_next("")
        # Falls back to nexti

    def test_next_reaches_different_line(self, capsys):
        d = _make_debugger()
        d.tracer.ethdebug_info = None
        d.tracer.srcmap_info = None
        # Steps: PC 0 -> line 1, PC 10 -> line 2
        d.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 100, 1, 0, []),
                TraceStep(10, "PUSH1", 90, 1, 0, []),
                TraceStep(20, "STOP", 80, 1, 0, []),
            ],
            success=True,
        )
        d.source_map = {0: ("C.sol", 1), 10: ("C.sol", 2), 20: ("C.sol", 3)}
        d.source_lines = {"C.sol": ["l1\n", "l2\n", "l3\n"]}
        d.function_trace = [
            FunctionCall("f", "", 0, 2, 100, 0, [], contract_address=ADDR, call_id=0),
        ]
        d.current_function = d.function_trace[0]
        d.current_step = 0
        d.do_next("")
        assert d.current_step == 1  # moved to next line

    def test_next_reaches_call_opcode(self, capsys):
        d = _make_debugger()
        d.tracer.ethdebug_info = None
        d.tracer.srcmap_info = None
        d.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 100, 1, 0, []),
                TraceStep(10, "CALL", 90, 2, 0,
                          ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "bb" * 20, "0x0"]),
                TraceStep(20, "STOP", 80, 1, 0, []),
            ],
            success=True,
        )
        d.source_map = {0: ("C.sol", 1), 10: ("C.sol", 1), 20: ("C.sol", 2)}
        d.source_lines = {"C.sol": ["l1\n", "l2\n"]}
        d.function_trace = [
            FunctionCall("f", "", 0, 2, 100, 0, [], contract_address=ADDR, call_id=0),
        ]
        d.current_function = d.function_trace[0]
        d.current_step = 0
        d.do_next("")
        # Should stop at the CALL opcode
        assert d.current_step == 1

    def test_next_reaches_return(self, capsys):
        d = _make_debugger()
        d.tracer.ethdebug_info = None
        d.tracer.srcmap_info = None
        d.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 100, 1, 0, []),
                TraceStep(10, "RETURN", 90, 1, 0, ["0x0", "0x02"], memory="aabb"),
                TraceStep(20, "STOP", 80, 1, 0, []),
            ],
            success=True,
        )
        d.source_map = {0: ("C.sol", 1), 10: ("C.sol", 1), 20: ("C.sol", 2)}
        d.source_lines = {"C.sol": ["l1\n", "l2\n"]}
        d.function_trace = [
            FunctionCall("f", "", 0, 2, 100, 0, [], contract_address=ADDR, call_id=0),
        ]
        d.current_function = d.function_trace[0]
        d.current_step = 0
        d.do_next("")
        # Should handle the RETURN

    def test_next_reaches_end(self, capsys):
        d = _make_debugger()
        d.tracer.ethdebug_info = None
        d.tracer.srcmap_info = None
        d.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 100, 1, 0, []),
                TraceStep(10, "PUSH1", 90, 1, 0, []),
            ],
            success=True,
        )
        d.source_map = {0: ("C.sol", 1), 10: ("C.sol", 1)}
        d.source_lines = {"C.sol": ["l1\n"]}
        d.function_trace = [
            FunctionCall("f", "", 0, 1, 100, 0, [], contract_address=ADDR, call_id=0),
        ]
        d.current_function = d.function_trace[0]
        d.current_step = 0
        d.do_next("")
        out = capsys.readouterr().out
        assert "end" in out.lower()


class TestDoNextSteppingFlow:
    """Exercise the full do_next stepping with CALL detection and RETURN handling (lines 886-964)."""

    def _build_debugger_with_source(self):
        d = _make_debugger()
        d.tracer.ethdebug_info = SimpleNamespace(
            contract_name="Token",
            get_variables_at_pc=lambda pc: [],
        )
        d.tracer.ethdebug_parser = SimpleNamespace(
            debug_info=True,
            get_source_context=lambda pc, context_lines=2: {
                "file": "Token.sol", "line": pc // 10 + 1, "column": 0,
                "content": f"line {pc // 10 + 1}",
            },
        )
        d.source_map = None  # Force use of ethdebug_info path
        d.source_lines = {"Token.sol": [f"line {i}\n" for i in range(1, 20)]}
        return d

    def test_next_steps_to_different_line(self, capsys):
        d = self._build_debugger_with_source()
        d.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 100, 1, 0, []),    # line 1
                TraceStep(5, "PUSH1", 95, 1, 0, []),     # line 1 (same)
                TraceStep(10, "PUSH1", 90, 1, 0, []),    # line 2 (different!)
                TraceStep(20, "STOP", 80, 1, 0, []),     # line 3
            ],
            success=True,
        )
        d.function_trace = [FunctionCall("f", "", 0, 3, 100, 0, [], contract_address=ADDR, call_id=0)]
        d.current_function = d.function_trace[0]
        d.current_step = 0
        d.do_next("")
        # Should stop at step 2 (PC 10, line 2)
        assert d.current_step == 2

    def test_next_encounters_call_stops(self, capsys):
        d = self._build_debugger_with_source()
        d.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 100, 1, 0, []),    # line 1
                TraceStep(5, "PUSH1", 95, 1, 0, []),     # line 1
                TraceStep(5, "CALL", 90, 2, 0,           # still line 1 but CALL
                          ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "bb" * 20, "0x0"]),
                TraceStep(20, "STOP", 80, 1, 0, []),
            ],
            success=True,
        )
        d.function_trace = [FunctionCall("f", "", 0, 3, 100, 0, [], contract_address=ADDR, call_id=0)]
        d.current_function = d.function_trace[0]
        d.current_step = 0
        d.do_next("")
        assert d.current_step == 2  # stopped at CALL

    def test_next_encounters_return_no_call_stack(self, capsys):
        d = self._build_debugger_with_source()
        d.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 100, 1, 0, []),
                TraceStep(5, "RETURN", 90, 1, 0, ["0x0", "0x20"], memory="00" * 32),
                TraceStep(20, "STOP", 80, 1, 0, []),
            ],
            success=True,
        )
        d.function_trace = [FunctionCall("f", "", 0, 2, 100, 0, [], contract_address=ADDR, call_id=0)]
        d.current_function = d.function_trace[0]
        d.current_step = 0
        d.call_stack = []  # no call stack
        d.do_next("")
        # Should handle RETURN and advance

    def test_next_reaches_end_of_trace(self, capsys):
        d = self._build_debugger_with_source()
        # All steps on same line — will reach end
        d.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 100, 1, 0, []),
                TraceStep(5, "PUSH1", 95, 1, 0, []),
            ],
            success=True,
        )
        d.function_trace = [FunctionCall("f", "", 0, 1, 100, 0, [], contract_address=ADDR, call_id=0)]
        d.current_function = d.function_trace[0]
        d.current_step = 0
        d.do_next("")
        out = capsys.readouterr().out
        assert "end" in out.lower()

    def test_next_call_with_multi_contract_target(self, capsys):
        d = self._build_debugger_with_source()
        target = "0x" + "bb" * 20
        d.tracer.multi_contract_parser = SimpleNamespace(
            get_contract_at_address=lambda addr: SimpleNamespace(name="Router") if "bb" in addr.lower() else None,
        )
        d.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 100, 1, 0, []),
                TraceStep(5, "STATICCALL", 90, 2, 0,
                          ["0x0", "0x04", "0x00", "0x0", target, "0x500"]),
                TraceStep(20, "STOP", 80, 1, 0, []),
            ],
            success=True,
        )
        d.function_trace = [FunctionCall("f", "", 0, 2, 100, 0, [], contract_address=ADDR, call_id=0)]
        d.current_function = d.function_trace[0]
        d.current_step = 0
        d.do_next("")
        # Should stop at CALL opcode
        assert d.current_step == 1
        assert d.on_call_opcode is True


class TestDoNextNoCallSourceStepping:
    """Directly test the source-stepping path at lines 886-964 (no CALL opcodes in trace)."""

    def test_steps_to_next_line_pure_push(self, capsys):
        d = _make_debugger()
        d.tracer.ethdebug_info = SimpleNamespace(
            contract_name="Token",
            get_variables_at_pc=lambda pc: [],
        )
        d.tracer.ethdebug_parser = SimpleNamespace(
            debug_info=True,
            get_source_context=lambda pc, context_lines=2: {
                "file": "T.sol", "line": pc // 10 + 1, "column": 0,
                "content": f"line {pc // 10 + 1}",
            },
        )
        d.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 100, 1, 0, []),     # line 1
                TraceStep(5, "PUSH1", 95, 1, 0, []),      # line 1
                TraceStep(10, "ADD", 90, 1, 0, []),        # line 2
                TraceStep(20, "SSTORE", 80, 1, 0, []),     # line 3
                TraceStep(30, "STOP", 70, 1, 0, []),       # line 4
            ],
            success=True,
        )
        d.source_map = None  # Use ethdebug path
        d.source_lines = {"T.sol": [f"line {i}\n" for i in range(1, 10)]}
        d.function_trace = [FunctionCall("f", "", 0, 4, 100, 0, [], contract_address=ADDR, call_id=0)]
        d.current_function = d.function_trace[0]
        d.current_step = 0
        d.on_call_opcode = False

        # First next: should advance past line 1
        d.do_next("")
        initial_step = d.current_step
        assert initial_step > 0

        # Keep stepping until end
        prev_step = initial_step
        d.do_next("")
        assert d.current_step > prev_step or d.current_step == len(d.current_trace.steps) - 1

    def test_steps_with_return_in_middle(self, capsys):
        d = _make_debugger()
        d.tracer.ethdebug_info = SimpleNamespace(
            contract_name="Token",
            get_variables_at_pc=lambda pc: [],
        )
        d.tracer.ethdebug_parser = SimpleNamespace(
            debug_info=True,
            get_source_context=lambda pc, context_lines=2: {
                "file": "T.sol", "line": pc // 10 + 1, "column": 0,
                "content": f"line {pc // 10 + 1}",
            },
        )
        d.current_trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=[
                TraceStep(0, "PUSH1", 100, 1, 0, []),      # line 1
                TraceStep(5, "STOP", 95, 1, 0, []),         # line 1 STOP
                TraceStep(10, "PUSH1", 90, 1, 0, []),       # line 2
            ],
            success=True,
        )
        d.source_map = None
        d.source_lines = {"T.sol": [f"line {i}\n" for i in range(1, 10)]}
        d.function_trace = [FunctionCall("f", "", 0, 2, 100, 0, [], contract_address=ADDR, call_id=0)]
        d.current_function = d.function_trace[0]
        d.current_step = 0
        d.on_call_opcode = False
        d.call_stack = []

        d.do_next("")
        # Should handle the STOP opcode


class TestDoContinueMore:
    def test_continue_at_end(self, capsys):
        d = _make_debugger()
        d.current_step = len(d.current_trace.steps) - 1
        d.do_continue("")
        out = capsys.readouterr().out
        assert "end" in out.lower()

    def test_continue_to_completion(self, capsys):
        d = _make_debugger()
        d.breakpoints = set()  # no breakpoints
        d.current_step = 0
        d.do_continue("")
        out = capsys.readouterr().out
        assert "completed" in out.lower() or "Execution" in out


class TestLoadSourceFiles:
    def test_load_source_files_for_contract(self):
        d = _make_debugger()
        parser = SimpleNamespace(
            load_source_file=lambda path: ["line 1\n", "line 2\n"]
        )
        info = SimpleNamespace(sources={0: "New.sol", 1: "Lib.sol"})
        contract = SimpleNamespace(
            name="TestContract",
            parser=parser, ethdebug_info=info,
            srcmap_info=None, srcmap_parser=None,
            get_parser=lambda: parser,
        )
        d._load_source_files_for_contract(contract)
        assert "New.sol" in d.source_lines
        assert "Lib.sol" in d.source_lines

    def test_load_source_files_srcmap(self):
        d = _make_debugger()
        srcmap_parser = SimpleNamespace(
            load_source_file=lambda path: ["src line 1\n"]
        )
        srcmap_info = SimpleNamespace(
            sources={0: "Legacy.sol"},
            compiler_version="0.8.16",
        )
        contract = SimpleNamespace(
            name="LegacyContract",
            parser=None, ethdebug_info=None,
            srcmap_info=srcmap_info, srcmap_parser=srcmap_parser,
            get_parser=lambda: srcmap_parser,
        )
        d._load_source_files_for_contract(contract)
        # Source loaded by source ID key (0) or path
        assert any("src line" in "".join(v) for v in d.source_lines.values() if isinstance(v, list))


class TestVariableFallback:
    def test_do_print_with_function_args_no_ethdebug(self, capsys):
        """When ethdebug_info has no variables, fall back to function args."""
        debugger = _make_debugger()
        debugger.tracer.ethdebug_info = SimpleNamespace(
            get_variables_at_pc=lambda pc: []
        )
        debugger.current_function = FunctionCall(
            "set", "0x12345678", 0, 2, 10, 0,
            [("amount", 42), ("addr", ADDR)],
            contract_address=ADDR, call_id=0,
        )
        debugger.do_print("")
        out = capsys.readouterr().out
        assert "amount" in out

    def test_do_print_named_var_from_args(self, capsys):
        debugger = _make_debugger()
        debugger.tracer.ethdebug_info = SimpleNamespace(
            get_variables_at_pc=lambda pc: []
        )
        debugger.current_function = FunctionCall(
            "set", "0x12345678", 0, 2, 10, 0,
            [("amount", 42)],
            contract_address=ADDR, call_id=0,
        )
        debugger.do_print("amount")
        out = capsys.readouterr().out
        assert "42" in out
