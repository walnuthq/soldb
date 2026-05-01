"""Additional tests for compiler/ethdebug.py main() and transaction_tracer.py deeper paths."""

import json
import sys
from types import SimpleNamespace

import pytest
from web3 import Web3

from soldb.compiler.config import CompilerConfig, CompilationError, dual_compile
import soldb.compiler.ethdebug as compiler_ethdebug
from soldb.core.transaction_tracer import (
    FunctionCall,
    TraceStep,
    TransactionTrace,
    TransactionTracer,
)

ADDR = "0x00000000000000000000000000000000000000aa"
FROM_ADDR = "0x0000000000000000000000000000000000000001"


# ---------------------------------------------------------------------------
# compiler/ethdebug.py main() — cover dual-compile success printing
# ---------------------------------------------------------------------------


class TestCompilerEthdebugMain:
    def test_dual_compile_success(self, monkeypatch, tmp_path, capsys):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")

        monkeypatch.setattr(
            CompilerConfig, "verify_solc_version",
            lambda self: {"supported": True, "version": "0.8.31"},
        )
        monkeypatch.setattr(
            compiler_ethdebug, "dual_compile",
            lambda path, config: {
                "production": {"success": True, "output_dir": "prod"},
                "debug": {
                    "success": True,
                    "output_dir": "debug",
                    "files": {
                        "ethdebug": "out/ethdebug.json",
                        "contracts": {
                            "C": {
                                "bytecode": "C.bin",
                                "abi": "C.abi",
                                "ethdebug": "C_ethdebug.json",
                                "ethdebug_runtime": "C_ethdebug-runtime.json",
                            }
                        },
                    },
                },
            },
        )

        monkeypatch.setattr(
            sys, "argv", ["ethdebug", str(contract), "--dual-compile"]
        )
        compiler_ethdebug.main()
        out = capsys.readouterr().out
        assert "Production build created" in out
        assert "ETHDebug build created" in out
        assert "C.bin" in out
        assert "C.abi" in out
        assert "C_ethdebug.json" in out
        assert "C_ethdebug-runtime.json" in out

    def test_dual_compile_json_output(self, monkeypatch, tmp_path, capsys):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        monkeypatch.setattr(
            compiler_ethdebug, "dual_compile",
            lambda path, config: {"production": {"success": True}, "debug": {"success": True}},
        )
        monkeypatch.setattr(
            sys, "argv", ["ethdebug", str(contract), "--dual-compile", "--json"]
        )
        compiler_ethdebug.main()
        out = json.loads(capsys.readouterr().out)
        assert out["production"]["success"] is True

    def test_compile_success_with_warnings(self, monkeypatch, tmp_path, capsys):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        monkeypatch.setattr(
            CompilerConfig, "compile_with_ethdebug",
            lambda self, path: {
                "success": True,
                "output_dir": "out",
                "files": {
                    "ethdebug": "out/ethdebug.json",
                    "contracts": {
                        "C": {
                            "bytecode": "C.bin",
                            "abi": None,
                            "ethdebug": None,
                            "ethdebug_runtime": "C_ethdebug-runtime.json",
                        }
                    },
                },
                "stderr": "Warning: unused variable",
            },
        )
        monkeypatch.setattr(sys, "argv", ["ethdebug", str(contract)])
        compiler_ethdebug.main()
        out = capsys.readouterr().out
        assert "ETHDebug compilation successful" in out
        assert "Compiler warnings" in out
        assert "unused variable" in out

    def test_compile_json_mode(self, monkeypatch, tmp_path, capsys):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        monkeypatch.setattr(
            CompilerConfig, "compile_with_ethdebug",
            lambda self, path: {"success": True, "files": {"ethdebug": None, "contracts": {}}},
        )
        monkeypatch.setattr(sys, "argv", ["ethdebug", str(contract), "--json"])
        compiler_ethdebug.main()
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is True

    def test_verify_version_json_unsupported(self, monkeypatch, tmp_path, capsys):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        monkeypatch.setattr(
            CompilerConfig, "verify_solc_version",
            lambda self: {"supported": False, "error": "requires 0.8.29+"},
        )
        monkeypatch.setattr(
            sys, "argv", ["ethdebug", str(contract), "--verify-version", "--json"]
        )
        with pytest.raises(SystemExit) as exc:
            compiler_ethdebug.main()
        assert exc.value.code == 1
        out = json.loads(capsys.readouterr().out)
        assert out["supported"] is False

    def test_verify_version_text_unsupported(self, monkeypatch, tmp_path, capsys):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        monkeypatch.setattr(
            CompilerConfig, "verify_solc_version",
            lambda self: {"supported": False, "error": "requires 0.8.29+"},
        )
        monkeypatch.setattr(
            sys, "argv", ["ethdebug", str(contract), "--verify-version"]
        )
        with pytest.raises(SystemExit) as exc:
            compiler_ethdebug.main()
        assert exc.value.code == 1

    def test_general_exception(self, monkeypatch, tmp_path, capsys):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        monkeypatch.setattr(
            CompilerConfig, "compile_with_ethdebug",
            lambda self, path: (_ for _ in ()).throw(RuntimeError("internal error")),
        )
        monkeypatch.setattr(sys, "argv", ["ethdebug", str(contract)])
        with pytest.raises(SystemExit) as exc:
            compiler_ethdebug.main()
        assert exc.value.code == 1

    def test_general_exception_json(self, monkeypatch, tmp_path, capsys):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        monkeypatch.setattr(
            CompilerConfig, "compile_with_ethdebug",
            lambda self, path: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        monkeypatch.setattr(sys, "argv", ["ethdebug", str(contract), "--json"])
        with pytest.raises(SystemExit) as exc:
            compiler_ethdebug.main()
        assert exc.value.code == 1
        out = json.loads(capsys.readouterr().out)
        assert out["success"] is False

    def test_save_config_error(self, monkeypatch, tmp_path, capsys):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        monkeypatch.setattr(
            CompilerConfig, "save_to_soldb_config",
            lambda self: (_ for _ in ()).throw(RuntimeError("no yaml")),
        )
        monkeypatch.setattr(sys, "argv", ["ethdebug", str(contract), "--save-config"])
        with pytest.raises(SystemExit) as exc:
            compiler_ethdebug.main()
        assert exc.value.code == 1


# ---------------------------------------------------------------------------
# transaction_tracer.py — deeper paths
# ---------------------------------------------------------------------------


def _tracer():
    t = TransactionTracer.__new__(TransactionTracer)
    t.rpc_url = "http://rpc"
    t.quiet_mode = True
    t.w3 = Web3()
    t.multi_contract_parser = None
    t.stylus_bridge = None
    t._stylus_traces = {}
    t.missing_mappings_warned = False
    t.function_signatures = {}
    t.function_abis = {}
    t.function_abis_by_name = {}
    t.function_params = {}
    t.event_signatures = {}
    t.event_abis = {}
    t.ethdebug_info = None
    t.ethdebug_parser = None
    t.srcmap_info = None
    t.srcmap_parser = None
    t.source_maps = {}
    t.contracts = {}
    return t


class TestTracerDecodeHelpers:
    def test_extract_address_from_stack(self):
        t = _tracer()
        result = t.extract_address_from_stack("0x" + "00" * 12 + "aa" * 20)
        assert result is not None and "aa" in result.lower()

    def test_extract_calldata_from_step(self):
        t = _tracer()
        step = TraceStep(
            10, "CALL", 100, 2, 0,
            ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "aa" * 20, "0x0"],
            memory="12345678" + "00" * 32,
        )
        result = t.extract_calldata_from_step(step)
        assert result is not None

    def test_decode_function_parameters(self):
        t = _tracer()
        t.function_abis = {
            "0x12345678": {
                "name": "set",
                "inputs": [{"name": "x", "type": "uint256"}],
            }
        }
        # Selector + uint256(42)
        calldata = "12345678" + f"{42:064x}"
        result = t.decode_function_parameters("0x12345678", calldata)
        assert result is not None

    def test_decode_function_parameters_no_match(self):
        t = _tracer()
        t.function_abis = {}
        result = t.decode_function_parameters("0xdeadbeef", "deadbeef")
        assert result is None or result == []


class TestTracerPrintFunctionTraceDeep:
    def test_external_call_chain(self, capsys):
        t = _tracer()
        steps = [TraceStep(i, "PUSH1", 1000 - i, 1, 0, []) for i in range(10)]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x12345678", gas_used=300,
            output="0x", steps=steps, success=True,
        )
        root = FunctionCall("dispatcher", "", 0, 9, 300, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0,
                            children_call_ids=[1, 2])
        ext_call = FunctionCall("Token::transfer", "0xa9059cbb", 2, 5, 100, 1,
                                [("to", ADDR), ("amount", 1000)],
                                call_type="CALL", contract_address=ADDR, call_id=1,
                                parent_call_id=0)
        int_call = FunctionCall("_update", "0x00000000", 6, 8, 50, 1,
                                [("from", ADDR)],
                                call_type="internal", contract_address=ADDR, call_id=2,
                                parent_call_id=0)

        t.print_function_trace(trace, [root, ext_call, int_call])
        out = capsys.readouterr().out
        assert "Function Call Trace" in out

    def test_create_in_trace(self, capsys):
        t = _tracer()
        steps = [TraceStep(i, "PUSH1", 100, 1, 0, []) for i in range(5)]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=None,
            value=0, input_data="0x6000", gas_used=50,
            output="0x", steps=steps, success=True,
            contract_address=ADDR,
        )
        root = FunctionCall("constructor", "", 0, 4, 50, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0)
        t.print_function_trace(trace, [root])
        out = capsys.readouterr().out
        assert "Function Call Trace" in out


class TestExtractFunctionName:
    def test_regular_function(self):
        t = _tracer()
        assert t._extract_function_name("function transfer(address to, uint256 amount)") == "transfer"

    def test_constructor(self):
        t = _tracer()
        assert t._extract_function_name("constructor(uint256 x)") == "constructor"

    def test_fallback(self):
        t = _tracer()
        assert t._extract_function_name("fallback()") == "fallback"

    def test_receive(self):
        t = _tracer()
        assert t._extract_function_name("receive() external") == "receive"

    def test_empty_string(self):
        t = _tracer()
        assert t._extract_function_name("") is None

    def test_no_function(self):
        t = _tracer()
        assert t._extract_function_name("uint256 x = 42;") is None

    def test_none_input(self):
        t = _tracer()
        assert t._extract_function_name(None) is None


class TestDetectInternalCall:
    def test_no_context(self):
        t = _tracer()
        step = TraceStep(0, "JUMPDEST", 100, 1, 0, [])
        result = t._detect_internal_call(step, 0, ADDR, [], [])
        # Returns None or (None, warned_flag) when no context
        if isinstance(result, tuple):
            assert result[0] is None
        else:
            assert result is None

    def test_with_context_function(self):
        t = _tracer()
        t.ethdebug_info = SimpleNamespace()
        t.ethdebug_parser = SimpleNamespace(
            debug_info=True,
            get_source_context=lambda pc, context_lines=2: {
                "file": "C.sol", "line": 5, "column": 0,
                "content": "function helper(uint256 x) public {"
            }
        )
        step = TraceStep(10, "JUMPDEST", 100, 1, 0, ["0x2a"])
        parent = FunctionCall("dispatcher", "", 0, None, 0, 0, [],
                              call_type="entry", contract_address=ADDR, call_id=0)
        result = t._detect_internal_call(step, 1, ADDR, [parent], [parent])
        if isinstance(result, tuple):
            call = result[0]
        else:
            call = result
        assert call is not None
        assert call.name == "helper"

    def test_duplicate_function_ignored(self):
        t = _tracer()
        t.ethdebug_info = SimpleNamespace()
        t.ethdebug_parser = SimpleNamespace(
            debug_info=True,
            get_source_context=lambda pc, context_lines=2: {
                "file": "C.sol", "line": 5, "column": 0,
                "content": "function helper() public {"
            }
        )
        step = TraceStep(10, "JUMPDEST", 100, 1, 0, [])
        existing = FunctionCall("helper", "", 5, None, 0, 1, [],
                                call_type="internal", contract_address=ADDR, call_id=1)
        parent = FunctionCall("dispatcher", "", 0, None, 0, 0, [],
                              call_type="entry", contract_address=ADDR, call_id=0)
        result = t._detect_internal_call(step, 1, ADDR, [parent, existing], [parent, existing])
        if isinstance(result, tuple):
            assert result[0] is None
        else:
            assert result is None

    def test_missing_mappings_warning(self, capsys):
        t = _tracer()
        t.ethdebug_info = SimpleNamespace()
        t.ethdebug_parser = SimpleNamespace(
            debug_info=True,
            get_source_context=lambda pc, context_lines=2: None
        )
        t.missing_mappings_warned = False
        step = TraceStep(10, "JUMPDEST", 100, 1, 0, [])
        result = t._detect_internal_call(step, 1, ADDR, [], [])
        assert isinstance(result, tuple)
        assert result[0] is None
        assert result[1] is True  # warned flag set


class TestAnalyzeFunctionCalls:
    def test_minimal_trace(self):
        t = _tracer()
        t.function_signatures = {"0x12345678": {"name": "set(uint256)"}}
        t.function_abis = {}
        t.function_abis_by_name = {}
        steps = [
            TraceStep(0, "PUSH1", 1000, 1, 0, ["0x01"]),
            TraceStep(1, "STOP", 990, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x12345678" + "0" * 64,
            gas_used=100, output="0x", steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        assert len(calls) >= 1
        assert calls[0].call_type == "entry"

    def test_trace_with_call_opcode(self, monkeypatch):
        t = _tracer()
        t.function_signatures = {}
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        steps = [
            TraceStep(0, "PUSH1", 1000, 1, 0, ["0x01"]),
            TraceStep(1, "CALL", 900, 2, 0,
                      ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "bb" * 20, "0x0"],
                      memory="12345678" + "00" * 32),
            TraceStep(2, "PUSH1", 800, 1, 1, ["0x01"]),
            TraceStep(3, "RETURN", 700, 1, 0, ["0x0", "0x0"]),
            TraceStep(4, "STOP", 600, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x", gas_used=300,
            output="0x", steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        assert any(c.call_type in ["CALL", "entry"] for c in calls)

    def test_trace_with_revert(self, monkeypatch):
        t = _tracer()
        t.function_signatures = {}
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        steps = [
            TraceStep(0, "PUSH1", 1000, 1, 0, ["0x01"]),
            TraceStep(1, "REVERT", 900, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x", gas_used=100,
            output="0x", steps=steps, success=False, error="reverted",
        )
        calls = t.analyze_function_calls(trace)
        assert any(c.caused_revert for c in calls)

    def test_trace_deployment_no_to(self, monkeypatch):
        t = _tracer()
        t.function_signatures = {}
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        steps = [
            TraceStep(0, "PUSH1", 1000, 1, 0, ["0x01"]),
            TraceStep(1, "STOP", 990, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=None,
            value=0, input_data="0x6000", gas_used=50,
            output="0x", steps=steps, success=True,
            contract_address=ADDR,
        )
        calls = t.analyze_function_calls(trace)
        assert calls[0].call_type == "entry"


class TestPrintFunctionTraceRich:
    """Exercise the many branches in print_function_trace."""

    def test_multi_contract_mode(self, capsys):
        t = _tracer()
        contract_info = SimpleNamespace(
            name="Token",
            ethdebug_info=SimpleNamespace(sources={0: "Token.sol"}),
        )
        t.multi_contract_parser = SimpleNamespace(
            get_all_loaded_contracts=lambda: [(ADDR, "Token")],
            get_contract_at_address=lambda addr: contract_info if addr == ADDR else None,
            get_source_info_for_address=lambda addr, pc: {"file": "Token.sol", "line": 10, "column": 0} if addr == ADDR else None,
            get_current_context=lambda: SimpleNamespace(address=ADDR),
        )
        t.ethdebug_info = SimpleNamespace(sources={0: "Token.sol"})
        steps = [TraceStep(i, "PUSH1", 100, 1, 0, []) for i in range(5)]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=1000, input_data="0x12345678" + "0" * 64,
            gas_used=300, output="0x", steps=steps, success=True,
        )
        root = FunctionCall("dispatcher", "", 0, 4, 300, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0,
                            children_call_ids=[1, 2, 3])
        ext_call = FunctionCall("Token::transfer", "0xa9059cbb", 1, 2, 100, 1,
                                [("to", "0x" + "bb" * 20), ("amount", 1000)],
                                call_type="CALL", contract_address=ADDR, call_id=1,
                                parent_call_id=0, source_line=42, value=500)
        int_call = FunctionCall("_update", "", 3, 4, 30, 2,
                                [("amount", 7)],
                                call_type="internal", contract_address=ADDR, call_id=2,
                                parent_call_id=0, source_line=55)
        static_call = FunctionCall("balanceOf", "0x70a08231", 2, 3, 20, 1,
                                   [], call_type="STATICCALL",
                                   contract_address="0x" + "cc" * 20, call_id=3,
                                   parent_call_id=0)
        t.print_function_trace(trace, [root, ext_call, int_call, static_call])
        out = capsys.readouterr().out
        assert "Function Call Trace" in out
        assert "Token" in out
        assert "CALL" in out
        assert "STATICCALL" in out
        assert "internal" in out
        assert "value" in out.lower()
        assert "non-verified" in out  # static_call has no debug info

    def test_reverted_with_args(self, capsys):
        t = _tracer()
        steps = [TraceStep(i, "PUSH1", 100, 1, 0, []) for i in range(3)]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x", gas_used=100, output="0x",
            steps=steps, success=False, error="ERC20: insufficient balance",
        )
        root = FunctionCall("dispatcher", "", 0, 2, 100, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0,
                            children_call_ids=[1])
        child = FunctionCall("transfer", "0xa9059cbb", 1, 2, 50, 1,
                             [("to", "0x" + "bb" * 20), ("amount", 99999)],
                             call_type="external", contract_address=ADDR, call_id=1,
                             parent_call_id=0, source_line=10,
                             caused_revert=True, error="ERC20: insufficient balance")
        t.print_function_trace(trace, [root, child])
        out = capsys.readouterr().out
        assert "REVERTED" in out
        assert "insufficient balance" in out
        assert "!!!" in out  # deepest error indicator

    def test_no_function_calls(self, capsys):
        t = _tracer()
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x", gas_used=50, output="0x",
            steps=[], success=True,
        )
        t.print_function_trace(trace, [])
        out = capsys.readouterr().out
        assert "fallback" in out

    def test_entry_with_no_debug_info(self, capsys):
        t = _tracer()
        steps = [TraceStep(0, "PUSH1", 100, 1, 0, [])]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x", gas_used=50, output="0x",
            steps=steps, success=True,
        )
        root = FunctionCall("dispatcher", "", 0, 0, 50, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0)
        t.print_function_trace(trace, [root])
        out = capsys.readouterr().out
        assert "non-verified" in out

    def test_entry_with_ethdebug_info(self, capsys):
        t = _tracer()
        t.ethdebug_info = SimpleNamespace(sources={0: "Token.sol"})
        steps = [TraceStep(0, "PUSH1", 100, 1, 0, [])]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x", gas_used=50, output="0x",
            steps=steps, success=True,
        )
        root = FunctionCall("dispatcher", "", 0, 0, 50, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0)
        t.print_function_trace(trace, [root])
        out = capsys.readouterr().out
        assert "Token.sol" in out

    def test_delegate_call(self, capsys):
        t = _tracer()
        steps = [TraceStep(i, "PUSH1", 100, 1, 0, []) for i in range(3)]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x", gas_used=100, output="0x",
            steps=steps, success=True,
        )
        root = FunctionCall("dispatcher", "", 0, 2, 100, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0,
                            children_call_ids=[1])
        delegate = FunctionCall("impl::execute", "0x12345678", 1, 2, 50, 1,
                                [], call_type="DELEGATECALL",
                                contract_address=ADDR, call_id=1,
                                parent_call_id=0)
        t.print_function_trace(trace, [root, delegate])
        out = capsys.readouterr().out
        assert "DELEGATECALL" in out

    def test_with_step_ranges_displayed(self, capsys):
        t = _tracer()
        steps = [TraceStep(i, "PUSH1", 100, 1, 0, []) for i in range(5)]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x", gas_used=100, output="0x",
            steps=steps, success=True,
        )
        root = FunctionCall("dispatcher", "", 0, 4, 100, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0,
                            children_call_ids=[1])
        child = FunctionCall("f", "", 1, 3, 50, 1,
                             [], call_type="internal", contract_address=ADDR,
                             call_id=1, parent_call_id=0)
        t.print_function_trace(trace, [root, child])
        out = capsys.readouterr().out
        assert "steps:" in out


class TestFormatTupleValue:
    def test_basic_tuple(self):
        t = _tracer()
        components = [
            {"name": "amount", "type": "uint256"},
            {"name": "flag", "type": "bool"},
        ]
        result = t.format_tuple_value((42, True), components)
        assert "amount" in result
        assert "42" in result
        assert "True" in result

    def test_tuple_with_address(self):
        t = _tracer()
        components = [{"name": "to", "type": "address"}]
        result = t.format_tuple_value(("0x" + "aa" * 20,), components)
        assert "to" in result

    def test_tuple_with_string(self):
        t = _tracer()
        components = [{"name": "name", "type": "string"}]
        result = t.format_tuple_value(("hello",), components)
        assert "hello" in result

    def test_nested_tuple(self):
        t = _tracer()
        components = [{
            "name": "inner", "type": "tuple",
            "components": [{"name": "x", "type": "uint256"}],
        }]
        result = t.format_tuple_value(((42,),), components)
        assert "inner" in result
        assert "42" in result

    def test_empty_components(self):
        t = _tracer()
        assert t.format_tuple_value((1, 2), []) == "(1, 2)"


class TestFormatAddressDisplay:
    def test_with_multi_parser_known_contract(self):
        t = _tracer()
        t.multi_contract_parser = SimpleNamespace(
            get_contract_at_address=lambda addr: SimpleNamespace(name="Token")
        )
        result = t.format_address_display(ADDR)
        assert "Token" in result

    def test_with_multi_parser_unknown(self):
        t = _tracer()
        t.multi_contract_parser = SimpleNamespace(
            get_contract_at_address=lambda addr: None
        )
        result = t.format_address_display(ADDR)
        assert "0x" in result

    def test_short_format(self):
        t = _tracer()
        result = t.format_address_display(ADDR, short=True)
        assert "0x" in result

    def test_no_multi_parser(self):
        t = _tracer()
        result = t.format_address_display(ADDR)
        assert "0x" in result


class TestSourceMapper:
    def test_basic_mapping(self, tmp_path):
        from soldb.core.transaction_tracer import SourceMapper
        source = tmp_path / "C.sol"
        source.write_text("line 1\nline 2\nline 3\n")
        mapper = SourceMapper(str(source), "0:6:0;6:6:0")
        assert 0 in mapper.pc_to_source
        assert mapper.pc_to_source[0][0] == 1  # line 1

    def test_get_source_line(self, tmp_path):
        from soldb.core.transaction_tracer import SourceMapper
        source = tmp_path / "C.sol"
        source.write_text("uint256 x = 1;\nreturn x;\n")
        mapper = SourceMapper(str(source), "0:14:0;14:9:0")
        line = mapper.get_source_line(0)
        assert line is not None
        assert "uint256" in line

    def test_get_source_line_missing_pc(self, tmp_path):
        from soldb.core.transaction_tracer import SourceMapper
        source = tmp_path / "C.sol"
        source.write_text("x = 1;\n")
        mapper = SourceMapper(str(source), "0:6:0")
        assert mapper.get_source_line(99) is None

    def test_missing_file(self):
        from soldb.core.transaction_tracer import SourceMapper
        mapper = SourceMapper("/nonexistent/file.sol", "0:6:0")
        assert mapper.source_lines == []

    def test_empty_source_map(self, tmp_path):
        from soldb.core.transaction_tracer import SourceMapper
        source = tmp_path / "C.sol"
        source.write_text("x = 1;\n")
        mapper = SourceMapper(str(source), "")
        assert mapper.pc_to_source == {}


class TestPrintFunctionTraceArgs:
    """Test args display in print_function_trace."""
    def test_create_with_deployed_address(self, capsys):
        t = _tracer()
        steps = [TraceStep(i, "PUSH1", 100, 1, 0, []) for i in range(3)]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x", gas_used=100, output="0x",
            steps=steps, success=True,
        )
        root = FunctionCall("dispatcher", "", 0, 2, 100, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0,
                            children_call_ids=[1])
        create = FunctionCall("Token", "", 1, 2, 50, 1,
                              [("salt", 42)],
                              call_type="CREATE", contract_address="0x" + "dd" * 20,
                              call_id=1, parent_call_id=0)
        t.print_function_trace(trace, [root, create])
        out = capsys.readouterr().out
        assert "deployed at" in out

    def test_with_return_value(self, capsys):
        t = _tracer()
        steps = [TraceStep(0, "PUSH1", 100, 1, 0, [])]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x", gas_used=50, output="0x",
            steps=steps, success=True,
        )
        root = FunctionCall("dispatcher", "", 0, 0, 50, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0,
                            children_call_ids=[1])
        child = FunctionCall("get", "0x12345678", 0, 0, 20, 1,
                             [], call_type="internal", contract_address=ADDR,
                             call_id=1, parent_call_id=0, return_value="42")
        t.print_function_trace(trace, [root, child])
        out = capsys.readouterr().out
        assert "42" in out

    def test_external_call_verified(self, capsys):
        t = _tracer()
        steps = [TraceStep(0, "PUSH1", 100, 1, 0, [])]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x12345678" + "0" * 64,
            gas_used=50, output="0x", steps=steps, success=True,
        )
        root = FunctionCall("dispatcher", "", 0, 0, 50, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0,
                            children_call_ids=[1])
        ext = FunctionCall("set", "0x12345678", 0, 0, 20, 1,
                           [], call_type="external", contract_address=ADDR,
                           call_id=1, parent_call_id=0, source_line=10)
        t.print_function_trace(trace, [root, ext])
        out = capsys.readouterr().out
        assert "external" in out


class TestProcessExternalCall:
    def test_call_with_known_selector(self):
        t = _tracer()
        t.function_signatures = {
            "0x12345678": {"name": "set(uint256)", "signature": "set(uint256)"},
        }
        t.function_abis = {
            "0x12345678": {
                "name": "set",
                "inputs": [{"name": "x", "type": "uint256"}],
            }
        }
        step = TraceStep(
            10, "CALL", 900, 2, 0,
            ["0x0", "0x0", "0x24", "0x00", "0x0", "0x" + "bb" * 20, "0x1000"],
            memory="12345678" + f"{42:064x}",
        )
        result = t._process_external_call(step, 1, ADDR, 0)
        assert result is not None
        assert "set" in result.name
        assert result.call_type == "CALL"

    def test_staticcall(self):
        t = _tracer()
        step = TraceStep(
            10, "STATICCALL", 900, 2, 0,
            ["0x0", "0x24", "0x00", "0x0", "0x" + "bb" * 20, "0x1000"],
            memory="70a08231" + "0" * 64,
        )
        result = t._process_external_call(step, 1, ADDR, 0)
        assert result is not None
        assert result.call_type == "STATICCALL"
        assert result.value is None  # STATICCALL has no value

    def test_delegatecall(self):
        t = _tracer()
        step = TraceStep(
            10, "DELEGATECALL", 900, 2, 0,
            ["0x0", "0x04", "0x00", "0x0", "0x" + "cc" * 20, "0x500"],
            memory="12345678",
        )
        result = t._process_external_call(step, 1, ADDR, 0)
        assert result is not None
        assert result.call_type == "DELEGATECALL"

    def test_insufficient_stack(self):
        t = _tracer()
        step = TraceStep(10, "CALL", 900, 2, 0, ["0x0", "0x0"])
        result = t._process_external_call(step, 1, ADDR, 0)
        assert result is None

    def test_unknown_function(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        step = TraceStep(
            10, "CALL", 900, 2, 0,
            ["0x0", "0x0", "0x24", "0x00", "0x0", "0x" + "bb" * 20, "0x1000"],
            memory="deadbeef" + "0" * 64,
        )
        result = t._process_external_call(step, 1, ADDR, 0)
        assert result is not None
        assert "function_0x" in result.name

    def test_no_calldata(self):
        t = _tracer()
        step = TraceStep(
            10, "CALL", 900, 2, 0,
            ["0x0", "0x0", "0x00", "0x00", "0x0", "0x" + "bb" * 20, "0x1000"],
            memory="",
        )
        result = t._process_external_call(step, 1, ADDR, 0)
        assert result is not None
        assert "function_0x" in result.name

    def test_with_multi_contract_parser(self):
        t = _tracer()
        target = "0x" + "bb" * 20
        t.multi_contract_parser = SimpleNamespace(
            get_contract_at_address=lambda addr: SimpleNamespace(name="Router") if "bb" in addr.lower() else None,
        )
        step = TraceStep(
            10, "CALL", 900, 2, 0,
            ["0x0", "0x0", "0x04", "0x00", "0x0", target, "0x1000"],
            memory="12345678",
        )
        result = t._process_external_call(step, 1, ADDR, 0)
        assert "Router" in result.name

    def test_zero_selector(self):
        t = _tracer()
        step = TraceStep(
            10, "CALL", 900, 2, 0,
            ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "bb" * 20, "0x1000"],
            memory="00000000",
        )
        result = t._process_external_call(step, 1, ADDR, 0)
        assert result is not None
        assert "function_0x" in result.name


class TestProcessCreateCall:
    def test_create(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "_extract_created_address",
                            lambda step_idx, trace: "0x" + "dd" * 20)
        step = TraceStep(
            10, "CREATE", 900, 3, 0,
            ["0x06", "0x00", "0x00"],
            memory="600160020300",
        )
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x", gas_used=100, output="0x",
            steps=[step], success=True,
        )
        result = t._process_create_call(step, 0, ADDR, 0, trace)
        assert result is not None
        assert "CREATE" in result.call_type


class TestAnalyzeFunctionCallsDeep:
    """Tests exercising the analyze_function_calls loop with complex traces."""

    def test_delegatecall_and_return(self, monkeypatch):
        t = _tracer()
        t.function_signatures = {}
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        # Trace: entry -> DELEGATECALL -> internal -> RETURN -> STOP
        steps = [
            TraceStep(0, "PUSH1", 1000, 1, 0, ["0x01"]),
            TraceStep(1, "DELEGATECALL", 900, 2, 0,
                      ["0x0", "0x04", "0x00", "0x0", "0x" + "cc" * 20, "0x500"],
                      memory="12345678"),
            TraceStep(2, "PUSH1", 850, 1, 1, ["0x01"]),
            TraceStep(3, "RETURN", 800, 1, 0, ["0x0", "0x0"]),
            TraceStep(4, "PUSH1", 750, 1, 0, ["0x01"]),
            TraceStep(5, "STOP", 700, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x12345678" + "0" * 64,
            gas_used=300, output="0x", steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        assert len(calls) >= 1
        # Should detect the DELEGATECALL
        has_delegate = any(c.call_type == "DELEGATECALL" for c in calls)
        assert has_delegate

    def test_staticcall_and_revert(self, monkeypatch):
        t = _tracer()
        t.function_signatures = {"0xdeadbeef": {"name": "check()", "signature": "check()"}}
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        steps = [
            TraceStep(0, "PUSH1", 1000, 1, 0, ["0x01"]),
            TraceStep(1, "STATICCALL", 900, 2, 0,
                      ["0x0", "0x04", "0x00", "0x0", "0x" + "dd" * 20, "0x500"],
                      memory="deadbeef"),
            TraceStep(2, "PUSH1", 850, 1, 1, []),
            TraceStep(3, "REVERT", 800, 1, 1, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0xdeadbeef",
            gas_used=200, output="0x", steps=steps, success=False, error="reverted",
        )
        calls = t.analyze_function_calls(trace)
        assert any(c.caused_revert for c in calls)

    def test_create_opcode(self, monkeypatch):
        t = _tracer()
        t.function_signatures = {}
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        monkeypatch.setattr(t, "_extract_created_address",
                            lambda step_idx, trace: "0x" + "ee" * 20)
        steps = [
            TraceStep(0, "PUSH1", 1000, 1, 0, ["0x01"]),
            TraceStep(1, "CREATE", 900, 3, 0,
                      ["0x06", "0x00", "0x00"],
                      memory="600160020300"),
            TraceStep(2, "PUSH1", 850, 1, 1, ["0x01"]),
            TraceStep(3, "STOP", 800, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x",
            gas_used=200, output="0x", steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        has_create = any(c.call_type == "CREATE" for c in calls)
        assert has_create

    def test_with_ethdebug_internal_detection(self, monkeypatch):
        t = _tracer()
        t.function_signatures = {"0x12345678": {"name": "set(uint256)"}}
        t.function_abis_by_name = {
            "helper": {
                "name": "helper",
                "inputs": [{"name": "x", "type": "uint256"}],
            }
        }
        t.ethdebug_info = SimpleNamespace(
            contract_name="Token", sources={0: "Token.sol"}
        )
        t.ethdebug_parser = SimpleNamespace(
            debug_info=True,
            get_source_context=lambda pc, context_lines=2: {
                "file": "Token.sol", "line": pc + 1, "column": 0,
                "content": "function helper(uint256 x) public {"
            } if pc == 5 else None,
        )
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        steps = [
            TraceStep(0, "PUSH1", 1000, 1, 0, ["0x01"]),
            TraceStep(5, "JUMPDEST", 950, 1, 0, ["0x2a"]),
            TraceStep(6, "PUSH1", 940, 1, 0, ["0x01"]),
            TraceStep(7, "STOP", 930, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x12345678" + "0" * 64,
            gas_used=100, output="0x", steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        has_helper = any("helper" in c.name for c in calls)
        assert has_helper

    def test_multiple_returns_depth_tracking(self, monkeypatch):
        t = _tracer()
        t.function_signatures = {}
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        # Simulate depth changes: 0->1->0
        steps = [
            TraceStep(0, "PUSH1", 1000, 1, 0, ["0x01"]),   # depth 0
            TraceStep(1, "CALL", 900, 2, 0,                  # depth 0, calls to depth 1
                      ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "bb" * 20, "0x0"],
                      memory="12345678"),
            TraceStep(2, "PUSH1", 850, 1, 1, []),             # depth 1
            TraceStep(3, "STOP", 800, 1, 1, []),              # depth 1
            # depth decreases back to 0
            TraceStep(4, "PUSH1", 750, 1, 0, ["0x01"]),       # depth 0
            TraceStep(5, "STOP", 700, 1, 0, []),              # depth 0
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
            value=0, input_data="0x",
            gas_used=300, output="0x", steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        assert len(calls) >= 2  # entry + CALL


class TestLoggingConvenience:
    def test_log_functions(self):
        from soldb.utils.logging import log_debug, log_info, log_warning, log_error, log_trace
        # These should not raise
        log_debug("test debug")
        log_info("test info")
        log_warning("test warning")
        log_error("test error")
        log_trace("test trace")


class TestCompilerEthdebugMainFileListing:
    """Cover remaining lines in compiler/ethdebug.py main() dual-compile file listing."""
    def test_dual_compile_partial_files(self, monkeypatch, tmp_path, capsys):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        monkeypatch.setattr(
            compiler_ethdebug, "dual_compile",
            lambda path, config: {
                "production": {"success": True, "output_dir": "prod"},
                "debug": {
                    "success": True, "output_dir": "debug",
                    "files": {
                        "ethdebug": None,  # no global ethdebug
                        "contracts": {
                            "C": {
                                "bytecode": None,
                                "abi": "C.abi",
                                "ethdebug": None,
                                "ethdebug_runtime": None,
                            }
                        },
                    },
                },
            },
        )
        monkeypatch.setattr(sys, "argv", ["ethdebug", str(contract), "--dual-compile"])
        compiler_ethdebug.main()
        out = capsys.readouterr().out
        assert "C.abi" in out

    def test_single_compile_with_all_files(self, monkeypatch, tmp_path, capsys):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}")
        monkeypatch.setattr(
            CompilerConfig, "compile_with_ethdebug",
            lambda self, path: {
                "success": True, "output_dir": "out",
                "files": {
                    "ethdebug": "out/ethdebug.json",
                    "contracts": {
                        "C": {
                            "bytecode": "C.bin",
                            "abi": "C.abi",
                            "ethdebug": "C_ethdebug.json",
                            "ethdebug_runtime": "C_ethdebug-runtime.json",
                        }
                    },
                },
                "stderr": "",
            },
        )
        monkeypatch.setattr(sys, "argv", ["ethdebug", str(contract)])
        compiler_ethdebug.main()
        out = capsys.readouterr().out
        assert "C.bin" in out
        assert "C.abi" in out
        assert "C_ethdebug.json" in out


class TestTracerLoadAbiEdgeCases:
    def test_load_abi_with_event_indexed_params(self, tmp_path):
        t = _tracer()
        abi = [{
            "type": "event",
            "name": "Transfer",
            "inputs": [
                {"name": "from", "type": "address", "indexed": True},
                {"name": "to", "type": "address", "indexed": True},
                {"name": "value", "type": "uint256", "indexed": False},
            ],
        }]
        p = tmp_path / "ERC20.abi"
        p.write_text(json.dumps(abi))
        t.load_abi(str(p))
        assert len(t.event_abis) == 1
        assert any("Transfer" in v for v in t.event_signatures.values())

    def test_load_abi_invalid_json(self, tmp_path, capsys):
        t = _tracer()
        p = tmp_path / "bad.abi"
        p.write_text("not json")
        t.load_abi(str(p))
        assert len(t.function_abis) == 0
