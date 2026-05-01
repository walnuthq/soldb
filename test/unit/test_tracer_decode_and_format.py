"""Additional tests for transaction_tracer.py helper methods to boost coverage."""

import json
from types import SimpleNamespace

import pytest
from web3 import Web3

from soldb.core.transaction_tracer import (
    FunctionCall,
    TraceStep,
    TransactionTrace,
    TransactionTracer,
)

ADDR = "0x00000000000000000000000000000000000000aa"
OTHER_ADDR = "0x00000000000000000000000000000000000000bb"
FROM_ADDR = "0x0000000000000000000000000000000000000001"


def _tracer():
    """Create a minimal TransactionTracer without RPC connection."""
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


def _trace(**kw):
    defaults = dict(
        tx_hash="0xtx", from_addr=FROM_ADDR, to_addr=ADDR,
        value=0, input_data="0x12345678", gas_used=100, output="0x",
        steps=[
            TraceStep(0, "PUSH1", 1000, 1, 0, ["0x2a"]),
            TraceStep(2, "ADD", 990, 1, 0, ["0x2a", "0x01"]),
            TraceStep(4, "STOP", 980, 1, 0, []),
        ],
        success=True,
    )
    defaults.update(kw)
    return TransactionTrace(**defaults)


class TestFormatAbiType:
    def test_simple_type(self):
        t = _tracer()
        assert t.format_abi_type({"type": "uint256"}) == "uint256"

    def test_tuple_type(self):
        t = _tracer()
        result = t.format_abi_type({
            "type": "tuple",
            "components": [
                {"type": "uint256"},
                {"type": "address"},
            ],
        })
        assert result == "(uint256,address)"

    def test_nested_tuple(self):
        t = _tracer()
        result = t.format_abi_type({
            "type": "tuple",
            "components": [
                {"type": "tuple", "components": [{"type": "uint256"}]},
                {"type": "bool"},
            ],
        })
        assert result == "((uint256),bool)"

    def test_array_type(self):
        t = _tracer()
        assert t.format_abi_type({"type": "uint256[]"}) == "uint256[]"

    def test_tuple_array(self):
        t = _tracer()
        result = t.format_abi_type({
            "type": "tuple[]",
            "components": [{"type": "uint256"}, {"type": "bool"}],
        })
        assert result == "(uint256,bool)[]"


class TestLoadAbi:
    def test_load_direct_array(self, tmp_path):
        t = _tracer()
        abi = [
            {"type": "function", "name": "set",
             "inputs": [{"name": "x", "type": "uint256"}]},
            {"type": "event", "name": "Set",
             "inputs": [{"name": "x", "type": "uint256", "indexed": False}]},
        ]
        p = tmp_path / "Token.abi"
        p.write_text(json.dumps(abi))
        t.load_abi(str(p))
        assert "set" in t.function_abis_by_name
        assert len(t.event_abis) == 1

    def test_load_forge_artifact(self, tmp_path):
        t = _tracer()
        artifact = {
            "abi": [
                {"type": "function", "name": "get", "inputs": []},
            ]
        }
        p = tmp_path / "Token.json"
        p.write_text(json.dumps(artifact))
        t.load_abi(str(p))
        assert "get" in t.function_abis_by_name

    def test_load_unknown_format(self, tmp_path, capsys):
        t = _tracer()
        p = tmp_path / "bad.json"
        p.write_text('{"not_abi": true}')
        t.load_abi(str(p))
        assert len(t.function_abis) == 0

    def test_load_missing_file(self, capsys):
        t = _tracer()
        t.load_abi("/nonexistent/path.abi")
        # Should print warning, not crash

    def test_load_with_tuple_input(self, tmp_path):
        t = _tracer()
        abi = [{
            "type": "function", "name": "swap",
            "inputs": [{
                "name": "params", "type": "tuple",
                "components": [
                    {"name": "tokenIn", "type": "address"},
                    {"name": "amount", "type": "uint256"},
                ],
            }],
        }]
        p = tmp_path / "Router.abi"
        p.write_text(json.dumps(abi))
        t.load_abi(str(p))
        assert "swap" in t.function_abis_by_name
        # Selector should be based on tuple signature
        found = any("swap" in v.get("name", "") for v in t.function_signatures.values())
        assert found


class TestFormatTraceStep:
    def test_basic_step(self):
        t = _tracer()
        trace = _trace()
        step = trace.steps[0]
        result = t.format_trace_step(step, {0: ("C.sol", 5)}, 0, 3)
        assert "PUSH1" in result

    def test_step_with_ethdebug(self):
        t = _tracer()
        t.ethdebug_info = SimpleNamespace()
        t.ethdebug_parser = SimpleNamespace(
            get_source_context=lambda pc, context_lines=0: {
                "file": "Token.sol", "line": 42, "column": 3
            }
        )
        trace = _trace()
        result = t.format_trace_step(trace.steps[0], {}, 0, 3, trace, 0)
        assert "Token.sol" in result

    def test_step_with_source_map_only(self):
        t = _tracer()
        trace = _trace()
        result = t.format_trace_step(trace.steps[0], {0: ("C.sol", 7)}, 0, 3)
        assert "line 7" in result

    def test_step_empty_stack(self):
        t = _tracer()
        trace = _trace()
        result = t.format_trace_step(trace.steps[2], {}, 0, 3)
        assert "empty" in result

    def test_step_large_stack(self):
        t = _tracer()
        step = TraceStep(0, "PUSH1", 100, 1, 0,
                         ["0x" + "aa" * 20, "0x01", "0x02", "0x03", "0x04"])
        trace = _trace()
        result = t.format_trace_step(step, {}, 0, 1)
        assert "more" in result


class TestPrintTrace:
    def test_print_trace_basic(self, capsys):
        t = _tracer()
        trace = _trace()
        t.print_trace(trace, {0: ("C.sol", 1)}, max_steps=2)
        out = capsys.readouterr().out
        assert "0xtx" in out
        assert "PUSH1" in out
        assert "more steps" in out

    def test_print_trace_all_steps(self, capsys):
        t = _tracer()
        trace = _trace()
        t.print_trace(trace, {}, max_steps=0)
        out = capsys.readouterr().out
        assert "all 3 steps" in out

    def test_print_trace_with_error(self, capsys):
        t = _tracer()
        trace = _trace(success=False, error="reverted", output="0xdead")
        t.print_trace(trace, {}, max_steps=10)
        out = capsys.readouterr().out
        assert "reverted" in out
        assert "0xdead" in out


class TestPrintFunctionTrace:
    def test_basic_function_trace(self, capsys):
        t = _tracer()
        trace = _trace()
        root = FunctionCall("runtime_dispatcher", "", 0, 2, 100, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0,
                            children_call_ids=[1])
        child = FunctionCall("set", "0x12345678", 0, 2, 50, 1,
                             [("amount", 42)],
                             call_type="internal", contract_address=ADDR,
                             call_id=1, parent_call_id=0)
        t.print_function_trace(trace, [root, child])
        out = capsys.readouterr().out
        assert "Function Call Trace" in out

    def test_function_trace_with_value(self, capsys):
        t = _tracer()
        trace = _trace(value=1000000000000000000)  # 1 ETH
        root = FunctionCall("receive", "", 0, 2, 100, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0)
        t.print_function_trace(trace, [root])
        out = capsys.readouterr().out
        assert "Function Call Trace" in out

    def test_function_trace_reverted(self, capsys):
        t = _tracer()
        trace = _trace(success=False, error="revert reason")
        root = FunctionCall("bad", "", 0, 0, 100, 0, [],
                            call_type="entry", contract_address=ADDR, call_id=0,
                            caused_revert=True)
        t.print_function_trace(trace, [root])
        out = capsys.readouterr().out
        assert "REVERTED" in out or "revert" in out.lower()


class TestReplayTransaction:
    def test_replay_full(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "trace_transaction", lambda tx: _trace())
        result = t.replay_transaction("0xtx")
        assert len(result.steps) == 3

    def test_replay_stop_at_pc(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "trace_transaction", lambda tx: _trace())
        result = t.replay_transaction("0xtx", stop_at_pc=2)
        assert len(result.steps) == 2
        assert result.steps[-1].pc == 2

    def test_replay_stop_at_nonexistent_pc(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "trace_transaction", lambda tx: _trace())
        result = t.replay_transaction("0xtx", stop_at_pc=999)
        assert len(result.steps) == 3  # All steps returned


class TestDecodeHelpers:
    def test_decode_value_uint(self):
        t = _tracer()
        assert t.decode_value("0x2a", "uint256") == 42

    def test_decode_value_bool(self):
        t = _tracer()
        assert t.decode_value("0x1", "bool") is True
        assert t.decode_value("0x0", "bool") is False

    def test_decode_value_address(self):
        t = _tracer()
        result = t.decode_value("0x" + "00" * 12 + "aa" * 20, "address")
        assert isinstance(result, str)
        assert result.startswith("0x") or result.startswith("0X")

    def test_decode_value_bytes(self):
        t = _tracer()
        result = t.decode_value("0xdeadbeef", "bytes4")
        assert "deadbeef" in str(result).lower()

    def test_decode_value_string(self):
        t = _tracer()
        result = t.decode_value("0x48656c6c6f", "string")
        assert isinstance(result, str)


class TestLookupFunctionSignature:
    def test_lookup_unknown(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "_lookup_openchain", lambda s: None)
        monkeypatch.setattr(t, "_lookup_4byte", lambda s: None)
        assert t.lookup_function_signature("0xdeadbeef") is None

    def test_lookup_with_prefix(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "_lookup_openchain", lambda s: "transfer(address,uint256)")
        monkeypatch.setattr(t, "_lookup_4byte", lambda s: None)
        result = t.lookup_function_signature("0xa9059cbb")
        assert result == "transfer(address,uint256)"

    def test_lookup_4byte_fallback(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "_lookup_openchain", lambda s: None)
        monkeypatch.setattr(t, "_lookup_4byte", lambda s: "approve(address,uint256)")
        result = t.lookup_function_signature("095ea7b3")
        assert result == "approve(address,uint256)"


class TestTraceStep:
    def test_format_stack_short(self):
        step = TraceStep(0, "PUSH1", 100, 1, 0, ["0x01", "0x02"])
        result = step.format_stack()
        assert "[0]" in result
        assert "[1]" in result

    def test_format_stack_long_values(self):
        step = TraceStep(0, "PUSH1", 100, 1, 0, ["0x" + "aa" * 20])
        result = step.format_stack()
        assert "..." in result

    def test_format_stack_many_items(self):
        step = TraceStep(0, "PUSH1", 100, 1, 0, ["0x01"] * 10)
        result = step.format_stack()
        assert "more" in result

    def test_format_stack_empty(self):
        step = TraceStep(0, "PUSH1", 100, 1, 0, [])
        result = step.format_stack()
        assert result == "[empty]"


class TestConvertStylusCallsToFunctionCalls:
    def test_empty_trace(self):
        t = _tracer()
        stylus_trace = SimpleNamespace(calls=[])
        result = t._convert_stylus_calls_to_function_calls(stylus_trace)
        assert result == []

    def test_single_root_call(self):
        t = _tracer()
        call = SimpleNamespace(
            function_name="transfer",
            function_selector="0xa9059cbb",
            gas_used=1000,
            args=[SimpleNamespace(name="to", value=ADDR)],
            call_type="call",
            contract_address=ADDR,
            call_id=1,
            parent_call_id=None,
            success=True,
            error=None,
            source_location=SimpleNamespace(line=42),
            children=[],
        )
        stylus_trace = SimpleNamespace(calls=[call])
        result = t._convert_stylus_calls_to_function_calls(stylus_trace, depth_offset=1)
        assert len(result) == 1
        assert "[Stylus]" in result[0].name
        assert result[0].depth == 2

    def test_nested_calls(self):
        t = _tracer()
        child = SimpleNamespace(
            function_name="inner",
            function_selector="",
            gas_used=100,
            args=[],
            call_type="internal",
            contract_address=ADDR,
            call_id=2,
            parent_call_id=1,
            success=True,
            error=None,
            source_location=None,
            children=[],
        )
        root = SimpleNamespace(
            function_name="outer",
            function_selector="0x12345678",
            gas_used=500,
            args=[],
            call_type="call",
            contract_address=ADDR,
            call_id=1,
            parent_call_id=None,
            success=True,
            error=None,
            source_location=None,
            children=[child],
        )
        stylus_trace = SimpleNamespace(calls=[root, child])
        result = t._convert_stylus_calls_to_function_calls(stylus_trace)
        assert len(result) == 2
        assert result[0].name == "[Stylus] outer"
        assert result[1].name == "[Stylus] inner"

    def test_failed_call(self):
        t = _tracer()
        call = SimpleNamespace(
            function_name="bad",
            function_selector="",
            gas_used=0,
            args=[],
            call_type="call",
            contract_address=ADDR,
            call_id=1,
            parent_call_id=None,
            success=False,
            error="out of gas",
            source_location=None,
            children=[],
        )
        stylus_trace = SimpleNamespace(calls=[call])
        result = t._convert_stylus_calls_to_function_calls(stylus_trace)
        assert result[0].caused_revert is True
        assert result[0].error == "out of gas"


class TestDecodeValueExtended:
    def test_int256_positive(self):
        t = _tracer()
        assert t.decode_value("0x2a", "int256") == 42

    def test_int256_negative(self):
        t = _tracer()
        # -1 in int256 = 0xfff...fff
        result = t.decode_value("ff" * 32, "int256")
        assert result == -1

    def test_int8_negative(self):
        t = _tracer()
        result = t.decode_value("0x80", "int8")
        assert result == -128

    def test_bytes32(self):
        t = _tracer()
        result = t.decode_value("0xdeadbeef", "bytes32")
        assert result == "0xdeadbeef"

    def test_bytes_generic(self):
        t = _tracer()
        result = t.decode_value("0xabcd", "bytes4")
        assert result == "0xabcd"

    def test_string_type(self):
        t = _tracer()
        result = t.decode_value("0x1234", "string")
        assert "string" in result.lower()

    def test_unknown_type(self):
        t = _tracer()
        result = t.decode_value("0xbeef", "unknown_type")
        assert result == "0xbeef"

    def test_empty_value_uint(self):
        t = _tracer()
        assert t.decode_value("", "uint256") == 0

    def test_empty_value_other(self):
        t = _tracer()
        assert t.decode_value("", "address") == "0x"

    def test_decode_error(self):
        t = _tracer()
        # Invalid hex
        result = t.decode_value("not_hex", "uint256")
        assert isinstance(result, (int, str))


class TestExtractFromMemory:
    def test_uint256_from_memory(self):
        t = _tracer()
        # 32 bytes of memory, value = 42 at offset 0
        memory = f"{42:064x}"
        result = t.extract_from_memory(memory, 0, "uint256")
        assert result == 42

    def test_string_from_memory(self):
        t = _tracer()
        # length=5 at offset 0, then "hello"
        length = f"{5:064x}"
        data = "68656c6c6f"  # "hello"
        memory = length + data + "00" * 27
        result = t.extract_from_memory(memory, 0, "string")
        assert result == "hello"

    def test_bytes32_from_memory(self):
        t = _tracer()
        memory = "ab" * 32
        result = t.extract_from_memory(memory, 0, "bytes32")
        assert result.startswith("0x")

    def test_dynamic_bytes_from_memory(self):
        t = _tracer()
        length = f"{4:064x}"
        data = "deadbeef"
        memory = length + data + "00" * 28
        result = t.extract_from_memory(memory, 0, "bytes")
        assert "deadbeef" in result

    def test_fixed_bytes_from_memory(self):
        t = _tracer()
        memory = "aabb" + "00" * 30
        result = t.extract_from_memory(memory, 0, "bytes2")
        assert result.startswith("0x")

    def test_memory_error(self):
        t = _tracer()
        result = t.extract_from_memory("", 1000, "uint256")
        assert result is None


class TestExtractFromStorage:
    def test_existing_slot(self):
        t = _tracer()
        storage = {"0x0": f"{100:064x}"}
        result = t.extract_from_storage(storage, 0, "uint256")
        assert result == 100

    def test_missing_slot(self):
        t = _tracer()
        result = t.extract_from_storage({}, 5, "uint256")
        assert result is None

    def test_string_slot_key(self):
        t = _tracer()
        storage = {"0x1": "00" * 31 + "01"}
        result = t.extract_from_storage(storage, 1, "bool")
        assert result is True


class TestFindParameterValueFromEthdebug:
    def test_stack_variable(self):
        t = _tracer()
        t.ethdebug_info = SimpleNamespace(
            get_variables_at_pc=lambda pc: [
                SimpleNamespace(name="amount", type="uint256", location_type="stack", offset=0),
            ]
        )
        steps = [TraceStep(10, "PUSH1", 100, 1, 0, ["0x2a"])]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=steps, success=True,
        )
        result = t.find_parameter_value_from_ethdebug(trace, 0, "amount", "uint256")
        assert result == 42

    def test_memory_variable(self):
        t = _tracer()
        t.ethdebug_info = SimpleNamespace(
            get_variables_at_pc=lambda pc: [
                SimpleNamespace(name="data", type="uint256", location_type="memory", offset=0),
            ]
        )
        steps = [TraceStep(10, "PUSH1", 100, 1, 0, [], memory=f"{7:064x}")]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=steps, success=True,
        )
        result = t.find_parameter_value_from_ethdebug(trace, 0, "data", "uint256")
        assert result == 7

    def test_storage_variable(self):
        t = _tracer()
        t.ethdebug_info = SimpleNamespace(
            get_variables_at_pc=lambda pc: [
                SimpleNamespace(name="stored", type="uint256", location_type="storage", offset=1),
            ]
        )
        steps = [TraceStep(10, "PUSH1", 100, 1, 0, [], storage={"0x1": f"{99:064x}"})]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=steps, success=True,
        )
        result = t.find_parameter_value_from_ethdebug(trace, 0, "stored", "uint256")
        assert result == 99

    def test_variable_not_found(self):
        t = _tracer()
        t.ethdebug_info = SimpleNamespace(
            get_variables_at_pc=lambda pc: []
        )
        steps = [TraceStep(10, "PUSH1", 100, 1, 0, [])]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=steps, success=True,
        )
        result = t.find_parameter_value_from_ethdebug(trace, 0, "missing", "uint256")
        assert result is None

    def test_stack_offset_out_of_range(self):
        t = _tracer()
        t.ethdebug_info = SimpleNamespace(
            get_variables_at_pc=lambda pc: [
                SimpleNamespace(name="x", type="uint256", location_type="stack", offset=99),
            ]
        )
        steps = [TraceStep(10, "PUSH1", 100, 1, 0, ["0x01"])]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr="0x0000000000000000000000000000000000000001",
            to_addr=ADDR, value=0, input_data="0x", gas_used=100, output="0x",
            steps=steps, success=True,
        )
        result = t.find_parameter_value_from_ethdebug(trace, 0, "x", "uint256")
        assert result is None


class TestGetSourceContext:
    def test_with_multi_parser(self):
        t = _tracer()
        t.multi_contract_parser = SimpleNamespace(
            get_source_info_for_address=lambda addr, pc: {"file": "M.sol", "line": 5, "column": 0}
        )
        step = TraceStep(10, "PUSH1", 100, 1, 0, [])
        result = t.get_source_context_for_step(step, address=ADDR)
        assert result["file"] == "M.sol"

    def test_with_ethdebug_parser(self):
        t = _tracer()
        t.ethdebug_info = SimpleNamespace()
        t.ethdebug_parser = SimpleNamespace(
            get_source_context=lambda pc, context_lines=2: {"file": "E.sol", "line": 3, "column": 1}
        )
        step = TraceStep(10, "PUSH1", 100, 1, 0, [])
        result = t.get_source_context_for_step(step)
        assert result["file"] == "E.sol"

    def test_with_srcmap_parser(self):
        t = _tracer()
        t.srcmap_info = SimpleNamespace()
        t.srcmap_parser = SimpleNamespace(
            get_source_context=lambda pc, context_lines=2: {"file": "S.sol", "line": 7}
        )
        step = TraceStep(10, "PUSH1", 100, 1, 0, [])
        result = t.get_source_context_for_step(step)
        assert result["file"] == "S.sol"

    def test_no_parser(self):
        t = _tracer()
        step = TraceStep(10, "PUSH1", 100, 1, 0, [])
        result = t.get_source_context_for_step(step)
        assert result is None
