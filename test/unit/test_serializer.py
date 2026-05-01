import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from hexbytes import HexBytes

from soldb.core.serializer import TraceSerializer
from soldb.core.transaction_tracer import FunctionCall, TraceStep, TransactionTrace
from soldb.parsers.ethdebug import ETHDebugInfo, Instruction, SourceLocation


ADDR = "0x00000000000000000000000000000000000000aa"
FROM_ADDR = "0x0000000000000000000000000000000000000001"


def _trace(**kw):
    defaults = dict(
        tx_hash="0xtx",
        from_addr=FROM_ADDR,
        to_addr=ADDR,
        value=0,
        input_data="0x12345678",
        gas_used=100,
        output="0x",
        steps=[TraceStep(0, "PUSH1", 100, 1, 0, [])],
        success=True,
    )
    defaults.update(kw)
    return TransactionTrace(**defaults)


def _call(name="f", selector="0x12345678", entry=0, exit_step=1, gas=10,
          depth=0, args=None, **kw):
    defaults = dict(
        call_type="internal",
        contract_address=ADDR,
        call_id=0,
        children_call_ids=[],
    )
    defaults.update(kw)
    return FunctionCall(name, selector, entry, exit_step, gas, depth,
                        args or [], **defaults)


class TestConvertToSerializable:
    def test_tuple(self):
        s = TraceSerializer()
        assert s._convert_to_serializable((1, b"\x01")) == [1, "0x01"]

    def test_object_with_dict(self):
        s = TraceSerializer()
        obj = SimpleNamespace(x=1, y=HexBytes("0xab"))
        result = s._convert_to_serializable(obj)
        assert result["x"] == 1
        assert result["y"] == "ab"


class TestExtractLogs:
    def test_log0_no_memory(self):
        s = TraceSerializer()
        t = _trace(steps=[
            TraceStep(0, "LOG0", 10, 1, 0, ["0x00", "0x04"], memory=None),
        ])
        logs = s.extract_logs_from_trace(t)
        assert len(logs) == 1
        assert logs[0][1]["data"] == "0x00000000"

    def test_log_with_large_offset(self):
        s = TraceSerializer()
        t = _trace(steps=[
            TraceStep(0, "LOG0", 10, 1, 0, ["0xffffffff", "0x02"], memory="aa" * 100),
        ])
        logs = s.extract_logs_from_trace(t)
        assert len(logs) == 1

    def test_log_insufficient_stack(self):
        s = TraceSerializer()
        t = _trace(steps=[
            TraceStep(0, "LOG2", 10, 1, 0, ["0x00"]),
        ])
        logs = s.extract_logs_from_trace(t)
        assert len(logs) == 0

    def test_log_with_int_topic(self):
        s = TraceSerializer()
        # Topic must have enough high bits to pass zero-filter
        big_topic = (0xdead << 224) | 0xbeef
        t = _trace(steps=[
            TraceStep(0, "LOG1", 10, 1, 0, ["0x00", "0x00", big_topic], memory=""),
        ])
        logs = s.extract_logs_from_trace(t)
        assert len(logs) == 1
        topic = logs[0][1]["topics"][0]
        assert topic.startswith("0x")
        assert "dead" in topic

    def test_log_with_string_topic_no_prefix(self):
        s = TraceSerializer()
        # Non-zero topic (so it's not filtered)
        t = _trace(steps=[
            TraceStep(0, "LOG1", 10, 1, 0, ["0x00", "0x00", "abcdef" * 10 + "abcd"], memory=""),
        ])
        logs = s.extract_logs_from_trace(t)
        assert len(logs) == 1
        topic = logs[0][1]["topics"][0]
        assert topic.startswith("0x")

    def test_log_memory_partial_read(self):
        s = TraceSerializer()
        # memory is shorter than requested size
        t = _trace(steps=[
            TraceStep(0, "LOG0", 10, 1, 0, ["0x00", "0x10"], memory="aabb"),
        ])
        logs = s.extract_logs_from_trace(t)
        assert logs[0][1]["data"].startswith("0x")

    def test_log_negative_offset_clamped(self):
        s = TraceSerializer()
        t = _trace(steps=[
            TraceStep(0, "LOG0", 10, 1, 0, ["-1", "0x02"], memory="aabb"),
        ])
        # Should handle ValueError for "-1"
        logs = s.extract_logs_from_trace(t)
        assert len(logs) == 1

    def test_log4_multiple_topics(self):
        s = TraceSerializer()
        topics = ["0x00", "0x02", "0x" + "aa" * 32, "0x" + "bb" * 32, "0x" + "cc" * 32, "0x" + "dd" * 32]
        t = _trace(steps=[
            TraceStep(0, "LOG4", 10, 1, 0, topics, memory="1122"),
        ])
        logs = s.extract_logs_from_trace(t)
        assert len(logs) == 1
        assert len(logs[0][1]["topics"]) == 4

    def test_log_zero_topic_filtered(self):
        s = TraceSerializer()
        zero_topic = "0x" + "0" * 64
        t = _trace(steps=[
            TraceStep(0, "LOG1", 10, 1, 0, ["0x00", "0x00", zero_topic], memory=""),
        ])
        logs = s.extract_logs_from_trace(t)
        assert len(logs) == 0  # filtered as invalid


class TestEncodeFunctionInput:
    def test_depth_1_with_input(self):
        s = TraceSerializer()
        t = _trace(input_data=HexBytes("0xdeadbeef"))
        call = _call(depth=1)
        result = s.encode_function_input(call, t)
        assert "deadbeef" in result

    def test_depth_1_with_bytes_input(self):
        s = TraceSerializer()
        t = _trace(input_data=b"\xde\xad")
        call = _call(depth=1)
        assert s.encode_function_input(call, t) == "0xdead"

    def test_no_selector(self):
        s = TraceSerializer()
        t = _trace()
        call = _call(selector=None)
        assert s.encode_function_input(call, t) == "0x"

    def test_overflow_value(self):
        s = TraceSerializer()
        t = _trace()
        call = _call(args=[("x", 2**257)])  # > 2**256
        result = s.encode_function_input(call, t)
        assert "0x" in result


class TestConvertFunctionCallToTraceCall:
    def test_external_call_type(self):
        s = TraceSerializer()
        t = _trace()
        call = _call(call_type="external", args=[("to", ADDR)])
        result = s.convert_function_call_to_trace_call(call, t, [], [call])
        assert result["type"] == "CALL"

    def test_create_call_type(self):
        s = TraceSerializer()
        t = _trace(contract_address=ADDR)
        call = _call(call_type="CREATE", depth=0)
        result = s.convert_function_call_to_trace_call(call, t, [], [call])
        assert result["type"] == "CREATE"

    def test_entry_with_contract_address(self):
        s = TraceSerializer()
        t = _trace(contract_address=ADDR)
        call = _call(call_type="entry", depth=0)
        result = s.convert_function_call_to_trace_call(call, t, [], [call])
        assert result["type"] == "CREATE"

    def test_internal_call_no_selector(self):
        s = TraceSerializer()
        t = _trace()
        call = _call(selector=None, call_type="internal", args=[("x", 7)])
        result = s.convert_function_call_to_trace_call(call, t, [], [call])
        assert result["type"] == "INTERNALCALL"
        assert "contractAddress" in result or "to" in result

    def test_args_with_abi_tuple(self):
        s = TraceSerializer()
        t = _trace()
        call = _call(args=[("s", "(1, true)")])
        tracer = SimpleNamespace(
            to_addr=ADDR,
            function_abis={
                "0x12345678": {
                    "name": "f",
                    "inputs": [{
                        "name": "s", "type": "tuple",
                        "components": [
                            {"name": "a", "type": "uint256"},
                            {"name": "b", "type": "bool"},
                        ],
                    }],
                }
            },
        )
        result = s.convert_function_call_to_trace_call(
            call, t, [], [call], tracer_instance=tracer
        )
        assert "tuple" in result["inputs"]["argumentsType"][0]

    def test_args_without_abi_address_detection(self):
        s = TraceSerializer()
        t = _trace()
        call = _call(args=[("to", "0x" + "aa" * 20)])
        result = s.convert_function_call_to_trace_call(call, t, [], [call])
        assert result["inputs"]["argumentsType"][0] == "address"

    def test_args_without_abi_string_detection(self):
        s = TraceSerializer()
        t = _trace()
        call = _call(args=[("name", "hello")])
        result = s.convert_function_call_to_trace_call(call, t, [], [call])
        assert result["inputs"]["argumentsType"][0] == "string"

    def test_call_with_logs(self):
        s = TraceSerializer()
        t = _trace(steps=[
            TraceStep(0, "PUSH1", 100, 1, 0, []),
            TraceStep(1, "PUSH1", 90, 2, 0, []),
        ])
        call = _call(entry=0, exit_step=1, call_id=0)
        log = {"address": ADDR, "topics": [], "data": "0x", "position": 0}
        result = s.convert_function_call_to_trace_call(
            call, t, [(0, log)], [call]
        )
        assert "logs" in result
        assert len(result["logs"]) == 1

    def test_revert_frame_with_call_error(self):
        s = TraceSerializer()
        t = _trace(success=False, error="trace error")
        call = _call(caused_revert=True, error="call error")
        result = s.convert_function_call_to_trace_call(call, t, [], [call])
        assert result["isRevertedFrame"] is True
        assert result["error"] == "call error"

    def test_revert_frame_fallback_to_trace_error(self):
        s = TraceSerializer()
        t = _trace(success=False, error="trace error")
        call = _call(caused_revert=True, error=None)
        result = s.convert_function_call_to_trace_call(call, t, [], [call])
        assert result["error"] == "trace error"

    def test_entry_with_multi_parser_verified(self):
        s = TraceSerializer()
        t = _trace()
        call = _call(call_type="entry")
        contract = SimpleNamespace(ethdebug_info="info")
        multi = SimpleNamespace(
            get_contract_at_address=lambda addr: contract
        )
        result = s.convert_function_call_to_trace_call(
            call, t, [], [call], multi_parser=multi
        )
        assert result["isVerified"] is True

    def test_non_entry_with_multi_parser(self):
        s = TraceSerializer()
        t = _trace()
        call = _call(call_type="internal")
        multi = SimpleNamespace(
            get_contract_at_address=lambda addr: SimpleNamespace(ethdebug_info=None)
        )
        result = s.convert_function_call_to_trace_call(
            call, t, [], [call], multi_parser=multi
        )
        assert result["isVerified"] is True  # contract exists (not None)

    def test_with_children(self):
        s = TraceSerializer()
        t = _trace(steps=[
            TraceStep(0, "PUSH1", 100, 1, 0, []),
            TraceStep(1, "PUSH1", 90, 2, 0, []),
            TraceStep(2, "PUSH1", 80, 3, 0, []),
        ])
        parent = _call(entry=0, exit_step=2, call_id=0, children_call_ids=[1])
        child = _call(name="g", entry=1, exit_step=1, call_id=1,
                       parent_call_id=0, depth=1)
        result = s.convert_function_call_to_trace_call(
            parent, t, [], [parent, child]
        )
        assert "calls" in result
        assert result["calls"][0]["functionName"] == "g"

    def test_delegatecall_type(self):
        s = TraceSerializer()
        t = _trace()
        call = _call(call_type="DELEGATECALL", depth=0)
        result = s.convert_function_call_to_trace_call(call, t, [], [call])
        assert result["type"] == "DELEGATECALL"

    def test_missing_gas_info(self):
        s = TraceSerializer()
        t = _trace(steps=[])
        call = _call(entry=None)
        result = s.convert_function_call_to_trace_call(call, t, [], [call])
        assert "gas" not in result or result.get("gas") is None


class TestExtractInternalFunctionABI:
    def test_with_tracer_abis(self):
        s = TraceSerializer()
        tracer = SimpleNamespace(
            to_addr=ADDR,
            function_abis={
                "0x1": {"name": "set", "inputs": [{"type": "uint256"}]},
            },
        )
        result = s.extract_internal_function_abi([], tracer)
        assert len(result) == 1

    def test_with_internal_calls(self):
        s = TraceSerializer()
        tracer = SimpleNamespace(to_addr=ADDR, function_abis={})
        calls = [
            _call(name="helper", call_type="internal",
                  args=[("x", 42), ("addr", "0x" + "bb" * 20)]),
        ]
        result = s.extract_internal_function_abi(calls, tracer)
        addr = list(result.keys())[0]
        func = result[addr][0]
        assert func["name"] == "helper"
        assert func["inputs"][0]["type"] == "uint256"
        assert func["inputs"][1]["type"] == "address"

    def test_skips_dispatcher_and_constructor(self):
        s = TraceSerializer()
        tracer = SimpleNamespace(to_addr=ADDR, function_abis={})
        calls = [
            _call(name="runtime_dispatcher", call_type="internal"),
            _call(name="constructor", call_type="internal"),
            _call(name="helper", call_type="internal"),
        ]
        result = s.extract_internal_function_abi(calls, tracer)
        addr = list(result.keys())[0]
        names = [f["name"] for f in result[addr]]
        assert "runtime_dispatcher" not in names
        assert "constructor" not in names
        assert "helper" in names

    def test_deduplication(self):
        s = TraceSerializer()
        tracer = SimpleNamespace(to_addr=ADDR, function_abis={})
        calls = [
            _call(name="helper", call_type="internal", call_id=0),
            _call(name="helper", call_type="internal", call_id=1),
        ]
        result = s.extract_internal_function_abi(calls, tracer)
        addr = list(result.keys())[0]
        assert len(result[addr]) == 1


class TestBuildStepsArray:
    def test_basic_steps(self):
        s = TraceSerializer()
        t = _trace(steps=[
            TraceStep(0, "PUSH1", 100, 1, 0, []),
            TraceStep(2, "PUSH1", 90, 2, 0, []),
        ])
        calls = [_call(entry=0, exit_step=1, call_id=0)]
        result = s.build_steps_array(t, calls)
        assert len(result) == 2
        assert result[0]["pc"] == 0

    def test_call_step_with_stack(self):
        s = TraceSerializer()
        t = _trace(steps=[
            TraceStep(0, "CALL", 100, 1, 0, ["0x00", "0x" + "aa" * 20, "0x00"]),
        ])
        calls = [_call(entry=0, exit_step=0, call_id=0)]
        result = s.build_steps_array(t, calls)
        assert result[0].get("targetContract") is not None

    def test_call_step_no_debug_info(self):
        s = TraceSerializer()
        t = _trace(steps=[
            TraceStep(0, "STATICCALL", 100, 1, 0, ["0x00", "0x" + "bb" * 20]),
        ])
        calls = [_call(entry=0, exit_step=0, call_id=0)]
        result = s.build_steps_array(t, calls)
        assert result[0]["debugInfo"] is False

    def test_call_step_with_multi_parser(self):
        s = TraceSerializer()
        target = "0x" + "aa" * 20
        t = _trace(steps=[
            TraceStep(0, "CALL", 100, 1, 0, ["0x00", target, "0x00"]),
        ])
        calls = [_call(entry=0, exit_step=0, call_id=0)]
        contract = SimpleNamespace(ethdebug_info="info")
        multi = SimpleNamespace(
            get_contract_at_address=lambda addr: contract
        )
        result = s.build_steps_array(t, calls, multi_parser=multi)
        assert "debugInfo" not in result[0]  # has debug info, so field omitted


class TestBuildContractsMapping:
    def test_with_multi_parser(self, tmp_path):
        s = TraceSerializer()
        t = _trace()
        abi_file = tmp_path / "Token.abi"
        abi_file.write_text('[{"name": "set"}]')

        parser = SimpleNamespace(
            load_source_file=lambda path: ["contract Token {}"]
        )
        info = ETHDebugInfo(
            compilation={},
            contract_name="Token",
            environment="runtime",
            instructions=[
                Instruction(0, {"mnemonic": "PUSH1"},
                            {"code": {"source": {"id": 0}, "range": {"offset": 0, "length": 8}}})
            ],
            sources={0: "Token.sol"},
        )
        contract = SimpleNamespace(
            debug_dir=tmp_path, name="Token", parser=parser,
            ethdebug_info=info,
        )
        multi = SimpleNamespace(
            contracts={ADDR: contract}
        )
        result = s.build_contracts_mapping(t, None, multi, {})
        assert ADDR in result
        assert "pcToSourceMappings" in result[ADDR]
        assert result[ADDR]["abi"][0]["name"] == "set"

    def test_with_ethdebug_info_no_multi(self):
        s = TraceSerializer()
        t = _trace()
        parser = SimpleNamespace(
            load_source_file=lambda path: ["contract C {}"]
        )
        info = ETHDebugInfo(
            compilation={},
            contract_name="C",
            environment="runtime",
            instructions=[],
            sources={0: "C.sol"},
        )
        tracer = SimpleNamespace(ethdebug_parser=parser)
        result = s.build_contracts_mapping(t, info, None, {}, tracer)
        assert ADDR in result

    def test_no_parser_no_info(self):
        s = TraceSerializer()
        t = _trace()
        result = s.build_contracts_mapping(t, None, None, {})
        assert result == {}


class TestSerializeTrace:
    def test_success_with_steps_no_debug(self):
        s = TraceSerializer()
        t = _trace()
        call = _call(call_type="entry", depth=0)
        result = s.serialize_trace(t, [call])
        assert result["status"] == "success"
        assert "abis" in result
        assert "traceCall" in result

    def test_reverted_with_deepest_error(self):
        s = TraceSerializer()
        t = _trace(success=False, error="top error", steps=[
            TraceStep(0, "PUSH1", 100, 1, 0, []),
            TraceStep(1, "PUSH1", 90, 2, 0, []),
        ])
        root = _call(call_type="entry", depth=0, call_id=0, entry=0, exit_step=1,
                       children_call_ids=[1])
        child = _call(name="inner", depth=1, call_id=1, entry=1, exit_step=1,
                       parent_call_id=0,
                       caused_revert=True, error="deep error")
        tracer = SimpleNamespace(to_addr=ADDR, function_abis={}, ethdebug_info=None)
        result = s.serialize_trace(t, [root, child], tracer_instance=tracer)
        assert result["error"] == "deep error"

    def test_no_root_entry_call(self):
        s = TraceSerializer()
        t = _trace()
        call = _call(call_type="internal", depth=1)
        tracer = SimpleNamespace(to_addr=ADDR, function_abis={}, ethdebug_info=None)
        result = s.serialize_trace(t, [call], tracer_instance=tracer)
        assert "traceCall" in result

    def test_contract_creation(self):
        s = TraceSerializer()
        t = _trace(contract_address="0x" + "cc" * 20)
        call = _call(call_type="entry", depth=0)
        result = s.serialize_trace(t, [call])
        assert result["isContractCreation"] is True

    def test_no_steps(self):
        s = TraceSerializer()
        t = _trace(steps=[])
        call = _call(call_type="entry", depth=0, entry=None)
        result = s.serialize_trace(t, [call])
        assert "steps" not in result
        assert "abis" in result

    def test_with_ethdebug_info(self, tmp_path):
        s = TraceSerializer()
        t = _trace()
        parser = SimpleNamespace(
            load_source_file=lambda path: ["source"]
        )
        info = ETHDebugInfo(
            compilation={}, contract_name="C", environment="runtime",
            instructions=[], sources={},
        )
        tracer = SimpleNamespace(
            to_addr=ADDR, function_abis={}, ethdebug_parser=parser,
            ethdebug_info=info,
        )
        call = _call(call_type="entry", depth=0)
        result = s.serialize_trace(t, [call], ethdebug_info=info,
                                    tracer_instance=tracer)
        assert "contracts" in result

    def test_bytes_input_and_output(self):
        s = TraceSerializer()
        t = _trace(input_data=b"\xaa\xbb", output=b"\xcc")
        call = _call(call_type="entry", depth=0)
        result = s.serialize_trace(t, [call])
        assert result["traceCall"]["input"] == "0xaabb"
        assert result["traceCall"]["output"] == "0xcc"

    def test_hexbytes_output(self):
        s = TraceSerializer()
        t = _trace(output=HexBytes("0xdd"))
        call = _call(call_type="entry", depth=0)
        result = s.serialize_trace(t, [call])
        # HexBytes .hex() returns with or without 0x prefix depending on version
        assert "dd" in result["traceCall"]["output"]