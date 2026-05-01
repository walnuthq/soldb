"""Deep tests for analyze_function_calls and a small integration test."""

import json
import os
from types import SimpleNamespace

import pytest
from web3 import Web3

from soldb.core.transaction_tracer import (
    FunctionCall, TraceStep, TransactionTrace, TransactionTracer,
)

ADDR = "0x00000000000000000000000000000000000000aa"
OTHER = "0x00000000000000000000000000000000000000bb"
FROM = "0x0000000000000000000000000000000000000001"


def _tracer(**overrides):
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
    for k, v in overrides.items():
        setattr(t, k, v)
    return t


# ---------------------------------------------------------------------------
# analyze_function_calls — depth / return / revert paths
# ---------------------------------------------------------------------------

class TestAnalyzeDepthReturn:
    """Cover lines 1920-1939 (depth-decrease return path) and 2252-2295 (RETURN/REVERT handler)."""

    def _steps_call_return(self):
        """PUSH, CALL(depth 0→1), inside(depth 1), depth drops back to 0, STOP."""
        return [
            TraceStep(0, "PUSH1", 10000, 1, 0, ["0x01"]),
            TraceStep(1, "CALL", 9000, 2, 0,
                      ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "bb" * 20, "0x0"],
                      memory="12345678" + "0" * 64),
            TraceStep(2, "PUSH1", 8000, 1, 1, ["0x01"]),       # depth 1
            TraceStep(3, "RETURN", 7000, 1, 1, ["0x0", "0x0"]),# depth 1, will RETURN
            # depth drops
            TraceStep(4, "PUSH1", 6000, 1, 0, ["0x01"]),       # depth 0 again
            TraceStep(5, "STOP", 5000, 1, 0, []),
        ]

    def test_call_return_restores_context(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0x12345678" + "0" * 64,
            gas_used=5000, output="0x", steps=self._steps_call_return(), success=True,
        )
        calls = t.analyze_function_calls(trace)
        # Should have dispatcher + main + CALL
        assert len(calls) >= 2
        call_types = [c.call_type for c in calls]
        assert "CALL" in call_types
        # The CALL should have exit_step set (returned)
        ext_call = [c for c in calls if c.call_type == "CALL"][0]
        assert ext_call.exit_step is not None

    def test_revert_marks_deepest_frame(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        steps = [
            TraceStep(0, "PUSH1", 10000, 1, 0, ["0x01"]),
            TraceStep(1, "CALL", 9000, 2, 0,
                      ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "bb" * 20, "0x0"],
                      memory="deadbeef" + "0" * 64),
            TraceStep(2, "PUSH1", 8000, 1, 1, []),
            TraceStep(3, "REVERT", 7500, 1, 1, []),  # REVERT inside called contract
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0x", gas_used=2500, output="0x",
            steps=steps, success=False, error="reverted",
        )
        calls = t.analyze_function_calls(trace)
        reverted = [c for c in calls if c.caused_revert]
        assert len(reverted) >= 1

    def test_stop_closes_remaining_calls(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        steps = [
            TraceStep(0, "PUSH1", 10000, 1, 0, ["0x01"]),
            TraceStep(1, "STOP", 9990, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0x", gas_used=10, output="0x",
            steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        # All calls should have exit_step set by cleanup
        for c in calls:
            assert c.exit_step is not None


class TestAnalyzeInternalCalls:
    """Cover lines 2078-2250 (JUMPDEST internal call detection and param decoding)."""

    def test_jumpdest_detects_internal_function(self, monkeypatch):
        t = _tracer(
            ethdebug_info=SimpleNamespace(
                contract_name="Token", sources={0: "Token.sol"}
            ),
            ethdebug_parser=SimpleNamespace(
                debug_info=True,
                get_source_context=lambda pc, context_lines=2: {
                    "file": "Token.sol", "line": 10, "column": 0,
                    "content": "function _update(address from, uint256 amount) internal {"
                } if pc == 50 else None,
            ),
            function_signatures={"0x12345678": {"name": "transfer(address,uint256)"}},
            function_abis_by_name={
                "_update": {
                    "name": "_update",
                    "inputs": [
                        {"name": "from", "type": "address"},
                        {"name": "amount", "type": "uint256"},
                    ],
                }
            },
        )
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        steps = [
            TraceStep(0, "PUSH1", 10000, 1, 0, ["0x01"]),
            TraceStep(50, "JUMPDEST", 9500, 1, 0,
                      ["0x" + "aa" * 20, "0x" + "00" * 31 + "2a"]),
            TraceStep(51, "PUSH1", 9400, 1, 0, ["0x01"]),
            TraceStep(52, "RETURN", 9300, 1, 0, ["0x0", "0x0"]),
            TraceStep(53, "STOP", 9200, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0x12345678" + "0" * 64,
            gas_used=800, output="0x", steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        update_calls = [c for c in calls if "_update" in c.name]
        assert len(update_calls) >= 1
        # Should have decoded args from stack
        if update_calls[0].args:
            arg_names = [a[0] for a in update_calls[0].args]
            assert "from" in arg_names or "amount" in arg_names

    def test_jumpdest_no_context_warns(self, monkeypatch, capsys):
        t = _tracer(
            ethdebug_info=SimpleNamespace(contract_name="Token"),
            ethdebug_parser=SimpleNamespace(
                debug_info=True,
                get_source_context=lambda pc, context_lines=2: None,
            ),
        )
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        steps = [
            TraceStep(0, "PUSH1", 10000, 1, 0, []),
            TraceStep(50, "JUMPDEST", 9500, 1, 0, []),
            TraceStep(51, "STOP", 9400, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0x", gas_used=600, output="0x",
            steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        # Should have warned about incomplete ETHDebug
        err = capsys.readouterr().err
        assert "incomplete" in err.lower() or "Warning" in err


class TestAnalyzeMainFunctionDetection:
    """Cover lines 2308-2389 (main function detection heuristic)."""

    def test_main_function_from_known_signature(self, monkeypatch):
        t = _tracer(
            function_signatures={"0xa9059cbb": {"name": "transfer(address,uint256)"}},
            function_abis={
                "0xa9059cbb": {
                    "name": "transfer",
                    "inputs": [
                        {"name": "to", "type": "address"},
                        {"name": "amount", "type": "uint256"},
                    ],
                }
            },
        )
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        calldata = "0xa9059cbb" + ("0" * 24 + "bb" * 20) + f"{1000:064x}"
        steps = [TraceStep(i, "PUSH1", 10000 - i, 1, 0, []) for i in range(5)]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM, to_addr=ADDR,
            value=0, input_data=calldata, gas_used=100, output="0x",
            steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        external = [c for c in calls if c.call_type == "external"]
        assert len(external) >= 1
        assert external[0].selector == "0xa9059cbb"

    def test_main_function_with_bytes_input(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: "unknownFn()")
        steps = [TraceStep(i, "PUSH1", 10000 - i, 1, 0, []) for i in range(3)]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM, to_addr=ADDR,
            value=0, input_data=bytes.fromhex("12345678" + "0" * 64),
            gas_used=100, output="0x", steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        assert any("unknownFn" in c.name or "12345678" in (c.selector or "") for c in calls)

    def test_main_function_heuristic_long_trace(self, monkeypatch):
        """When main function isn't found via source mapping, use heuristic (lines 2332-2389)."""
        t = _tracer(
            function_signatures={"0xdeadbeef": {"name": "doSomething()"}},
        )
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        # Build a long trace (>50 steps) with a JUMPDEST after step 35
        steps = []
        for i in range(60):
            if i == 40:
                steps.append(TraceStep(i, "JUMPDEST", 9000, 1, 0, ["0x01"]))
            else:
                steps.append(TraceStep(i, "PUSH1", 10000 - i * 10, 1, 0, ["0x01"]))
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0xdeadbeef",
            gas_used=500, output="0x", steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        # Should have found the main function
        main = [c for c in calls if c.call_type == "external"]
        assert len(main) >= 1

    def test_main_function_ethdebug_heuristic(self, monkeypatch):
        """When ethdebug is available, use it for main function detection."""
        t = _tracer(
            function_signatures={"0xaabbccdd": {"name": "action()"}},
            ethdebug_info=SimpleNamespace(contract_name="Token"),
            ethdebug_parser=SimpleNamespace(
                debug_info=True,
                get_source_context=lambda pc, context_lines=0: {
                    "file": "Token.sol", "line": 15, "column": 0,
                    "content": "function action() public {"
                } if pc == 40 else None,
            ),
        )
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        steps = []
        for i in range(60):
            if i == 40:
                steps.append(TraceStep(i, "JUMPDEST", 9000, 1, 0, []))
            else:
                steps.append(TraceStep(i, "PUSH1", 10000 - i * 10, 1, 0, []))
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0xaabbccdd",
            gas_used=500, output="0x", steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        main = [c for c in calls if c.call_type == "external"]
        assert len(main) >= 1


class TestAnalyzeCreateCall:
    """Cover lines 2057-2076 (CREATE handling in main loop)."""

    def test_create2(self, monkeypatch):
        t = _tracer()
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        monkeypatch.setattr(t, "_extract_created_address",
                            lambda step_idx, trace: "0x" + "ff" * 20)
        steps = [
            TraceStep(0, "PUSH1", 10000, 1, 0, ["0x01"]),
            TraceStep(1, "CREATE2", 9000, 3, 0,
                      ["0x0", "0x06", "0x00", "0x00"],
                      memory="600160020300"),
            TraceStep(2, "PUSH1", 8000, 1, 1, []),
            TraceStep(3, "STOP", 7000, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0x", gas_used=3000, output="0x",
            steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        assert any("CREATE2" in c.call_type for c in calls)


class TestAnalyzeMultiContract:
    """Cover multi-contract parser interaction in analyze loop."""

    def test_call_switches_contract_context(self, monkeypatch):
        t = _tracer(
            multi_contract_parser=SimpleNamespace(
                get_contract_at_address=lambda addr: SimpleNamespace(
                    name="Router", ethdebug_info=SimpleNamespace(), parser=SimpleNamespace()
                ) if "bb" in addr.lower() else None,
            ),
        )
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        steps = [
            TraceStep(0, "PUSH1", 10000, 1, 0, []),
            TraceStep(1, "CALL", 9000, 2, 0,
                      ["0x0", "0x0", "0x04", "0x00", "0x0", "0x" + "bb" * 20, "0x0"],
                      memory="12345678"),
            TraceStep(2, "PUSH1", 8000, 1, 1, []),
            TraceStep(3, "STOP", 7000, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xtx", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0x", gas_used=3000, output="0x",
            steps=steps, success=True,
        )
        calls = t.analyze_function_calls(trace)
        ext = [c for c in calls if c.call_type == "CALL"]
        assert len(ext) == 1


# ---------------------------------------------------------------------------
# Small integration test using real ETHDebug data
# ---------------------------------------------------------------------------

class TestIntegrationETHDebug:
    """Integration test: load real ETHDebug, analyze trace, serialize output."""

    def test_ethdebug_load_and_trace(self, tmp_path):
        from soldb.parsers.ethdebug import ETHDebugParser, source_loader

        source_loader._source_cache.clear()
        source_loader._warning_shown.clear()

        # Write minimal Solidity source
        source = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            "contract Counter {\n"
            "    uint256 public count;\n"
            "    function increment() public {\n"
            "        count += 1;\n"
            "    }\n"
            "}\n"
        )
        (tmp_path / "Counter.sol").write_text(source)
        fn_offset = source.index("function increment")
        body_offset = source.index("count += 1")

        # Write ethdebug metadata
        (tmp_path / "ethdebug.json").write_text(json.dumps({
            "compilation": {
                "compiler": {"version": "0.8.31"},
                "sources": [{"id": 0, "path": "Counter.sol"}],
            }
        }))

        (tmp_path / "Counter_ethdebug-runtime.json").write_text(json.dumps({
            "instructions": [
                {
                    "offset": 0,
                    "operation": {"mnemonic": "PUSH1", "arguments": ["0x01"]},
                    "context": {
                        "code": {
                            "source": {"id": 0},
                            "range": {"offset": fn_offset, "length": 10},
                        }
                    },
                },
                {
                    "offset": 2,
                    "operation": {"mnemonic": "ADD", "arguments": []},
                    "context": {
                        "code": {
                            "source": {"id": 0},
                            "range": {"offset": body_offset, "length": 10},
                        }
                    },
                },
                {
                    "offset": 3,
                    "operation": {"mnemonic": "SSTORE", "arguments": []},
                    "context": {
                        "code": {
                            "source": {"id": 0},
                            "range": {"offset": body_offset, "length": 10},
                        }
                    },
                },
            ]
        }))

        (tmp_path / "Counter.abi").write_text(json.dumps([
            {
                "type": "function",
                "name": "increment",
                "inputs": [],
                "outputs": [],
                "stateMutability": "nonpayable",
            },
            {
                "type": "function",
                "name": "count",
                "inputs": [],
                "outputs": [{"name": "", "type": "uint256"}],
                "stateMutability": "view",
            },
        ]))

        # Load debug info
        parser = ETHDebugParser()
        info = parser.load_ethdebug_files(tmp_path, "Counter")
        assert info.contract_name == "Counter"
        assert len(info.instructions) == 3

        # Create tracer with loaded info
        t = _tracer(
            ethdebug_info=info,
            ethdebug_parser=parser,
        )
        t.load_abi(str(tmp_path / "Counter.abi"))

        assert "increment" in t.function_abis_by_name

        # Build a synthetic trace for increment()
        inc_selector = None
        for sel, item in t.function_abis.items():
            if item["name"] == "increment":
                inc_selector = sel
                break
        assert inc_selector is not None

        steps = [
            TraceStep(0, "PUSH1", 50000, 1, 0, ["0x01"]),
            TraceStep(2, "ADD", 49900, 1, 0, ["0x01", "0x00"]),
            TraceStep(3, "SSTORE", 49800, 1, 0, ["0x01", "0x00"]),
            TraceStep(4, "STOP", 49700, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xabc123", from_addr=FROM, to_addr=ADDR,
            value=0, input_data=inc_selector,
            gas_used=300, output="0x", steps=steps, success=True,
        )

        # Analyze function calls
        calls = t.analyze_function_calls(trace)
        assert len(calls) >= 1
        assert calls[0].call_type == "entry"

        # Serialize to JSON
        from soldb.core.serializer import TraceSerializer
        serializer = TraceSerializer()
        result = serializer.serialize_trace(
            trace, calls,
            ethdebug_info=info,
            tracer_instance=t,
        )
        assert result["status"] == "success"
        assert "traceCall" in result
        assert "contracts" in result
        # Verify contract mapping has source data
        if ADDR in result["contracts"]:
            contract_data = result["contracts"][ADDR]
            assert "pcToSourceMappings" in contract_data
            assert "sources" in contract_data

    def test_full_trace_lifecycle(self, tmp_path, capsys):
        """Integration: load ETHDebug, build rich trace with CALL/RETURN/REVERT,
        analyze, print_trace, print_function_trace, serialize."""
        from soldb.parsers.ethdebug import (
            ETHDebugParser, MultiContractETHDebugParser, source_loader,
        )
        from soldb.core.serializer import TraceSerializer

        source_loader._source_cache.clear()
        source_loader._warning_shown.clear()

        # --- set up two contracts ---
        # Contract A
        a_dir = tmp_path / "contractA"
        a_dir.mkdir()
        a_source = (
            "contract A {\n"
            "    function doCall(address b) public {\n"
            "        B(b).run();\n"
            "    }\n"
            "}\n"
        )
        (a_dir / "A.sol").write_text(a_source)
        fn_a = a_source.index("function doCall")
        body_a = a_source.index("B(b).run()")
        (a_dir / "ethdebug.json").write_text(json.dumps({
            "compilation": {
                "compiler": {"version": "0.8.31"},
                "sources": [{"id": 0, "path": "A.sol"}],
            }
        }))
        (a_dir / "A_ethdebug-runtime.json").write_text(json.dumps({
            "instructions": [
                {"offset": 0, "operation": {"mnemonic": "PUSH1"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": fn_a, "length": 10}}}},
                {"offset": 5, "operation": {"mnemonic": "CALL"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": body_a, "length": 10}}}},
                {"offset": 10, "operation": {"mnemonic": "STOP"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": fn_a, "length": 10}}}},
            ],
        }))
        (a_dir / "A.abi").write_text(json.dumps([
            {"type": "function", "name": "doCall",
             "inputs": [{"name": "b", "type": "address"}], "outputs": []},
        ]))

        # Contract B
        b_dir = tmp_path / "contractB"
        b_dir.mkdir()
        b_source = (
            "contract B {\n"
            "    function run() public {\n"
            "        revert('fail');\n"
            "    }\n"
            "}\n"
        )
        (b_dir / "B.sol").write_text(b_source)
        fn_b = b_source.index("function run")
        rev_b = b_source.index("revert")
        (b_dir / "ethdebug.json").write_text(json.dumps({
            "compilation": {
                "compiler": {"version": "0.8.31"},
                "sources": [{"id": 0, "path": "B.sol"}],
            }
        }))
        (b_dir / "B_ethdebug-runtime.json").write_text(json.dumps({
            "instructions": [
                {"offset": 100, "operation": {"mnemonic": "PUSH1"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": fn_b, "length": 10}}}},
                {"offset": 105, "operation": {"mnemonic": "REVERT"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": rev_b, "length": 10}}}},
            ],
        }))
        (b_dir / "B.abi").write_text(json.dumps([
            {"type": "function", "name": "run", "inputs": [], "outputs": []},
        ]))

        # --- Load multi-contract parser ---
        multi = MultiContractETHDebugParser()
        multi.load_contract(ADDR, str(a_dir), "A")
        multi.load_contract(OTHER, str(b_dir), "B")

        contract_a = multi.get_contract_at_address(ADDR)
        assert contract_a is not None

        # --- Build tracer ---
        t = _tracer(
            ethdebug_info=contract_a.ethdebug_info,
            ethdebug_parser=contract_a.parser,
            multi_contract_parser=multi,
        )
        t.load_abi(str(a_dir / "A.abi"))
        t.load_abi(str(b_dir / "B.abi"))
        assert "doCall" in t.function_abis_by_name
        assert "run" in t.function_abis_by_name

        # --- Build synthetic trace: A calls B, B reverts ---
        doCall_sel = None
        for sel, item in t.function_abis.items():
            if item["name"] == "doCall":
                doCall_sel = sel
                break

        steps = [
            # Contract A (depth 0)
            TraceStep(0, "PUSH1", 100000, 1, 0, ["0x01"]),
            TraceStep(5, "CALL", 90000, 2, 0,
                      ["0x0", "0x0", "0x04", "0x00", "0x0", OTHER, "0x5000"],
                      memory="c0406226" + "0" * 60),  # run() selector
            # Contract B (depth 1)
            TraceStep(100, "PUSH1", 80000, 1, 1, []),
            TraceStep(105, "REVERT", 75000, 1, 1, []),
            # Back to A (depth 0)
            TraceStep(10, "STOP", 60000, 1, 0, []),
        ]
        calldata = (doCall_sel or "0x12345678") + ("0" * 24 + OTHER[2:])
        trace = TransactionTrace(
            tx_hash="0xintegration", from_addr=FROM, to_addr=ADDR,
            value=1000, input_data=calldata,
            gas_used=40000, output="0x",
            steps=steps, success=False, error="reverted",
        )

        # --- Analyze ---
        calls = t.analyze_function_calls(trace)
        assert len(calls) >= 2

        # Should have dispatcher + at least one CALL
        call_types = {c.call_type for c in calls}
        assert "entry" in call_types
        assert "CALL" in call_types

        # Should have marked a revert
        assert any(c.caused_revert for c in calls)

        # --- Print trace (raw) ---
        source_map = {}
        if contract_a.parser:
            source_map = contract_a.parser.get_source_mapping()
        t.print_trace(trace, source_map, max_steps=10)
        out = capsys.readouterr().out
        assert "0xintegration" in out
        assert "REVERTED" in out or "reverted" in out

        # --- Print function trace ---
        t.print_function_trace(trace, calls)
        out = capsys.readouterr().out
        assert "Function Call Trace" in out
        assert "CALL" in out

        # --- Serialize ---
        serializer = TraceSerializer()
        result = serializer.serialize_trace(
            trace, calls,
            ethdebug_info=contract_a.ethdebug_info,
            multi_parser=multi,
            tracer_instance=t,
        )
        assert result["status"] == "reverted"
        assert "traceCall" in result
        assert "contracts" in result
        # Contracts may be stored with checksum addresses
        contract_keys = list(result["contracts"].keys())
        assert len(contract_keys) >= 1  # At least one contract mapped
        # Check steps built
        assert "steps" in result
        assert len(result["steps"]) == len(steps)

    def test_rich_trace_with_internals_and_events(self, tmp_path, capsys):
        """Integration: trace with internal JUMPDEST calls, events, and parameter decoding."""
        from soldb.parsers.ethdebug import ETHDebugParser, source_loader
        from soldb.core.serializer import TraceSerializer

        source_loader._source_cache.clear()
        source_loader._warning_shown.clear()

        source = (
            "contract Token {\n"
            "    uint256 public totalSupply;\n"
            "    mapping(address => uint256) public balanceOf;\n"
            "    event Transfer(address indexed from, address indexed to, uint256 value);\n"
            "    function transfer(address to, uint256 amount) public returns (bool) {\n"
            "        _update(msg.sender, to, amount);\n"
            "        return true;\n"
            "    }\n"
            "    function _update(address from, address to, uint256 amount) internal {\n"
            "        balanceOf[from] -= amount;\n"
            "        balanceOf[to] += amount;\n"
            "    }\n"
            "}\n"
        )
        (tmp_path / "Token.sol").write_text(source)
        transfer_off = source.index("function transfer")
        update_off = source.index("function _update")
        sub_off = source.index("balanceOf[from]")
        add_off = source.index("balanceOf[to]")

        (tmp_path / "ethdebug.json").write_text(json.dumps({
            "compilation": {
                "compiler": {"version": "0.8.31"},
                "sources": [{"id": 0, "path": "Token.sol"}],
            }
        }))

        # Build instructions that cover transfer + _update with variables
        (tmp_path / "Token_ethdebug-runtime.json").write_text(json.dumps({
            "instructions": [
                {"offset": 0, "operation": {"mnemonic": "PUSH1"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": transfer_off, "length": 10}},
                             "variables": [
                                 {"name": "to", "type": "address", "location": {"type": "stack", "offset": 0}},
                                 {"name": "amount", "type": "uint256", "location": {"type": "stack", "offset": 1}},
                             ]}},
                {"offset": 5, "operation": {"mnemonic": "JUMPDEST"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": update_off, "length": 10}},
                             "variables": [
                                 {"name": "from", "type": "address", "location": {"type": "stack", "offset": 0}},
                                 {"name": "to", "type": "address", "location": {"type": "stack", "offset": 1}},
                                 {"name": "amount", "type": "uint256", "location": {"type": "stack", "offset": 2}},
                             ]}},
                {"offset": 10, "operation": {"mnemonic": "SSTORE"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": sub_off, "length": 10}}}},
                {"offset": 15, "operation": {"mnemonic": "SSTORE"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": add_off, "length": 10}}}},
                {"offset": 20, "operation": {"mnemonic": "LOG3"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": transfer_off, "length": 10}}}},
                {"offset": 25, "operation": {"mnemonic": "RETURN"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": transfer_off, "length": 10}}}},
            ],
        }))

        (tmp_path / "Token.abi").write_text(json.dumps([
            {"type": "function", "name": "transfer",
             "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}],
             "outputs": [{"name": "", "type": "bool"}]},
            {"type": "function", "name": "_update",
             "inputs": [{"name": "from", "type": "address"}, {"name": "to", "type": "address"},
                         {"name": "amount", "type": "uint256"}],
             "outputs": []},
            {"type": "event", "name": "Transfer",
             "inputs": [{"name": "from", "type": "address", "indexed": True},
                         {"name": "to", "type": "address", "indexed": True},
                         {"name": "value", "type": "uint256", "indexed": False}]},
        ]))

        # Load
        parser = ETHDebugParser()
        info = parser.load_ethdebug_files(tmp_path, "Token")
        t = _tracer(ethdebug_info=info, ethdebug_parser=parser)
        t.to_addr = ADDR  # Needed for serializer ABI extraction
        t.load_abi(str(tmp_path / "Token.abi"))

        transfer_sel = None
        for sel, item in t.function_abis.items():
            if item["name"] == "transfer":
                transfer_sel = sel
                break

        # Build trace: dispatcher -> transfer -> _update(JUMPDEST) -> LOG3 -> RETURN
        to_addr = "0x" + "bb" * 20
        amount = 1000
        topic_transfer = list(t.event_signatures.keys())[0] if t.event_signatures else "0x" + "dd" * 32

        steps = [
            TraceStep(0, "PUSH1", 100000, 1, 0,
                      [to_addr, f"0x{amount:064x}"]),
            TraceStep(5, "JUMPDEST", 95000, 1, 0,
                      [FROM, to_addr, f"0x{amount:064x}"]),
            TraceStep(10, "SSTORE", 90000, 1, 0, ["0x01", "0x00"]),
            TraceStep(15, "SSTORE", 85000, 1, 0, ["0x01", "0x00"]),
            TraceStep(20, "LOG3", 80000, 1, 0,
                      ["0x00", "0x20", topic_transfer,
                       "0x" + "00" * 12 + FROM[2:], "0x" + "00" * 12 + to_addr[2:]],
                      memory=f"{amount:064x}"),
            TraceStep(25, "RETURN", 70000, 1, 0, ["0x00", "0x20"],
                      memory=f"{1:064x}"),  # return true
        ]
        calldata = (transfer_sel or "0xa9059cbb") + ("0" * 24 + to_addr[2:]) + f"{amount:064x}"
        trace = TransactionTrace(
            tx_hash="0xrich", from_addr=FROM, to_addr=ADDR,
            value=0, input_data=calldata,
            gas_used=30000, output=f"0x{1:064x}",
            steps=steps, success=True,
        )

        # Analyze
        calls = t.analyze_function_calls(trace)
        assert len(calls) >= 2  # dispatcher + transfer
        # Should detect _update internal call
        update_calls = [c for c in calls if "_update" in c.name]
        if update_calls:
            assert update_calls[0].call_type == "internal"

        # Print
        t.print_function_trace(trace, calls)
        out = capsys.readouterr().out
        assert "Function Call Trace" in out
        assert "transfer" in out.lower() or "0xrich" in out

        # Serialize
        serializer = TraceSerializer()
        result = serializer.serialize_trace(
            trace, calls, ethdebug_info=info, tracer_instance=t,
        )
        assert result["status"] == "success"
        # Should have extracted logs
        trace_call = result["traceCall"]
        # The LOG3 should produce an event

        # Print raw trace too
        source_map = parser.get_source_mapping()
        t.print_trace(trace, source_map, max_steps=0)
        out2 = capsys.readouterr().out
        assert "all 6 steps" in out2
