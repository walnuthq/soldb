"""Integration test with rich traces exercising deep analyze_function_calls paths."""

import json
from types import SimpleNamespace

import pytest

from soldb.core.transaction_tracer import (
    FunctionCall, TraceStep, TransactionTrace, TransactionTracer,
)
from soldb.core.serializer import TraceSerializer
from soldb.parsers.ethdebug import ETHDebugParser, MultiContractETHDebugParser, source_loader

ADDR = "0x00000000000000000000000000000000000000aa"
OTHER = "0x00000000000000000000000000000000000000bb"
THIRD = "0x00000000000000000000000000000000000000cc"
FROM = "0x0000000000000000000000000000000000000001"


def _setup_contract(tmp_path, name, source, abi):
    """Write ETHDebug project for a contract."""
    source_loader._source_cache.clear()
    source_loader._warning_shown.clear()

    (tmp_path / f"{name}.sol").write_text(source)
    fn_offsets = {}
    for fn in ["function " + n for n in abi if not n.startswith("event")]:
        if fn.split("(")[0].replace("function ", "") in source:
            fn_name = fn.split("(")[0].replace("function ", "")
            idx = source.find(f"function {fn_name}")
            if idx >= 0:
                fn_offsets[fn_name] = idx

    instructions = []
    for i, (fn_name, offset) in enumerate(fn_offsets.items()):
        instructions.append({
            "offset": i * 10,
            "operation": {"mnemonic": "JUMPDEST" if i > 0 else "PUSH1"},
            "context": {
                "code": {"source": {"id": 0}, "range": {"offset": offset, "length": 10}},
                "variables": [
                    {"name": p["name"], "type": p["type"],
                     "location": {"type": "stack", "offset": j},
                     "scope": {"start": 0, "end": 100}}
                    for j, p in enumerate(abi.get(fn_name, {}).get("inputs", []))
                ] if fn_name in abi else [],
            },
        })
    # Add STOP
    instructions.append({
        "offset": len(fn_offsets) * 10 + 5,
        "operation": {"mnemonic": "STOP"},
        "context": {"code": {"source": {"id": 0},
                              "range": {"offset": list(fn_offsets.values())[0] if fn_offsets else 0, "length": 5}}},
    })

    (tmp_path / "ethdebug.json").write_text(json.dumps({
        "compilation": {
            "compiler": {"version": "0.8.31"},
            "sources": [{"id": 0, "path": f"{name}.sol"}],
        }
    }))
    (tmp_path / f"{name}_ethdebug-runtime.json").write_text(json.dumps({
        "instructions": instructions,
    }))

    abi_items = []
    for fn_name, fn_info in abi.items():
        abi_items.append({
            "type": fn_info.get("type", "function"),
            "name": fn_name,
            "inputs": fn_info.get("inputs", []),
            "outputs": fn_info.get("outputs", []),
        })
    (tmp_path / f"{name}.abi").write_text(json.dumps(abi_items))


def _tracer():
    from web3 import Web3
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
    t.ethdebug_parser = ETHDebugParser()
    t.srcmap_info = None
    t.srcmap_parser = None
    t.source_maps = {}
    t.contracts = {}
    t.to_addr = ADDR
    return t


class TestMultiContractTrace:
    """Exercise analyze + print + serialize with multi-contract CALL chain."""

    def test_call_chain_a_calls_b_calls_c(self, tmp_path, capsys):
        # Set up three contracts
        a_dir = tmp_path / "a"
        a_dir.mkdir()
        _setup_contract(a_dir, "Router", (
            "contract Router {\n"
            "    function swap(address token, uint256 amount) public {\n"
            "        // calls Pool\n"
            "    }\n"
            "}\n"
        ), {
            "swap": {"inputs": [{"name": "token", "type": "address"},
                                 {"name": "amount", "type": "uint256"}]},
        })

        b_dir = tmp_path / "b"
        b_dir.mkdir()
        _setup_contract(b_dir, "Pool", (
            "contract Pool {\n"
            "    function execute(uint256 qty) public {\n"
            "        // internal logic\n"
            "    }\n"
            "}\n"
        ), {
            "execute": {"inputs": [{"name": "qty", "type": "uint256"}]},
        })

        c_dir = tmp_path / "c"
        c_dir.mkdir()
        _setup_contract(c_dir, "Oracle", (
            "contract Oracle {\n"
            "    function getPrice() public view returns (uint256) {\n"
            "        return 42;\n"
            "    }\n"
            "}\n"
        ), {
            "getPrice": {"inputs": [], "outputs": [{"name": "", "type": "uint256"}]},
        })

        # Build multi-contract parser
        multi = MultiContractETHDebugParser()
        multi.load_contract(ADDR, str(a_dir), "Router")
        multi.load_contract(OTHER, str(b_dir), "Pool")
        multi.load_contract(THIRD, str(c_dir), "Oracle")

        # Build tracer
        t = _tracer()
        t.load_debug_info_auto(str(a_dir), "Router")
        t.load_abi(str(a_dir / "Router.abi"))
        t.load_abi(str(b_dir / "Pool.abi"))
        t.load_abi(str(c_dir / "Oracle.abi"))
        t.multi_contract_parser = multi

        # Get swap selector
        swap_sel = None
        for sel, item in t.function_abis.items():
            if item["name"] == "swap":
                swap_sel = sel
                break

        # Build trace: Router.swap -> CALL Pool -> Pool STATICCALL Oracle -> return
        steps = [
            # Router (depth 0)
            TraceStep(0, "PUSH1", 200000, 1, 0, [OTHER, f"0x{1000:064x}"]),
            # CALL to Pool
            TraceStep(1, "CALL", 190000, 2, 0,
                      ["0x0", "0x0", "0x24", "0x00", "0x0", OTHER, "0x10000"],
                      memory="b0b0b0b0" + f"{1000:064x}"),
            # Pool (depth 1)
            TraceStep(2, "PUSH1", 180000, 1, 1, [f"0x{1000:064x}"]),
            # Pool STATICCALL Oracle
            TraceStep(3, "STATICCALL", 170000, 2, 1,
                      ["0x0", "0x04", "0x00", "0x0", THIRD, "0x8000"],
                      memory="feeddead"),
            # Oracle (depth 2)
            TraceStep(4, "PUSH1", 160000, 1, 2, [f"0x{42:064x}"]),
            TraceStep(5, "RETURN", 155000, 1, 2, ["0x0", "0x20"],
                      memory=f"{42:064x}"),
            # Back to Pool (depth 1)
            TraceStep(6, "PUSH1", 150000, 1, 1, ["0x01"]),
            TraceStep(7, "RETURN", 145000, 1, 1, ["0x0", "0x0"]),
            # Back to Router (depth 0)
            TraceStep(8, "PUSH1", 140000, 1, 0, ["0x01"]),
            TraceStep(9, "STOP", 135000, 1, 0, []),
        ]

        calldata = (swap_sel or "0x12345678") + ("0" * 24 + OTHER[2:]) + f"{1000:064x}"
        trace = TransactionTrace(
            tx_hash="0xchain", from_addr=FROM, to_addr=ADDR,
            value=0, input_data=calldata,
            gas_used=65000, output="0x",
            steps=steps, success=True,
        )

        # Analyze
        calls = t.analyze_function_calls(trace)
        assert len(calls) >= 3  # dispatcher + at least CALL + STATICCALL

        call_types = {c.call_type for c in calls}
        assert "entry" in call_types
        assert "CALL" in call_types
        assert "STATICCALL" in call_types

        # Print
        t.print_function_trace(trace, calls)
        out = capsys.readouterr().out
        assert "Function Call Trace" in out
        assert "Router" in out
        assert "Pool" in out or "CALL" in out

        # Serialize with multi-parser
        serializer = TraceSerializer()
        result = serializer.serialize_trace(
            trace, calls,
            ethdebug_info=t.ethdebug_info,
            multi_parser=multi,
            tracer_instance=t,
        )
        assert result["status"] == "success"
        assert "contracts" in result
        assert len(result["contracts"]) >= 1

    def test_delegatecall_proxy_pattern(self, tmp_path, capsys, monkeypatch):
        """Proxy contract DELEGATECALL to implementation."""
        impl_dir = tmp_path / "impl"
        impl_dir.mkdir()
        _setup_contract(impl_dir, "Impl", (
            "contract Impl {\n"
            "    uint256 public val;\n"
            "    function setVal(uint256 v) public {\n"
            "        val = v;\n"
            "    }\n"
            "}\n"
        ), {
            "setVal": {"inputs": [{"name": "v", "type": "uint256"}]},
        })

        t = _tracer()
        t.load_abi(str(impl_dir / "Impl.abi"))
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)

        steps = [
            TraceStep(0, "PUSH1", 100000, 1, 0, []),
            TraceStep(1, "DELEGATECALL", 90000, 2, 0,
                      ["0x0", "0x24", "0x00", "0x0", OTHER, "0x5000"],
                      memory="aabbccdd" + f"{42:064x}"),
            TraceStep(2, "PUSH1", 80000, 1, 1, []),
            TraceStep(3, "RETURN", 75000, 1, 0, ["0x0", "0x0"]),
            TraceStep(4, "STOP", 70000, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xdelegate", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0xaabbccdd" + f"{42:064x}",
            gas_used=30000, output="0x", steps=steps, success=True,
        )

        calls = t.analyze_function_calls(trace)
        assert any(c.call_type == "DELEGATECALL" for c in calls)

        t.print_function_trace(trace, calls)
        out = capsys.readouterr().out
        assert "DELEGATECALL" in out

    def test_reverted_with_nested_error(self, tmp_path, capsys, monkeypatch):
        """Trace that reverts deep inside a nested call."""
        t = _tracer()
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)

        steps = [
            TraceStep(0, "PUSH1", 100000, 1, 0, []),
            TraceStep(1, "CALL", 90000, 2, 0,
                      ["0x0", "0x0", "0x04", "0x00", "0x0", OTHER, "0x5000"],
                      memory="12345678"),
            TraceStep(2, "PUSH1", 80000, 1, 1, []),
            TraceStep(3, "CALL", 70000, 2, 1,
                      ["0x0", "0x0", "0x04", "0x00", "0x0", THIRD, "0x3000"],
                      memory="deadbeef"),
            TraceStep(4, "PUSH1", 60000, 1, 2, []),
            TraceStep(5, "REVERT", 55000, 1, 2, []),  # Revert at depth 2
        ]
        trace = TransactionTrace(
            tx_hash="0xnested_revert", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0x",
            gas_used=45000, output="0x", steps=steps,
            success=False, error="execution reverted",
        )

        calls = t.analyze_function_calls(trace)
        reverted = [c for c in calls if c.caused_revert]
        assert len(reverted) >= 1

        t.print_function_trace(trace, calls)
        out = capsys.readouterr().out
        assert "REVERTED" in out

        # Serialize
        serializer = TraceSerializer()
        result = serializer.serialize_trace(trace, calls, tracer_instance=t)
        assert result["status"] == "reverted"
        assert result.get("error") is not None

    def test_create_and_internal_calls(self, tmp_path, capsys, monkeypatch):
        """Trace with CREATE opcode followed by internal JUMPDEST calls."""
        d = tmp_path / "factory"
        d.mkdir()
        _setup_contract(d, "Factory", (
            "contract Factory {\n"
            "    function deploy() public returns (address) {\n"
            "        return address(0);\n"
            "    }\n"
            "    function _init(address child) internal {\n"
            "        // init\n"
            "    }\n"
            "}\n"
        ), {
            "deploy": {"inputs": [], "outputs": [{"name": "", "type": "address"}]},
            "_init": {"inputs": [{"name": "child", "type": "address"}]},
        })

        t = _tracer()
        t.load_debug_info_auto(str(d), "Factory")
        t.load_abi(str(d / "Factory.abi"))
        monkeypatch.setattr(t, "lookup_function_signature", lambda s, **kw: None)
        monkeypatch.setattr(t, "_extract_created_address",
                            lambda step_idx, trace: "0x" + "dd" * 20)

        steps = [
            TraceStep(0, "PUSH1", 200000, 1, 0, []),
            TraceStep(1, "CREATE", 190000, 3, 0,
                      ["0x10", "0x00", "0x00"],
                      memory="600160020300" + "00" * 10),
            TraceStep(2, "PUSH1", 180000, 1, 1, []),
            TraceStep(3, "STOP", 175000, 1, 0, []),
            # After CREATE returns, internal call
            TraceStep(10, "JUMPDEST", 170000, 1, 0, ["0x" + "dd" * 20]),
            TraceStep(11, "PUSH1", 165000, 1, 0, []),
            TraceStep(12, "STOP", 160000, 1, 0, []),
        ]
        trace = TransactionTrace(
            tx_hash="0xfactory", from_addr=FROM, to_addr=ADDR,
            value=0, input_data="0x",
            gas_used=40000, output="0x", steps=steps, success=True,
            contract_address="0x" + "dd" * 20,
        )

        calls = t.analyze_function_calls(trace)
        assert any(c.call_type == "CREATE" for c in calls)

        t.print_function_trace(trace, calls)
        out = capsys.readouterr().out
        assert "deployed at" in out.lower() or "CREATE" in out
