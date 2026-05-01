"""Shared fixtures for integration tests."""

import json
from types import SimpleNamespace

import pytest

from soldb.core.transaction_tracer import TraceStep, TransactionTrace, TransactionTracer
from soldb.parsers.ethdebug import ETHDebugParser, source_loader

ADDR = "0x00000000000000000000000000000000000000aa"


@pytest.fixture(autouse=True)
def clear_source_cache():
    """Clear source loader caches before each test to avoid cross-test pollution."""
    source_loader._source_cache.clear()
    source_loader._warning_shown.clear()
    yield
    source_loader._source_cache.clear()
    source_loader._warning_shown.clear()


@pytest.fixture
def write_ethdebug_project():
    """Factory fixture that writes a complete ETHDebug project to a directory."""

    def _write(tmp_path, contract_name="Counter", source_text=None, abi=None):
        if source_text is None:
            source_text = (
                f"contract {contract_name} {{\n"
                f"    uint256 public value;\n"
                f"    function set(uint256 x) public {{\n"
                f"        value = x;\n"
                f"    }}\n"
                f"    function get() public view returns (uint256) {{\n"
                f"        return value;\n"
                f"    }}\n"
                f"}}\n"
            )
        (tmp_path / f"{contract_name}.sol").write_text(source_text)

        set_off = source_text.index("function set") if "function set" in source_text else 0
        body_off = source_text.index("value = x") if "value = x" in source_text else set_off + 20

        (tmp_path / "ethdebug.json").write_text(json.dumps({
            "compilation": {
                "compiler": {"version": "0.8.31"},
                "sources": [{"id": 0, "path": f"{contract_name}.sol"}],
            }
        }))

        instructions = [
            {"offset": i * 5, "operation": {"mnemonic": op},
             "context": {"code": {"source": {"id": 0},
                                   "range": {"offset": set_off if i < 3 else body_off, "length": 8}},
                          "variables": [{"name": "x", "type": "uint256",
                                         "location": {"type": "stack", "offset": 0},
                                         "scope": {"start": 0, "end": 50}}] if i == 0 else []}}
            for i, op in enumerate(["PUSH1", "JUMPDEST", "SLOAD", "SSTORE", "STOP"])
        ]
        (tmp_path / f"{contract_name}_ethdebug-runtime.json").write_text(
            json.dumps({"instructions": instructions})
        )

        if abi is None:
            abi = [
                {"type": "function", "name": "set",
                 "inputs": [{"name": "x", "type": "uint256"}], "outputs": []},
                {"type": "function", "name": "get",
                 "inputs": [],
                 "outputs": [{"name": "", "type": "uint256"}]},
                {"type": "event", "name": "ValueSet",
                 "inputs": [{"name": "newValue", "type": "uint256", "indexed": False}]},
            ]
        (tmp_path / f"{contract_name}.abi").write_text(json.dumps(abi))
        return set_off, body_off

    return _write


@pytest.fixture
def build_tracer():
    """Factory fixture that builds a TransactionTracer with loaded ETHDebug + ABI."""

    def _build(tmp_path, contract_name="Counter"):
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

        t.load_debug_info_auto(str(tmp_path), contract_name)
        t.load_abi(str(tmp_path / f"{contract_name}.abi"))

        # Mock RPC methods
        t.is_contract_deployed = lambda addr: True
        t.snapshot_state = lambda: "snap-1"
        t.revert_state = lambda target=None: True
        return t

    return _build
