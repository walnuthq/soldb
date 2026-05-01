"""Integration tests for simulate interactive mode and auto-deploy flow."""

import json
from types import SimpleNamespace

import pytest

from soldb.cli import simulate as simulate_mod
from soldb.core.transaction_tracer import (
    TraceStep, TransactionTrace,
)
from soldb.core.auto_deploy import AutoDeployDebugger
import soldb.core.auto_deploy as auto_deploy_mod

ADDR = "0x00000000000000000000000000000000000000aa"
FROM = "0x0000000000000000000000000000000000000001"


def _write_project(tmp_path, name="Token"):
    source = (
        f"contract {name} {{\n"
        f"    uint256 public value;\n"
        f"    function set(uint256 x) public {{ value = x; }}\n"
        f"}}\n"
    )
    sol = tmp_path / f"{name}.sol"
    sol.write_text(source)
    fn_off = source.index("function set")

    (tmp_path / "ethdebug.json").write_text(json.dumps({
        "compilation": {
            "compiler": {"version": "0.8.31"},
            "sources": [{"id": 0, "path": f"{name}.sol"}],
        }
    }))
    (tmp_path / f"{name}_ethdebug-runtime.json").write_text(json.dumps({
        "instructions": [
            {"offset": i * 5, "operation": {"mnemonic": op},
             "context": {"code": {"source": {"id": 0},
                                   "range": {"offset": fn_off, "length": 8}}}}
            for i, op in enumerate(["PUSH1", "SLOAD", "SSTORE", "STOP"])
        ],
    }))
    (tmp_path / f"{name}.abi").write_text(json.dumps([
        {"type": "function", "name": "set",
         "inputs": [{"name": "x", "type": "uint256"}], "outputs": []},
    ]))
    (tmp_path / f"{name}.bin").write_text("6000")
    return sol


def _trace(tracer, **kw):
    steps = [TraceStep(i, "PUSH1", 100000 - i * 100, 1, 0, ["0x01"]) for i in range(5)]
    sel = None
    for s, item in tracer.function_abis.items():
        if item["name"] == "set":
            sel = s
            break
    defaults = dict(
        tx_hash="0xsim", from_addr=FROM, to_addr=ADDR,
        value=0, input_data=(sel or "0x12345678") + f"{42:064x}",
        gas_used=100, output="0x", steps=steps, success=True,
    )
    defaults.update(kw)
    return TransactionTrace(**defaults)


class TestSimulateInteractiveAddress:
    """Exercise simulate _interactive_mode with contract address (not file)."""

    def test_interactive_address_with_ethdebug(self, monkeypatch, tmp_path, capsys, build_tracer):
        _write_project(tmp_path)
        tracer = build_tracer(tmp_path, "Token")
        trace = _trace(tracer)
        monkeypatch.setattr(tracer, "simulate_call_trace", lambda **kw: trace)

        class MockDebugger:
            def __init__(self, **kw):
                self.kw = kw
                self.tracer = kw.get("tracer", tracer)
                self.current_trace = None
                self.current_step = 0
                self.function_trace = []
                self.current_function = None
                self.init = False

            def _do_interactive(self):
                self.init = True

            def cmdloop(self):
                pass

        monkeypatch.setattr(simulate_mod, "EVMDebugger", MockDebugger)
        monkeypatch.setattr(simulate_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "snapshot_state", lambda: "snap")

        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["42"],
            raw_data=None, value=0,
            interactive=True,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=[f"{ADDR}:Token:{tmp_path}"],
            contracts=None, multi_contract=False,
            json=False, raw=False, max_steps=50,
            block=None, tx_index=None,
            no_snapshot=False,
        )
        result = simulate_mod.simulate_command(args)
        assert result == 0


class TestAutoDeployFlow:
    """Integration test for auto-deploy compile + deploy flow."""

    def test_auto_deploy_init_and_compile(self, monkeypatch, tmp_path, capsys):
        sol = _write_project(tmp_path)

        # Mock compile_ethdebug_run
        monkeypatch.setattr(
            auto_deploy_mod, "compile_ethdebug_run",
            lambda **kw: {"success": True, "output_dir": str(tmp_path)},
        )

        # Mock Web3 for deploy
        class FakeEth:
            accounts = [FROM]
            def contract(self, abi, bytecode):
                class Ctor:
                    def transact(self, tx):
                        return "0xtxhash"
                return SimpleNamespace(constructor=lambda *args: Ctor())
            def wait_for_transaction_receipt(self, tx_hash):
                return SimpleNamespace(contractAddress=ADDR)

        class FakeWeb3:
            eth = FakeEth()
            client_version = "anvil/1.0"
            def __init__(self, provider=None):
                pass
            @staticmethod
            def HTTPProvider(url, request_kwargs=None):
                return ("provider", url, request_kwargs)
            def is_connected(self):
                return True

        monkeypatch.setattr(auto_deploy_mod, "Web3", FakeWeb3)

        # Mock connect_or_launch_fork to skip actual connection
        monkeypatch.setattr(AutoDeployDebugger, "connect_or_launch_fork", lambda self: None)
        monkeypatch.setattr(AutoDeployDebugger, "_try_cache_hit", lambda self: False)
        monkeypatch.setattr(AutoDeployDebugger, "_store_cache", lambda self: None)

        session = AutoDeployDebugger(
            contract_file=str(sol),
            keep_build=True,
            output_dir=str(tmp_path / "out"),
        )
        assert session.contract_address == ADDR
        assert session.contract_name == "Token"
        out = capsys.readouterr().out
        assert "Compiled" in out
        assert "Deployed" in out

    def test_auto_deploy_cleanup(self, tmp_path, capsys):
        sol = _write_project(tmp_path)
        session = AutoDeployDebugger.__new__(AutoDeployDebugger)
        session.rpc_url = "http://rpc"
        session.keep_fork = True
        proc = SimpleNamespace(poll=lambda: None)
        session._fork_proc = proc
        session.cleanup()
        out = capsys.readouterr().out
        assert "keeping fork alive" in out


class TestSimulateAddressMismatch:
    """Test simulate with ETHDebug address different from contract address."""

    def test_address_mismatch_warning(self, monkeypatch, tmp_path, capsys, build_tracer):
        _write_project(tmp_path)
        tracer = build_tracer(tmp_path, "Token")
        trace = _trace(tracer)

        monkeypatch.setattr(simulate_mod, "TransactionTracer", lambda *a, **kw: tracer)
        monkeypatch.setattr(tracer, "simulate_call_trace", lambda *a, **kw: trace)

        # ETHDebug dir specifies OTHER address, but contract_address is ADDR
        other = "0x00000000000000000000000000000000000000bb"
        args = SimpleNamespace(
            rpc_url="http://rpc", from_addr=FROM,
            contract_address=ADDR,
            function_signature="set(uint256)",
            function_args=["42"],
            raw_data=None, value=0,
            interactive=False,
            cross_env_bridge=None, stylus_contracts=None,
            ethdebug_dir=[f"{other}:Token:{tmp_path}"],
            contracts=None, multi_contract=False,
            json=False, raw=False, max_steps=50,
            block=None, tx_index=None,
        )
        result = simulate_mod.simulate_command(args)
        assert result == 0
        out = capsys.readouterr().out
        assert "does not match" in out
