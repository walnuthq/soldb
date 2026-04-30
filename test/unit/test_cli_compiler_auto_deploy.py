import json
import sys
import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from web3 import Web3

from soldb.cli import bridge as cli_bridge
from soldb.cli import common, contracts, events, simulate, trace
import soldb.cli as cli_package

cli_main = importlib.import_module("soldb.cli.main")
from soldb.compiler import ethdebug as compiler_ethdebug
from soldb.compiler.config import CompilationError, CompilerConfig, dual_compile
from soldb.core import auto_deploy
from soldb.core.auto_deploy import AutoDeployDebugger
from soldb.core.transaction_tracer import FunctionCall, TraceStep, TransactionTrace

ADDR = "0x00000000000000000000000000000000000000aa"
OTHER_ADDR = "0x00000000000000000000000000000000000000bb"


class RunResult:
    def __init__(self, returncode=0, stdout="ok", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def make_trace():
    return TransactionTrace(
        tx_hash="0xtx",
        from_addr="0x0000000000000000000000000000000000000001",
        to_addr=ADDR,
        value=0,
        input_data="0x",
        gas_used=123,
        output="0x",
        steps=[TraceStep(0, "PUSH1", 100, 1, 0, ["0x1"])],
        success=True,
    )


def test_compiler_config_compile_verify_and_yaml(monkeypatch, tmp_path):
    contract = tmp_path / "Token.sol"
    contract.write_text("contract Token {}")

    def fake_run(cmd, capture_output=True, text=True):
        if "--version" in cmd:
            return RunResult(stdout="solc, Version: 0.8.31+commit")
        out_dir = Path(cmd[cmd.index("-o") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "ethdebug.json").write_text("{}")
        (out_dir / "Token.bin").write_text("6000")
        (out_dir / "Token.abi").write_text("[]")
        (out_dir / "Token_ethdebug.json").write_text("{}")
        (out_dir / "Token_ethdebug-runtime.json").write_text("{}")
        return RunResult()

    monkeypatch.setattr("subprocess.run", fake_run)
    config = CompilerConfig(
        solc_path="solc-test",
        debug_output_dir=str(tmp_path / "out"),
        build_dir=str(tmp_path / "build"),
    )

    debug = config.compile_with_ethdebug(str(contract))
    assert debug["success"] is True
    assert debug["files"]["ethdebug"].endswith("ethdebug.json")
    assert debug["files"]["contracts"]["Token"]["bytecode"].endswith("Token.bin")

    prod = config.compile_for_production(str(contract))
    assert prod["output_dir"] == str(tmp_path / "build")
    assert config.verify_solc_version()["supported"] is True

    monkeypatch.setattr(
        "subprocess.run", lambda *a, **k: RunResult(stdout="Version: 0.8.28")
    )
    assert "requires 0.8.29+" in config.verify_solc_version()["error"]
    monkeypatch.setattr(
        "subprocess.run", lambda *a, **k: RunResult(stdout="unparseable")
    )
    assert config.verify_solc_version()["error"] == "Could not parse version"
    monkeypatch.setattr("subprocess.run", lambda *a, **k: RunResult(returncode=1))
    assert config.verify_solc_version()["error"] == "Could not get solc version"

    monkeypatch.setattr(
        "subprocess.run", lambda *a, **k: RunResult(returncode=1, stderr="boom")
    )
    with pytest.raises(CompilationError):
        config.compile_with_ethdebug(str(contract))

    dumped = {}
    fake_yaml = SimpleNamespace(
        safe_load=lambda f: {
            "debug": {"ethdebug": {"solc_path": "solc-31", "path": "dbg"}},
            "build_dir": "prod",
        },
        dump=lambda data, f, default_flow_style=False, sort_keys=False: dumped.update(
            data
        ),
    )
    monkeypatch.setitem(sys.modules, "yaml", fake_yaml)
    cfg_file = tmp_path / "soldb.config.yaml"
    cfg_file.write_text("debug: {}")
    loaded = CompilerConfig.from_soldb_config(str(cfg_file))
    assert loaded.solc_path == "solc-31"
    assert loaded.debug_output_dir == "dbg"
    loaded.save_to_soldb_config(str(cfg_file))
    assert dumped["debug"]["ethdebug"]["enabled"] is True


def test_dual_compile_and_compile_ethdebug_run(monkeypatch, tmp_path):
    contract = tmp_path / "C.sol"
    contract.write_text("contract C {}")
    config = CompilerConfig()

    monkeypatch.setattr(
        config,
        "compile_for_production",
        lambda path: {"success": True, "output_dir": "prod"},
    )
    monkeypatch.setattr(
        config,
        "compile_with_ethdebug",
        lambda path: {"success": True, "output_dir": "debug"},
    )
    assert dual_compile(str(contract), config)["debug"]["success"] is True

    def fail(path):
        raise CompilationError("bad")

    monkeypatch.setattr(config, "compile_for_production", fail)
    result = dual_compile(str(contract), config)
    assert result["production"]["success"] is False

    monkeypatch.setattr(
        CompilerConfig,
        "verify_solc_version",
        lambda self: {"supported": True, "version": "0.8.31"},
    )
    monkeypatch.setattr(CompilerConfig, "save_to_soldb_config", lambda self: None)
    monkeypatch.setattr(
        CompilerConfig,
        "compile_with_ethdebug",
        lambda self, path: {"success": True, "path": path},
    )
    monkeypatch.setattr(
        compiler_ethdebug, "dual_compile", lambda path, config: {"dual": True}
    )

    assert (
        compiler_ethdebug.compile_ethdebug_run(str(contract), verify_version=True)[
            "success"
        ]
        is True
    )
    assert (
        compiler_ethdebug.compile_ethdebug_run(str(contract), save_config=True)["saved"]
        is True
    )
    assert (
        compiler_ethdebug.compile_ethdebug_run(str(contract), dual=True)["dual"] is True
    )
    with pytest.raises(FileNotFoundError):
        compiler_ethdebug.compile_ethdebug_run(str(tmp_path / "missing.sol"))


def test_compiler_ethdebug_main_modes(monkeypatch, tmp_path, capsys):
    contract = tmp_path / "C.sol"
    contract.write_text("contract C {}")

    monkeypatch.setattr(
        CompilerConfig,
        "verify_solc_version",
        lambda self: {"supported": True, "version": "0.8.31"},
    )
    monkeypatch.setattr(CompilerConfig, "save_to_soldb_config", lambda self: None)
    monkeypatch.setattr(
        CompilerConfig,
        "compile_with_ethdebug",
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
                        "ethdebug_runtime": None,
                    }
                },
            },
            "stderr": "warning",
        },
    )
    monkeypatch.setattr(
        compiler_ethdebug,
        "dual_compile",
        lambda path, config: {
            "production": {"success": True, "output_dir": "prod"},
            "debug": {"success": False, "error": "bad"},
        },
    )

    monkeypatch.setattr(
        sys, "argv", ["ethdebug", str(contract), "--verify-version", "--json"]
    )
    with pytest.raises(SystemExit) as exc:
        compiler_ethdebug.main()
    assert exc.value.code == 0

    monkeypatch.setattr(sys, "argv", ["ethdebug", str(contract), "--save-config"])
    compiler_ethdebug.main()
    assert "Configuration saved" in capsys.readouterr().out

    monkeypatch.setattr(sys, "argv", ["ethdebug", str(contract)])
    compiler_ethdebug.main()
    assert "ETHDebug compilation successful" in capsys.readouterr().out

    monkeypatch.setattr(sys, "argv", ["ethdebug", str(contract), "--dual-compile"])
    with pytest.raises(SystemExit) as exc:
        compiler_ethdebug.main()
    assert exc.value.code == 1

    monkeypatch.setattr(sys, "argv", ["ethdebug", str(tmp_path / "missing.sol")])
    with pytest.raises(SystemExit) as exc:
        compiler_ethdebug.main()
    assert exc.value.code == 1


def make_auto_session(tmp_path):
    contract = tmp_path / "Token.sol"
    contract.write_text("contract Token {}")
    session = AutoDeployDebugger.__new__(AutoDeployDebugger)
    session.contract_path = contract
    session.contract_name = "Token"
    session.rpc_url = "http://rpc"
    session.solc_path = "solc"
    session.dual_compile = False
    session.verify_version = False
    session.constructor_args = []
    session.use_cache = True
    session.cache_root = tmp_path / "cache"
    session.cache_root.mkdir(exist_ok=True)
    session.contract_address = None
    session.abi_path = tmp_path / "Token.abi"
    session.bin_path = tmp_path / "Token.bin"
    session.debug_dir = tmp_path
    session.debug_output_dir = tmp_path
    session.production_dir = tmp_path / "prod"
    session.production_dir.mkdir(exist_ok=True)
    session.abi_path.write_text("[]")
    session.bin_path.write_text("6000")
    return session


def test_auto_deploy_init_cache_compile_and_parsing(monkeypatch, tmp_path):
    contract = tmp_path / "Token.sol"
    contract.write_text("contract Token {}")
    calls = []

    monkeypatch.setattr(
        AutoDeployDebugger,
        "connect_or_launch_fork",
        lambda self: calls.append("connect"),
    )
    monkeypatch.setattr(AutoDeployDebugger, "_try_cache_hit", lambda self: False)
    monkeypatch.setattr(
        AutoDeployDebugger, "compile_contract", lambda self: calls.append("compile")
    )
    monkeypatch.setattr(
        AutoDeployDebugger,
        "deploy_contract",
        lambda self: setattr(self, "contract_address", ADDR),
    )
    monkeypatch.setattr(
        AutoDeployDebugger, "_store_cache", lambda self: calls.append("store")
    )

    session = AutoDeployDebugger(
        str(contract), keep_build=True, output_dir=str(tmp_path / "out")
    )
    assert session.debug_output_dir.name == "Token"
    assert calls == ["connect", "compile", "store"]

    parser = make_auto_session(tmp_path)
    inputs = [
        {"type": "uint256"},
        {"type": "bool"},
        {"type": "address"},
        {"type": "bytes2"},
        {"type": "bytes"},
        {"type": "string"},
        {"type": "uint256[]"},
        {"type": "tuple", "components": [{"type": "uint256"}, {"type": "bool"}]},
    ]
    parsed = parser._parse_constructor_args(
        ["7", "yes", ADDR, "0xabcd", "hello", "name", "[1,2]", "[3, False]"],
        inputs,
    )
    assert parsed[:3] == [7, True, Web3.to_checksum_address(ADDR)]
    assert parsed[3] == bytes.fromhex("abcd")
    assert parsed[4] == b"hello"
    assert parsed[6] == [1, 2]
    assert parsed[7] == [3, False]
    with pytest.raises(ValueError):
        parser._parse_constructor_args(["1"], [])
    with pytest.raises(ValueError):
        parser._parse_arg("5", {"type": "uint256[]"})
    with pytest.raises(AssertionError):
        parser._parse_typed([1], "tuple", [{"type": "uint256"}])


def test_auto_deploy_cache_compile_deploy_and_fork(monkeypatch, tmp_path):
    session = make_auto_session(tmp_path)
    session.contract_address = ADDR

    class FakeCode:
        def hex(self):
            return "0x6000"

    class FakeEth:
        chain_id = 31337
        accounts = ["0x0000000000000000000000000000000000000001"]

        def get_code(self, address):
            return FakeCode()

        def contract(self, abi, bytecode):
            class Constructor:
                def transact(self, tx):
                    return "0xtx"

            return SimpleNamespace(constructor=lambda *args: Constructor())

        def wait_for_transaction_receipt(self, tx_hash):
            return SimpleNamespace(contractAddress=OTHER_ADDR)

    class FakeWeb3:
        eth = FakeEth()
        client_version = "anvil/1.0"

        def __init__(self, provider=None):
            self.provider = provider

        @staticmethod
        def HTTPProvider(url, request_kwargs=None):
            return ("provider", url, request_kwargs)

        def is_connected(self):
            return True

    monkeypatch.setattr(auto_deploy, "Web3", FakeWeb3)

    entry = session._cache_entry_path()
    entry.mkdir()
    (entry / "Token.abi").write_text("[]")
    (entry / "Token.bin").write_text("6000")
    (entry / "meta.json").write_text(
        json.dumps({"chain_id": 31337, "address": ADDR, "runtime_code": "0x6000"})
    )
    session.contract_address = None
    assert session._try_cache_hit() is True

    session = make_auto_session(tmp_path)
    monkeypatch.setattr(
        auto_deploy,
        "compile_ethdebug_run",
        lambda **kwargs: {"success": True, "output_dir": str(tmp_path)},
    )
    session.compile_contract()
    assert session.debug_dir == tmp_path

    session.deploy_contract()
    assert session.contract_address == OTHER_ADDR

    session.contract_address = ADDR
    (tmp_path / "Token_ethdebug.json").write_text("{}")
    session._store_cache()
    assert (session._cache_entry_path() / "meta.json").exists()

    session.reuse_fork = True
    session.fork_port = 8545
    assert session._is_local_fork_running("http://127.0.0.1:8545") is True
    session.rpc_url = "old"
    session.connect_or_launch_fork()
    assert session.rpc_url.endswith(":8545")

    proc = SimpleNamespace(
        poll=lambda: None, terminate=lambda: setattr(proc, "terminated", True)
    )
    session._fork_proc = proc
    session.keep_fork = False
    session.cleanup()
    assert proc.terminated is True


def test_cli_common_helpers(monkeypatch, tmp_path, capsys):
    tracer = SimpleNamespace(is_contract_deployed=lambda address: address == ADDR)
    monkeypatch.setattr(
        common, "TransactionTracer", lambda rpc_url, quiet_mode=False: tracer
    )
    assert common.create_tracer("http://rpc") is tracer
    monkeypatch.setattr(
        common,
        "TransactionTracer",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")),
    )
    with pytest.raises(common.RPCConnectionError):
        common.create_tracer("http://rpc")

    assert common.normalize_address(ADDR.lower()) == Web3.to_checksum_address(ADDR)
    with pytest.raises(ValueError):
        common.normalize_address("bad")
    assert common.get_ethdebug_dirs(SimpleNamespace(ethdebug_dir="out")) == ["out"]
    assert (
        common.is_multi_contract_mode(
            SimpleNamespace(ethdebug_dir=["a", "b"], contracts=None)
        )
        is True
    )

    class FakeParser:
        def __init__(self):
            self.contracts = {}
            self.loaded = []

        def load_from_mapping_file(self, path):
            self.loaded.append(("mapping", path))

        def load_contract(self, *args):
            self.loaded.append(args)

        def load_from_deployment(self, path):
            self.loaded.append(("deployment", str(path)))

    fake_parser = FakeParser()
    monkeypatch.setattr(common, "MultiContractETHDebugParser", lambda: fake_parser)
    monkeypatch.setattr(
        common.ETHDebugDirParser,
        "parse_ethdebug_dirs",
        lambda dirs: [SimpleNamespace(address=ADDR, name="Token", path="out")],
    )
    parser, errors = common.load_multi_contract_parser(["out"])
    assert parser is fake_parser
    assert errors == []
    assert fake_parser.loaded[-1] == (ADDR, "out", "Token")

    abi_dir = tmp_path / "abi"
    abi_dir.mkdir()
    (abi_dir / "Token.abi").write_text("[]")
    fake_parser.contracts = {ADDR: SimpleNamespace(debug_dir=abi_dir, name="Token")}
    loaded_abis = []
    common.load_abi_files(
        SimpleNamespace(load_abi=lambda path: loaded_abis.append(path)), fake_parser
    )
    assert loaded_abis == [str(abi_dir / "Token.abi")]

    assert common.validate_contract_address(ADDR, tracer) is True
    assert common.validate_contract_address("bad", tracer) is False
    assert common.validate_contract_address(OTHER_ADDR, tracer, json_mode=True) is False
    assert (
        common.parse_value_arg("0.5ether", SimpleNamespace(to_wei=lambda v, unit: 500))
        == 500
    )
    with pytest.raises(ValueError):
        common.parse_value_arg("bad", SimpleNamespace(to_wei=lambda v, unit: 0))
    assert common.handle_command_error(ValueError("x"), exit_code=7) == 7
    common.print_connection_info("http://rpc")
    assert "Connecting to RPC" in capsys.readouterr().out

    old_cwd = Path.cwd()
    try:
        import os

        os.chdir(tmp_path)
        debug = tmp_path / "debug"
        debug.mkdir()
        (debug / "deployment.json").write_text(json.dumps({"address": ADDR}))
        (debug / "Contract.runtime.zasm").write_text("zasm")
        assert common.find_debug_file(ADDR).endswith(".runtime.zasm")
    finally:
        os.chdir(old_cwd)


def test_cli_command_modules(monkeypatch, capsys):
    trace_obj = make_trace()

    class FakeTracer:
        def __init__(self, rpc_url, quiet_mode=False):
            self.rpc_url = rpc_url
            self.quiet_mode = quiet_mode
            self.multi_contract_parser = None
            self.ethdebug_info = None
            self.w3 = SimpleNamespace(
                eth=SimpleNamespace(get_transaction_receipt=lambda tx: {"logs": []})
            )
            self.function_abis = {}

        def trace_transaction(self, tx_hash):
            return trace_obj

        def analyze_function_calls(self, trace):
            return [
                FunctionCall("f", "0x12345678", 0, 0, 1, 0, [], contract_address=ADDR)
            ]

        def print_function_trace(self, trace, calls):
            print("function trace")

        def print_trace(self, trace, source_map, max_steps=None):
            print("raw trace")

        def load_abi(self, path):
            pass

    monkeypatch.setattr(contracts, "TransactionTracer", FakeTracer)
    monkeypatch.setattr(events, "TransactionTracer", FakeTracer)
    monkeypatch.setattr(trace, "TransactionTracer", FakeTracer)
    monkeypatch.setattr(simulate, "TransactionTracer", FakeTracer)
    monkeypatch.setattr(
        contracts,
        "_print_contracts_in_transaction",
        lambda tracer, trace: print("contracts"),
    )
    monkeypatch.setattr(
        events, "_print_events", lambda tracer, receipt, json_mode: print("events")
    )

    args = SimpleNamespace(
        rpc_url="http://rpc",
        rpc="http://rpc",
        tx_hash="0xtx",
        ethdebug_dir=None,
        contracts=None,
        multi_contract=False,
    )
    assert contracts.list_contracts_command(args) == 0
    assert (
        events.list_events_command(SimpleNamespace(**args.__dict__, json_events=False))
        == 0
    )

    trace_args = SimpleNamespace(
        rpc="http://rpc",
        tx_hash="0xtx",
        json=False,
        cross_env_bridge=None,
        stylus_contracts=None,
        interactive=False,
        raw=False,
        max_steps=10,
        ethdebug_dir=None,
        contracts=None,
        multi_contract=False,
        debug_info_from_zasm_file=None,
    )
    monkeypatch.setattr(
        trace, "_load_debug_info", lambda tracer, trace_obj, args, json_mode: ({}, None)
    )
    assert trace.trace_command(trace_args) == 0

    unavailable_trace = make_trace()
    unavailable_trace.debug_trace_available = False
    unavailable_trace.error = "disabled"
    monkeypatch.setattr(
        FakeTracer, "trace_transaction", lambda self, tx_hash: unavailable_trace
    )
    trace_json_args = SimpleNamespace(**{**trace_args.__dict__, "json": True})
    assert trace.trace_command(trace_json_args) == 1
    monkeypatch.setattr(
        FakeTracer, "trace_transaction", lambda self, tx_hash: trace_obj
    )

    sim_args = SimpleNamespace(
        rpc_url="http://rpc",
        from_addr="0x0000000000000000000000000000000000000001",
        contract_address=ADDR,
        function_signature="set(uint256)",
        function_args=["7"],
        raw_data=None,
        value=0,
        interactive=False,
        cross_env_bridge=None,
        stylus_contracts=None,
        ethdebug_dir=None,
        contracts=None,
        multi_contract=False,
        json=False,
        raw=False,
        max_steps=10,
        block=None,
        tx_index=None,
    )
    monkeypatch.setattr(
        simulate, "_load_debug_info_for_simulate", lambda tracer, args, json_mode: {}
    )
    real_execute_simulation = simulate._execute_simulation
    monkeypatch.setattr(
        simulate,
        "_execute_simulation",
        lambda tracer, args, source_map, token_value, json_mode: 0,
    )
    assert simulate.simulate_command(sim_args) == 0
    bad_sim_args = SimpleNamespace(**{**sim_args.__dict__, "contract_address": "bad"})
    assert simulate.simulate_command(bad_sim_args) == 1

    assert trace._extract_error_detail("{'message': 'bad'}") == "bad"
    assert trace._extract_error_detail("plain") == "plain"
    unavailable = SimpleNamespace(
        tx_hash="0xtx",
        from_addr="0x1",
        to_addr=ADDR,
        gas_used=1,
        success=False,
        error="{'message': 'debug disabled'}",
    )
    assert trace._handle_debug_trace_unavailable(unavailable, json_mode=True) == 1

    output_args = SimpleNamespace(raw=False, max_steps=10, contract_address=ADDR)
    assert (
        trace._print_trace_output(
            FakeTracer("rpc"), trace_obj, {}, output_args, json_mode=False
        )
        == 0
    )
    output_args.raw = True
    assert (
        trace._print_trace_output(
            FakeTracer("rpc"), trace_obj, {}, output_args, json_mode=False
        )
        == 0
    )

    assert simulate._validate_raw_data_args(
        SimpleNamespace(raw_data="0x00", function_signature=None, function_args=[])
    )
    assert not simulate._validate_raw_data_args(
        SimpleNamespace(raw_data="0x00", function_signature="f()", function_args=[])
    )
    fake = FakeTracer("rpc")
    fake.w3 = SimpleNamespace(to_wei=lambda value, unit: 10)
    assert simulate._parse_value(SimpleNamespace(value="1ether"), fake, False) == 10
    assert simulate._parse_value(SimpleNamespace(value="bad"), fake, True) is None
    assert simulate._parse_signature("set(uint256)") == ("set", ["uint256"])
    assert simulate._parse_single_arg_simple("true", "bool") is True
    assert simulate._parse_single_arg("0xabcd", "bytes2", {}) == bytes.fromhex("abcd")
    assert simulate._encode_calldata("set", ["uint256"], [7]).startswith("0x")
    assert simulate._encode_calldata("set", ["uint256"], ["bad"]) is None

    fake.function_abis = {
        "0x1": {"name": "set", "inputs": [{"type": "uint256", "name": "amount"}]},
        "0x2": {"name": "tupled", "inputs": [{"type": "tuple", "name": "t"}]},
    }
    assert simulate._find_abi_item(fake, "set", ["uint256"])["name"] == "set"
    assert simulate._parse_function_args(
        SimpleNamespace(function_args=["7"], function_signature="set(uint256)"),
        ["uint256"],
        fake.function_abis["0x1"],
        True,
    ) == [7]
    assert (
        simulate._parse_function_args(
            SimpleNamespace(function_args=[], function_signature="set(uint256)"),
            ["uint256"],
            fake.function_abis["0x1"],
            True,
        )
        is None
    )

    monkeypatch.setattr(simulate, "_simulate_with_raw_data", lambda *a: 3)
    assert (
        real_execute_simulation(fake, SimpleNamespace(raw_data="0x00"), {}, 0, False)
        == 3
    )

    monkeypatch.setattr(cli_bridge, "run_bridge_server", lambda **kwargs: None)
    assert (
        cli_bridge.bridge_command(
            SimpleNamespace(host="h", port=1, config_file=None, quiet=False, json=False)
        )
        == 0
    )
    monkeypatch.setattr(
        cli_bridge,
        "run_bridge_server",
        lambda **kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    assert (
        cli_bridge.bridge_command(
            SimpleNamespace(host="h", port=1, config_file=None, quiet=False, json=False)
        )
        == 0
    )
    monkeypatch.setattr(
        cli_bridge,
        "run_bridge_server",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("bad")),
    )
    assert (
        cli_bridge.bridge_command(
            SimpleNamespace(host="h", port=1, config_file=None, quiet=True, json=True)
        )
        == 1
    )

    assert "events" in capsys.readouterr().out


def test_cli_main_and_lazy_exports(monkeypatch):
    calls = []
    monkeypatch.setattr(
        cli_main,
        "trace_command",
        lambda args: calls.append(("trace", args.tx_hash)) or 0,
    )
    monkeypatch.setattr(
        cli_main,
        "simulate_command",
        lambda args: calls.append(("simulate", args.contract_address)) or 0,
    )
    monkeypatch.setattr(
        cli_main,
        "bridge_command",
        lambda args: calls.append(("bridge", args.port)) or 0,
    )
    monkeypatch.setattr(
        cli_main,
        "list_events_command",
        lambda args: calls.append(("events", args.tx_hash)) or 0,
    )
    monkeypatch.setattr(
        cli_main,
        "list_contracts_command",
        lambda args: calls.append(("contracts", args.tx_hash)) or 0,
    )

    for argv in [
        ["soldb", "trace", "0xtx"],
        [
            "soldb",
            "simulate",
            "--from",
            "0x0000000000000000000000000000000000000001",
            ADDR,
            "set(uint256)",
            "7",
        ],
        ["soldb", "bridge", "--port", "9999"],
        ["soldb", "list-events", "0xtx"],
        ["soldb", "list-contracts", "0xtx"],
    ]:
        monkeypatch.setattr(sys, "argv", argv)
        assert cli_main.main() == 0

    import soldb.cli.trace as trace_module
    import soldb.cli.simulate as simulate_module
    import soldb.cli.events as events_module
    import soldb.cli.contracts as contracts_module

    monkeypatch.setattr(trace_module, "trace_command", lambda args: "trace")
    monkeypatch.setattr(simulate_module, "simulate_command", lambda args: "simulate")
    monkeypatch.setattr(events_module, "list_events_command", lambda args: "events")
    monkeypatch.setattr(
        contracts_module, "list_contracts_command", lambda args: "contracts"
    )
    assert cli_package.trace_command(SimpleNamespace()) == "trace"
    assert cli_package.simulate_command(SimpleNamespace()) == "simulate"
    assert cli_package.list_events_command(SimpleNamespace()) == "events"
    assert cli_package.list_contracts_command(SimpleNamespace()) == "contracts"
    assert [c[0] for c in calls] == [
        "trace",
        "simulate",
        "bridge",
        "events",
        "contracts",
    ]
