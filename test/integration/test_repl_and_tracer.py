from pathlib import Path
from types import SimpleNamespace

import pytest
from web3 import Web3

import soldb.core.evm_repl as repl_module
import soldb.core.transaction_tracer as tracer_module
from soldb.core.evm_repl import EVMDebugger
from soldb.core.transaction_tracer import (
    FunctionCall,
    TraceStep,
    TransactionTrace,
    TransactionTracer,
)

ADDR = "0x00000000000000000000000000000000000000aa"
OTHER_ADDR = "0x00000000000000000000000000000000000000bb"


def make_trace():
    steps = [
        TraceStep(
            0, "PUSH1", 100, 1, 0, ["0x2a"], memory="000102030405", storage={"1": "0b"}
        ),
        TraceStep(
            10,
            "CALL",
            90,
            2,
            0,
            ["0x0", "0x0", "0x04", "0x00", "0x0", OTHER_ADDR, "0x0"],
            memory="12345678",
        ),
        TraceStep(20, "RETURN", 80, 1, 1, ["0x0", "0x02"], memory="aabb"),
        TraceStep(30, "STOP", 70, 1, 0, []),
    ]
    return TransactionTrace(
        tx_hash="0xtx",
        from_addr="0x0000000000000000000000000000000000000001",
        to_addr=ADDR,
        value=0,
        input_data="0x",
        gas_used=123,
        output="0x",
        steps=steps,
        success=True,
    )


class FakeFunctions:
    def __getattr__(self, name):
        return lambda *args: SimpleNamespace(
            build_transaction=lambda tx: {"data": f"0x{name}{len(args)}"}
        )


class FakeEth:
    def contract(self, abi):
        return SimpleNamespace(functions=FakeFunctions())


class FakeParser:
    def get_source_context(self, pc, context_lines=2):
        line = pc // 10 + 1
        return {"file": "C.sol", "line": line, "content": f"line {line}"}

    def offset_to_line_col(self, source_path, offset):
        return 1, 2

    def load_source_file(self, source_path):
        return ["line 1\n", "line 2\n", "line 3\n", "line 4\n"]

    def get_source_mapping(self):
        return {0: ("C.sol", 1), 10: ("C.sol", 2), 20: ("C.sol", 3), 30: ("C.sol", 4)}


class FakeEthDebugInfo:
    contract_name = "Token"
    environment = "runtime"
    sources = {0: "C.sol"}

    def get_variables_at_pc(self, pc):
        return [
            SimpleNamespace(
                name="amount",
                type="uint256",
                location_type="stack",
                offset=0,
                pc_range=(0, 99),
            ),
            SimpleNamespace(
                name="stored",
                type="uint256",
                location_type="storage",
                offset=1,
                pc_range=(0, 99),
            ),
            SimpleNamespace(
                name="_tmp",
                type="uint256",
                location_type="stack",
                offset=0,
                pc_range=(0, 99),
            ),
        ]

    def get_instruction_at_pc(self, pc):
        return SimpleNamespace(mnemonic="PUSH1", arguments=["0x2a"])

    def get_source_info(self, pc):
        return ("C.sol", 0, 6)


class FakeTracer:
    def __init__(self):
        self.w3 = SimpleNamespace(eth=FakeEth())
        self.function_abis_by_name = {
            "set": {"name": "set", "inputs": [{"name": "amount", "type": "uint256"}]},
            "ping": {"name": "ping", "inputs": []},
        }
        self.function_signatures = {"0x12345678": {"name": "set(uint256)"}}
        self.function_abis = {}
        self.ethdebug_info = FakeEthDebugInfo()
        self.ethdebug_parser = FakeParser()
        self.srcmap_info = None
        self.srcmap_parser = None
        self.multi_contract_parser = None

    def trace_transaction(self, tx_hash):
        return make_trace()

    def analyze_function_calls(self, trace):
        return [
            FunctionCall(
                "dispatcher", "", 0, 0, 0, 0, [], contract_address=ADDR, call_id=0
            ),
            FunctionCall(
                "set",
                "0x12345678",
                0,
                3,
                10,
                0,
                [("amount", 42)],
                contract_address=ADDR,
                call_id=1,
            ),
        ]

    def simulate_call_trace(self, **kwargs):
        return make_trace()

    def decode_value(self, raw_value, param_type):
        return int(raw_value, 16) if param_type.startswith("uint") else raw_value

    def extract_from_memory(self, memory, offset, param_type):
        return "mem"

    def extract_from_storage(self, storage, slot, param_type):
        return int(storage.get(str(slot), "0"), 16)

    def extract_address_from_stack(self, value):
        return OTHER_ADDR

    def extract_calldata_from_step(self, step):
        return "0x12345678" + "00" * 32

    def decode_function_parameters(self, selector, calldata):
        return [("amount", 7)]

    def snapshot_state(self):
        return "snap-1"

    def revert_state(self, target=None):
        return True


def make_debugger():
    debugger = EVMDebugger(tracer=FakeTracer())
    debugger.current_trace = make_trace()
    debugger.function_trace = debugger.tracer.analyze_function_calls(
        debugger.current_trace
    )
    debugger.current_function = debugger.function_trace[1]
    debugger.current_step = 0
    debugger.contract_address = ADDR
    debugger.source_map = {
        0: ("C.sol", 1),
        10: ("C.sol", 2),
        20: ("C.sol", 3),
        30: ("C.sol", 4),
    }
    debugger.source_lines = {"C.sol": ["line 1\n", "line 2\n", "line 3\n", "line 4\n"]}
    return debugger


def test_repl_encoding_run_and_basic_commands(capsys):
    debugger = make_debugger()
    assert "soldb" in debugger._get_prompt()
    assert debugger._encode_function_call("set(uint256)", ["7"]) == "0xset1"
    assert debugger._encode_function_call("ping()", []) == "0xping0"
    assert debugger._encode_function_call("missing()", []) is None
    assert debugger._encode_function_call("set", ["7"]) is None
    assert debugger._encode_function_call("set(bool)", ["true"]) is None
    assert debugger._encode_function_call("set(uint256,uint256)", ["1", "2"]) is None
    assert debugger._encode_function_call("set(uint256)", []) is None
    assert debugger._convert_argument("true", "bool") is True
    assert debugger._convert_argument(ADDR[2:], "address").startswith("0x")
    assert debugger._convert_argument("abcd", "bytes2") == "0xabcd"
    assert debugger._convert_argument('{"x": 1}', "tuple") == {"x": 1}

    debugger.init = False
    debugger.do_run("0xtx")
    assert debugger.init is True
    debugger.do_nexti("")
    assert debugger.current_step == 1
    debugger.do_ni("")
    debugger.do_stepi("")
    debugger.do_si("")
    assert debugger.current_step >= 1

    no_trace = make_debugger()
    no_trace.current_trace = None
    no_trace.do_nexti("")
    no_trace.do_step("")
    no_trace.do_continue("")
    assert "No transaction" in capsys.readouterr().out


def test_repl_initialization_and_interactive_simulation(monkeypatch, tmp_path, capsys):
    abi_path = tmp_path / "Token.abi"
    abi_path.write_text("[]")

    target_contract = SimpleNamespace(
        name="Token",
        ethdebug_info=SimpleNamespace(
            contract_name="Token", environment="runtime", sources={0: "Token.sol"}
        ),
        parser=FakeParser(),
        srcmap_info=None,
        srcmap_parser=None,
        get_parser=lambda: FakeParser(),
    )

    class InitTracer(FakeTracer):
        def __init__(self):
            super().__init__()
            self.ethdebug_info = None
            self.ethdebug_parser = None
            self.srcmap_info = None
            self.srcmap_parser = None
            self.loaded_abis = []
            self.loaded_debug = []
            self.multi_contract_parser = SimpleNamespace(
                get_contract_at_address=lambda address: target_contract
            )

        def is_contract_deployed(self, address):
            return False

        def load_debug_info_auto(self, ethdebug_dir, contract_name=None):
            self.loaded_debug.append((ethdebug_dir, contract_name))
            self.ethdebug_info = target_contract.ethdebug_info
            self.ethdebug_parser = target_contract.parser
            return {0: ("Token.sol", 1)}

        def load_abi(self, path):
            self.loaded_abis.append(path)

    monkeypatch.setattr(
        repl_module.ETHDebugDirParser,
        "find_abi_file",
        lambda spec, contract_name=None: str(abi_path),
    )

    tracer = InitTracer()
    debugger = EVMDebugger(
        contract_address=ADDR,
        ethdebug_dir=f"{ADDR}:Token:{tmp_path}",
        abi_path=str(abi_path),
        tracer=tracer,
        function_name="ping()",
        function_args=[],
        from_addr="0x0000000000000000000000000000000000000001",
        block=5,
        value=3,
    )
    assert tracer.loaded_abis == [str(abi_path), str(abi_path)]
    assert tracer.loaded_debug == [(str(tmp_path), "Token")]
    assert "Token.sol" in debugger.source_lines

    debugger._do_interactive()
    assert debugger.init is True
    assert debugger.current_trace.success is True

    no_contract = make_debugger()
    no_contract.contract_address = None
    no_contract._do_interactive()

    bad_function = make_debugger()
    bad_function.function_name = "missing()"
    bad_function.function_args = []
    bad_function._do_interactive()

    failing = make_debugger()
    failing.tracer.simulate_call_trace = lambda **kwargs: (_ for _ in ()).throw(
        RuntimeError("boom")
    )
    failing.function_name = "ping()"
    failing.function_args = []
    failing._do_interactive()
    output = capsys.readouterr().out
    assert "Simulation complete" in output
    assert "No contract address set" in output
    assert "Failed to encode function call" in output
    assert "Simulation failed" in output


def test_repl_debug_file_and_navigation_paths(monkeypatch, tmp_path, capsys):
    source = tmp_path / "Source.sol"
    source.write_text("line 1\nline 2\n")
    debug_file = tmp_path / "Source.sol_runtime.zasm"
    debug_file.write_text(".loc 1 1 0\n")

    tracer = FakeTracer()
    tracer.ethdebug_info = None
    tracer.srcmap_info = None
    tracer.multi_contract_parser = None
    tracer.load_debug_info = lambda path: {0: (str(source), 1)}
    monkeypatch.chdir(tmp_path)
    debugger = EVMDebugger(debug_file=debug_file.name, tracer=tracer)
    assert source.name in debugger.source_lines

    debugger = make_debugger()
    debugger.current_step = 0
    debugger.do_next("")
    assert debugger.current_step == 1
    assert debugger.on_call_opcode is True
    debugger.do_next("")
    assert debugger.current_step == 2
    assert debugger.on_call_opcode is False

    debugger.current_step = 2
    debugger.do_next("")
    assert debugger.current_step >= len(debugger.current_trace.steps) - 1

    debugger = make_debugger()
    debugger.current_step = 0
    debugger.do_step("")
    assert "only allowed for CALL" in capsys.readouterr().out

    debugger.current_step = 1
    debugger.function_trace.append(
        FunctionCall(
            "target",
            "0x",
            2,
            3,
            1,
            1,
            [],
            contract_address=OTHER_ADDR,
            call_id=4,
        )
    )
    target_contract = SimpleNamespace(
        name="Target",
        ethdebug_info=FakeEthDebugInfo(),
        parser=FakeParser(),
        srcmap_info=None,
        srcmap_parser=None,
        get_parser=lambda: FakeParser(),
    )
    debugger.tracer.multi_contract_parser = SimpleNamespace(
        get_contract_at_address=lambda address: target_contract
    )
    debugger.do_step("")
    assert debugger.current_step >= 2
    assert debugger.manual_contract_switch is True

    no_debug = make_debugger()
    no_debug.current_step = 1
    no_debug.function_trace = []
    no_debug.tracer.multi_contract_parser = SimpleNamespace(
        get_contract_at_address=lambda address: None
    )
    no_debug.do_step("")
    assert "Cannot step into contract" in capsys.readouterr().out

    cont = make_debugger()
    cont.breakpoints = {10}
    cont.do_continue("")
    assert cont.current_step == 1
    cont.breakpoints = set()
    cont.current_step = 1
    cont.current_trace.steps[2].error = "boom"
    cont.do_c("")
    assert "Execution error" in capsys.readouterr().out


def test_repl_navigation_breakpoints_and_display(capsys):
    debugger = make_debugger()
    debugger.do_break("")
    debugger.do_break("0x10")
    debugger.do_break("bad")
    debugger.do_break("C.sol:2")
    debugger.do_break("set")
    assert 16 in debugger.breakpoints
    debugger.do_clear("0x10")
    debugger.do_clear("0x10")
    debugger.do_clear("bad")

    debugger.do_list("")
    debugger.do_l("")
    debugger.do_print("")
    debugger.do_print("amount")
    debugger.do_print("stack[0]")
    debugger.do_print("stack[99]")
    debugger.do_print("storage[0x1]")
    debugger.do_print("memory[0x0:0x2]")
    debugger.do_print("memory[bad]")
    debugger.do_print("unknown")
    debugger.do_p("stack[0]")

    debugger.do_info("")
    debugger.do_info("memory")
    debugger.do_info("storage")
    debugger.do_info("gas")
    debugger.do_disasm("")
    debugger.do_where("")
    debugger.do_backtrace("")
    debugger.do_bt("")
    assert "Call Stack" in capsys.readouterr().out


def test_repl_watch_vars_filters_and_debug_helpers(capsys):
    debugger = make_debugger()
    debugger.do_watch("")
    debugger.do_watch("amount")
    debugger.do_watch("stack[0]")
    debugger.do_watch("storage[0x1]")
    debugger.do_watch("remove 1")
    debugger.do_watch("delete 99")
    debugger.do_watch("clear")
    debugger.variable_history = {"amount": [(0, 7, "uint256", "stack[0]")]}
    debugger.do_history("")
    debugger.do_history("amount")
    debugger.do_history("missing")

    debugger.do_vars("")
    debugger.tracer.ethdebug_info = None
    debugger.do_vars("")
    debugger.tracer.ethdebug_info = FakeEthDebugInfo()
    debugger._print_variable_info(
        SimpleNamespace(name="bad", type="uint256", location_type="stack", offset=99),
        debugger.current_trace.steps[0],
    )

    for command in [
        "",
        "hide-params",
        "show-params",
        "hide-temps",
        "show-temps",
        "show-type uint256",
        "hide-type address",
        "show-location stack",
        "hide-location storage",
        "name-pattern ^a",
        "name-pattern [",
        "clear-filters",
        "unknown",
    ]:
        debugger.do_filter(command)

    var = SimpleNamespace(name="amount", type="uint256", location_type="stack")
    assert debugger._should_show_variable(var, {"amount"}) is True
    debugger.do_goto("2")
    assert debugger.current_step == 2
    debugger.do_goto("")
    debugger.do_goto("bad")
    debugger.do_goto("99")
    debugger.do_debug_ethdebug("0x0")
    debugger.do_debug_ethdebug("bad")
    debugger.do_debug_ethdebug("")
    assert "ETHDebug Information" in capsys.readouterr().out


def test_repl_state_rendering_calls_returns_and_modes(capsys):
    debugger = make_debugger()
    debugger.watch_expressions = [
        "amount",
        "stack[0]",
        "stack[99]",
        "storage[0x1]",
        "unsupported",
    ]
    debugger._show_current_state()
    debugger.current_step = 1
    debugger._show_call_opcode_info(debugger.current_trace.steps[1], show_options=True)
    debugger._show_call_opcode_info(debugger.current_trace.steps[1], show_options=False)
    debugger.current_step = 2
    debugger._show_return_opcode_info(debugger.current_trace.steps[2])
    debugger._evaluate_watch_expressions(debugger.current_trace.steps[0])
    assert "CALL DETECTED" in capsys.readouterr().out

    debugger.do_mode("")
    debugger.do_mode("asm")
    assert debugger.display_mode == "asm"
    debugger.do_mode("source")
    assert debugger.display_mode == "source"
    debugger.do_mode("bad")
    debugger.do_snapshot("")
    debugger.do_revert("")
    debugger.default("wat")
    debugger.emptyline()
    debugger.do_help("")
    assert debugger.do_exit("") is True
    assert debugger.do_quit("") is True
    assert debugger.do_q("") is True
    assert debugger.do_EOF("") is True


def test_repl_contract_switch_and_source_loading(capsys):
    debugger = make_debugger()
    target_contract = SimpleNamespace(
        name="Target",
        ethdebug_info=FakeEthDebugInfo(),
        parser=FakeParser(),
        srcmap_info=None,
        srcmap_parser=None,
        get_parser=lambda: FakeParser(),
    )
    debugger.tracer.multi_contract_parser = SimpleNamespace(
        get_contract_at_address=lambda address: target_contract,
    )
    debugger._load_source_files_for_contract(target_contract)
    assert "C.sol" in debugger.source_lines

    debugger.call_stack = [
        {"contract": ADDR, "target_contract": OTHER_ADDR, "call_type": "CALL"}
    ]
    debugger.contract_address = OTHER_ADDR
    debugger.current_step = 2
    debugger._handle_return_opcode(debugger.current_trace.steps[2])
    debugger._check_contract_return_transition(ADDR)
    debugger.enable_depth_detection = False
    debugger._check_depth_change()
    assert (
        debugger.previous_depth
        == debugger.current_trace.steps[debugger.current_step].depth
    )

    debugger.function_trace.append(
        FunctionCall(
            "target", "0x", 2, 3, 1, 1, [], contract_address=OTHER_ADDR, call_id=3
        )
    )
    debugger.current_step = 2
    debugger._in_step_mode = True
    debugger._update_current_function()
    assert debugger.current_function is not None
    assert "Returned to contract" in capsys.readouterr().out


def test_transaction_tracer_lifecycle_and_debug_loading(monkeypatch, tmp_path, capsys):
    class FakeProvider:
        def __init__(self):
            self.requests = []

        def make_request(self, method, params):
            self.requests.append((method, params))
            return {"result": "snap-1" if method == "evm_snapshot" else True}

    class FakeEth:
        block_number = 99

        def get_code(self, address):
            return b"\x60"

    class FakeWeb3:
        def __init__(self, provider):
            self.provider = FakeProvider()
            self.eth = FakeEth()

        @staticmethod
        def HTTPProvider(url, request_kwargs=None):
            return ("provider", url, request_kwargs)

        @staticmethod
        def to_checksum_address(address):
            return Web3.to_checksum_address(address)

    monkeypatch.setattr(tracer_module, "Web3", FakeWeb3)
    tracer = TransactionTracer("http://rpc", quiet_mode=True)
    assert tracer.rpc_url == "http://rpc"
    assert tracer.snapshot_state() == "snap-1"
    assert tracer.revert_state() is True
    assert tracer.is_contract_deployed(ADDR) is True

    class Bridge:
        def __init__(self, bridge_url):
            self.bridge_url = bridge_url
            self.is_connected = True

        def connect(self):
            return True

        def register_contract(self, contract):
            self.contract = contract
            return True

        def is_stylus_contract(self, address):
            return address == ADDR

        def request_trace(self, **kwargs):
            return SimpleNamespace(calls=[])

    monkeypatch.setattr(tracer_module, "StylusBridgeIntegration", Bridge)
    assert tracer.setup_stylus_bridge("http://bridge") is True
    assert tracer.register_stylus_contract(ADDR, "Stylus", "lib.so") is True
    assert tracer.is_stylus_contract(ADDR) is True
    assert tracer._request_stylus_trace(ADDR, "0x") is not None

    zasm = tmp_path / "C.runtime.zasm"
    zasm.write_text(".loc 1 7 0\nPUSH1 0x01\nADD\n.loc 1 8 0\nSTOP\n")
    assert tracer.load_debug_info(str(zasm))[0] == (1, 7)
    assert tracer.load_debug_info(str(tmp_path / "missing.zasm")) == {}
    assert "Loaded" in capsys.readouterr().out


def test_transaction_tracer_trace_transaction_and_basic_trace(capsys):
    tracer = TransactionTracer.__new__(TransactionTracer)
    tracer.rpc_url = "http://rpc"
    tracer.quiet_mode = False

    revert_reason = (
        "08c379a0" + f"{32:064x}" + f"{3:064x}" + "bad".encode().hex().ljust(64, "0")
    )

    class FakeManager:
        def __init__(self):
            self.fail = False

        def request_blocking(self, method, params):
            assert method == "debug_traceTransaction"
            if self.fail:
                raise RuntimeError("debug unavailable")
            return {
                "returnValue": revert_reason,
                "structLogs": [
                    {
                        "pc": 1,
                        "op": "CALL",
                        "gas": 100,
                        "gasCost": 7,
                        "depth": 1,
                        "stack": ["0x1"],
                        "memory": ["aa", "bb"],
                        "storage": {"0": "1"},
                    },
                    {
                        "pc": 2,
                        "op": "STOP",
                        "gas": 90,
                        "depth": 1,
                        "stack": [],
                    },
                ],
            }

    class FakeEth:
        def __init__(self):
            self.fail_tx = None
            self.receipt = {"status": 0, "gasUsed": 21000, "contractAddress": ADDR}

        def get_transaction(self, tx_hash):
            if self.fail_tx == "not_found":
                raise RuntimeError("transaction not found")
            if self.fail_tx == "other":
                raise RuntimeError("rpc down")
            return {
                "from": "0x0000000000000000000000000000000000000001",
                "to": ADDR,
                "value": 5,
                "input": "0x12345678",
                "gas": 50000,
                "blockNumber": 9,
            }

        def get_transaction_receipt(self, tx_hash):
            if self.receipt == "missing":
                return None
            return self.receipt

        def call(self, params, block_number):
            return b"\x12\x34"

    tracer.w3 = SimpleNamespace(eth=FakeEth(), manager=FakeManager())

    trace = tracer.trace_transaction("abc")
    assert trace.tx_hash == "0xabc"
    assert trace.success is False
    assert trace.error == "bad"
    assert trace.steps[0].memory == "aabb"
    assert trace.contract_address == ADDR

    tracer.w3.eth.receipt = {"status": 1, "gasUsed": 21000, "contractAddress": ADDR}
    tracer.w3.manager.fail = True
    fallback = tracer.trace_transaction("0xabc")
    assert fallback.debug_trace_available is False
    assert "debug unavailable" in fallback.error
    assert "debug_traceTransaction not available" in capsys.readouterr().out

    assert tracer._basic_trace("0xabc")["returnValue"] == "1234"
    tracer.w3.eth.call = lambda params, block_number: (_ for _ in ()).throw(
        RuntimeError("reverted")
    )
    assert tracer._basic_trace("0xabc")["error"] == "reverted"

    tracer.w3.eth.fail_tx = "not_found"
    with pytest.raises(ValueError, match="Transaction not found"):
        tracer.trace_transaction("0xmissing")
    tracer.w3.eth.fail_tx = "other"
    with pytest.raises(ValueError, match="Failed to fetch transaction"):
        tracer.trace_transaction("0xerr")
    tracer.w3.eth.fail_tx = None
    tracer.w3.eth.receipt = "missing"
    with pytest.raises(ValueError, match="receipt not available"):
        tracer.trace_transaction("0xno-receipt")


def test_transaction_tracer_simulate_call_trace_paths(capsys):
    tracer = TransactionTracer.__new__(TransactionTracer)
    tracer.rpc_url = "http://rpc"
    tracer.quiet_mode = True

    revert_reason = (
        "0x08c379a0" + f"{32:064x}" + f"{4:064x}" + "nope".encode().hex().ljust(64, "0")
    )

    class FakeManager:
        def __init__(self):
            self.fail = False
            self.response = {
                "gas": 12345,
                "returnValue": "0x",
                "failed": False,
                "structLogs": [
                    {
                        "pc": 10,
                        "op": "CALL",
                        "gas": 1000,
                        "gasCost": 3,
                        "depth": 1,
                        "stack": ["0x0"],
                        "memory": ["12", "34"],
                        "storage": {"1": "2"},
                    },
                    {
                        "pc": 11,
                        "op": "RETURN",
                        "gas": 900,
                        "depth": 1,
                        "stack": [],
                    },
                ],
            }

        def request_blocking(self, method, params):
            assert method == "debug_traceCall"
            call_obj, block_param, trace_config = params
            assert call_obj["to"] == Web3.to_checksum_address(ADDR)
            assert call_obj["data"] in {"0x1234", "0x"}
            assert call_obj["gas"].startswith("0x")
            assert block_param in {"latest", "0x7"}
            if block_param == "0x7":
                assert trace_config["txIndex"] == "0x2"
            if self.fail:
                raise RuntimeError("trace call disabled")
            return self.response

    class FakeEth:
        gas_price = 20

        def __init__(self):
            self.raise_block = False
            self.raise_estimate = False
            self.base_fee = 100

        def get_block(self, block_number):
            if self.raise_block:
                raise RuntimeError("no block")
            return {"baseFeePerGas": self.base_fee}

        def estimate_gas(self, call_obj, block_number):
            if self.raise_estimate:
                raise RuntimeError("cannot estimate")
            return 21000

    class FakeW3:
        def __init__(self):
            self.eth = FakeEth()
            self.manager = FakeManager()

        def to_wei(self, value, unit):
            assert unit == "gwei"
            return int(value * 1_000_000_000)

    tracer.w3 = FakeW3()

    simulated = tracer.simulate_call_trace(
        ADDR.lower(),
        "0x0000000000000000000000000000000000000001",
        "1234",
        block=None,
        value="5",
    )
    assert simulated.success is True
    assert simulated.steps[0].memory == "1234"
    assert simulated.value == "5"

    tracer.w3.eth.base_fee = 0
    tracer.w3.eth.raise_estimate = True
    tracer.w3.manager.response = {
        "gas": 999,
        "returnValue": revert_reason,
        "failed": True,
        "structLogs": [],
    }
    failed = tracer.simulate_call_trace(
        ADDR,
        "0x0000000000000000000000000000000000000001",
        "0x1234",
        block=7,
        tx_index=2,
        value="0x10",
    )
    assert failed.success is False
    assert failed.error == "nope"

    tracer.w3.eth.raise_block = True
    tracer.w3.manager.response = {
        "failed": True,
        "returnValue": "deadbeef",
        "structLogs": [],
    }
    failed_with_data = tracer.simulate_call_trace(
        ADDR,
        "0x0000000000000000000000000000000000000001",
        "0x",
        block=None,
        value=object(),
    )
    assert failed_with_data.error == "Reverted with data: 0xdeadbeef"

    tracer.w3.manager.fail = True
    with pytest.raises(RuntimeError, match="trace call disabled"):
        tracer.simulate_call_trace(
            ADDR,
            "0x0000000000000000000000000000000000000001",
            "0x",
            block=None,
        )
    assert "debug_traceCall not available" in capsys.readouterr().out


def test_transaction_tracer_debug_info_variants(monkeypatch, tmp_path):
    tracer = TransactionTracer.__new__(TransactionTracer)
    tracer.quiet_mode = True
    tracer.ethdebug_info = None
    tracer.ethdebug_parser = SimpleNamespace(
        load_ethdebug_files=lambda path, name=None: SimpleNamespace(
            contract_name="Token",
            environment="runtime",
            instructions=[SimpleNamespace(offset=1), SimpleNamespace(offset=2)],
            get_source_info=lambda pc: ("C.sol", pc, 1),
        ),
        offset_to_line_col=lambda source, offset: (offset + 10, 0),
    )
    assert tracer.load_ethdebug_info(str(tmp_path)) == {1: (0, 11), 2: (0, 12)}

    class FakeSourceMapParser:
        def load_combined_json(self, path, contract_name=None):
            return SimpleNamespace(
                contract_name="Legacy",
                compiler_version="0.8.16",
                pc_to_instruction_index={5: 0},
                get_source_info=lambda pc: ("L.sol", 3, 1),
            )

        def offset_to_line_col(self, source, offset):
            return 22, 0

        def get_source_context(self, pc, context_lines=2):
            return {"file": "L.sol", "line": 22}

    monkeypatch.setattr(tracer_module, "SourceMapParser", FakeSourceMapParser)
    assert tracer.load_srcmap_info(str(tmp_path)) == {5: (0, 22)}

    eth_dir = tmp_path / "eth"
    eth_dir.mkdir()
    (eth_dir / "ethdebug.json").write_text("{}")
    monkeypatch.setattr(
        tracer, "load_ethdebug_info", lambda path, name=None: {"eth": 1}
    )
    assert tracer.load_debug_info_auto(str(eth_dir)) == {"eth": 1}

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "combined.json").write_text("{}")
    monkeypatch.setattr(tracer, "load_srcmap_info", lambda path, name=None: {"src": 1})
    assert tracer.load_debug_info_auto(str(src_dir)) == {"src": 1}
    with pytest.raises(FileNotFoundError):
        tracer.load_debug_info_auto(str(tmp_path / "none"))

    tracer.multi_contract_parser = SimpleNamespace(
        get_source_info_for_address=lambda address, pc: {"file": "M.sol", "line": 1},
        get_current_context=lambda: SimpleNamespace(address=OTHER_ADDR),
        contracts={
            ADDR.lower(): SimpleNamespace(ethdebug_info=True, parser=FakeParser())
        },
    )
    step = TraceStep(0, "PUSH1", 1, 1, 0, [])
    trace = TransactionTrace("0xtx", "0x1", ADDR, 0, "0x", 1, "0x", [step], True)
    assert tracer.get_source_context_for_step(step, address=ADDR)["file"] == "M.sol"
    assert tracer.get_current_contract_address(trace, 0) == OTHER_ADDR
    assert tracer.detect_executing_contract(trace, 0) == ADDR.lower()
    assert tracer.detect_executing_contract(trace, 99) is None


def test_transaction_tracer_analyze_and_print_function_trace(monkeypatch, capsys):
    tracer = TransactionTracer.__new__(TransactionTracer)
    tracer.quiet_mode = True
    tracer.rpc_url = "http://rpc"
    tracer.w3 = Web3()
    tracer.multi_contract_parser = None
    tracer.stylus_bridge = None
    tracer._stylus_traces = {}
    tracer.missing_mappings_warned = False
    tracer.function_signatures = {"0x12345678": {"name": "set(uint256)"}}
    tracer.function_abis = {
        "0x12345678": {
            "type": "function",
            "name": "set",
            "inputs": [{"name": "amount", "type": "uint256"}],
        }
    }
    tracer.function_abis_by_name = {
        "set": tracer.function_abis["0x12345678"],
        "helper": {
            "type": "function",
            "name": "helper",
            "inputs": [{"name": "x", "type": "uint256"}],
        },
    }
    tracer.ethdebug_info = SimpleNamespace(
        contract_name="Token", sources={0: "Token.sol"}
    )
    tracer.ethdebug_parser = SimpleNamespace(
        debug_info=True,
        get_source_context=lambda pc, context_lines=2: {
            "file": "Token.sol",
            "line": pc + 1,
            "content": "function helper(uint256 x) public returns (uint256) {",
        },
    )
    tracer.srcmap_info = None
    tracer.srcmap_parser = None

    monkeypatch.setattr(tracer, "lookup_function_signature", lambda selector: None)
    monkeypatch.setattr(
        tracer, "_extract_created_address", lambda step_idx, trace: OTHER_ADDR
    )

    steps = []
    for pc in range(45):
        if pc == 5:
            steps.append(TraceStep(pc, "JUMPDEST", 1000 - pc, 1, 0, ["0x2a"]))
        elif pc == 10:
            steps.append(
                TraceStep(
                    pc,
                    "CALL",
                    900,
                    2,
                    0,
                    ["0x0", "0x0", "0x04", "0x00", "0x0", OTHER_ADDR, "0x0"],
                    memory="12345678" + "00" * 32,
                )
            )
        elif pc == 11:
            steps.append(TraceStep(pc, "JUMPDEST", 850, 1, 1, ["0x07"]))
        elif pc == 12:
            steps.append(TraceStep(pc, "RETURN", 830, 1, 0, ["0x0", "0x0"]))
        elif pc == 20:
            steps.append(
                TraceStep(
                    pc,
                    "CREATE",
                    800,
                    3,
                    0,
                    ["0x06", "0x00", "0x00"],
                    memory="600160020300",
                )
            )
        elif pc == 21:
            steps.append(TraceStep(pc, "JUMPDEST", 780, 1, 1, ["0x01"]))
        elif pc == 30:
            steps.append(TraceStep(pc, "REVERT", 700, 1, 1, []))
        else:
            steps.append(TraceStep(pc, "PUSH1", 1000 - pc, 1, 0, ["0x01"]))

    trace = TransactionTrace(
        tx_hash="0xtx",
        from_addr="0x0000000000000000000000000000000000000001",
        to_addr=ADDR,
        value=5,
        input_data="0x12345678" + "00" * 31 + "07",
        gas_used=300,
        output="0x",
        steps=steps,
        success=False,
        error="reverted",
    )

    calls = tracer.analyze_function_calls(trace)
    assert calls[0].call_type == "entry"
    assert any(call.call_type == "CALL" for call in calls)
    assert any(call.call_type == "CREATE" for call in calls)
    assert any(call.name == "helper" for call in calls)
    assert any(call.caused_revert for call in calls)

    tracer.print_function_trace(trace, calls)
    assert "Function Call Trace" in capsys.readouterr().out
