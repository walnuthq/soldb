import json
from types import SimpleNamespace

from eth_abi import encode
from web3 import Web3

from soldb.core.transaction_tracer import (
    SourceMapper,
    FunctionCall,
    TraceStep,
    TransactionTrace,
    TransactionTracer,
)
from soldb.parsers.ethdebug import ETHDebugInfo, VariableLocation

ADDR = "0x00000000000000000000000000000000000000aa"
OTHER_ADDR = "0x00000000000000000000000000000000000000bb"


def make_tracer():
    tracer = TransactionTracer.__new__(TransactionTracer)
    tracer.w3 = Web3()
    tracer.quiet_mode = True
    tracer.multi_contract_parser = None
    tracer.ethdebug_info = None
    tracer.ethdebug_parser = None
    tracer.srcmap_info = None
    tracer.srcmap_parser = None
    tracer.stylus_bridge = None
    tracer.function_signatures = {}
    tracer.function_abis = {}
    tracer.function_params = {}
    tracer.function_abis_by_name = {}
    tracer.event_signatures = {}
    tracer.event_abis = {}
    tracer.to_addr = ADDR
    return tracer


def make_trace(steps):
    return TransactionTrace(
        tx_hash="0xtx",
        from_addr="0x0000000000000000000000000000000000000001",
        to_addr=ADDR,
        value=0,
        input_data="0x",
        gas_used=100,
        output="0x",
        steps=steps,
        success=True,
    )


def test_trace_step_and_address_memory_helpers():
    tracer = make_tracer()
    long_value = "0x" + "12" * 32
    assert TraceStep(0, "PUSH1", 1, 1, 0, []).format_stack() == "[empty]"
    assert (
        "0x1212..."
        in TraceStep(
            0, "PUSH1", 1, 1, 0, [long_value, "0x2", "0x3", "0x4"]
        ).format_stack()
    )

    assert tracer.extract_address_from_stack("0x" + "00" * 12 + "11" * 20).endswith(
        "1111"
    )
    memory = "00" * 12 + "22" * 20
    assert tracer.extract_address_from_memory(memory, 0).endswith("2222")
    assert tracer.extract_address_from_memory("00", 1) is None

    step = TraceStep(
        0,
        "CALL",
        1,
        1,
        1,
        ["0x0", "0x0", "0x04", "0x00", "0x0", "0x0", "0x0"],
        memory="12345678",
    )
    assert tracer.extract_calldata_from_step(step) == "0x12345678"
    assert (
        tracer.extract_calldata_from_step(TraceStep(0, "STATICCALL", 1, 1, 1, []))
        is None
    )
    assert tracer.is_likely_memory_offset("0xff")
    assert not tracer.is_likely_memory_offset("0x" + "ff" * 20)
    assert tracer.format_address_display("") == "<unknown>"
    assert tracer.format_address_display(OTHER_ADDR) == "0x0000...00bb"
    assert tracer.format_address_display(OTHER_ADDR, short=False) == OTHER_ADDR


def test_abi_decoding_and_value_extraction(tmp_path):
    tracer = make_tracer()
    tuple_input = {
        "type": "tuple[]",
        "components": [{"type": "uint256"}, {"type": "address"}],
    }
    assert tracer.format_abi_type(tuple_input) == "(uint256,address)[]"

    selector = "0x12345678"
    tracer.function_abis[selector] = {
        "type": "function",
        "name": "set",
        "inputs": [
            {"name": "amount", "type": "uint256"},
            {"name": "recipient", "type": "address"},
        ],
    }
    encoded = encode(["uint256", "address"], [7, OTHER_ADDR]).hex()
    assert tracer.decode_function_parameters(selector, selector + encoded) == [
        ("amount", 7),
        ("recipient", Web3.to_checksum_address(OTHER_ADDR)),
    ]
    assert tracer.decode_function_parameters("0xdeadbeef", "0xdeadbeef" + "0" * 64) == [
        ("arguments", "0x" + "0" * 64)
    ]

    assert tracer.decode_value("0x0a", "uint256") == 10
    assert tracer.decode_value("0xff", "int8") == -1
    assert tracer.decode_value("0x01", "bool") is True
    assert tracer.decode_value("0x1234", "bytes2") == "0x1234"
    assert tracer.decode_value("0x20", "string") == "<string at 0x20>"

    string_memory = "0" * 63 + "2" + "6869"
    assert tracer.extract_from_memory(string_memory, 0, "string") == "hi"
    assert tracer.extract_from_memory("aabbccdd", 0, "bytes2") == "0xaabb"
    assert tracer.extract_from_storage({"0x1": "0x0a"}, 1, "uint256") == 10
    assert tracer.extract_from_storage({"2": "0x01"}, 2, "bool") is True
    assert tracer.extract_from_storage({}, 3, "uint256") is None

    formatted = tracer.format_tuple_value(
        (7, OTHER_ADDR),
        [{"name": "n", "type": "uint256"}, {"name": "a", "type": "address"}],
    )
    assert "n[uint256]=7" in formatted
    assert Web3.to_checksum_address(OTHER_ADDR) in formatted

    abi_path = tmp_path / "Contract.abi"
    abi_path.write_text(
        json.dumps(
            [
                tracer.function_abis[selector],
                {"type": "event", "name": "Updated", "inputs": []},
            ]
        )
    )
    tracer.load_abi(str(abi_path))
    assert any(
        sig["name"].startswith("set(") for sig in tracer.function_signatures.values()
    )
    assert any(sig == "Updated()" for sig in tracer.event_signatures.values())


def test_call_pattern_ethdebug_parameter_and_call_processing(monkeypatch):
    tracer = make_tracer()
    trace = make_trace(
        [
            TraceStep(0, "JUMPDEST", 100, 1, 0, []),
            TraceStep(1, "CALLDATALOAD", 99, 1, 0, []),
            TraceStep(5, "JUMPDEST", 98, 1, 0, ["0x2a"], storage={"0x1": "0x0b"}),
        ]
    )
    pattern = tracer.analyze_calling_pattern(trace, 2, "f")
    assert pattern["call_type"] == "external"
    assert pattern["stack_depth"] == 1

    tracer.ethdebug_info = ETHDebugInfo(
        compilation={},
        contract_name="Contract",
        environment="runtime",
        instructions=[],
        sources={},
        variable_locations={
            5: [
                VariableLocation("amount", "uint256", "stack", 0, (5, 5)),
                VariableLocation("stored", "uint256", "storage", 1, (5, 5)),
            ]
        },
    )
    assert (
        tracer.find_parameter_value_from_ethdebug(trace, 2, "amount", "uint256") == 42
    )
    assert (
        tracer.find_parameter_value_from_ethdebug(trace, 2, "stored", "uint256") == 11
    )
    assert (
        tracer.find_parameter_value_from_ethdebug(trace, 99, "amount", "uint256")
        is None
    )

    monkeypatch.setattr(
        tracer,
        "lookup_function_signature",
        lambda selector: "transfer(address,uint256)",
    )
    call_step = TraceStep(
        10,
        "CALL",
        100,
        1,
        0,
        ["0x0", "0x0", "0x04", "0x00", "0x0", OTHER_ADDR, "0x0"],
        memory="a9059cbb" + "00" * 32,
    )
    call = tracer._process_external_call(call_step, 10, ADDR, 0)
    assert call.call_type == "CALL"
    assert "transfer(address,uint256)" in call.name

    create_step = TraceStep(
        11,
        "CREATE2",
        100,
        1,
        0,
        ["0x1234", "0x06", "0x00", "0x00"],
        memory="600160020300",
    )
    monkeypatch.setattr(
        tracer, "_extract_created_address", lambda idx, tx_trace: OTHER_ADDR
    )
    created = tracer._process_create_call(create_step, 11, ADDR, 0, trace)
    assert created.call_type == "CREATE2"
    assert created.contract_address == OTHER_ADDR
    assert ("init_code", "0x600160020300...") in created.args


def test_function_boundary_return_and_signature_lookup(monkeypatch, capsys):
    tracer = make_tracer()
    trace = make_trace(
        [
            TraceStep(0, "PUSH1", 100, 1, 0, []),
            TraceStep(1, "CALL", 99, 1, 0, []),
            TraceStep(
                2,
                "RETURN",
                98,
                1,
                1,
                ["0x0", "0x20"],
                memory=f"{7:064x}",
            ),
            TraceStep(3, "STOP", 97, 1, 1, []),
        ]
    )

    source_lines = {
        10: {
            "content": "function set(uint256 amount, address user) public {",
            "line": 4,
        },
        20: {"content": "constructor(uint256 supply) {", "line": 8},
        30: {"content": "receive() external payable {", "line": 12},
        40: {"content": "fallback(bytes calldata data) external {", "line": 16},
        50: {"content": "function set(uint256 amount) public {", "line": 20},
        60: None,
    }
    tracer.ethdebug_info = SimpleNamespace(
        instructions=[
            SimpleNamespace(offset=10, context=True),
            SimpleNamespace(offset=20, context=True),
            SimpleNamespace(offset=30, context=True),
            SimpleNamespace(offset=40, context=True),
            SimpleNamespace(offset=50, context=True),
            SimpleNamespace(offset=60, context=False),
        ]
    )
    tracer.ethdebug_parser = SimpleNamespace(
        get_source_context=lambda pc, context_lines=5: source_lines[pc]
    )
    boundaries = tracer.identify_function_boundaries_from_ethdebug(trace)
    assert boundaries[10]["name"] == "set"
    assert boundaries[10]["params"] == [
        {"type": "uint256", "name": "amount"},
        {"type": "address", "name": "user"},
    ]
    assert boundaries[20]["name"] == "constructor"
    assert boundaries[30]["name"] == "receive"
    assert boundaries[40]["name"] == "fallback"
    assert 50 not in boundaries

    assert tracer.detect_call_type(trace, 99) == "internal"
    assert tracer.detect_call_type(trace, 1) == "CALL"
    assert tracer.detect_call_type(trace, 2) == "CALL"
    assert (
        tracer.detect_call_type(make_trace([TraceStep(0, "CREATE2", 1, 1, 0, [])]), 0)
        == "CREATE2"
    )

    selector = "0xabcdef01"
    tracer.function_abis[selector] = {
        "name": "answer",
        "outputs": [{"name": "value", "type": "uint256"}],
    }
    assert tracer.extract_return_value(trace, 2, "answer", selector) == 7
    assert (
        tracer.extract_return_value(
            make_trace(
                [
                    TraceStep(
                        0,
                        "RETURN",
                        1,
                        1,
                        0,
                        ["0x0", "0x02"],
                        memory="aabb",
                    )
                ]
            ),
            0,
            "raw",
        )
        == "0xaabb"
    )
    tracer.function_abis["0xvoid"] = {"name": "void", "outputs": []}
    assert tracer.extract_return_value(trace, 2, "void", "0xvoid") is None
    assert tracer.extract_return_value(trace, 99, "answer") is None
    assert (
        tracer.extract_return_value(
            make_trace([TraceStep(0, "RETURN", 1, 1, 0, ["nothex", "0x20"])]),
            0,
            "answer",
        )
        is None
    )
    assert "Failed to extract return value" in capsys.readouterr().err

    class Response:
        def __init__(self, status_code, data):
            self.status_code = status_code
            self._data = data

        def json(self):
            return self._data

    calls = []

    def fake_get(url, timeout=5):
        calls.append(url)
        if "openchain" in url:
            return Response(
                200,
                {
                    "result": {
                        "function": {
                            "0x12345678": [{"name": "set(uint256)"}],
                        }
                    }
                },
            )
        return Response(
            200,
            {
                "results": [
                    {"id": 20, "text_signature": "newer()"},
                    {"id": 1, "text_signature": "older()"},
                ]
            },
        )

    monkeypatch.setattr("soldb.core.transaction_tracer.requests.get", fake_get)
    assert tracer.lookup_function_signature("0x12345678") == "set(uint256)"
    monkeypatch.setattr(tracer, "_lookup_openchain", lambda selector: None)
    assert tracer.lookup_function_signature("12345678") == "older()"
    monkeypatch.setattr(
        "soldb.core.transaction_tracer.requests.get",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("offline")),
    )
    assert tracer._lookup_4byte("12345678") is None
    assert tracer._lookup_openchain("12345678") is None


def test_context_lookup_and_source_mapper(tmp_path):
    tracer = make_tracer()
    step = TraceStep(0, "PUSH1", 100, 1, 0, [])
    trace = make_trace([step])

    tracer.ethdebug_parser = SimpleNamespace(
        get_source_context=lambda pc, context_lines=2: {
            "file": "C.sol",
            "line": 2,
            "column": 5,
        }
    )
    tracer.ethdebug_info = object()
    assert tracer.get_source_context_for_step(step)["line"] == 2
    assert tracer.get_current_contract_address(trace, 0) == ADDR

    tracer.ethdebug_info = None
    tracer.srcmap_parser = SimpleNamespace(
        get_source_context=lambda pc, context_lines=2: {"file": "Legacy.sol", "line": 3}
    )
    tracer.srcmap_info = object()
    assert tracer.get_source_context_for_step(step)["file"] == "Legacy.sol"

    assert (
        tracer._extract_function_name("function increment(uint256 amount) public")
        == "increment"
    )
    assert tracer._extract_function_name("constructor()") == "constructor"
    assert tracer._extract_function_name("fallback() external") == "fallback"
    assert tracer._extract_function_name("receive() external payable") == "receive"
    assert tracer._extract_function_name("uint256 value;") is None

    assert (
        tracer._extract_memory_slice(
            TraceStep(0, "CREATE", 1, 1, 0, [], memory="aabbcc"), 1, 2
        )
        == "bbcc"
    )
    assert (
        tracer._extract_memory_slice(
            TraceStep(0, "CREATE", 1, 1, 0, [], memory=None), 0, 1
        )
        is None
    )

    contract_info = SimpleNamespace(
        ethdebug_info=SimpleNamespace(instructions=[SimpleNamespace(offset=0)]),
        parser=SimpleNamespace(
            get_source_context=lambda pc, context_lines=5: {
                "content": "contract Contract {",
                "line": 4,
            }
        ),
    )
    assert tracer._find_contract_definition_line(contract_info) == 4

    source_file = tmp_path / "C.sol"
    source_file.write_text("contract C {\n    function f() public {}\n}\n")
    mapper = SourceMapper(str(source_file), "0:10:0:-;13:8:0:-")
    assert mapper.get_source_line(0) == "contract C {"
    assert mapper.get_source_line(1).strip().startswith("function f")
    assert mapper.get_source_line(99) is None
