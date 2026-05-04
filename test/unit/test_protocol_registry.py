import json

from soldb.cross_env.contract_registry import ContractRegistry, detect_stylus_bytecode
from soldb.cross_env.protocol import (
    BridgeMessage,
    CallArgument,
    ContractInfo,
    CrossEnvCall,
    CrossEnvTrace,
    Environment,
    MessageType,
    SourceLocation,
    TraceRequest,
    TraceResponse,
)


def test_protocol_round_trips_nested_trace():
    location = SourceLocation(file="Counter.sol", line=12, column=4)
    arg = CallArgument(name="amount", type="uint256", value="7")
    child = CrossEnvCall(
        call_id=2,
        parent_call_id=1,
        environment=Environment.STYLUS.value,
        contract_address="0x2222",
        function_name="stylus_increment",
        function_selector="0x12345678",
        function_signature="stylus_increment(uint256)",
        source_location=location,
        args=[arg],
        return_data="0x01",
        return_value="1",
        gas_used=44,
        success=False,
        error="boom",
        call_type="delegatecall",
        value=5,
        cross_env_ref="trace:2",
    )
    root = CrossEnvCall(
        call_id=1,
        parent_call_id=None,
        environment=Environment.EVM.value,
        contract_address="0x1111",
        function_name="increment",
        children=[child],
    )
    trace = CrossEnvTrace(
        trace_id="trace",
        transaction_hash="0xabc",
        root_call=root,
        calls=[root, child],
        from_address="0xaaa",
        to_address="0xbbb",
        value=9,
        gas_used=123,
        success=False,
        error="revert",
    )

    data = trace.to_dict()
    assert data["root_call"]["children"][0]["source_location"] == {
        "file": "Counter.sol",
        "line": 12,
        "column": 4,
    }
    restored = CrossEnvTrace.from_json(trace.to_json())
    assert restored.calls[1].args[0].value == "7"
    assert restored.root_call.children[0].error == "boom"


def test_protocol_request_response_message_defaults():
    request = TraceRequest.from_dict(
        {
            "request_id": "req",
            "target_address": "0x1",
            "calldata": "0xabcd",
            "block_number": 5,
        }
    )
    assert request.to_dict()["value"] == 0
    assert request.source_environment == "evm"

    trace = CrossEnvTrace(trace_id="trace")
    response = TraceResponse.from_dict(
        {
            "request_id": "req",
            "status": "success",
            "trace": trace.to_dict(),
            "error_message": "ignored",
            "error_code": "E",
        }
    )
    assert response.trace.trace_id == "trace"
    assert response.to_dict()["error_code"] == "E"

    message = BridgeMessage(MessageType.HEALTH_CHECK.value, {"ok": True})
    assert BridgeMessage.from_json(message.to_json()).payload == {"ok": True}


def test_contract_registry_formats_and_persists(tmp_path):
    registry = ContractRegistry()
    evm = ContractInfo(address="ABCDEF", environment="evm", name="EVM", debug_dir="debug")
    stylus = ContractInfo(address="0x1234", environment=Environment.STYLUS, name="Stylus", lib_path="lib.so")

    registry.register(evm)
    registry.register(stylus)

    assert registry.is_registered("0xabcdef")
    assert registry.is_evm("abcdef")
    assert registry.is_stylus("1234")
    assert registry.get_environment("0x1234") == Environment.STYLUS
    assert [c.name for c in registry.get_evm_contracts()] == ["EVM"]
    assert [c.name for c in registry.get_stylus_contracts()] == ["Stylus"]

    saved = tmp_path / "registry.json"
    registry.save(str(saved))
    loaded = ContractRegistry.load(str(saved))
    assert loaded.get("abcdef").address == "0xabcdef"

    config = tmp_path / "contracts.json"
    config.write_text(
        json.dumps(
            {
                "contracts": {
                    "0xbeef": {"environment": "stylus", "name": "Beef", "project_path": "proj"}
                }
            }
        )
    )
    assert registry.load_from_file(str(config)) == 1
    assert registry.unregister("0xbeef").name == "Beef"
    registry.clear()
    assert registry.get_all_contracts() == []


def test_detect_stylus_bytecode_patterns():
    assert not detect_stylus_bytecode(b"")
    assert not detect_stylus_bytecode(b"\x01\x02\x03")
    assert detect_stylus_bytecode(bytes.fromhex("ef0001") + b"payload")
    assert detect_stylus_bytecode(b"\x00asm" + b"\x00" * 10)


def test_detect_stylus_bytecode_returns_false_for_unrelated_payload():
    # 4-byte minimum so we get past the length guard, but neither the WASM
    # marker nor the EOF prefix is present — must fall through to False.
    assert detect_stylus_bytecode(b"\x60\x80\x60\x40" * 8) is False


def test_get_environment_returns_none_for_unregistered_address():
    registry = ContractRegistry()
    assert registry.get_environment("0xdeadbeef") is None


def test_unregister_unknown_address_returns_none():
    registry = ContractRegistry()
    assert registry.unregister("0xdeadbeef") is None


def test_register_moves_contract_between_environment_sets():
    registry = ContractRegistry()
    addr = "0xabc"
    registry.register(ContractInfo(address=addr, environment="evm", name="X"))
    assert registry.is_evm(addr)
    assert not registry.is_stylus(addr)

    # Re-registering as Stylus must drop the EVM set entry, not duplicate it.
    registry.register(ContractInfo(address=addr, environment=Environment.STYLUS, name="X"))
    assert registry.is_stylus(addr)
    assert not registry.is_evm(addr)

    # And back again.
    registry.register(ContractInfo(address=addr, environment=Environment.EVM, name="X"))
    assert registry.is_evm(addr)
    assert not registry.is_stylus(addr)


def test_load_from_file_supports_list_format(tmp_path):
    registry = ContractRegistry()
    config = tmp_path / "list.json"
    config.write_text(
        json.dumps(
            {
                "contracts": [
                    {"address": "0xaaa", "environment": "evm", "name": "A", "debug_dir": "d"},
                    {"address": "0xbbb", "environment": "stylus", "name": "B", "lib_path": "l"},
                ]
            }
        )
    )
    assert registry.load_from_file(str(config)) == 2
    assert registry.is_evm("0xaaa")
    assert registry.is_stylus("0xbbb")


def test_contract_info_round_trip_preserves_optional_fields():
    info = ContractInfo(
        address="0x1",
        environment="stylus",
        name="S",
        lib_path="lib.so",
        project_path="proj",
        compiler_version="1.0",
        source_files=["a.rs", "b.rs"],
    )
    restored = ContractInfo.from_dict(info.to_dict())
    assert restored == info
    # Default ContractInfo omits optional fields entirely from to_dict().
    minimal = ContractInfo(address="0x2", environment="evm", name="E")
    assert minimal.to_dict() == {"address": "0x2", "environment": "evm", "name": "E"}
