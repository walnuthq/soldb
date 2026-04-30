from collections import namedtuple
from types import SimpleNamespace

from eth_abi import encode
from hexbytes import HexBytes

from soldb.core.transaction_tracer import TraceStep, TransactionTrace
from soldb.utils import helpers

EVENT_HASH = "0x" + "11" * 32
UNKNOWN_EVENT_HASH_BYTES = bytes.fromhex("22" * 32)
ADDR = "0x00000000000000000000000000000000000000aa"
OTHER_ADDR = "0x00000000000000000000000000000000000000bb"


class FakeContractRegistry:
    def get_contract_at_address(self, address):
        return (
            SimpleNamespace(name="TestContract")
            if address.lower() == ADDR.lower()
            else None
        )


def make_tracer():
    return SimpleNamespace(
        event_abis={
            EVENT_HASH: {
                "name": "BalanceUpdated",
                "inputs": [
                    {"name": "account", "type": "address", "indexed": True},
                    {"name": "amount", "type": "uint256", "indexed": False},
                    {"name": "active", "type": "bool", "indexed": False},
                ],
            }
        },
        event_signatures={EVENT_HASH: "BalanceUpdated(address,uint256,bool)"},
        multi_contract_parser=FakeContractRegistry(),
    )


def topic_address(address):
    return "0x" + address[2:].rjust(64, "0")


def test_format_error_json_and_exception_message():
    assert helpers.format_error_json("missing", "NotFound", tx="0x1") == {
        "soldbFailed": "missing",
        "error": {"message": "missing", "type": "NotFound", "tx": "0x1"},
    }
    assert (
        helpers.format_exception_message(Exception({"message": "rpc failed"}))
        == "rpc failed"
    )
    assert helpers.format_exception_message(Exception("plain")) == "plain"
    assert helpers.format_exception_message(Exception(7)) == "7"
    assert helpers.format_exception_message(Exception()) == ""


def test_decode_event_log_with_known_abi_and_fallback_errors():
    tracer = make_tracer()
    log = {
        "address": ADDR,
        "topics": [EVENT_HASH, topic_address(OTHER_ADDR)],
        "data": "0x" + encode(["uint256", "bool"], [123, True]).hex(),
    }

    decoded = helpers.decode_event_log(tracer, log)
    assert decoded["decoded"]["event"] == "BalanceUpdated"
    assert decoded["decoded"]["args"]["account"]["value"] == OTHER_ADDR.lower()
    assert decoded["decoded"]["args"]["amount"]["value"] == 123
    assert decoded["decoded"]["args"]["active"]["value"] is True

    bytes_topic_log = {
        "address": ADDR,
        "topics": [
            bytes.fromhex(EVENT_HASH[2:]),
            bytes.fromhex(OTHER_ADDR[2:].rjust(64, "0")),
        ],
        "data": encode(["uint256", "bool"], [5, False]),
    }
    decoded_bytes = helpers.decode_event_log(tracer, bytes_topic_log)
    assert decoded_bytes["decoded"]["args"]["amount"]["value"] == 5
    assert decoded_bytes["decoded"]["args"]["active"]["value"] is False

    bad_data_log = {**log, "data": "0xdead"}
    decoded_bad_data = helpers.decode_event_log(tracer, bad_data_log)
    assert decoded_bad_data["decoded"]["args"]["amount"]["value"].startswith(
        "decode_error:"
    )

    broken_tracer = SimpleNamespace(
        event_abis={EVENT_HASH: {"name": "Broken"}},
        event_signatures={EVENT_HASH: "Broken()"},
    )
    decoded_broken = helpers.decode_event_log(broken_tracer, log)
    assert decoded_broken["decoded"]["error"].startswith("Failed to decode event:")

    assert (
        helpers.decode_event_log(tracer, {"address": ADDR, "topics": [], "data": "0x"})[
            "decoded"
        ]
        is None
    )


def test_decode_unknown_event_and_serialize_events(monkeypatch):
    class Response:
        def __init__(self, payload):
            self.payload = payload

        def json(self):
            return self.payload

    monkeypatch.setattr(
        helpers.requests,
        "get",
        lambda url, timeout: Response(
            {"results": [{"text_signature": "Mystery(uint256)"}]}
        ),
    )

    tracer = make_tracer()
    unknown_log = {
        "address": ADDR,
        "topics": [UNKNOWN_EVENT_HASH_BYTES],
        "data": (31 * b"\x00") + b"\x07",
    }
    decoded_unknown = helpers.decode_event_log(tracer, unknown_log)
    assert decoded_unknown["decoded"]["event"] == "Unknown"
    assert decoded_unknown["decoded"]["event_name"] == "Mystery"
    assert decoded_unknown["decoded"]["data"] == "0x7"

    receipt = {
        "transactionHash": HexBytes("0x" + "ab" * 32),
        "logs": [
            {
                "address": ADDR,
                "topics": [EVENT_HASH, topic_address(OTHER_ADDR)],
                "data": "0x" + encode(["uint256", "bool"], [44, False]).hex(),
            },
            unknown_log,
            {"address": OTHER_ADDR, "topics": [], "data": "abcd"},
        ],
    }
    events = helpers.serialize_events_to_json(tracer, receipt)

    assert events["transaction_hash"].startswith("0xabab")
    assert events["total_events"] == 3
    assert events["events"][0]["event"] == "BalanceUpdated"
    assert events["events"][0]["contract_name"] == "TestContract"
    assert events["events"][0]["datas"][0] == {
        "name": "account",
        "type": "address",
        "value": OTHER_ADDR.lower(),
    }
    assert events["events"][1]["event_name"] == "Mystery"
    assert events["events"][1]["contract_name"] == "TestContract"
    assert events["events"][2]["datas"] == [
        {"name": None, "type": "hex", "value": "0xabcd"}
    ]

    assert (
        helpers.print_contracts_events(tracer, receipt, json_output=True)[
            "total_events"
        ]
        == 3
    )


def test_event_printing_and_serialization_branches(monkeypatch, capsys):
    tracer = make_tracer()
    known_log = {
        "address": ADDR,
        "topics": [EVENT_HASH, topic_address(OTHER_ADDR)],
        "data": "0x" + encode(["uint256", "bool"], [11, True]).hex(),
    }
    unknown_log = {
        "address": ADDR,
        "topics": [UNKNOWN_EVENT_HASH_BYTES],
        "data": (32 * b"\x00") + (31 * b"\x00") + b"\x09",
    }

    monkeypatch.setattr(
        helpers.requests, "get", lambda url, timeout: SimpleNamespace(json=lambda: {})
    )
    helpers.print_contracts_events(tracer, {"logs": [known_log, unknown_log]})
    printed = capsys.readouterr().out
    assert "BalanceUpdated(address,uint256,bool)" in printed
    assert "TestContract" in printed
    assert "Event #2:" in printed

    broken_tracer = SimpleNamespace(
        event_abis={EVENT_HASH: {"name": "Broken"}},
        event_signatures={EVENT_HASH: "Broken()"},
        multi_contract_parser=None,
    )
    helpers.print_contracts_events(broken_tracer, {"logs": [known_log]})
    assert "Failed to decode event" in capsys.readouterr().out

    original_decode = helpers.decode_event_log

    def fake_decode(tracer, log):
        case = log["case"]
        if case == "bytes_string":
            return {
                "address": ADDR,
                "topics": [],
                "data": "0x",
                "decoded": {
                    "event": "Message",
                    "signature": "Message(string,bytes)",
                    "args": {
                        "message": {"type": "string", "value": b"hello\x00\x00"},
                        "blob": {"type": "bytes", "value": b"\x01\x02"},
                        "plain": "raw",
                    },
                },
            }
        if case == "error":
            return {
                "address": ADDR,
                "topics": [],
                "data": "0x",
                "decoded": {"error": "decode failed"},
            }
        return {
            "address": ADDR,
            "topics": [],
            "data": "0x" + "ab" * 32,
            "decoded": None,
        }

    monkeypatch.setattr(helpers, "decode_event_log", fake_decode)
    serialized = helpers.serialize_events_to_json(
        tracer,
        {
            "transactionHash": "0xtx",
            "logs": [
                {"case": "bytes_string", "address": ADDR},
                {"case": "error", "address": ADDR},
                {"case": "raw", "address": ADDR},
            ],
        },
    )
    assert serialized["events"][0]["datas"] == [
        {"name": "message", "type": "string", "value": "hello"},
        {"name": "blob", "type": "bytes", "value": "0xb'\\x01\\x02'"},
        {"name": "plain", "type": "unknown", "value": "raw"},
    ]
    assert serialized["events"][1]["error"] == "decode failed"
    assert serialized["events"][2]["datas"][0]["value"] == "0x" + "ab" * 32
    monkeypatch.setattr(helpers, "decode_event_log", original_decode)


def test_decode_event_log_indexed_bool_and_decode_error_paths(monkeypatch):
    bool_hash = "0x" + "33" * 32
    tracer = SimpleNamespace(
        event_abis={
            bool_hash: {
                "name": "Flag",
                "inputs": [
                    {"name": "enabled", "type": "bool", "indexed": True},
                    {"name": "note", "type": "bytes32", "indexed": True},
                ],
            }
        },
        event_signatures={bool_hash: "Flag(bool,bytes32)"},
        multi_contract_parser=None,
    )
    decoded = helpers.decode_event_log(
        tracer,
        {
            "address": ADDR,
            "topics": [
                bool_hash,
                bytearray((31 * b"\x00") + b"\x01"),
                "0x" + "aa" * 32,
            ],
            "data": "0x",
        },
    )
    assert decoded["decoded"]["args"]["enabled"]["value"] is True
    assert decoded["decoded"]["args"]["note"]["value"] == "0x" + "aa" * 32

    monkeypatch.setattr(
        helpers.requests,
        "get",
        lambda url, timeout: SimpleNamespace(
            json=lambda: {"text_signature": ["Named(uint256,uint256)"]}
        ),
    )
    unknown_non_aligned = helpers.decode_event_log(
        make_tracer(),
        {"address": ADDR, "topics": [UNKNOWN_EVENT_HASH_BYTES], "data": b"\x01\x02"},
    )
    assert unknown_non_aligned["decoded"]["data"] == "0102"


def test_hex_conversion_and_print_helpers(capsys):
    Item = namedtuple("Item", ["payload"])
    converted = helpers._convert_hexbytes_to_string(
        {
            "hex": HexBytes("0x1234"),
            "bytes": b"\xab",
            "tuple": (HexBytes("0xcd"),),
            "named": Item(HexBytes("0xef")),
            "object": SimpleNamespace(value=HexBytes("0x42")),
            "iterable": (x for x in [HexBytes("0x01"), HexBytes("0x02")]),
        }
    )
    assert converted["hex"] == "0x1234"
    assert converted["bytes"] == "0xab"
    assert converted["tuple"] == ("0xcd",)
    assert converted["named"] == ("0xef",)
    assert converted["object"]["value"] == "0x42"
    assert converted["iterable"] == ["0x01", "0x02"]

    tracer = SimpleNamespace(
        rpc_url="http://rpc",
        multi_contract_parser=None,
        function_signatures={"0x12345678": {"name": "increment(uint256)"}},
        extract_address_from_stack=lambda value: OTHER_ADDR,
        extract_calldata_from_step=lambda step: "0x12345678" + "00" * 32,
    )
    trace = TransactionTrace(
        tx_hash="0xtx",
        from_addr="0x1",
        to_addr=ADDR,
        value=0,
        input_data="0x",
        gas_used=0,
        output="0x",
        steps=[
            TraceStep(
                0,
                "CALL",
                99,
                1,
                0,
                ["0x0", "0x0", "0x0", "0x0", "0x0", OTHER_ADDR, "0x0"],
            )
        ],
        success=True,
    )
    helpers.print_contracts_in_transaction(tracer, trace)
    assert "increment(uint256)" in capsys.readouterr().out

    no_call_trace = TransactionTrace(
        tx_hash="0xtx",
        from_addr="0x1",
        to_addr=ADDR,
        value=0,
        input_data="0x",
        gas_used=0,
        output="0x",
        steps=[TraceStep(0, "PUSH1", 99, 1, 0, [])],
        success=True,
    )
    helpers.print_contracts_in_transaction(tracer, no_call_trace)
    assert "No contract calls detected" in capsys.readouterr().out

    helpers.print_contracts_events(make_tracer(), {"logs": []})
    assert "No events emitted" in capsys.readouterr().out

    named_tracer = SimpleNamespace(
        rpc_url="http://rpc",
        function_signatures={},
        multi_contract_parser=SimpleNamespace(
            get_contract_at_address=lambda address: SimpleNamespace(name="KnownTarget")
        ),
        extract_address_from_stack=lambda value: OTHER_ADDR,
        extract_calldata_from_step=lambda step: None,
    )
    helpers.print_contracts_in_transaction(named_tracer, trace)
    assert "KnownTarget" in capsys.readouterr().out
