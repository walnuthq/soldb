import json
import logging
from types import SimpleNamespace

import pytest

from soldb.cli import common
from soldb.parsers.abi import match_abi_types, match_single_type, parse_signature, parse_tuple_arg
from soldb.utils import exceptions
from soldb.utils.logging import TRACE, ColoredFormatter, SoldbLogger, get_logger, setup_logging


def test_abi_parsing_and_matching():
    assert match_abi_types(["uint256", "(address,uint256)", "uint256[]"], ["uint256", "tuple", "uint256[]"])
    assert not match_abi_types(["uint256"], ["uint256", "address"])
    assert match_single_type("(uint256)", "tuple")
    assert match_single_type("tuple(uint256)", "tuple")
    assert not match_single_type("address", "uint256")
    assert parse_signature("transfer(address,uint256)") == ("transfer", ["address", "uint256"])
    assert parse_signature("foo((uint256,address),uint8[])") == ("foo", ["(uint256,address)", "uint8[]"])
    assert parse_signature("not a signature") == ("", [])

    abi_input = {
        "type": "tuple",
        "components": [
            {"type": "uint256"},
            {"type": "tuple", "components": [{"type": "address"}]},
            {"type": "tuple[]", "components": [{"type": "uint256"}]},
        ],
    }
    assert parse_tuple_arg([1, ["0xabc"], [[2], [3]]], abi_input) == (1, ("0xabc",), [(2,), (3,)])
    with pytest.raises(ValueError):
        parse_tuple_arg("bad", abi_input)


def test_exception_types_and_formatting():
    errors = [
        exceptions.RPCConnectionError("no rpc", rpc_url="http://x"),
        exceptions.TransactionError("bad tx", tx_hash="0x1"),
        exceptions.TransactionNotFoundError("0x2"),
        exceptions.DebugTraceUnavailableError("0x3", "disabled"),
        exceptions.ContractError("bad contract", contract_address="0x4"),
        exceptions.ContractNotFoundError("0x5"),
        exceptions.InsufficientFundsError("0x6", 1, 2),
        exceptions.ETHDebugError("bad debug", debug_dir="out"),
        exceptions.ETHDebugNotFoundError("out", compiler_version="0.8.16"),
        exceptions.InvalidETHDebugSpecError("spec", "reason"),
        exceptions.CompilerError("compile", compiler_version="0.8.31"),
        exceptions.UnsupportedCompilerVersionError("0.8.16", "0.8.29"),
        exceptions.ParseError("parse", source="file"),
        exceptions.ABIParseError("abi"),
        exceptions.SourceMapParseError("srcmap"),
    ]

    for err in errors:
        data = err.to_dict()
        assert data["error"] is True
        assert data["message"]
        assert json.loads(err.to_json())["type"] == err.error_code
        assert exceptions.format_error(err, json_mode=True)

    assert exceptions.format_error(ValueError("plain"), json_mode=True)
    assert "plain" in exceptions.format_error(ValueError("plain"), json_mode=False)
    assert exceptions.format_error_json("msg", "Kind", extra=1)["extra"] == 1
    assert exceptions.format_exception_message(Exception({"message": "rpc message"})) == "rpc message"
    assert exceptions.format_exception_message(Exception(7)) == "7"
    assert exceptions.ConnectionError is exceptions.RPCConnectionError


def test_logging_setup_and_helpers(tmp_path):
    record = logging.LogRecord("soldb", logging.INFO, __file__, 1, "hello", (), None)
    assert "INFO" in ColoredFormatter("%(levelname)s:%(message)s", use_colors=False).format(record)

    logger = setup_logging(quiet=False, debug=True, use_colors=False)
    assert logger.level == logging.DEBUG
    assert logger.handlers
    quiet_logger = setup_logging(quiet=True, verbose=True)
    assert quiet_logger.level == TRACE
    assert not quiet_logger.handlers

    log_file = tmp_path / "soldb.log"
    file_logger = setup_logging(log_file=str(log_file), use_colors=False)
    file_logger.info("written")
    for handler in file_logger.handlers:
        handler.flush()
    assert "written" in log_file.read_text()

    child = get_logger("child")
    assert child.name == "soldb.child"
    assert isinstance(logging.getLogger("soldb"), SoldbLogger)
    logging.getLogger("soldb").trace("trace message")


def test_cli_common_helpers(tmp_path, monkeypatch, capsys):
    args = SimpleNamespace(ethdebug_dir="out", multi_contract=False, contracts=None)
    assert common.get_ethdebug_dirs(args) == ["out"]
    args.ethdebug_dir = ["one", "two"]
    assert common.get_ethdebug_dirs(args) == ["one", "two"]
    assert common.is_multi_contract_mode(args)
    args.ethdebug_dir = []
    args.contracts = "contracts.json"
    assert common.is_multi_contract_mode(args)

    assert common.normalize_address("0000000000000000000000000000000000000001").startswith("0x")
    with pytest.raises(ValueError):
        common.normalize_address("")
    with pytest.raises(ValueError):
        common.normalize_address("not-an-address")

    class W3:
        def to_wei(self, value, unit):
            assert unit == "ether"
            return int(value * 10**18)

    assert common.parse_value_arg("", W3()) == 0
    assert common.parse_value_arg("10", W3()) == 10
    assert common.parse_value_arg("0.5ether", W3()) == 5 * 10**17
    with pytest.raises(ValueError):
        common.parse_value_arg("bad", W3())

    class Tracer:
        def __init__(self, deployed):
            self.deployed = deployed

        def is_contract_deployed(self, address):
            return self.deployed

    assert not common.validate_contract_address("bad", Tracer(True))
    assert not common.validate_contract_address("0x0000000000000000000000000000000000000001", Tracer(False), json_mode=True)
    assert common.validate_contract_address("0x0000000000000000000000000000000000000001", Tracer(True))
    common.print_connection_info("http://rpc")
    common.print_connection_info("http://rpc", json_mode=True)
    assert common.handle_command_error(ValueError("oops"), exit_code=3) == 3

    debug_dir = tmp_path / "debug"
    debug_dir.mkdir()
    (debug_dir / "deployment.json").write_text(json.dumps({"address": "0xabc"}))
    (debug_dir / "Contract.runtime.zasm").write_text("zasm")
    monkeypatch.chdir(tmp_path)
    assert common.find_debug_file("0xabc").endswith(".runtime.zasm")
