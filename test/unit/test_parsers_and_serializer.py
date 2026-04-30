import json
from types import SimpleNamespace

from hexbytes import HexBytes

from soldb.core.serializer import TraceSerializer
from soldb.core.transaction_tracer import FunctionCall, TraceStep, TransactionTrace
from soldb.parsers.ethdebug import (
    ContractDebugInfo,
    ETHDebugDirParser,
    ETHDebugInfo,
    ETHDebugParser,
    Instruction,
    MultiContractETHDebugParser,
    SourceLocation as ETHSourceLocation,
    VariableLocation,
    source_loader,
)
from soldb.parsers.source_map import SourceMapParser, SourceMappingManager, load_debug_info


ADDR = "0x00000000000000000000000000000000000000aa"
OTHER_ADDR = "0x00000000000000000000000000000000000000bb"


def write_ethdebug_dir(tmp_path):
    source_loader._source_cache.clear()
    source_loader._warning_shown.clear()

    source = (
        "contract Contract {\n"
        "    function f(uint256 x) public returns (uint256) {\n"
        "        return x + 1;\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "Contract.sol").write_text(source)
    fn_offset = source.index("function")
    ret_offset = source.index("return x")

    (tmp_path / "ethdebug.json").write_text(
        json.dumps(
            {
                "compilation": {
                    "compiler": {"version": "0.8.31"},
                    "sources": [{"id": 0, "path": "Contract.sol"}],
                }
            }
        )
    )
    (tmp_path / "Contract_ethdebug-runtime.json").write_text(
        json.dumps(
            {
                "instructions": [
                    {
                        "offset": 0,
                        "operation": {"mnemonic": "PUSH1", "arguments": ["0x01"]},
                        "context": {
                            "code": {
                                "source": {"id": 0},
                                "range": {"offset": fn_offset, "length": 8},
                            },
                            "variables": [
                                {
                                    "name": "x",
                                    "type": "uint256",
                                    "location": {"type": "stack", "offset": 0},
                                    "scope": {"start": 0, "end": 3},
                                }
                            ],
                        },
                    },
                    {
                        "offset": 2,
                        "operation": {"mnemonic": "RETURN", "arguments": []},
                        "context": {
                            "code": {
                                "source": {"id": 0},
                                "range": {"offset": ret_offset, "length": 6},
                            }
                        },
                    },
                ],
                "variables": [
                    {
                        "name": "stored",
                        "type": "uint256",
                        "location_type": "storage",
                        "offset": 1,
                        "pc_start": 2,
                        "pc_end": 3,
                    }
                ],
            }
        )
    )
    (tmp_path / "Contract.abi").write_text("[]")
    return fn_offset


def write_combined_dir(tmp_path):
    source_loader._source_cache.clear()
    source = (
        "contract Legacy {\n"
        "    function f() public pure returns (uint256) {\n"
        "        return 1;\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "Legacy.sol").write_text(source)
    fn_offset = source.index("function")
    ret_offset = source.index("return 1")
    metadata = json.dumps({"compiler": {"version": "0.8.16+commit.07a7930e"}})
    (tmp_path / "combined.json").write_text(
        json.dumps(
            {
                "sourceList": ["Legacy.sol"],
                "contracts": {
                    "Legacy.sol:Legacy": {
                        "bin-runtime": "6001600201",
                        "srcmap-runtime": f"{fn_offset}:8:0:-:0;{ret_offset}:6:0:i:0;:4::o:",
                        "metadata": metadata,
                    }
                },
            }
        )
    )
    return fn_offset, ret_offset


def test_ethdebug_parser_and_multi_contract_helpers(tmp_path):
    fn_offset = write_ethdebug_dir(tmp_path)

    spec = ETHDebugDirParser.parse_single_contract(f"{ADDR}:Contract:{tmp_path}")
    assert spec.address == ADDR
    assert spec.name == "Contract"
    assert ETHDebugDirParser.find_abi_file(spec, "Contract").endswith("Contract.abi")
    assert ETHDebugDirParser.parse_multi_contract(f"{ADDR}:{tmp_path}").path == str(tmp_path)
    assert ETHDebugDirParser.parse_ethdebug_dirs([f"{ADDR}:Contract:{tmp_path}"])[0].name == "Contract"

    parser = ETHDebugParser()
    info = parser.load_ethdebug_files(tmp_path, "Contract")

    assert info.contract_name == "Contract"
    assert info.environment == "runtime"
    assert info.get_instruction_at_pc(0).mnemonic == "PUSH1"
    assert info.get_instruction_at_pc(0).arguments == ["0x01"]
    assert info.get_source_info(0) == ("Contract.sol", fn_offset, 8)
    assert {var.name for var in info.get_variables_at_pc(1)} == {"x"}
    assert {var.name for var in info.get_variables_at_pc(2)} == {"stored"}
    assert parser.offset_to_line_col("Contract.sol", fn_offset)[0] == 2
    assert parser.get_source_mapping()[0][0] == "Contract.sol"
    assert "Contract.sol:2:" in parser.format_instruction_debug(0)
    assert parser.get_variables_debug_info(0)["variables"][0]["name"] == "x"
    assert "x: 0x7" in parser.format_variables_debug(0, stack=[7])
    assert ETHDebugParser._get_compiler_info(str(tmp_path)) == "solc 0.8.31"

    multi = MultiContractETHDebugParser()
    contract = multi.load_contract(ADDR, tmp_path, "Contract")
    assert contract.has_debug_info
    assert contract.get_parser() is contract.parser
    assert multi.get_contract_at_address(ADDR).name == "Contract"
    context = multi.push_context(contract.address, "STATICCALL")
    assert "STATICCALL" in repr(context)
    assert multi.get_current_context().address == contract.address
    assert multi.get_current_contract().name == "Contract"
    assert multi.get_source_info_for_address(ADDR, 0)["line"] == 2
    assert "Contract [STATICCALL]" in multi.format_call_stack()
    assert (multi.get_all_loaded_contracts()[0][1]) == "Contract"
    assert "Contract@" in repr(multi)
    assert multi.pop_context().call_type == "STATICCALL"

    deployment = tmp_path / "deployment.json"
    deployment.write_text(json.dumps({"address": OTHER_ADDR, "contract": "Contract", "ethdebug": {"enabled": True}}))
    loaded = multi.load_from_deployment(deployment)
    assert OTHER_ADDR in {addr.lower() for addr in loaded}

    multi.clear()
    assert multi.get_all_loaded_contracts() == []


def test_source_map_parser_manager_and_loader(tmp_path):
    fn_offset, ret_offset = write_combined_dir(tmp_path)

    parser = SourceMapParser()
    info = parser.load_combined_json(tmp_path, "Legacy")

    assert info.contract_name == "Legacy"
    assert info.pc_to_instruction_index == {0: 0, 2: 1, 4: 2}
    assert info.get_source_info(0) == ("Legacy.sol", fn_offset, 8)
    assert info.get_source_entry_at_pc(4).jump_type == "o"
    assert parser.offset_to_line_col("Legacy.sol", ret_offset)[0] == 3
    assert parser.get_source_context(0)["content"].strip().startswith("function f")
    assert parser.get_source_mapping()[0][0] == "Legacy.sol"
    assert SourceMapParser.is_legacy_compiler("0.8.16+commit") is True
    assert SourceMapParser.is_legacy_compiler("0.8.31") is False
    assert SourceMapParser.is_legacy_compiler("invalid") is True

    loaded_parser, loaded_info = load_debug_info(tmp_path, "Legacy")
    assert isinstance(loaded_parser, SourceMapParser)
    assert loaded_info.contract_name == "Legacy"

    eth_parser = ETHDebugParser()
    eth_info = ETHDebugInfo(
        compilation={},
        contract_name="Contract",
        environment="runtime",
        instructions=[
            Instruction(
                0,
                {"mnemonic": "PUSH1"},
                {"code": {"source": {"id": 0}, "range": {"offset": fn_offset, "length": 8}}},
            )
        ],
        sources={0: "Legacy.sol"},
    )
    eth_parser.debug_dir = tmp_path
    eth_parser.debug_info = eth_info
    manager = SourceMappingManager(eth_parser, eth_info)
    step = SimpleNamespace(pc=0)

    assert manager.get_pcs_for_line("Legacy.sol", 2) == {0}
    assert manager.get_steps_for_line("Legacy.sol", 2, [step]) == [0]
    assert manager.get_source_info_for_step(0, [step]) == ("Legacy.sol", 2)
    assert manager.get_source_info_for_pc(0).content.startswith("function f")
    assert manager.get_line_content("Legacy.sol", 1) == "contract Legacy {"
    assert manager.is_contract_declaration_line("Legacy.sol", 1)
    assert manager.is_function_return_line("Legacy.sol", 3)
    assert manager.get_all_mappings_for_file("Legacy.sol")[2][0].pc == 0
    assert manager.find_next_available_line("Legacy.sol", 1, [step]) == (2, [0])
    assert manager.get_cache_stats()["line_to_pcs_cache_entries"] >= 1
    manager.clear_cache()
    assert manager.get_cache_stats()["pc_to_source_cache_entries"] == 0


def test_trace_serializer_outputs_contract_calls_logs_and_abis():
    trace = TransactionTrace(
        tx_hash="0xtx",
        from_addr="0x0000000000000000000000000000000000000001",
        to_addr=ADDR,
        value=0,
        input_data=HexBytes("0x12345678"),
        gas_used=21,
        output=b"\x01",
        steps=[
            TraceStep(0, "PUSH1", 100, 3, 0, []),
            TraceStep(1, "LOG1", 90, 10, 1, ["0x00", "0x02", "0x" + "11" * 32], memory="abcd"),
            TraceStep(2, "CALL", 80, 20, 1, ["0x00", OTHER_ADDR, "0x00"]),
        ],
        success=False,
        error="root revert",
    )
    root = FunctionCall(
        "runtime_dispatcher",
        "",
        0,
        2,
        21,
        0,
        [],
        call_type="entry",
        contract_address=ADDR,
        call_id=0,
        children_call_ids=[1],
    )
    child = FunctionCall(
        "increment",
        "0x12345678",
        1,
        2,
        7,
        1,
        [("amount", 7), ("recipient", OTHER_ADDR)],
        call_type="internal",
        contract_address=ADDR,
        call_id=1,
        parent_call_id=0,
        caused_revert=True,
        error="child revert",
    )
    tracer = SimpleNamespace(
        to_addr=ADDR,
        function_abis={
            "0x12345678": {
                "type": "function",
                "name": "increment",
                "inputs": [{"name": "amount", "type": "uint256"}, {"name": "recipient", "type": "address"}],
                "outputs": [],
            }
        },
        ethdebug_info=None,
    )

    serializer = TraceSerializer()
    assert serializer._convert_to_serializable({"raw": b"\x01", "hex": HexBytes("0x02")}) == {
        "raw": "0x01",
        "hex": "02",
    }
    assert serializer.extract_logs_from_trace(trace)[0][1]["data"] == "0xabcd"
    assert serializer.encode_function_input(child, trace).startswith("0x12345678")
    assert serializer.get_function_signature_hash("increment", ["uint256"]).startswith("0x")

    serialized_child = serializer.convert_function_call_to_trace_call(child, trace, [], [root, child], tracer_instance=tracer)
    assert serialized_child["inputs"]["argumentsType"] == ["uint256", "address"]
    assert serialized_child["isRevertedFrame"]

    response = serializer.serialize_trace(trace, [root, child], tracer_instance=tracer)
    assert response["status"] == "reverted"
    assert response["traceCall"]["calls"][0]["functionName"] == "increment"
    assert response["traceCall"]["calls"][0]["logs"][0]["topics"][0].startswith("0x11")
    assert response["steps"][2]["debugInfo"] is False
    assert next(iter(response["abis"].values()))[0]["name"] == "increment"
    assert response["error"] == "child revert"
