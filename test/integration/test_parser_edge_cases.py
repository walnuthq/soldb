"""Integration tests for ETHDebug and SourceMap parser edge cases."""

import json
from types import SimpleNamespace

import pytest

from soldb.parsers.ethdebug import (
    ETHDebugParser, ETHDebugInfo, MultiContractETHDebugParser,
    Instruction, SourceLocation, VariableLocation,
)
from soldb.parsers.source_map import SourceMapParser, SourceMappingManager, load_debug_info


class TestETHDebugParserVariables:
    """Test variable location parsing and formatting."""

    def test_format_variables_with_storage_and_memory(self, tmp_path):

        source = "contract C {\n  uint256 x;\n  function f() public { x = 1; }\n}\n"
        (tmp_path / "C.sol").write_text(source)
        fn_off = source.index("function f")

        (tmp_path / "ethdebug.json").write_text(json.dumps({
            "compilation": {
                "compiler": {"version": "0.8.31"},
                "sources": [{"id": 0, "path": "C.sol"}],
            }
        }))
        (tmp_path / "C_ethdebug-runtime.json").write_text(json.dumps({
            "instructions": [
                {"offset": 0, "operation": {"mnemonic": "PUSH1"},
                 "context": {
                     "code": {"source": {"id": 0}, "range": {"offset": fn_off, "length": 10}},
                     "variables": [
                         {"name": "x", "type": "uint256",
                          "location": {"type": "storage", "offset": 0},
                          "scope": {"start": 0, "end": 10}},
                         {"name": "y", "type": "uint256",
                          "location": {"type": "memory", "offset": 0x40},
                          "scope": {"start": 0, "end": 10}},
                         {"name": "z", "type": "uint256",
                          "location": {"type": "stack", "offset": 0},
                          "scope": {"start": 0, "end": 10}},
                     ],
                 }},
            ],
        }))

        parser = ETHDebugParser()
        info = parser.load_ethdebug_files(tmp_path, "C")
        vars_at_0 = info.get_variables_at_pc(0)
        assert len(vars_at_0) == 3
        names = {v.name for v in vars_at_0}
        assert names == {"x", "y", "z"}

        # Test format_variables_debug
        debug = parser.get_variables_debug_info(0)
        assert len(debug["variables"]) == 3

        # Test format with stack values
        formatted = parser.format_variables_debug(0, stack=[42], storage={"0": "0x0a"}, memory="00" * 128)
        assert "x" in formatted or "z" in formatted


class TestETHDebugMultiContractDeployment:
    """Test multi-contract parser with deployment.json."""

    def test_load_from_deployment_multi(self, tmp_path):

        source = "contract A {\n  function f() public {}\n}\n"
        (tmp_path / "A.sol").write_text(source)
        fn_off = source.index("function f")

        (tmp_path / "ethdebug.json").write_text(json.dumps({
            "compilation": {
                "compiler": {"version": "0.8.31"},
                "sources": [{"id": 0, "path": "A.sol"}],
            }
        }))
        (tmp_path / "A_ethdebug-runtime.json").write_text(json.dumps({
            "instructions": [
                {"offset": 0, "operation": {"mnemonic": "PUSH1"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": fn_off, "length": 5}}}},
            ],
        }))
        addr = "0x00000000000000000000000000000000000000aa"
        (tmp_path / "deployment.json").write_text(json.dumps({
            "address": addr,
            "contract": "A",
            "ethdebug": {"enabled": True},
        }))

        multi = MultiContractETHDebugParser()
        loaded = multi.load_from_deployment(tmp_path / "deployment.json")
        assert len(loaded) >= 1

        contract = multi.get_contract_at_address(addr)
        assert contract is not None
        assert contract.name == "A"

        # Test context push/pop
        ctx = multi.push_context(addr, "CALL")
        assert multi.get_current_context().address == addr
        multi.pop_context()


class TestSourceMapParserEdges:
    """Test SourceMapParser with various srcmap patterns."""

    def test_srcmap_with_jump_types(self, tmp_path):

        source = "contract L {\n  function g() public pure returns (uint256) {\n    return 1;\n  }\n}\n"
        (tmp_path / "L.sol").write_text(source)
        fn_off = source.index("function g")
        ret_off = source.index("return 1")
        metadata = json.dumps({"compiler": {"version": "0.8.16+commit.07a7930e"}})
        (tmp_path / "combined.json").write_text(json.dumps({
            "sourceList": ["L.sol"],
            "contracts": {
                "L.sol:L": {
                    "bin-runtime": "6001600201",
                    "srcmap-runtime": f"{fn_off}:8:0:-:0;{ret_off}:6:0:i:0;:4::o:",
                    "metadata": metadata,
                }
            },
        }))

        parser = SourceMapParser()
        info = parser.load_combined_json(tmp_path, "L")
        assert info.contract_name == "L"
        assert info.pc_to_instruction_index is not None

        # Test source context
        ctx = parser.get_source_context(0)
        assert ctx is not None
        assert ctx["file"] == "L.sol"

        # Test source mapping
        mapping = parser.get_source_mapping()
        assert len(mapping) > 0

        # Test offset_to_line_col
        line, col = parser.offset_to_line_col("L.sol", fn_off)
        assert line == 2

        # Test _parse_srcmap with various patterns
        entries = parser._parse_srcmap(f"{fn_off}:8:0:i:0;;:6::o:")
        assert len(entries) == 3  # 3 entries including repeated

    def test_srcmap_manager_with_ethdebug(self, tmp_path):
        """SourceMappingManager requires ETHDebugInfo, not SourceMapInfo."""

        source = "contract E {\n  function f() public { }\n}\n"
        (tmp_path / "E.sol").write_text(source)
        fn_off = source.index("function f")

        (tmp_path / "ethdebug.json").write_text(json.dumps({
            "compilation": {
                "compiler": {"version": "0.8.31"},
                "sources": [{"id": 0, "path": "E.sol"}],
            }
        }))
        (tmp_path / "E_ethdebug-runtime.json").write_text(json.dumps({
            "instructions": [
                {"offset": 0, "operation": {"mnemonic": "PUSH1"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": fn_off, "length": 5}}}},
                {"offset": 5, "operation": {"mnemonic": "STOP"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": fn_off + 10, "length": 3}}}},
            ],
        }))

        parser = ETHDebugParser()
        info = parser.load_ethdebug_files(tmp_path, "E")

        manager = SourceMappingManager(parser, info)

        # get_pcs_for_line
        pcs = manager.get_pcs_for_line("E.sol", 2)
        assert len(pcs) > 0

        # line content
        content = manager.get_line_content("E.sol", 1)
        assert "contract" in content

        # is_contract_declaration_line
        assert manager.is_contract_declaration_line("E.sol", 1)

        # get_all_mappings_for_file
        mappings = manager.get_all_mappings_for_file("E.sol")
        assert len(mappings) > 0

        # get_source_info_for_pc
        src_info = manager.get_source_info_for_pc(0)
        assert src_info is not None

        # find_next_available_line
        step = SimpleNamespace(pc=0)
        line_num, step_indices = manager.find_next_available_line("E.sol", 1, [step])
        assert line_num >= 1

        # cache stats
        stats = manager.get_cache_stats()
        assert stats["line_to_pcs_cache_entries"] >= 1


class TestSourceMapLoaderFallback:
    """Test load_debug_info with various directory states."""

    def test_load_combined_json_auto(self, tmp_path):

        source = "contract M {\n  function h() public pure { }\n}\n"
        (tmp_path / "M.sol").write_text(source)
        fn_off = source.index("function h")
        metadata = json.dumps({"compiler": {"version": "0.8.16"}})
        (tmp_path / "combined.json").write_text(json.dumps({
            "sourceList": ["M.sol"],
            "contracts": {
                "M.sol:M": {
                    "bin-runtime": "6001",
                    "srcmap-runtime": f"{fn_off}:8:0:-:0",
                    "metadata": metadata,
                }
            },
        }))

        parser, info = load_debug_info(tmp_path)
        assert isinstance(parser, SourceMapParser)
        assert info.contract_name == "M"

    def test_load_ethdebug_auto(self, tmp_path):

        source = "contract N {\n  function j() public { }\n}\n"
        (tmp_path / "N.sol").write_text(source)
        fn_off = source.index("function j")
        (tmp_path / "ethdebug.json").write_text(json.dumps({
            "compilation": {
                "compiler": {"version": "0.8.31"},
                "sources": [{"id": 0, "path": "N.sol"}],
            }
        }))
        (tmp_path / "N_ethdebug-runtime.json").write_text(json.dumps({
            "instructions": [
                {"offset": 0, "operation": {"mnemonic": "STOP"},
                 "context": {"code": {"source": {"id": 0}, "range": {"offset": fn_off, "length": 5}}}},
            ],
        }))

        parser, info = load_debug_info(tmp_path)
        assert isinstance(parser, ETHDebugParser)
        assert info.contract_name == "N"
