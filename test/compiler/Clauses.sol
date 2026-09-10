// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Clauses {
    uint256 public total;

    modifier tagged(uint256 tag) {
        uint256 seen = tag;
        _;
        total += seen;
    }

    function guarded(uint256 v) public tagged(9) {
        uint256 kept = v + 1;
        total = kept;
    }

    function sum(uint256[] calldata xs, bytes calldata tag) public pure returns (uint256 s) {
        require(tag.length > 0, "empty");
        for (uint256 i = 0; i < xs.length; i++) {
            s += xs[i];
        }
        s += tag.length;
    }

    function probe(address target, bool fail) public returns (uint256 got) {
        uint256[] memory xs = new uint256[](2);
        xs[0] = 3;
        xs[1] = 4;
        try Clauses(target).sum(xs, fail ? bytes("") : bytes("ab")) returns (uint256 value) {
            got = value + 1;
        } catch Error(string memory reason) {
            got = bytes(reason).length;
        } catch (bytes memory data) {
            got = data.length;
        }
    }
}
