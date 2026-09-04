// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Functions taking values that live in memory rather than on the stack, so a frame's
/// arguments have to be followed through Solidity's memory layout to be read.
contract MemoryArgs {
    uint256 public total;

    function run(string memory label, uint256[] memory values, uint256 factor) public {
        total = sum(values, factor) + bytes(label).length;
    }

    function sum(uint256[] memory values, uint256 factor) internal pure returns (uint256) {
        uint256 acc;
        for (uint256 i = 0; i < values.length; i++) {
            acc += values[i] * factor;
        }
        return acc;
    }
}
