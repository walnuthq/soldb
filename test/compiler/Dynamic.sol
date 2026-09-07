// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Dynamic {
    function size(bytes calldata data) external pure returns (uint256) {
        return data.length; // debug-check: bytes-length
    }

    function sum(uint256[] calldata values) external pure returns (uint256 total) {
        for (uint256 i; i < values.length; i++) {
            total += values[i]; // debug-check: array-sum
        }
    }
}
