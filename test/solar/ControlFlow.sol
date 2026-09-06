// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ControlFlow {
    uint256 private stored;

    modifier record() {
        stored = 3; // debug-check: modifier-before
        _;
        stored += 1; // debug-check: modifier-after
    }

    function modified(uint256 value) external record returns (uint256) {
        return stored + value; // debug-check: modified
    }

    function sum(uint256 count) external pure returns (uint256 total) {
        for (uint256 i; i < count; i++) {
            total += i; // debug-check: loop
        }
    }

    function internalCall(uint256 value) external pure returns (uint256) {
        return twice(value) + 1;
    }

    function twice(uint256 value) internal pure returns (uint256) {
        return value * 2; // debug-check: helper
    }

    function checked(uint256 value) external pure returns (uint256) {
        require(value != 0, "zero"); // debug-check: require
        return value; // debug-check: checked
    }
}
