// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Both functions share the same ABI return tail after optimization.
contract SharedReturns {
    function checked(uint256 value) external pure returns (uint256) {
        require(value != 0); // debug-check: require
        return value; // debug-check: checked
    }

    function size(bytes calldata data) external pure returns (uint256) {
        return data.length; // debug-check: bytes-length
    }
}
