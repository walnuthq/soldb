// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// Recursion and mutual recursion, for the debugger's frame inference.
contract Recursion {
    function fact(uint256 n) public pure returns (uint256) {
        if (n <= 1) {
            return 1;
        }
        return n * fact(n - 1);
    }

    function ping(uint256 n) public pure returns (uint256) {
        if (n == 0) {
            return 0;
        }
        return pong(n - 1) + 1;
    }

    function pong(uint256 n) internal pure returns (uint256) {
        if (n == 0) {
            return 0;
        }
        return ping(n - 1) + 1;
    }
}
