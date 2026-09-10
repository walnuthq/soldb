// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Inline {
    uint256 public total;

    function twice(uint256 x) internal pure returns (uint256 r) {
        unchecked { r = x * 2; }
    }

    function run(uint256 a) public returns (uint256 out) {
        uint256 t = twice(a);
        unchecked { out = t + 1; }
        total = out;
    }
}
