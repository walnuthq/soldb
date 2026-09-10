// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Locals {
    uint256 public total;

    function accumulate(uint256 a, uint256 b) public returns (uint256 sum) {
        uint256 twice = a * 2;
        bool big = twice > b;
        sum = twice + b;
        if (big) {
            total += sum;
        }
    }
}
