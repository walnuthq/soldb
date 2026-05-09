// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Callee {
    event Ping(uint256 value);

    function ping(uint256 value) external returns (uint256) {
        emit Ping(value);
        return value + 1;
    }
}

contract Caller {
    Callee public callee;

    event Done(uint256 value);

    constructor(address calleeAddress) {
        callee = Callee(calleeAddress);
    }

    function callPing(uint256 value) public returns (uint256) {
        uint256 result = callee.ping(value);
        emit Done(result);
        return result;
    }
}
