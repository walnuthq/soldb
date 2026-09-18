// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// State variables of every kind the ETHDebug resources describe: the type
// table gets one document per type and the pointer table one template per
// variable in storage or transient storage.

type Price is uint128;

enum Color {
    Red,
    Green,
    Blue
}

struct Point {
    uint8 x;
    uint8 y;
}

contract Base {
    uint256 inherited;
}

contract Resources is Base {
    uint256 total;
    uint8 small;
    bool flag;
    address owner;
    bytes32 hash;
    Color color;
    Price price;
    Point origin;
    uint16[4] packed;
    uint256[] values;
    bytes blob;
    string text;
    mapping(address => uint256) balances;
    mapping(address => mapping(uint256 => bool)) nested;
    uint256 transient scratch;
    uint256 constant LIMIT = 100;
    uint256 immutable createdAt;

    constructor() {
        createdAt = block.number;
    }

    function read() public view returns (uint256) {
        return total + inherited;
    }
}
