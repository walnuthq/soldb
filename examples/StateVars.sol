// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// State variables in every storage shape the debugger reads by name: packed value types
/// sharing a slot, a struct, a static and a dynamic array, a string, and a mapping.
contract StateVars {
    struct Config {
        address owner;
        uint256 limit;
    }

    uint256 public counter;
    bool public active;
    address public owner;
    int8 public delta;
    string public label;
    uint8[3] public small;
    uint256[] public items;
    Config public config;
    mapping(address => uint256) public balances;

    /// Writes every variable, then calls an internal function so a breakpoint has a
    /// place to stop with all of them written.
    function touchAll(address who) public {
        counter = 42;
        active = true;
        owner = who;
        delta = -2;
        label = "soldb";
        small[0] = 1;
        small[2] = 3;
        items.push(7);
        items.push(9);
        config.owner = who;
        config.limit = 99;
        balances[who] = 25;
        counter = total();
    }

    /// Reads two of them back, so the call has a frame of its own.
    function total() internal view returns (uint256) {
        return counter + config.limit;
    }
}
