// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// A state variable in storage next to immutables of three widths, one of them
// left-aligned: the debugger reads the immutables from the deployed code.
contract Immutables {
    uint256 public counter;
    uint256 immutable step = 7;
    address immutable owner = msg.sender;
    bytes4 immutable tag = 0xdeadbeef;

    function bump() public returns (bytes4) {
        require(msg.sender == owner);
        counter += step;
        return tag;
    }
}
