// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Counter} from "../src/Counter.sol";

contract CounterTest {
    Counter counter;

    function setUp() public {
        counter = new Counter();
        counter.setNumber(1);
    }

    function test_Increment() public {
        counter.increment();
        require(counter.number() == 2, "not incremented");
    }
}
