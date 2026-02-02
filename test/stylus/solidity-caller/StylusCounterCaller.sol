// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title StylusCounterCaller
 * @dev Solidity contract that calls a Stylus Counter contract
 *
 * This demonstrates how Solidity can interact with Stylus contracts.
 * The Stylus contract is ABI-compatible, so it can be called just like
 * any other Solidity contract.
 */
interface IStylusCounter {
    function number() external view returns (uint256);
    function setNumber(uint256 new_number) external;
    function increment() external;
    function addNumber(uint256 new_number) external;
}

contract StylusCounterCaller {
    IStylusCounter public stylusCounter;
    uint256 public callCount;
    uint256 public lastResult;

    constructor(address _stylusCounter) {
        stylusCounter = IStylusCounter(_stylusCounter);
        callCount = 0;
    }

    function getStylusNumber() external view returns (uint256) {
        return stylusCounter.number();
    }

    function incrementStylusCounter() external {
        callCount++;
        stylusCounter.increment();
        lastResult = stylusCounter.number();
    }

    function setStylusNumber(uint256 newValue) external {
        callCount++;
        stylusCounter.setNumber(newValue);
        lastResult = newValue;
    }

    function addToStylusCounter(uint256 value) external {
        callCount++;
        stylusCounter.addNumber(value);
        lastResult = stylusCounter.number();
    }

    /**
     * @dev Performs multiple operations on Stylus Counter
     * Used for testing complex cross-environment traces
     */
    function complexStylusOperation(
        uint256 initialValue,
        uint256 incrementTimes,
        uint256 addValue
    ) external returns (uint256) {
        callCount++;

        // Set initial value
        stylusCounter.setNumber(initialValue);

        // Increment multiple times
        for (uint256 i = 0; i < incrementTimes; i++) {
            stylusCounter.increment();
        }

        // Add final value
        stylusCounter.addNumber(addValue);

        // Get and return final value
        uint256 finalValue = stylusCounter.number();
        lastResult = finalValue;

        return finalValue;
    }

    function batchIncrement(uint256 times) external {
        callCount++;
        for (uint256 i = 0; i < times; i++) {
            stylusCounter.increment();
        }
        lastResult = stylusCounter.number();
    }

    function getStats() external view returns (
        uint256 _callCount,
        uint256 _lastResult,
        uint256 _currentStylusValue
    ) {
        return (
            callCount,
            lastResult,
            stylusCounter.number()
        );
    }
}
