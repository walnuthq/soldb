// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TaxCalculator {
    event TaxComputed(address caller, uint256 orderValue, uint256 taxAmount);

    function calculateTax(uint256 value, string calldata orderType) external returns (uint256) {
        require(value > 0, "Order value must be positive");

        uint256 rate = getBaseRate(orderType);
        uint256 tax = (value * rate) / 100;

        emit TaxComputed(msg.sender, value, tax);

        return tax;
    }

    function getBaseRate(string calldata orderType) public pure returns (uint256) {
        bytes32 otype = keccak256(bytes(orderType));
        if (otype == keccak256("digital")) {
            return 5;
        } else if (otype == keccak256("physical")) {
            return 8;
        } else {
            return 10;
        }
    }
}
