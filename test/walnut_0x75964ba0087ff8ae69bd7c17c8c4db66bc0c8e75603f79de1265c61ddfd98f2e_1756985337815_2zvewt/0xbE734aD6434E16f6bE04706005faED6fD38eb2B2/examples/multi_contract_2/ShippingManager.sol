// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ShippingManager {
    event ShippingStarted(address to, string method);
    event ShippingEstimate(uint256 cost);

    function initiateShipping(address customer, string calldata method) external returns (uint256) {
        emit ShippingStarted(customer, method);

        uint256 cost = estimateShipping(method);
        emit ShippingEstimate(cost);

        return cost;
    }

    function estimateShipping(string calldata method) public pure returns (uint256) {
        if (keccak256(bytes(method)) == keccak256("express")) {
            return 50;
        } else if (keccak256(bytes(method)) == keccak256("standard")) {
            return 20;
        } else {
            return 30;
        }
    }
}
