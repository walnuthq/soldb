// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PaymentProcessor {
    event PaymentReceived(address from, uint256 amount);

    function processPayment(address from, uint256 amount) external payable {
        require(msg.value >= amount, "Not enough funds");
        emit PaymentReceived(from, amount);
    }
}
