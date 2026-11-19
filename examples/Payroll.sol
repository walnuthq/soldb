// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// A ledger whose debit reverts with a custom error when the balance is short.
contract Ledger {
    error InsufficientBalance(uint256 available, uint256 required);

    mapping(address => uint256) public balanceOf;

    function credit(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function debit(address from, uint256 amount) public returns (bool) {
        uint256 available = balanceOf[from];
        if (available < amount) revert InsufficientBalance(available, amount);
        balanceOf[from] = available - amount;
        return true;
    }

    function debitWithMemo(address from, uint256 amount, bytes32 memo) external returns (bool) {
        require(memo != bytes32(0), "memo required");
        return debit(from, amount);
    }
}

/// Pays out of a ledger it creates: an internal call, then an external one that can
/// revert two contracts down.
contract Payroll {
    Ledger public immutable ledger;

    constructor() {
        ledger = new Ledger();
        ledger.credit(address(this), 1000);
    }

    function pay(uint256 amount) external returns (uint256 net) {
        uint256 fee = _fee(amount);
        net = amount - fee;
        ledger.debitWithMemo(address(this), net, bytes32(amount));
    }

    function _fee(uint256 amount) internal pure returns (uint256) {
        return amount / 100;
    }
}
