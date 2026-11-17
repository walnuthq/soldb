// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

error ZeroAmount();

contract Token {
    error InsufficientBalance(uint256 available, uint256 required, address token);

    mapping(address => uint256) public balanceOf;

    constructor(uint256 supply) {
        if (supply == 0) revert ZeroAmount();
        balanceOf[msg.sender] = supply;
    }

    function transfer(address to, uint256 amount) external {
        uint256 have = balanceOf[msg.sender];
        if (have < amount) revert InsufficientBalance(have, amount, address(this));
        balanceOf[msg.sender] = have - amount;
        balanceOf[to] += amount;
    }
}

contract Vault {
    error Unauthorized(address caller);

    Token public token;

    constructor(uint256 supply) {
        token = new Token(supply);
    }

    function pay(address to, uint256 amount) external {
        token.transfer(to, amount);
    }

    function tryPay(address to, uint256 amount) external returns (bool) {
        try token.transfer(to, amount) {
            return true;
        } catch {
            return false;
        }
    }

    function deployToken(uint256 supply) external returns (address) {
        return address(new Token(supply));
    }

    function onlyOwner() external view {
        if (msg.sender != address(1)) revert Unauthorized(msg.sender);
    }

    function addOne(uint8 x) external pure returns (uint8) {
        return x + 255;
    }

    function requirePositive(uint256 x) external pure {
        require(x > 0, "x must be positive");
    }
}
