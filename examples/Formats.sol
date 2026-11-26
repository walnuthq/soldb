// SPDX-License-Identifier: MIT
pragma solidity ^0.8.8;

/// A token-like contract whose numbers mean more than their integers: amounts in the
/// token's decimals, a deadline in seconds, a fee in basis points, a price in Q64.96, a
/// symbol in a `bytes32`, and a struct worth reading as one line.
contract Formats {
    type Price is uint160;

    struct Position {
        uint128 liquidity;
        int24 tickLower;
        int24 tickUpper;
    }

    event Minted(address indexed to, uint256 amount);

    uint8 public decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    uint256 public deadline;
    uint16 public feeBps;
    Price public sqrtPriceX96;
    bytes32 public symbol;
    Position public position;

    function mint(address to, uint256 whole) public {
        uint256 amount = whole * 10 ** decimals;
        totalSupply += amount;
        balances[to] += amount;
        deadline = 1_700_000_000;
        feeBps = 250;
        sqrtPriceX96 = Price.wrap(uint160(1) << 96);
        symbol = "USDC";
        position = Position(3e18, -10, 10);
        emit Minted(to, amount);
    }
}
