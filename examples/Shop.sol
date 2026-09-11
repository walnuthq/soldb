// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// A small shop, with one of everything the debugger can show: a struct with a string,
/// an enum, a user-defined value type, and an array in memory and in storage; a mapping
/// of those structs; a modifier; internal calls; and a loop to set a conditional
/// breakpoint in.
contract Shop {
    type Price is uint128;

    enum Status { Open, Paid, Shipped }

    struct Order {
        uint256 id;
        string item;
        Price price;
        Status status;
        uint256[] quantities;
    }

    mapping(uint256 => Order) internal orders;
    uint256 public nextId;
    uint256 public revenue;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not the owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// Places an order of `count` lines of `item` at `unitPrice` each, and returns its id.
    function place(string memory item, uint128 unitPrice, uint256 count) public returns (uint256 id) {
        id = ++nextId;
        Order memory order = build(id, item, unitPrice, count);
        store(order);
        revenue += total(order);
    }

    function build(uint256 id, string memory item, uint128 unitPrice, uint256 count)
        internal
        pure
        returns (Order memory order)
    {
        order.id = id;
        order.item = item;
        order.price = Price.wrap(unitPrice);
        order.status = Status.Open;
        order.quantities = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            order.quantities[i] = i + 1;
        }
    }

    function store(Order memory order) internal {
        Order storage saved = orders[order.id];
        saved.id = order.id;
        saved.item = order.item;
        saved.price = order.price;
        saved.status = Status.Paid;
        for (uint256 i = 0; i < order.quantities.length; i++) {
            saved.quantities.push(order.quantities[i]);
        }
    }

    function total(Order memory order) internal pure returns (uint256 sum) {
        uint128 unit = Price.unwrap(order.price);
        for (uint256 i = 0; i < order.quantities.length; i++) {
            sum += unit * order.quantities[i];
        }
    }

    function ship(uint256 id) public onlyOwner {
        Order storage order = orders[id];
        require(order.status == Status.Paid, "not paid");
        order.status = Status.Shipped;
    }

    function status(uint256 id) public view returns (Status) {
        return orders[id].status;
    }
}
