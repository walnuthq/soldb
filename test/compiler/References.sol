// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

type Price is uint128;

contract References {
    enum Color { Red, Green, Blue }

    struct Item {
        uint256 id;
        string name;
        Color color;
        uint256[] tags;
    }

    mapping(uint256 => Item) internal byId;
    uint256 public built;

    function make(uint256 id, Color color) internal pure returns (Item memory item) {
        item.id = id;
        item.name = "widget";
        item.color = color;
        item.tags = new uint256[](2);
        item.tags[0] = 7;
        item.tags[1] = 8;
    }

    function store(Item memory item, Price price, bytes memory blob) internal returns (uint256) {
        Item storage stored = byId[item.id];
        stored.id = item.id;
        stored.name = item.name;
        stored.color = item.color;
        stored.tags.push(Price.unwrap(price));
        built += blob.length;
        return stored.tags.length;
    }

    function build(uint256 id, Color color) public returns (uint256 count) {
        Item memory item = make(id, color);
        Price price = Price.wrap(uint128(id * 3));
        bytes memory blob = hex"c0ffee";
        count = store(item, price, blob);
        count += built;
    }
}
