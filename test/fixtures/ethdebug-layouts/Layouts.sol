// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30;

type Price is uint64;
enum Color { Red, Green }
struct Point { uint8 x; int16 y; }
struct Record {
    Point point;
    uint16[] values;
    string text;
    bytes4 tag;
    Price price;
    Color color;
    function () external callback;
}

contract Layouts {
    Record stored;
    uint16 transient temporary;

    function snapshot(Record calldata input) external returns (uint256 pointer, Record memory result) {
        result = input;
        stored.point = input.point;
        stored.values = input.values;
        stored.text = input.text;
        stored.tag = input.tag;
        stored.price = input.price;
        stored.color = input.color;
        stored.callback = input.callback;
        temporary = input.values[0];
        assembly ("memory-safe") { pointer := result }
    }

    function arrays(uint16[2][3] calldata fixedValues, bytes[][2] calldata blobs)
        external pure returns (
            uint256 fixedPointer, uint256 blobPointer,
            uint16[2][3] memory fixedResult, bytes[][2] memory blobResult
        )
    {
        fixedResult = fixedValues;
        blobResult = blobs;
        assembly ("memory-safe") {
            fixedPointer := fixedResult
            blobPointer := blobResult
        }
    }
}
