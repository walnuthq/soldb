// SPDX-License-Identifier: MIT
pragma solidity >=0.8.30;

contract FunctionTypes {
    function () external externalEmpty;
    function (uint32) external externalNoReturns;
    function () external returns (uint32) externalOneReturn;
    function (uint32) external returns (uint32) externalSingle;
    function (uint32, bool, address) external returns (bytes4, int16) externalMultiple;
    function () internal internalEmpty;
    function (uint32) internal returns (uint32) internalSingle;
    function (uint32, bool, address) internal returns (bytes4, int16) internalMultiple;

    constructor(uint8, bool) {}
    modifier m(uint80) { _; }
    function empty() external pure {}
    function single(uint64 value) external pure m(value) returns (bool) { return false; }
    function multiple(uint32, bool, address) external pure returns (bytes4, int16) { return (bytes4(0), 0); }
    function unused(uint200) internal pure returns (uint208) { return 0; }
}
