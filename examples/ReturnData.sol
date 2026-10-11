// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// External calls whose results land in the return data buffer: a value and a revert.
contract ReturnData {
    function double(uint256 x) external pure returns (uint256) {
        return x * 2;
    }

    function callDouble(uint256 x) external view returns (uint256) {
        return this.double(x);
    }

    function fail() external pure {
        revert("undone");
    }

    function catchFail() external view returns (string memory) {
        try this.fail() {
            return "";
        } catch Error(string memory reason) {
            return reason;
        }
    }
}
