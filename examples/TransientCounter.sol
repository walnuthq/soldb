// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// One counter in storage and one in transient storage, which is zero again in every
/// transaction.
contract TransientCounter {
    uint256 public storedCount;
    uint256 transient transientCount;
    bool transient locked;

    function incrementStored() external returns (uint256) {
        storedCount += 1;
        return storedCount;
    }

    function incrementTransient() external returns (uint256) {
        transientCount += 1;
        transientCount += 1;
        return transientCount;
    }

    function guarded() external returns (uint256) {
        require(!locked, "reentered");
        locked = true;
        storedCount += 1;
        locked = false;
        return storedCount;
    }

    function setAndRevert(uint256 value) external {
        transientCount = value;
        revert("undone");
    }

    /// The inner write is undone with its frame, so this returns `first`.
    function writeSurvivesRevert(uint256 first, uint256 second) external returns (uint256) {
        transientCount = first;
        try this.setAndRevert(second) {} catch {}
        return transientCount;
    }
}
