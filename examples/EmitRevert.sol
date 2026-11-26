// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title EmitRevert
 * @dev Emits events of every kind a call tree places: in the frame itself, anonymously,
 *      through a delegatecall, and in calls a revert later undoes, one the caller
 *      catches and one that fails as a whole.
 */
contract EmitRevert {
    event Started(uint256 value);
    event Raw(uint256 value) anonymous;
    event Noted(uint256 value);
    event Inner(uint256 value);
    event Caught(string reason);
    event Finished(uint256 value);

    function note(uint256 value) external {
        emit Noted(value);
    }

    function inner(uint256 value) external {
        emit Inner(value);
        revert("inner failed");
    }

    /// Succeeds for a value below 10, with the event of the caught call undone; reverts
    /// after all its events otherwise.
    function run(uint256 value) external {
        emit Started(value);
        emit Raw(value);
        (bool success,) = address(this).delegatecall(abi.encodeCall(this.note, (value)));
        require(success, "note failed");
        try this.inner(value) {} catch Error(string memory reason) {
            emit Caught(reason);
        }
        require(value < 10, "value too large");
        emit Finished(value);
    }
}
