// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ErrorHandling {
    uint256 public value;
    
    // Custom errors
    error InvalidValue(uint256 provided, uint256 minimum);
    error UnauthorizedAccess(address caller, address owner);
    error InsufficientBalance(uint256 available, uint256 required);
    
    constructor() {
        value = 100;
    }
    
    function testRequire(uint256 _value) public {
        require(_value > 0, "Value must be greater than zero");
        value = _value;
    }
    
    function testRevert(uint256 _value) public {
        if (_value == 0) {
            revert("Cannot set value to zero");
        }
        value = _value;
    }
    
    function testCustomError(uint256 _value) public {
        if (_value < 10) {
            revert InvalidValue(_value, 10);
        }
        value = _value;
    }
    
    function testPanic() public {
        // This will cause a panic due to division by zero
        uint256 result = value / 0;
    }
    
    function testAssert() public {
        // This will cause a panic if value is 0
        assert(value != 0);
    }
    
    function testArrayBounds() public {
        uint256[] memory arr = new uint256[](5);
        // This will cause a panic due to array bounds
        uint256 val = arr[10];
    }
}

