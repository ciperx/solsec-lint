// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Initializer is one-shot via OpenZeppelin's Initializable and the
/// implementation contract is locked in its constructor.
abstract contract Initializable {
    bool private _initialized;

    modifier initializer() {
        require(!_initialized, "already initialized");
        _initialized = true;
        _;
    }

    function _disableInitializers() internal {
        _initialized = true;
    }
}

contract ProtectedVault is Initializable {
    address public owner;
    address public treasury;
    uint256 public feeBps;

    constructor() {
        _disableInitializers();
    }

    function initialize(address _owner, address _treasury) public initializer {
        require(_owner != address(0), "zero owner");
        owner = _owner;
        treasury = _treasury;
        feeBps = 30;
    }

    function setTreasury(address t) external {
        require(msg.sender == owner, "not owner");
        treasury = t;
    }
}
