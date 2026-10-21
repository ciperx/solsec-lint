// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Upgradeable-style storage with an unguarded initializer: anyone can call
/// initialize() after deployment (or front-run the proxy) and seize ownership.
contract UnprotectedVault {
    address public owner;
    address public treasury;
    uint256 public feeBps;
    bool private initialized;

    function initialize(address _owner, address _treasury) public {
        owner = _owner;
        treasury = _treasury;
        feeBps = 30;
    }

    function setTreasury(address t) external {
        require(msg.sender == owner, "not owner");
        treasury = t;
    }
}
