// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Checks-effects-interactions plus a reentrancy guard: state is zeroed before
/// the external call, and the modifier blocks nested entry.
contract SafeBank {
    mapping(address => uint256) public balances;
    bool private locked;
    address public owner;

    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function sweep(address payable to) external onlyOwner {
        uint256 bal = address(this).balance;
        (bool ok, ) = to.call{value: bal}("");
        require(ok, "sweep failed");
    }
}
