// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/// Pre-0.8 pragma with no SafeMath: every addition/multiplication wraps
/// silently, so balances can be inflated or drained.
contract LegacyToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
