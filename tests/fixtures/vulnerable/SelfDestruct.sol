// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Anyone can destroy the contract and route the whole balance to themselves.
contract Demolish {
    address public owner;
    uint256 public pot;

    function deposit() external payable {
        pot += msg.value;
    }

    function shutdown() external {
        selfdestruct(payable(msg.sender));
    }
}
