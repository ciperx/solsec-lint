// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// msg.sender authorization with an owner modifier on every privileged entry
/// point — no tx.origin anywhere.
contract Owned {
    address public owner;
    uint256 public feeBps;

    event OwnershipTransferred(address indexed from, address indexed to);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(address next) external onlyOwner {
        require(next != address(0), "zero owner");
        emit OwnershipTransferred(owner, next);
        owner = next;
    }

    function setFee(uint256 bps) external onlyOwner {
        require(bps <= 1000, "fee too high");
        feeBps = bps;
    }

    function rescue(address payable to) external onlyOwner {
        uint256 bal = address(this).balance;
        (bool ok, ) = to.call{value: bal}("");
        require(ok, "rescue failed");
    }
}
