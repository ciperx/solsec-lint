// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Authorization keyed on tx.origin: a phishing contract can call
/// changeOwner() on behalf of the victim EOA and pass the check.
contract TxOriginVault {
    address public owner;
    mapping(address => uint256) public credit;

    constructor() {
        owner = msg.sender;
    }

    function changeOwner(address next) external {
        require(tx.origin == owner, "not owner");
        owner = next;
    }

    function withdrawCredit() external {
        require(tx.origin == msg.sender, "no contracts");
        uint256 amount = credit[msg.sender];
        credit[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
