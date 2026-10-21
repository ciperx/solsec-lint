// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Low-level call/send return values are discarded: failed payouts revert
/// nothing, so the contract keeps the funds while the ledger says paid.
contract UncheckedPayouts {
    mapping(address => uint256) public balances;

    function payout(address payable to) external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(to).call{value: amount}("");
    }

    function tip(address payable to) external {
        to.send(1 ether);
    }

    function forward(address target, bytes calldata payload) external {
        target.call(payload);
    }
}
