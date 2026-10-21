// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Every low-level call result is captured and required to be true.
contract CheckedPayouts {
    mapping(address => uint256) public balances;

    error PayoutFailed();

    function payout(address payable to) external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to pay");
        balances[msg.sender] = 0;
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "payout failed");
    }

    function tip(address payable to) external {
        require(to.send(1 ether), "tip failed");
    }

    function forward(address target, bytes calldata payload) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(payload);
        if (!ok) revert PayoutFailed();
        return ret;
    }
}
