// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Classic single-function reentrancy: the balance is cleared only after the
/// ETH transfer, so the recipient can re-enter withdraw() and drain the vault.
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        payable(msg.sender).transfer(amount);
        balances[msg.sender] -= amount;
    }
}
