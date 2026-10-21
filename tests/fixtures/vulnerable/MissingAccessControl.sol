// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Privileged entry points with no owner/role check: anyone can drain the
/// vault, mint supply, or repoint protocol fees.
contract OpenVault {
    address public owner;
    uint256 public feeBps;
    mapping(address => uint256) public balanceOf;

    function withdrawAll() external {
        payable(msg.sender).transfer(address(this).balance);
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function setFee(uint256 bps) external {
        feeBps = bps;
    }

    function setOracle(address oracle) external {
        require(oracle != address(0), "zero oracle");
        owner = oracle;
    }
}
