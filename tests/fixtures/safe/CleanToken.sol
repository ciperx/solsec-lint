// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Clean baseline: no tx.origin, no delegatecall, state updated before any
/// external call, initializer gated, arithmetic multiply-before-divide.
/// A comment that mentions tx.origin and delegatecall must NOT be reported.
contract CleanToken {
    string public name = "Clean";
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    uint256 public feeBps = 30;
    address public owner;
    address public treasury;
    bool private _initialized;
    mapping(address => uint256) public balanceOf;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _treasury) {
        require(_treasury != address(0), "zero treasury");
        owner = msg.sender;
        treasury = _treasury;
        _initialized = true;
        totalSupply = 1_000_000e18;
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(to != address(0), "zero recipient");
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function feeOn(uint256 amount) public view returns (uint256) {
        return (amount * feeBps) / 10_000;
    }

    function sweep(address payable to) external onlyOwner {
        uint256 bal = address(this).balance;
        (bool ok, ) = to.call{value: bal}("");
        require(ok, "sweep failed");
    }

    function setTreasury(address t) external onlyOwner {
        require(t != address(0), "zero treasury");
        treasury = t;
    }
}
