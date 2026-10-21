// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Every privileged function is gated by onlyOwner or an AccessControl role.
contract GuardedVault {
    address public owner;
    uint256 public feeBps;
    mapping(address => uint256) public balanceOf;
    mapping(bytes32 => mapping(address => bool)) private roles;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyRole(bytes32 role) {
        require(roles[role][msg.sender], "missing role");
        _;
    }

    constructor() {
        owner = msg.sender;
        roles[MINTER_ROLE][msg.sender] = true;
    }

    function grantRole(bytes32 role, address account) external onlyOwner {
        roles[role][account] = true;
    }

    function withdrawAll() external onlyOwner {
        uint256 bal = address(this).balance;
        (bool ok, ) = payable(owner).call{value: bal}("");
        require(ok, "withdraw failed");
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        balanceOf[to] += amount;
    }

    function setFee(uint256 bps) external onlyOwner {
        require(bps <= 1000, "fee too high");
        feeBps = bps;
    }
}
