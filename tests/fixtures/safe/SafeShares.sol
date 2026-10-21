// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Checked arithmetic with the multiplication done before the division, so no
/// precision is lost to truncation.
contract SafeShares {
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    uint256 private constant FEE_BPS = 30;
    uint256 private constant BPS_DENOMINATOR = 10_000;

    function previewFee(uint256 assets) public pure returns (uint256) {
        return (assets * FEE_BPS) / BPS_DENOMINATOR;
    }

    function deposit(uint256 assets) external returns (uint256 minted) {
        require(assets > 0, "zero assets");
        uint256 fee = (assets * FEE_BPS) / BPS_DENOMINATOR;
        uint256 net = assets - fee;
        minted = totalShares == 0
            ? net
            : (net * totalShares) / totalAssets;
        shares[msg.sender] += minted;
        totalShares += minted;
        totalAssets += net;
    }
}
