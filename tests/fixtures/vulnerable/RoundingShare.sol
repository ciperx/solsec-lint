// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Share accounting that divides before multiplying: integer truncation makes
/// the fee round to zero for small amounts and loses precision for large ones.
contract RoundingVault {
    uint256 public totalAssets;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    function deposit(uint256 assets) external returns (uint256 minted) {
        uint256 fee = assets / 1000 * 3;
        uint256 net = assets - fee;
        minted = totalShares == 0 ? net : net / totalAssets * totalShares;
        shares[msg.sender] += minted;
        totalShares += minted;
        totalAssets += net;
    }

    function previewFee(uint256 assets) public pure returns (uint256) {
        return assets / 10000 * 30;
    }
}
