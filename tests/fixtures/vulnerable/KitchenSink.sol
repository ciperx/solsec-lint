// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Every rule fires at least once here. Used for the end-to-end CLI test and
/// as the sample input in the README. Note this comment says "tx.origin" and
/// "delegatecall" — the lexer must ignore both.
contract KitchenSink {
    address public owner;
    uint256 public feeBps;
    mapping(address => uint256) public balances;

    function initialize(address _owner) public {
        owner = _owner;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");
        balances[msg.sender] = 0;
    }

    function payout(address payable to) external {
        to.send(1 ether);
    }

    function adminOnly() external {
        require(tx.origin == owner, "not owner");
        owner = msg.sender;
    }

    function mint(address to) external {
        balances[to] += 1e18;
    }

    function fee(uint256 assets) public pure returns (uint256) {
        return assets / 1000 * 3;
    }

    function exec(address target, bytes calldata data) external {
        target.delegatecall(data);
    }

    function shutdown() external {
        selfdestruct(payable(msg.sender));
    }
}
