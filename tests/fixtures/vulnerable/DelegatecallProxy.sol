// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Executes arbitrary calldata against a caller-supplied address with
/// delegatecall: the attacker's code runs in this contract's storage context
/// and can overwrite owner, then drain the balance.
contract ArbitraryDelegate {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function execute(address target, bytes calldata data)
        external
        payable
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }

    function batch(address[] calldata targets, bytes[] calldata data) external {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, ) = targets[i].delegatecall(data[i]);
            require(ok, "batch failed");
        }
    }
}
