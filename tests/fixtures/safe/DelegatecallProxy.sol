// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// The delegatecall target is an immutable, constructor-fixed implementation;
/// callers cannot influence it.
contract ImmutableProxy {
    address public immutable implementation;
    address public owner;

    constructor(address impl) {
        require(impl != address(0), "zero impl");
        implementation = impl;
        owner = msg.sender;
    }

    function execute(bytes calldata data)
        external
        payable
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = implementation.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}
