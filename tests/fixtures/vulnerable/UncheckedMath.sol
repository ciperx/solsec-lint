// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// unchecked { } disables the compiler's overflow checks on the loop counter
/// and the accumulator, so a crafted array length can wrap the total.
contract UncheckedMath {
    uint256 public total;

    function sum(uint256[] calldata values) external returns (uint256 acc) {
        unchecked {
            for (uint256 i = 0; i < values.length; i++) {
                acc += values[i];
            }
            total += acc;
        }
    }
}
