# Solidity Security Audit

**Tool:** `solsec-lint` v1.0.0  
**Files scanned:** 11  
**Findings:** Critical 7, High 15, Medium 7, Low 0, Info 0 — total **29**

## Summary

| Severity | Rule | Title | File | Line |
|---|---|---|---|---|
| 🟥 CRITICAL | `SOL-007` | Dangerous delegatecall to a caller-controlled target | `tests/fixtures/vulnerable/DelegatecallProxy.sol` | 20 |
| 🟥 CRITICAL | `SOL-007` | Dangerous delegatecall to a caller-controlled target | `tests/fixtures/vulnerable/DelegatecallProxy.sol` | 27 |
| 🟧 HIGH | `SOL-004` | Unchecked integer overflow/underflow (pre-0.8 pragma) | `tests/fixtures/vulnerable/IntegerOverflow.sol` | 1 |
| 🟧 HIGH | `SOL-006` | Missing access control on 'mint' | `tests/fixtures/vulnerable/IntegerOverflow.sol` | 10 |
| 🟥 CRITICAL | `SOL-005` | Unprotected initializer | `tests/fixtures/vulnerable/KitchenSink.sol` | 12 |
| 🟥 CRITICAL | `SOL-001` | Reentrancy: state written after external call | `tests/fixtures/vulnerable/KitchenSink.sol` | 18 |
| 🟥 CRITICAL | `SOL-007` | Dangerous delegatecall to a caller-controlled target | `tests/fixtures/vulnerable/KitchenSink.sol` | 41 |
| 🟧 HIGH | `SOL-002` | Unchecked low-level send return value | `tests/fixtures/vulnerable/KitchenSink.sol` | 24 |
| 🟧 HIGH | `SOL-003` | Authorization via tx.origin | `tests/fixtures/vulnerable/KitchenSink.sol` | 28 |
| 🟧 HIGH | `SOL-006` | Missing access control on 'mint' | `tests/fixtures/vulnerable/KitchenSink.sol` | 32 |
| 🟧 HIGH | `SOL-002` | Unchecked low-level delegatecall return value | `tests/fixtures/vulnerable/KitchenSink.sol` | 41 |
| 🟧 HIGH | `SOL-008` | Unprotected selfdestruct | `tests/fixtures/vulnerable/KitchenSink.sol` | 45 |
| 🟨 MEDIUM | `SOL-004` | Precision loss: division before multiplication | `tests/fixtures/vulnerable/KitchenSink.sol` | 37 |
| 🟧 HIGH | `SOL-006` | Missing access control on 'withdrawAll' | `tests/fixtures/vulnerable/MissingAccessControl.sol` | 11 |
| 🟧 HIGH | `SOL-006` | Missing access control on 'mint' | `tests/fixtures/vulnerable/MissingAccessControl.sol` | 15 |
| 🟨 MEDIUM | `SOL-006` | Missing access control on 'setFee' | `tests/fixtures/vulnerable/MissingAccessControl.sol` | 19 |
| 🟨 MEDIUM | `SOL-006` | Missing access control on 'setOracle' | `tests/fixtures/vulnerable/MissingAccessControl.sol` | 23 |
| 🟥 CRITICAL | `SOL-001` | Reentrancy: state written after external call | `tests/fixtures/vulnerable/Reentrancy.sol` | 16 |
| 🟨 MEDIUM | `SOL-004` | Precision loss: division before multiplication | `tests/fixtures/vulnerable/RoundingShare.sol` | 12 |
| 🟨 MEDIUM | `SOL-004` | Precision loss: division before multiplication | `tests/fixtures/vulnerable/RoundingShare.sol` | 14 |
| 🟨 MEDIUM | `SOL-004` | Precision loss: division before multiplication | `tests/fixtures/vulnerable/RoundingShare.sol` | 21 |
| 🟧 HIGH | `SOL-008` | Unprotected selfdestruct | `tests/fixtures/vulnerable/SelfDestruct.sol` | 14 |
| 🟧 HIGH | `SOL-003` | Authorization via tx.origin | `tests/fixtures/vulnerable/TxOriginAuth.sol` | 15 |
| 🟧 HIGH | `SOL-003` | Authorization via tx.origin | `tests/fixtures/vulnerable/TxOriginAuth.sol` | 20 |
| 🟧 HIGH | `SOL-002` | Unchecked low-level call return value | `tests/fixtures/vulnerable/UncheckedCall.sol` | 12 |
| 🟧 HIGH | `SOL-002` | Unchecked low-level send return value | `tests/fixtures/vulnerable/UncheckedCall.sol` | 16 |
| 🟧 HIGH | `SOL-002` | Unchecked low-level call return value | `tests/fixtures/vulnerable/UncheckedCall.sol` | 20 |
| 🟨 MEDIUM | `SOL-004` | Arithmetic inside unchecked block | `tests/fixtures/vulnerable/UncheckedMath.sol` | 10 |
| 🟥 CRITICAL | `SOL-005` | Unprotected initializer | `tests/fixtures/vulnerable/UnprotectedInit.sol` | 12 |

## Details

### `tests/fixtures/vulnerable/DelegatecallProxy.sol`

#### 1. [CRITICAL] SOL-007 — Dangerous delegatecall to a caller-controlled target

- **Location:** `tests/fixtures/vulnerable/DelegatecallProxy.sol:20` in `execute()`
- **Confidence:** high
- **Issue:** 'execute' delegatecalls target, which the caller can choose; delegatecall runs the callee's code with this contract's storage and balance, allowing full takeover.
- **Fix:** Whitelist an immutable implementation: `require(target == implementation)` with `address public immutable implementation`.

```solidity
(bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
```

#### 2. [CRITICAL] SOL-007 — Dangerous delegatecall to a caller-controlled target

- **Location:** `tests/fixtures/vulnerable/DelegatecallProxy.sol:27` in `batch()`
- **Confidence:** high
- **Issue:** 'batch' delegatecalls targets[i], which the caller can choose; delegatecall runs the callee's code with this contract's storage and balance, allowing full takeover.
- **Fix:** Whitelist an immutable implementation: `require(target == implementation)` with `address public immutable implementation`.

```solidity
(bool ok, ) = targets[i].delegatecall(data[i]);
            require(ok, "batch failed");
        }
```

### `tests/fixtures/vulnerable/IntegerOverflow.sol`

#### 1. [HIGH] SOL-004 — Unchecked integer overflow/underflow (pre-0.8 pragma)

- **Location:** `tests/fixtures/vulnerable/IntegerOverflow.sol:1`
- **Confidence:** high
- **Issue:** pragma targets Solidity 0.8.7x: arithmetic silently wraps and no SafeMath is used in this file.
- **Fix:** Bump to pragma solidity ^0.8.20 (checked arithmetic) or wrap all math in SafeMath.

```solidity
// SPDX-License-Identifier: MIT
```

#### 2. [HIGH] SOL-006 — Missing access control on 'mint'

- **Location:** `tests/fixtures/vulnerable/IntegerOverflow.sol:10` in `mint()`
- **Confidence:** high
- **Issue:** 'mint' is public and mutates privileged state but carries no owner/role modifier and no msg.sender check in its body.
- **Fix:** Restrict it: `mint(...) external onlyOwner` (or an AccessControl role).

```solidity
function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
```

### `tests/fixtures/vulnerable/KitchenSink.sol`

#### 1. [CRITICAL] SOL-005 — Unprotected initializer

- **Location:** `tests/fixtures/vulnerable/KitchenSink.sol:12` in `initialize()`
- **Confidence:** high
- **Issue:** 'initialize' is public and has no initializer modifier or one-shot guard; anyone can call it again to reset owner/state (or front-run deployment in a proxy setup).
- **Fix:** Add OpenZeppelin's `initializer` modifier (and `_disableInitializers()` in the constructor).

```solidity
function initialize(address _owner) public {
        owner = _owner;
    }

    function withdraw() external {
```

#### 2. [CRITICAL] SOL-001 — Reentrancy: state written after external call

- **Location:** `tests/fixtures/vulnerable/KitchenSink.sol:18` in `withdraw()`
- **Confidence:** high
- **Issue:** 'withdraw' performs an external call to msg.sender and only updates state afterwards; a malicious callee can re-enter before the balance/flag is updated.
- **Fix:** Apply checks-effects-interactions: update state before the call, and add a nonReentrant guard.

```solidity
(bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");
        balances[msg.sender] = 0;
```

#### 3. [CRITICAL] SOL-007 — Dangerous delegatecall to a caller-controlled target

- **Location:** `tests/fixtures/vulnerable/KitchenSink.sol:41` in `exec()`
- **Confidence:** high
- **Issue:** 'exec' delegatecalls target, which the caller can choose; delegatecall runs the callee's code with this contract's storage and balance, allowing full takeover.
- **Fix:** Whitelist an immutable implementation: `require(target == implementation)` with `address public immutable implementation`.

```solidity
target.delegatecall(data);
    }
```

#### 4. [HIGH] SOL-002 — Unchecked low-level send return value

- **Location:** `tests/fixtures/vulnerable/KitchenSink.sol:24` in `payout()`
- **Confidence:** high
- **Issue:** Return value of send() in 'payout' is ignored, so a failing transfer/execution continues silently.
- **Fix:** Capture the bool: (bool ok, ) = ...; require(ok, "send failed");

```solidity
to.send(1 ether);
    }
```

#### 5. [HIGH] SOL-003 — Authorization via tx.origin

- **Location:** `tests/fixtures/vulnerable/KitchenSink.sol:28` in `adminOnly()`
- **Confidence:** high
- **Issue:** tx.origin authenticates the transaction's origin EOA, so a phished user can be made to call an attacker contract that passes the check on their behalf.
- **Fix:** Use msg.sender for authorization (or a signed permit / EIP-712 nonce).

```solidity
require(tx.origin == owner, "not owner");
        owner = msg.sender;
```

#### 6. [HIGH] SOL-006 — Missing access control on 'mint'

- **Location:** `tests/fixtures/vulnerable/KitchenSink.sol:32` in `mint()`
- **Confidence:** high
- **Issue:** 'mint' is external and mutates privileged state but carries no owner/role modifier and no msg.sender check in its body.
- **Fix:** Restrict it: `mint(...) external onlyOwner` (or an AccessControl role).

```solidity
function mint(address to) external {
        balances[to] += 1e18;
    }
```

#### 7. [HIGH] SOL-002 — Unchecked low-level delegatecall return value

- **Location:** `tests/fixtures/vulnerable/KitchenSink.sol:41` in `exec()`
- **Confidence:** high
- **Issue:** Return value of delegatecall() in 'exec' is ignored, so a failing transfer/execution continues silently.
- **Fix:** Capture the bool: (bool ok, ) = ...; require(ok, "delegatecall failed");

```solidity
target.delegatecall(data);
    }
```

#### 8. [HIGH] SOL-008 — Unprotected selfdestruct

- **Location:** `tests/fixtures/vulnerable/KitchenSink.sol:45` in `shutdown()`
- **Confidence:** high
- **Issue:** 'shutdown' can destroy the contract and forward its balance without any owner/role check.
- **Fix:** Gate destruction behind onlyOwner + a timelock, or remove selfdestruct entirely.

```solidity
selfdestruct(payable(msg.sender));
    }
```

#### 9. [MEDIUM] SOL-004 — Precision loss: division before multiplication

- **Location:** `tests/fixtures/vulnerable/KitchenSink.sol:37` in `fee()`
- **Confidence:** medium
- **Issue:** 'fee' divides before multiplying (assets / 1000 * ...), truncating the intermediate result and losing value on small amounts.
- **Fix:** Multiply first, then divide: (a * b) / c, and round in the protocol's favour.

```solidity
return assets / 1000 * 3;
    }
```

### `tests/fixtures/vulnerable/MissingAccessControl.sol`

#### 1. [HIGH] SOL-006 — Missing access control on 'withdrawAll'

- **Location:** `tests/fixtures/vulnerable/MissingAccessControl.sol:11` in `withdrawAll()`
- **Confidence:** high
- **Issue:** 'withdrawAll' is external and mutates privileged state but carries no owner/role modifier and no msg.sender check in its body.
- **Fix:** Restrict it: `withdrawAll(...) external onlyOwner` (or an AccessControl role).

```solidity
function withdrawAll() external {
        payable(msg.sender).transfer(address(this).balance);
    }
```

#### 2. [HIGH] SOL-006 — Missing access control on 'mint'

- **Location:** `tests/fixtures/vulnerable/MissingAccessControl.sol:15` in `mint()`
- **Confidence:** high
- **Issue:** 'mint' is external and mutates privileged state but carries no owner/role modifier and no msg.sender check in its body.
- **Fix:** Restrict it: `mint(...) external onlyOwner` (or an AccessControl role).

```solidity
function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
```

#### 3. [MEDIUM] SOL-006 — Missing access control on 'setFee'

- **Location:** `tests/fixtures/vulnerable/MissingAccessControl.sol:19` in `setFee()`
- **Confidence:** high
- **Issue:** 'setFee' is external and mutates privileged state but carries no owner/role modifier and no msg.sender check in its body.
- **Fix:** Restrict it: `setFee(...) external onlyOwner` (or an AccessControl role).

```solidity
function setFee(uint256 bps) external {
        feeBps = bps;
    }
```

#### 4. [MEDIUM] SOL-006 — Missing access control on 'setOracle'

- **Location:** `tests/fixtures/vulnerable/MissingAccessControl.sol:23` in `setOracle()`
- **Confidence:** high
- **Issue:** 'setOracle' is external and mutates privileged state but carries no owner/role modifier and no msg.sender check in its body.
- **Fix:** Restrict it: `setOracle(...) external onlyOwner` (or an AccessControl role).

```solidity
function setOracle(address oracle) external {
        require(oracle != address(0), "zero oracle");
        owner = oracle;
    }
```

### `tests/fixtures/vulnerable/Reentrancy.sol`

#### 1. [CRITICAL] SOL-001 — Reentrancy: state written after external call

- **Location:** `tests/fixtures/vulnerable/Reentrancy.sol:16` in `withdraw()`
- **Confidence:** high
- **Issue:** 'withdraw' performs an external call to msg.sender and only updates state afterwards; a malicious callee can re-enter before the balance/flag is updated.
- **Fix:** Apply checks-effects-interactions: update state before the call, and add a nonReentrant guard.

```solidity
(bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
```

### `tests/fixtures/vulnerable/RoundingShare.sol`

#### 1. [MEDIUM] SOL-004 — Precision loss: division before multiplication

- **Location:** `tests/fixtures/vulnerable/RoundingShare.sol:12` in `deposit()`
- **Confidence:** medium
- **Issue:** 'deposit' divides before multiplying (assets / 1000 * ...), truncating the intermediate result and losing value on small amounts.
- **Fix:** Multiply first, then divide: (a * b) / c, and round in the protocol's favour.

```solidity
uint256 fee = assets / 1000 * 3;
        uint256 net = assets - fee;
```

#### 2. [MEDIUM] SOL-004 — Precision loss: division before multiplication

- **Location:** `tests/fixtures/vulnerable/RoundingShare.sol:14` in `deposit()`
- **Confidence:** medium
- **Issue:** 'deposit' divides before multiplying (net / totalAssets * ...), truncating the intermediate result and losing value on small amounts.
- **Fix:** Multiply first, then divide: (a * b) / c, and round in the protocol's favour.

```solidity
minted = totalShares == 0 ? net : net / totalAssets * totalShares;
        shares[msg.sender] += minted;
```

#### 3. [MEDIUM] SOL-004 — Precision loss: division before multiplication

- **Location:** `tests/fixtures/vulnerable/RoundingShare.sol:21` in `previewFee()`
- **Confidence:** medium
- **Issue:** 'previewFee' divides before multiplying (assets / 10000 * ...), truncating the intermediate result and losing value on small amounts.
- **Fix:** Multiply first, then divide: (a * b) / c, and round in the protocol's favour.

```solidity
return assets / 10000 * 30;
    }
```

### `tests/fixtures/vulnerable/SelfDestruct.sol`

#### 1. [HIGH] SOL-008 — Unprotected selfdestruct

- **Location:** `tests/fixtures/vulnerable/SelfDestruct.sol:14` in `shutdown()`
- **Confidence:** high
- **Issue:** 'shutdown' can destroy the contract and forward its balance without any owner/role check.
- **Fix:** Gate destruction behind onlyOwner + a timelock, or remove selfdestruct entirely.

```solidity
selfdestruct(payable(msg.sender));
    }
```

### `tests/fixtures/vulnerable/TxOriginAuth.sol`

#### 1. [HIGH] SOL-003 — Authorization via tx.origin

- **Location:** `tests/fixtures/vulnerable/TxOriginAuth.sol:15` in `changeOwner()`
- **Confidence:** high
- **Issue:** tx.origin authenticates the transaction's origin EOA, so a phished user can be made to call an attacker contract that passes the check on their behalf.
- **Fix:** Use msg.sender for authorization (or a signed permit / EIP-712 nonce).

```solidity
require(tx.origin == owner, "not owner");
        owner = next;
```

#### 2. [HIGH] SOL-003 — Authorization via tx.origin

- **Location:** `tests/fixtures/vulnerable/TxOriginAuth.sol:20` in `withdrawCredit()`
- **Confidence:** high
- **Issue:** tx.origin authenticates the transaction's origin EOA, so a phished user can be made to call an attacker contract that passes the check on their behalf.
- **Fix:** Use msg.sender for authorization (or a signed permit / EIP-712 nonce).

```solidity
require(tx.origin == msg.sender, "no contracts");
        uint256 amount = credit[msg.sender];
```

### `tests/fixtures/vulnerable/UncheckedCall.sol`

#### 1. [HIGH] SOL-002 — Unchecked low-level call return value

- **Location:** `tests/fixtures/vulnerable/UncheckedCall.sol:12` in `payout()`
- **Confidence:** high
- **Issue:** Return value of call() in 'payout' is ignored, so a failing transfer/execution continues silently.
- **Fix:** Capture the bool: (bool ok, ) = ...; require(ok, "call failed");

```solidity
payable(to).call{value: amount}("");
    }
```

#### 2. [HIGH] SOL-002 — Unchecked low-level send return value

- **Location:** `tests/fixtures/vulnerable/UncheckedCall.sol:16` in `tip()`
- **Confidence:** high
- **Issue:** Return value of send() in 'tip' is ignored, so a failing transfer/execution continues silently.
- **Fix:** Capture the bool: (bool ok, ) = ...; require(ok, "send failed");

```solidity
to.send(1 ether);
    }
```

#### 3. [HIGH] SOL-002 — Unchecked low-level call return value

- **Location:** `tests/fixtures/vulnerable/UncheckedCall.sol:20` in `forward()`
- **Confidence:** high
- **Issue:** Return value of call() in 'forward' is ignored, so a failing transfer/execution continues silently.
- **Fix:** Capture the bool: (bool ok, ) = ...; require(ok, "call failed");

```solidity
target.call(payload);
    }
```

### `tests/fixtures/vulnerable/UncheckedMath.sol`

#### 1. [MEDIUM] SOL-004 — Arithmetic inside unchecked block

- **Location:** `tests/fixtures/vulnerable/UncheckedMath.sol:10` in `sum()`
- **Confidence:** high
- **Issue:** 'sum' does arithmetic inside unchecked { }; overflow/underflow will wrap without revert.
- **Fix:** Remove the unchecked block, or prove the bound with an explicit require before the math.

```solidity
unchecked {
            for (uint256 i = 0; i < values.length; i++) {
                acc += values[i];
```

### `tests/fixtures/vulnerable/UnprotectedInit.sol`

#### 1. [CRITICAL] SOL-005 — Unprotected initializer

- **Location:** `tests/fixtures/vulnerable/UnprotectedInit.sol:12` in `initialize()`
- **Confidence:** high
- **Issue:** 'initialize' is public and has no initializer modifier or one-shot guard; anyone can call it again to reset owner/state (or front-run deployment in a proxy setup).
- **Fix:** Add OpenZeppelin's `initializer` modifier (and `_disableInitializers()` in the constructor).

```solidity
function initialize(address _owner, address _treasury) public {
        owner = _owner;
        treasury = _treasury;
        feeBps = 30;
    }
```

---

*Generated by solsec-lint — static pattern analysis, no execution, no paid APIs.*
