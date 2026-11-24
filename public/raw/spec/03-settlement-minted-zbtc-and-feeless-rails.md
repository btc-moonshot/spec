# Part 3: Settlement Contract, Atomic Treasury `zBTC`, Plasma & Peg-Free Rails

**Document Class:** Normative L1 Settlement, Tokenomics & Peg-Free Application Specification (`v2.5.0-rfc`)  
**Upstream Baselines:** `Project Zeno/spec/SPEC.md` v1.6.0, `GENERALIZED-AUTHORIZATION-BRIDGE-FRAMEWORK.md` v0.3.2, `MINTED Settlement Extension` v0.1.1 (subject to Upstream Amendments in [`SPEC.md §6`](../SPEC.md#L110-L122)), `go-zenon` `origin/release/0.0.11-rc1` (`f19955f`) / `origin/dev` (`770e893`)  
**Contract Address:** `SettlementContract` ([`spec/05 §5.1`](./05-go-zenon-upgrade-plan.md#L68-L72))  
**Numeric Oracle:** [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py).

---

## 1. Atomic Treasury Pre-Mint Issuance Model (Resolving C-11, R2-M2, R3-L11, A-MINT-1)

In `go-zenon` `release/dev`, embedded contracts execute inside per-account `AccountVmContext`s (`vm/vm_context/interfaces.go:12-37`), committed peer storage is read-only (`chain/store/momentum.go:51`), `dev:vm/vm.go:204-226` requires embedded→embedded `ContractSend`s to target a valid ABI method (data-less sends like `dev:vm/embedded/implementation/token.go:163-172` fail `applySend`), and `TokenContract.Burn` permits `Owner` to burn even when `IsBurnable == false` (`dev:vm/embedded/implementation/token.go:330`).

1. **Step 1 — `SettlementContract.InitiateMintedToken("ZenonBitcoin", "zBTC", domain, 8, 21_000_000*10^8)`** (Governance, attaches `1 ZNN`):
   - Emits descendant `ContractSend` (`1 ZNN`) calling `TokenContract.IssueMinted(...)`.
   - `TokenContract.IssueMinted` requires `sendBlock.Address == types.SettlementContract`, exempts `checkToken` regexes (`dev:vm/embedded/implementation/token.go:40,43`) ONLY for this method, sets `TotalSupply = MaxSupply = 21M*10^8`, `IsMintable = false`, `IsBurnable = false`, `Owner = types.SettlementContract`, and emits descendant `ContractSend` with `Data = ABISettlement.PackMethod("ReceiveTreasury")`.
   - **`SettlementContract.ReceiveTreasury()`**: Enforces `sendBlock.Address == types.TokenContract`, `TreasuryInitialized == 0` (single-use), `sendBlock.Amount == 21_000_000 * 10^8`, and stores immutable `TreasuryZts = sendBlock.TokenStandard` + `TreasuryInitialized = 1`.
   - **Sealing `TokenContract`**: `TokenContract.UpdateToken` AND `TokenContract.Burn` reject if `tokenInfo.Owner == types.SettlementContract`.
2. **Step 2 — `SettlementContract.BindMintedAsset(domainId, zbtcZts, ...)`** (Governance, after full exit window):
   - Verifies `TreasuryInitialized == 1 && zbtcZts == TreasuryZts`, reads committed `TokenContract` store, verifies `SettlementContract.Balance(zbtcZts) == MaxSupply`, enforces tuple/asset injectivity, initializes `AssetRegistry` + `CustodyRecord`, and appends initial `GOVERNANCE_ADD_BINDING` (`0x0E`).
3. **Single-Receive Atomic Transfers**:
   - **Mint (`MINTED_LOCK_V1`, `MINTED_REFUND_V1`)**: Descendant `ContractSend` from treasury to user (`dev:vm/vm.go:204-247`).
   - **Burn (`RequestPegOut`)**: User sends `zBTC` to `SettlementContract`; returned atomically to treasury.
   - **Exact L1 Invariant**: `SettlementContract.Balance(zBTC) + CustodyRecord.RepresentationOutstanding == 21,000,000 * 10^8`.

---

## 2. `SettlementContract` Storage, Per-Domain Input Sequencing & Never-Reused Batches

### 2.1 Storage Key Prefixes (`SettlementContract` Account Storage)

| Prefix | Entity | Storage Key | Contents |
|---|---|---|---|
| `0x01` | `DomainRecord` | `0x01 \|\| domainId(u32)` | `domainClass`, `runtimeKind`, `stfSpecHash`, `genesisStateRoot(32B)`, `inputSource`, `execProfile`, `foreignProfile`, `proposerPolicy`, `finalityModel`, `status(0=ACTIVE\|1=PAUSED)`, `dispatchFrozenByBatch(u64, 0=none)`, `lastFinalizedTipHeight(u64)`, `nextBatchId(u64, starts at 1)`, `lineageHeadBatchId(u64, 0=genesis sentinel)`, `aggregateInFlightMint(u256)` |
| `0x02` | `GlobalInputCounter` | `0x02` | `nextGlobalInputIndex(u64)` (global monotonic across ALL domains) |
| `0x03` | `DomainInputBySeq` | `0x03 \|\| domainId(u32) \|\| domainInputSeq(u64)` | Contiguous per-domain record: `globalInputIndex(u64) \|\| inputKind(u8: 6\|7) \|\| inputHash(32B) \|\| sourceBlockHash(32B) \|\| momentumTs(u64) \|\| spamDepositZnn(u64) \|\| submitterAddr(20B)` (+ system payload for `kind=7`) |
| `0x04` | `DomainCursor` | `0x04 \|\| domainId(u32)` | `nextDomainInputSeq(u64)`, `lastBatchedSeq(u64)`, `lastFinalizedSeq(u64)` |
| `0x05` | `BatchCommitment` | `0x05 \|\| domainId(u32) \|\| batchId(u64)` | `BatchCommitmentV3` + `state(0=CHALLENGE_OPEN\|1=FINALIZED\|2=REJECTED)` + `challengeDeadlineTs(u64)` + `activeChallengeSessions(u32)` + `activeChallengeCommits(u32)` + `dupRefundsClaimed(u16 <= 16)` |
| `0x06` | `AssetRegistry` | `0x06 \|\| domainId(u32) \|\| assetId(32B)` | `custodyMode`, `foreignChainId`, `foreignAssetRef`, `decimalsPolicy`, `maxRepresentationSupply`, `maxBatchMint`, `maxInFlightMintPerExecutor`, `maxAggregateInFlightMint`, `activeChainBindingHash`, `activeVaultUtxoCount(u64)`, `unrotatedVaultCount(u64)` (`R5-H3`), `bindingState`, `drainStopBitcoinHeight`, `drainGuardianExpiryTs`, `status` |
| `0x07` | `AssetReverseIndex` | `0x07 \|\| assetId(32B)` | `domainId(u32)` |
| `0x08` | `ForeignTupleIndex` | `0x08 \|\| SHA3-256(domainId \|\| foreignChainId \|\| foreignAssetRef)` | `assetId(32B)` |
| `0x09` | `CustodyRecord` | `0x09 \|\| domainId(u32) \|\| assetId(32B)` | `ESCROW` fields (`0`); `representationOutstanding`, `pendingForeignRelease`, `verifiedLockedCollateral`, `cumulativeProvenLocks`, `cumulativeMinted`, `cumulativeBurned`, `cumulativeReleased`, `cumulativeRefunded` |
| `0x0A` | `VaultUtxoSet` | `0x0A \|\| domainId(u32) \|\| outpoint(36B)` | `amount(u64) \|\| setupChainBindingHash(32B) \|\| epochEntries[<=2]{epochId(u16), eligibleOperatorsBitmask(u64), takeTxidsSmtRoot(32B)} \|\| status(0=UNASSIGNED\|1=ASSIGNED\|2=PENDING_TRAP\|3=RELEASED\|4=RECOVERED\|5=QUARANTINED\|6=ORPHANED) \|\| quarantineReason(0=NONE\|1=RECOVERY\|2=UNROTATED) \|\| assignedOutboxId(32B)` (**R6-L3**) |
| `0x0B` | `ClaimPolicy` | `0x0B \|\| domainId(u32) \|\| policyVersion(u32)` | `purpose`, `activationHeight`, `exitDelay`, exact 3-capability table |
| `0x0C` | `ProcessedClaim` | `0x0C \|\| claimId(32B)` | `u8(1)` (permanent) |
| `0x0D` | `ProcessedForeignEvent` | `0x0D \|\| domainId(u32) \|\| foreignEventId(32B)` | `u8(1)` (permanent) |
| `0x0E` | `ClaimReceipt` | `0x0E \|\| claimId(32B)` | `handlerId(32B) \|\| effectHash(32B) \|\| dispatchHeight(u64) \|\| custodyDigest(32B)` |
| `0x0F` | `PegOutRecord` | `0x0F \|\| outboxId(32B)` | Immutable authorization + `assignedVaultOutpoint(36B)` + `setupChainBindingHash(32B)` + `slotOperatorId(u32)` + `lastLapsedOperatorId(u32)` + `slotClaimZenonTs(u64)` + `slotExpiryBtcHeight(u64)` + `slotBondLockedZnn(u64)` + `reservedEpochLane(u16,u8)` + `reimbursementOperatorId(u32)` + `reimbursementRoundId(u32)` + one-way `state(0=PENDING\|1=RELEASED\|2=REFUNDED)` (**R6-M2/M4/M5**) |
| `0x10` | `PegOutNonce` | `0x10 \|\| domainId(u32)` | `u64` |
| `0x11` | `ExecutorRegistration` | `0x11 \|\| domainId(u32) \|\| executorAddr(20B)` | `znnBond(u256)`, `qsrBond(u256)`, `inFlightMintExposure(u256)`, `status`, `unbondUnlockTs(u64)` |
| `0x12` | `OperatorRegistry` | `0x12 \|\| domainId(u32) \|\| operatorId(u32)` | `operatorAddr(20B)`, `znnBond(u256 >= 31,500 ZNN)`, `qsrBond(u256)`, `active(u8)`, `slashed(u8)` + **`OperatorLaneState[opId\|\|u16(epochId)\|\|lane] = {anchorCutoffTs, anchorExpiryTs, nextUnusedIdx(0..8), nextEligibleKickoffTs, pendingReservations(u16), retired(u8)}`** + `RoundUsed[opId\|\|roundId]` (**R6-M2**) |
| `0x13` | `VerifierRegistry` | `0x13 \|\| verifierRef(32B)` | `kind`, `verifyingKeyId`, `active` |
| `0x14` | `ChallengeSession` | `0x14 \|\| sessionId(32B)` | Multi-Tx Witness accumulator `(batchId, batchTraceRoot, openTs, expiryTs = openTs + 43200s)` + `CommitChallenge` (`commitHash`, `revealDeadlineTs = commitTs + 3600s`) |
| `0x15` | `InputDepositClaimed` | `0x15 \|\| domainId(u32) \|\| domainInputSeq(u64)` | `u8(1)` |
| `0x16` | `DeferredLockQueue` | `0x16 \|\| claimId(32B)` | Validated lock claim deferred during pause / supply cap / `G-21` / missed-rotation pause |
| `0x17` | `PeripheryConfig` | `0x17` | `governanceContract`, `guardianMultisig`, `treasuryInitialized`, `treasuryZts`, `minOperatorBondZnn`, `softDelaySecs`, `exitWindowSecs`, `inputSpamDepositZnn`, `challengeDepositZnn` |

### 2.2 Canonical `BatchCommitmentV3` & Inductive Per-Leaf Accumulators (`328 B`)

**`ChallengeAggregation` is DELETED.** Every batch-level aggregate is committed via complete mathematical induction inside `StepTraceLeaf[0..inputCount-1]` (`MaxBatchInputs = 256`, `traceRoot` depth `<= 8`, **`328 B`** fixed per leaf), and `RelayClaim` routes directly through `traceRoot`:

```text
StepTraceLeaf (328 bytes fixed) :=
    domainInputSeq      : u64       // MUST equal batch.FirstInputSeq + stepIndex
    preRoot             : bytes32
    postRoot            : bytes32
    stepClaimsRoot      : bytes32   // domain-separated Merkle root of claim emitted by THIS step (0..1 claim)
    stepClaimCount      : u8        // 0 or 1
    stepLockAmount      : u256
    stepReleaseAmount   : u256
    stepNonDelivAmount  : u256
    stepHalted          : u8
    stepHaltedHeight    : u64
    cumLockAmount       : u256
    cumReleaseAmount    : u256
    cumNonDelivAmount   : u256
    cumClaimCount       : u32
    haltedSoFar         : u8
    haltedHeightSoFar   : u64
    observedTipAfter    : u64
    stepError           : u8        // 0=ok, 1=malformed error, 2=idempotent duplicate no-op (capped <=16 global/batch)

BatchCommitmentV3 :=
    protocolVersion     : u16 (2)
    commitmentVersion   : u16 (3)
    domainId            : u32
    batchId             : u64       // NEVER reused monotonic ID
    parentBatchId       : u64       // MUST equal domain.lineageHeadBatchId (0 = genesis sentinel)
    policyVersion       : u32
    firstInputSeq       : u64
    lastInputSeq        : u64       // == firstInputSeq + inputCount - 1
    inputCount          : u32       // 1 <= inputCount <= MaxBatchInputs (256)
    preStateRoot        : bytes32
    postStateRoot       : bytes32
    traceRoot           : bytes32
    inputRoot           : bytes32
    receiptRoot         : bytes32
    eventRoot           : bytes32
    outboxRoot          : bytes32   // MUST be zero32 for AUTHORIZATION domain
    observedChainHeight : u64
    domainHalted        : u8
    haltedReorgHeight   : u64
    daHash              : bytes32
    daMode              : u8
    executorId          : bytes20
    submittedAtHeight   : u64
    submittedAtTs       : u64
    assetFlowSummary    : Bytes     // MUST be empty
    claimEffectSummary  : List<ClaimEffectEntry>
    proofData           : Bytes     // MUST be empty for OPTIMISTIC at submit
```

---

## 3. Atomic State Transitions, Reachability `G-21` & Aligned Cross-Store Vault State Machine

### 3.1 `SubmitInput` — ALWAYS Open & Global Duplicate Refund Cap

`SubmitInput` is accepted in BOTH `ACTIVE` AND `PAUSED`, requires `len(payload) <= 15,600 B` and `0.1 ZNN` spam deposit, assigns monotonic `globalInputIndex` AND contiguous per-domain `domainInputSeq`, and supports trustless `ClaimInputDepositRefund` (`stepError == 0` always refundable; `stepError == 2` refundable while `batch.DupRefundsClaimed < 16` globally; `stepError == 1` forfeited).

### 3.2 `SubmitBatch`, `FinalizeBatch`, Bounded Sessions & Commit-Reveal

- `SubmitBatch`: Enforces `RANDOM_BACKUP`, monotonic `batchId`, `parentBatchId == lineageHeadBatchId`, `PreStateRoot` chaining, `finalLeaf` binding, per-executor + `10.0 BTC` aggregate in-flight caps, and dispatch-only `dispatchFrozenByBatch`.
- `FinalizeBatch`: Permitted in `ACTIVE` AND `PAUSED` (Shadow Mode); exempts `batchId == dispatchFrozenByBatch`; rejects while `ActiveChallengeSessions > 0 || ActiveChallengeCommits > 0` or parent unfinalized; releases `inFlightMintExposure` & `aggregateInFlightMint`.
- Challenges: Mandatory `ChallengeDepositZnn` (`10%` executor bond), `CommitChallenge` (`T_reveal = 1h`, 6-momentum priority), `ChallengeContinuity` (`1,700 B`), 1-tx `ChallengeStep`, bounded Multi-Tx Sessions (`T_session = 12h`, `UploadWitnessProof = 8,676 B` @ depth 256, re-verifies `(State, traceRoot, leaf)` at `ExecuteChallenge`), permissionless expiry cleanup, and `RefundRejectedBatchChallenge` refunding deposits on ancestor-rejected descendants.

### 3.3 Complete Aligned Cross-Store Vault State Machine (`R6-M2`, `R6-M3`, `R6-L3`, `R6-L4`)

| Event / Call | Domain `TrackedVaultRecord` (`0x08`) | Settlement `VaultUtxoSet` (`0x0A`) | Guard / Invariant |
|---|---|---|---|
| `BTC_LOCK_PROOF` → `MINTED_LOCK_V1` | `∅ → ACTIVE` (`activeEpochs=[{g, smtRoot}]`) | `∅ → UNASSIGNED` (`quarantineReason=NONE`, `epochEntries=[{g, mask, smtRoot}]`) | Enforces latency-aware `G-21` + `unrotatedVaultCount == 0` |
| `VAULT_GRAPH_EPOCH_ADDED` (`0x0D`) → `SyncVaultGraphEpoch` | `ACTIVE/RELEASED → same` (adds `g+1`); `QUARANTINED → ACTIVE` | `UNASSIGNED/ASSIGNED/RELEASED(ReimbRound==0) → same` (adds `g+1`); `QUARANTINED → UNASSIGNED/ASSIGNED` (**decrements `unrotatedVaultCount--` iff `quarantineReason == UNROTATED`!**) | Strict no-dup / `<= 2` active epochs (`R6-L2`); `RECOVERY` vaults NEVER touch `unrotatedVaultCount` (`R6-L3`)! |
| `QuarantineExpiredVault(outpoint)` (`now >= T_cutoff(g) + 60h`) | *(n/a)* | **`UNASSIGNED\|ASSIGNED → QUARANTINED`** (`quarantineReason=UNROTATED`, **`unrotatedVaultCount++`**) | Permissionless after `60h` finalization grace (`day 48.5`) if vault lacks live next-epoch graph; pauses new mints (`R6-L3`, `R6-L4`) |
| `RequestPegOut` | *(unchanged: `ACTIVE`)* | `UNASSIGNED → ASSIGNED` | Requires `status == UNASSIGNED` AND `>= 1` live epoch `e` with eligible op having `ReachableRounds(e, now + 3.0d) - pendingReservations >= 1` (`R6-M2`) |
| `BTC_RELEASE_PROOF` → `MINTED_RELEASE_V1` | `ACTIVE → RELEASED`; **`PENDING_TRAP/RECOVERED` preserved (ADMITS `FOREIGN_RELEASE`!)** | `ASSIGNED → RELEASED` (or leaves `PENDING_TRAP/RECOVERED` for `RepointTrappedPegOut`!) | **Keys `ReimbursementOperator` strictly from domain `FOREIGN_RELEASE.operatorId` (`R6-M4`); NEVER strands honest fronter (`R6-M3`)!** |
| `RepointTrappedPegOut(outboxId, newVaultOutpoint)` (`R6-M3`) | *(reads re-graphed `RecoveryVaultUTXO` or `UNASSIGNED` vault)* | Re-points `PegOutRecord.assignedVaultOutpoint` from `PENDING_TRAP\|RECOVERED` vault to re-graphed recovery vault or next `UNASSIGNED` vault | Permissionless once `PegOutRecord.State == RELEASED && ReimbursementRoundId == 0 && oldVault ∈ {PENDING_TRAP, RECOVERED}` |
| `BTC_NON_DELIVERY_PROOF` → `MINTED_REFUND_V1` | *(unchanged)* | **`ASSIGNED → UNASSIGNED`** *(IF `PENDING_TRAP`, `RECOVERED`, or `QUARANTINED`, refunds user ONLY — NEVER overwrites vault status!)* | Releases any held lane reservation; eliminates overwrite (`R5-M3`, `R6-L3`) |
| `BTC_VAULT_SPEND_PROOF` (SMT inclusion) → `SyncPendingTrapVault` | `ACTIVE → PENDING_TRAP(h_spend)` | `UNASSIGNED/ASSIGNED → PENDING_TRAP` | Mirrors `PENDING_TRAP` to Settlement so vault is non-assignable |
| `BTC_VAULT_RECOVERY_PROOF` → `SyncRecoveredVaultOutpoint` | `ACTIVE\|PENDING_TRAP → RECOVERED`; inserts `recOut` as `QUARANTINED`; writes `RecoveredVaultMap[old] = {recOut, opId, roundId}` | `old → RECOVERED`; inserts `recOut` as **`QUARANTINED (reason=RECOVERY)`** *(does NOT touch `unrotatedVaultCount`!)* | Cancels `PENDING_TRAP` with zero halt; `recOut` unassignable until `SyncVaultGraphEpoch`! |
| `SyncOrphanedVaultOutpoint(outboxId_X, oldOutpoint_d)` | *(reads `RecoveredVaultMap[oldOutpoint_d]`)* | **`RELEASED → ORPHANED`** | Deterministically checks `RecoveredVaultMap[d].(opId, roundId) == PegOutRecord[X].(reimbursementOpId, reimbursementRoundId)` |

### 3.4 `RelayClaim`, Latency-Aware `G-21`, Anti-Censorship Fronting & Reimbursement (`R6-M2..M5`, `R6-L6`, `R6-L8`)

- **`RelayClaim` (`MINTED_LOCK_V1`)**: Enforces **Latency-Aware, Reservation-Aware Dynamic Reachable Capacity (`G-21`, `R6-M2`, `R6-L9`)**: requires `unrotatedVaultCount == 0` AND `ActiveVaultUTXOs + 1 <= Σ_{m,e,l} ReachableRounds(m, e, l, now + 3.0d) - 25`, where `ReachableRounds = 0` if lane retired or `max(now + 3.0d, nextEligibleKickoffTs) > anchorCutoffTs`, else `max(0, min(8 - nextUnusedIdx, floor((anchorCutoffTs - max(now + 3.0d, nextEligibleKickoffTs)) / 5.5d) + 1) - pendingReservations)`! Defers smoothly to `DeferredLockQueue` during pause / supply cap / the disclosed `~5.0d` pre-epoch window before gen `g+1` registers (`DispatchDeferredLock`).
- **`ClaimFrontingSlot(outboxId, epochId, lane)` (`R6-M2`, `R6-M4`, `R6-M5`)**:
  - Requires `PegOutRecord.State == PENDING` AND `VaultUtxoSet[assignedOutpoint].status == ASSIGNED`.
  - **Single-Authority Expiry (`R6-M4`)**: Rejects while `po.SlotOperatorId != 0 && (frontier.TimestampUnix < po.SlotClaimZenonTs + 14_400 || DomainRecord.LastFinalizedTipHeight < po.SlotExpiryBtcHeight)`!
  - **Anti-Censorship (`R6-M5`)**: If a previous slot expired unfulfilled, slashes `100%` of the lapsed holder's **`SlotBondZnn = 500 ZNN`** (`SlashLapsedSlot` also callable permissionlessly!), decrements the lapsed holder's `pendingReservations--`, records `po.LastLapsedOperatorId = oldSlotOp`, and **rejects consecutive re-claim by `po.LastLapsedOperatorId`** (while any other eligible operator exists)!
  - **Reservation & Latency Check (`R6-M2`)**: Requires caller is eligible in `epochId` on `assignedOutpoint`, `ReachableRounds(caller, epochId, lane, now + 3.0d) >= 1` (accounting for `pendingReservations`), locks `500 ZNN` `SlotBondZnn`, increments `lane.pendingReservations++`, records `{SlotOperatorId, SlotClaimZenonTs, SlotExpiryBtcHeight = LastFinalizedTipHeight + 24, reservedEpochLane}`, and appends `PEGOUT_SLOT_CLAIMED` (`0x0A`).
- **`RegisterOperatorRound(opId, roundId, bondOutpoint, anchorCutoffTs, anchorExpiryTs, commSig)` (`R6-L6`)**: Requires `OperatorBond_ZNN >= MinOperatorBondZnn` (`31,500 ZNN`), `epoch := epoch(roundId) < 4096`, **`anchorExpiryTs == finalityEpochStartTs(epoch) + 58 days`** (exact equality!), `anchorCutoffTs == anchorExpiryTs - 12 days`, verified `CommitteeIdentityKey` sig; initializes `OperatorLaneState` and appends `OPERATOR_ROUND_REGISTERED` (`0x0B`).
- **`SyncRetiredLane(domainId, opId, epochId, lane, batchId, smtProof)`**: Permissionless; verifies `LaneRetired[opId || u16(epochId) || lane] == 1` (`0x11`) under finalized `postStateRoot` and sets `OperatorLaneState.retired = 1`, zeroing remaining capacity!
- **`ClaimReimbursementSlot(outboxId, opId, roundId)` (`R6-M2`, `R6-L8`)**: Callable ONCE by winning `opId` (`== PegOutRecord.ReimbursementOperatorId`, set from `FOREIGN_RELEASE`) after `PegOutRecord.State == RELEASED`; requires: (1) `epoch(roundId)` exists in `VaultUtxoSet[assignedOutpoint].epochEntries` with `opId`'s bit set, (2) lane is NOT retired and `idx(roundId) == lane.nextUnusedIdx`, (3) `RoundUsed[opId || roundId]` absent, and (4) `earliestKickoff := max(frontier.TimestampUnix, lane.nextEligibleKickoffTs) <= lane.anchorCutoffTs`! Decrements `pendingReservations--` (if reserved on this lane), advances `lane.nextUnusedIdx++`, sets `lane.nextEligibleKickoffTs = earliestKickoff + 5.5 days`, marks `RoundUsed = 1`, and writes `PegOutRecord.ReimbursementRoundId = roundId`! *(Recovery per `R6-L8`: if the claimed round expires/burns without operator fraud — e.g. slow blocks `> 1.476x` or fee spike `> 500 sat/vB` — Governance or deterministic proof of `StaleKilled`/`RoundRetired` with `assignedOutpoint` unspent invokes **`ResetFailedReimbursementSlot(outboxId, proof)`** clearing `ReimbursementRoundId = 0` so the honest operator may re-claim a fresh-epoch round!)*
- **`SlashOperatorBond(domainId, opId, batchId, smtProof)`**: Slashes `100%` of `OperatorBond_ZNN/QSR` (`>= 31,500 ZNN`), sets `active = 0`, and zeroes all remaining capacity across ALL lanes of `opId`.
- **Bounded Guardian Drain**: Guardian-initiated `DRAINING_ROLLOVER_STOP` carries mandatory `7-day` governance timer and NEVER blocks `RequestPegOut`.

---

## 4. Feeless Plasma, SHA3-256 PoW & Priority Lane Economics

- Standard `zBTC` transfers cost **0 satoshis** and `21,000` Plasma (`10 QSR` refundable fusion or `31.5M` SHA3-256 PoW hashes at floor price).
- **Challenge Priority Lane**: `chain/account_pool.go` reserves `10` of `100` Momentum slots for Settlement challenge/finalize calls ordered strictly by `ChallengeDepositZnn` descending; paired with 48h (`+12h` session) window defense-in-depth.

---

## 5. Peg-Free Atomic Swaps & Lightning Submarine-Swap Gateway

### 5.1 PTLC Taproot MuSig2 Adaptor Atomic Swap (BIP-327 Tweaked)

**Protocol (Alice sells BTC, Bob sells `zBTC`; Bob holds secret $t$):**
1. **Setup**: Bob samples $t \in \mathbb{Z}_n^*$, sends compressed 33-byte point $T = \text{compress}(t \cdot G)$ to Alice.
2. **Bitcoin Funding (BIP-327 Tweaked Taproot)**: Compute $P_{\text{swap}} = \text{MuSig2\_KeyAgg}(pk_A, pk_B)$, Tapscript refund leaf $L_{\text{ref}} = \text{<12> OP\_CSV OP\_DROP <pk\_A> OP\_CHECKSIG}$, tweak $t_{\text{tap}} = H_{\text{"TapTweak"}}(x(P_{\text{swap}}) \parallel \text{TapLeaf}(L_{\text{ref}}))$, and tweaked key $Q_{\text{swap}} = P_{\text{swap}} + t_{\text{tap}} \cdot G$ with BIP-327 accumulated tweak `t_acc` and key parity `g_key`. Alice funds `0x51 0x20 || x(Q_swap)`. Let $h_{\text{conf}}$ be confirmation height and $T_{\text{btc\_worst}}$ correspond to $h_{\text{conf}} + 12$.
3. **Bob Locks `zBTC` FIRST**: **BEFORE Alice releases ANY partial signature**, Bob calls `PtlcContract.Create(expirationTime = T_znn, pointType = 2, pointLock = compress(T), destination = Alice_Addr)` (`dev:vm/embedded/definition/ptlc.go:114-120`) with `T_znn >= T_btc_worst + 6 hours` (`21,600s`). Wait until confirmed.
4. **Alice Verifies Zenon Lock & Exchanges BIP-327 Tweaked Adaptor Signatures**: Alice verifies the confirmed PTLC, exchanges MuSig2 nonces $(R_A, R_B)$, forms $R' = R_A + R_B + T$ with parity $g_R$, computes $e = H_{\text{BIP0340/challenge}}(x(R') \parallel x(Q_{\text{swap}}) \parallel m)$, exchanges $(\tilde{s}_A, \tilde{s}_B)$, and aggregates per **BIP-327 `PartialSigAgg`**:
   $$\tilde{s} = \tilde{s}_A + \tilde{s}_B + e \cdot g_{\text{key}} \cdot t_{\text{acc}} \pmod n$$
5. **Atomic Claim**: Bob completes $s = \tilde{s} + g_R \cdot t \pmod n$ and broadcasts $(x(R'), s)$ before $h_{\text{conf}} + 12$. Alice extracts $t_{\text{ext}} = g_R \cdot (s - \tilde{s}) \bmod n$, verifies $\text{compress}(t_{\text{ext}} \cdot G) == \text{PointLock}$, and calls `PtlcContract.Unlock(ptlcId, t_ext)` (`dev:vm/embedded/implementation/ptlc.go:82-95`).

### 5.2 HTLC Atomic Swaps & Lightning Network Submarine-Swap Gateway (`hashType = 1` SHA256)

- **ALL** Bitcoin/Lightning HTLCs pass **`hashType = 1` (`HashTypeSHA256`, `dev:vm/embedded/definition/htlc.go:92`)**.
- **Inbound (LN → `zBTC`)**: User pays Gateway's LN Hold Invoice FIRST; ONLY AFTER Hold Invoice reaches `ACCEPTED` with CLTV `>= now + 2 * Δ_safety` does Gateway lock `zBTC` in `HtlcContract` (`T_znn <= T_ln - Δ_safety`).
- **Outbound (`zBTC` → LN)**: User locks `zBTC` (`hashType = 1`); Gateway pays BOLT-11 invoice (`T_ln <= T_znn - Δ_safety`), learns $r$, unlocks `zBTC`.
- **Mandatory Conformance Vectors (G-18)**: Signet↔Zenon tests for claim-then-reclaim rejection, odd-$y(R')$ parity, BIP-327 `PartialSigAgg` Taproot spend, `hashType = 0` rejection, Bob-locks-first ordering, and inbound LN Hold Invoice `ACCEPTED`-first enforcement.
