# Part 2: Bitcoin Authorization Domain (`d_btc_asset`) & Adversarially-Bounded SPV Verifier

**Document Class:** Normative Chain Specialization (`v2.5.0-rfc`, subject to Upstream Amendments `A-SPEC-1`, `A-SPEC-2`, `A-SPEC-6`, `A-BTC-1` in [`SPEC.md §6`](../SPEC.md#L110-L122))  
**Target Domain:** `d_btc_asset` (`domainClass = AUTHORIZATION`, `purpose = ASSET`)  
**Shared Implementation Mandate:** Deterministic, panic-free Go package `vm/embedded/btcspv/` executed identically by `zenon-executor` and `SettlementContract` fraud adjudication (`OPTIMISTIC_BTC_SPV_V1`).  
**Numeric Oracle:** [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py).

---

## 1. Domain Registration, `ChainBinding` & Parameters

> **Upstream Activation Blocker (`A-SPEC-1` / `A-SPEC-6`):** Requires Phase-2 ratification activating `inputSource = L1_RELAYED`, `input_kind` `6`/`7`, and reconciling `domainClass = AUTHORIZATION` & `finalityModel = CHALLENGE_WINDOW` / `PROOF_VERIFIED`.

```text
DomainRecord {
    domainId        = <assigned u32>
    domainClass     = AUTHORIZATION     // enum ordinal 1 (A-SPEC-6)
    runtimeKind     = BTC_SPV_V2        // panic-free deterministic Go plugin
    stfSpecHash     = SHA3-256(canonical(runtimeKind || chainBinding || claimPolicy || decimalsPolicy || profileConfig))
    inputSource     = L1_RELAYED        // enum ordinal 1 (A-SPEC-1)
    execProfile     = OPTIMISTIC        // enum ordinal 1
    foreignProfile  = LIGHT_CLIENT      // enum ordinal 2
    proposerPolicy  = RANDOM_BACKUP     // upstream enum (0=SINGLE, 1=RANDOM_BACKUP, 2=STAKE_WEIGHTED)
    finalityModel   = CHALLENGE_WINDOW  // enum ordinal 1
    status          = PAUSED            // 0=ACTIVE, 1=PAUSED (Shadow Mode: SubmitInput/SubmitBatch/Challenge/FinalizeBatch OPEN)
}

ChainBinding {
    foreignChainId      : ChainId    // u16(0x0001) || bytes30(SHA3-256("BTC_MAINNET_V1" || btcGenesisHashBE)[0:30])
    chainVerifierId     : bytes32    // SHA3-256("BTC_SPV_VERIFIER_V2.4" || reproducibleBuildDigest)
    genesisAnchor       : Bytes      // BitcoinAnchor { blockHashBE, height, header(80B), cumWork, retargetStartHash, retargetStartTime, retargetHeight, mtpWindow[11] }
    releaseAdapterRef   : Bytes      // { CommitteeIdentityKey(32B), qGraphXOnly(32B), committeeSizeN(u16>=7), vaultTweakTag("zBTC/VaultTweak/v1"), recoveryTweakTag("zBTC/RecoveryTweak/v1"), provisionalTimeoutBlocks(u16=144), bucketDenoms(List<u64>), vkBitvmHash(32B), fixedReserveFeeSats(u64), minOperatorFeeSats(u64), maxPegOutFeeSats(u64) }
    enforcementSpecHash : bytes32    // SHA3-256(activated BTC-ENFORCEMENT-V1 bytes); MUST be non-zero
    finalityParams      : Bytes      // BitcoinFinalityParams below
}
```

### 1.1 `BitcoinFinalityParams` (Asserted in `scripts/verify_spec_bounds.py`)

```text
BitcoinFinalityParams :=
    confirmationDepthK       : u32   // Pilot: 14; K >= max(12, ceil(2 * AggregateInFlightMint_BTC / S(h))). Passes pre-2028 (12) & post-2028 (13). Pre-2032: Governance MUST migrate to K>=26 OR lower cap <= 5 BTC (K>=13<=14)
    minimumPostAnchorWork    : u256
    retainedReorgDepth       : u32   // 144 blocks (stale HeaderNode pruning ONLY; ActiveChainByHeight NEVER pruned)
    maximumHeaderBatch       : u32   // 2 headers/input
    maximumMerkleBranchDepth : u32   // 16 levels (65,536 txs/block)
    maximumDepositTxBytes    : u32   // 4,096 B
    maximumRolloverTxBytes   : u32   // 1,024 B (2-input RolloverTx)
    maximumFrontingTxBytes   : u32   // 4,096 B
    maximumStreamChunkBytes  : u32   // 8,192 B per streaming SHA-256 chunk (zero 3rd-party coinbase/spend caps)
    maximumProofBytes        : u32   // 15,600 B (ABI <= 16,384 B)
    executionChallengeWindow : u64   // 172,800s (48h) + T_session 43,200s (12h) = 60h -> Poisson(360 * 1.10 [ASSUMED]) = 472 BTC blocks
    releaseTimeoutUnit       : u8    // 0 = DEST_HEIGHT
    minTimeoutAboveFinalTip  : u32   // 640 blocks
    maxTimeoutAboveFinalTip  : u32   // 2,512 blocks
    releaseSubmissionGrace   : u32   // 558 blocks (K(14) + 472 + 72 ≈ 93h)
    pendingTrapWindowBlocks  : u32   // 230 blocks (72 escrow + K(14) + 144 margin before BTC_TRAP_TIMEOUT_HALT)
    futureTimeGuardSecs      : u32   // 7,200s
    equalWorkTieBreak        : u8    // 0 = LOWEST_BLOCK_HASH_BE
```

### 1.2 `ClaimPolicy` (`btc_asset_claim_policy_v1` — Exact 3 Capabilities)

| `ClaimType` (0-based) | Name | `handlerId` | `Subject` | `Payload` |
|---|---|---|---|---|
| `0` | `FOREIGN_LOCK` | `SHA3-256("MINTED_LOCK_V1")` | 20B Zenon User Address (`[0]==0x00`) | 32B `ChainBindingHash ∈ RecognizedBindings` (`0x0E`) |
| `1` | `FOREIGN_RELEASE` | `SHA3-256("MINTED_RELEASE_V1")` | 32B `outboxId` | 32B `po.ChainBindingHash ∈ RecognizedBindings` |
| `2` | `FOREIGN_NON_DELIVERY` | `SHA3-256("MINTED_REFUND_V1")` | 32B `outboxId` | 32B `po.ChainBindingHash ∈ RecognizedBindings` |

---

## 2. Canonical Identifiers & Complete Field Definitions

```text
BitcoinOutpointID = SHA3-256("BTC_OUTPOINT_V1" || canonical(foreignChainId) || rolloverTxidBE || u32BE(0))
BitcoinReleaseEventID = SHA3-256("BTC_RELEASE_V1" || canonical(foreignChainId) || frontingTxidBE || u32BE(paymentVout))
BitcoinNonDeliveryEventID = SHA3-256("NON_DELIVERY" || po.ChainBindingHash || outboxId || ActiveChainByHeight[timeoutHeight + 558].blockHashBE)

BitcoinLockFinalityRef :=
    rolloverBlockHashBE      : bytes32
    rolloverBlockHeight      : u64
    rolloverTxIndex          : u32
    rolloverOutpoint         : bytes36    // rolloverTxidBE(32B) || u32BE(0)
    eligibleOperatorsBitmask : u64        // authenticated by CommitteeIdentityKey BIP-340 sig
    roundChainEpochId        : u16        // < 4096 (R5-L9)
    takeTxidsSmtRoot         : bytes32    // proof-format.md V1 SMT root of sorted released Take1/Take2 txids (R5-M1!)
    bestTipHashBE            : bytes32
    bestTipHeight            : u64
    bestTipChainWork         : u256
```

---

## 3. Canonical Domain Inputs (17 Tags — Zero 3rd-Party Size Caps!)

| Tag | Name | Source | Max Payload | Max ABI | Typical 1-Tx Fast Challenge ABI (`sib=26`) | Worst-Case Depth-256 (`Multi-Tx`) |
|---|---|---|---:|---:|---:|---:|
| `0x00` | `BTC_HEADER_BATCH` (`1..2` headers) | `SubmitInput` | `197 B` | `324 B` | `7,140 B` | `8,676 B` / proof |
| `0x01` | `BTC_REORG_STEP` (1 step) | `SubmitInput` | `1 B` | `132 B` | `6,340 B` | `8,676 B` / proof |
| `0x02` | `BTC_PRUNE_STEP` (`1..2` stale `HeaderNode`s) | `SubmitInput` | `65 B` | `196 B` | `4,388 B` | `8,676 B` / proof |
| `0x03` | `PEGOUT_CREATED` (`input_kind = 7`) | `RequestPegOut` | `190 B` | *(internal)* | `3,108 B` | `8,676 B` / proof |
| `0x04` | `BTC_TX_STREAM_CHUNK` (`<= 8 KiB` SHA-256 chunk) | `SubmitInput` | `8,234 B` | `8,356 B` | `3,300 B` | `8,676 B` / proof |
| `0x05` | `BTC_LOCK_PROOF` (`Dep` + 2-in `Rol` + 2 streams + `CommSig` + `takeSmtRoot` + `takeBlobHash`) | `SubmitInput` | `7,633 B` | `7,748 B` | `10,180 B` | `8,676 B` / proof |
| `0x06` | `BTC_RELEASE_PROOF` (`Fronting` + stream; decoupled from vault trap — **R6-M3**) | `SubmitInput` | `5,242 B` | `5,348 B` | `10,212 B` | `8,676 B` / proof |
| `0x07` | `BTC_NON_DELIVERY_PROOF` (`outboxId`) | `SubmitInput` | `33 B` | `164 B` | `6,212 B` | `8,676 B` / proof |
| `0x08` | `BTC_VAULT_SPEND_PROOF` (SMT absence/inclusion across `ACTIVE`/`RELEASED`/`QUARANTINED` — **R6-L5**) | `SubmitInput` | `2,142 B` | `2,244 B` | `7,396 B` | `8,676 B` / proof |
| `0x09` | `BTC_OPERATOR_SLASH_PROOF` (streamed `BondOut` burn) | `SubmitInput` | `1,183 B` | `1,284 B` | `8,292 B` | `8,676 B` / proof |
| `0x0A` | `PEGOUT_SLOT_CLAIMED` (`kind=7`, single-authority + anti-censorship — **R6-M4/M5**) | `ClaimFrontingSlot` | `48 B` | *(internal)* | `3,300 B` | `8,676 B` / proof |
| `0x0B` | `OPERATOR_ROUND_REGISTERED` (`CommSig` + exact epoch expiry equality — **R6-L6**) | `RegisterOperatorRound` | `125 B` | `228 B` | `3,108 B` | `8,676 B` / proof |
| `0x0C` | `BTC_VAULT_RECOVERY_PROOF` (`T1\|T2` → `QUARANTINED`, 10 keys incl. inserts — **S6-5**) | `SubmitInput` | `1,219 B` | `1,348 B` | `11,300 B` | `8,676 B` / proof |
| `0x0D` | **`VAULT_GRAPH_EPOCH_ADDED`** (`u16` epoch + `takeBlobHash` + `CommSig`, `ACTIVE`/`QUARANTINED`/`RELEASED` — **R6-M2/L2**) | `SubmitInput` | `175 B` | `292 B` | `5,124 B` | `8,676 B` / proof |
| `0x0E` | `GOVERNANCE_ADD_BINDING` (`kind=7`, Gov-only `RecognizedBindings`) | `GovernanceContract` | `33 B` | *(internal)* | `3,108 B` | `8,676 B` / proof |
| `0x0F` | `BTC_TRAP_TIMEOUT_HALT` (`PENDING_TRAP` expired `> 230` blks → `Halted`) | `SubmitInput` | `37 B` | `164 B` | `3,204 B` | `8,676 B` / proof |
| `0x10` | **`BTC_ROUND_RETIRED`** (permissionless SPV of `RoundRetireTx`, 7 keys — **S6-5**) | `SubmitInput` | `1,147 B` | `1,252 B` | `8,292 B` | `8,676 B` / proof |

*(Every byte count above is verified verbatim by [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py); all 17 tags fall back to bounded Multi-Tx `UploadWitnessProof` if SMT grinding pushes any path past `12 KiB`, bounded by design up to `sib_count = 256` subject to Gate G-9.)*

---

## 4. Deterministic, Panic-Free `BitcoinChainVerifier` (`vm/embedded/btcspv`)

### 4.1 Header Validation, Never-Pruned Merkle+Time Index & Reorg/Prune Rules

- **Idempotent Duplicate No-Op**: Re-submitting an already-present valid input returns `stepError = 2` (refundable up to a global cap of `<= 16` duplicate refunds per batch). Malformed/invalid inputs set `stepError = 1`.
- **`BTC_HEADER_BATCH` (`0x00`)**: Exact Bitcoin mainnet `SetCompact`, 2016-block `[302400, 4838400]`s retarget, embedded `mtpWindow[11]`, `futureTimeGuardSecs = 7,200`, `LOWEST_BLOCK_HASH_BE`, incremental reorg. Writes **`ActiveChainByHeight[height] = blockHashBE(32B) || merkleRootLE(32B) || blockTime(u32BE, 4B)` (68 B)** — **NEVER PRUNED**.
- **`BTC_REORG_STEP` (`0x01`)**: Walks 1 step/input (`<= 5` keys), updates `ActiveChainByHeight[h]`, sets `Halted = 1` on any orphaned `AdmittedEventBlocks[h]` or `ReorgSteps > 144`.
- **`BTC_PRUNE_STEP` (`0x02`)**: Rejects while `ReorgActive == 1`; deletes ONLY stale `HeaderNode`s at `height < BestTipHeight - 144 && height % 2016 != 0`.

### 4.2 Streaming SHA-256 Transaction Verifier (`BTC_TX_STREAM_CHUNK`, `0x04`)

Starts strictly from standard SHA-256 IV, enforces ordered 64 B-aligned chunks (`<= 8,192 B`), rejects SegWit marker `0x00 0x01`, verifies `totalBytes != 64` and zero trailing bytes, latches `txidLE`, `isCoinbase`, `matchedOutpoint`, and `opReturnBurnMatched` into `TxStreamState` (`175 B`). Small coinbases `<= 1,024 B` MAY pass inline (`mode = 0`) OR streamed (`mode = 1`).

### 4.3 Hardened Transaction & Claim Verification Rules (`R6-M2..M5`, `R6-L2`, `R6-L5`, `R6-L6`)

Every proof checks `ActiveChainByHeight[blockHeight]`, `BestTipHeight >= blockHeight + K - 1`, `len != 64`, `txIndex != 0`, valid coinbase, CVE-2012-2459, and `len(txBranch) == len(coinbaseBranch)`.

1. **`PEGOUT_CREATED` (`0x03`, `kind=7`)**: Writes `PegOutState[outboxId]` (`190 B`, `slotOperatorId = 0`, `lastLapsedOperatorId = 0`).
2. **`PEGOUT_SLOT_CLAIMED` (`0x0A`, `kind=7` — Single Authority & Anti-Censorship, Closing `R6-M4` & `R6-M5`)**: If `po.SlotOperatorId != 0 && (ChainMeta.BestTipHeight < po.SlotExpiryBtcHeight || inputMomentumTs < po.SlotExpiryBtcTs)`, **IGNORE (`stepError = 2`)** — NEVER overwrite an unexpired slot! If an old slot HAS expired (`BestTipHeight >= po.SlotExpiryBtcHeight && inputMomentumTs >= po.SlotExpiryBtcTs`), records `po.LastLapsedOperatorId = po.SlotOperatorId` and rejects consecutive re-claim (`newOpId == po.LastLapsedOperatorId` when another eligible op exists). Otherwise writes `po.SlotOperatorId = newOpId`, `po.SlotExpiryBtcHeight = ChainMeta.BestTipHeight + 24`, `po.SlotExpiryBtcTs = slotClaimZenonTs + 14_400`.
3. **`OPERATOR_ROUND_REGISTERED` (`0x0B` — Exact Epoch Alignment, Closing `R6-L6`)**: Requires `epoch := epoch(roundId) < 4096`, **`anchorExpiryTs == finalityEpochStartTs(epoch) + 58 days`** (exact equality!), and `anchorCutoffTs == anchorExpiryTs - 12 days`; verifies 64 B `CommitteeIdentityKey` sig over `(cfg.ChainBindingHash || opId || roundId || bondOutpoint || anchorCutoffTs || anchorExpiryTs)`; writes `OperatorBondRecord` (`52 B`).
4. **`GOVERNANCE_ADD_BINDING` (`0x0E`, `kind=7`, Governance-only)**: Writes `RecognizedBindings[chainBindingHash] = 1`.
5. **`BTC_LOCK_PROOF` (`0x05`) → `FOREIGN_LOCK`**: Proves `DepositTx` + mandatory 2-input `RolloverTx`, BIP-68/112 Leaf A, `Q_vault_d` from `releaseAdapterRef.qGraphXOnly`, `epochId < 4096`, BOTH replay keys absent, and 64 B `CommitteeIdentityKey` sig over `(cfg.ChainBindingHash || rolloverOutpoint || eligibleBitmask || epochId || takeTxidsSmtRoot || takeTxidsBlobHash)` (where `takeTxidsBlobHash` commits to the published sorted Take-txid leaf list — `R6-L5`). Writes multi-epoch `TrackedVaultRecord{ACTIVE, 0, activeEpochs=[{epochId, takeTxidsSmtRoot}]}` (`78 B`), `AdmittedEventBlocks[h_rol]`, and emits `FOREIGN_LOCK`.
6. **`BTC_RELEASE_PROOF` (`0x06` — Decoupled From Vault Status, Closing `R6-M3`)**: Loads `po := PegOutState[outboxId]` and `tv := TrackedVaultRecord[po.AssignedVaultOutpoint]`. **NEVER rejects a valid fronting proof merely because `tv.status` transitioned to `PENDING_TRAP` or `RECOVERED`!** Verifies `RecognizedBindings[po.ChainBindingHash] == 1`, `ResolutionSeenByOutboxId[outboxId]` absent, `FrontingOutpointUsed` absent, `h_front < po.TimeoutHeight`, `BestTipHeight <= po.TimeoutHeight + ReleaseSubmissionGrace + K`, exact payment + `"ZBTC_FNT"` tag, and domain-authoritative slot exclusivity (`h_front < po.SlotExpiryBtcHeight || ActiveChainByHeight[h_front].blockTime <= po.SlotExpiryBtcTs ⇒ operatorId == po.SlotOperatorId`). Transitions `tv.status = RELEASED` **iff** `tv.status == ACTIVE` (preserving `PENDING_TRAP`/`RECOVERED` so Settlement re-points `PegOutRecord` cleanly!), marks `ResolutionSeenByOutboxId[outboxId]`, and emits `FOREIGN_RELEASE(operatorId)`.
7. **`BTC_NON_DELIVERY_PROOF` (`0x07`) → `FOREIGN_NON_DELIVERY`**: Requires `ResolutionSeenByOutboxId[outboxId]` absent, `checkpointH = po.TimeoutHeight + 558`, `BestTipHeight >= checkpointH + K - 1`, emits `FOREIGN_NON_DELIVERY`.
8. **`BTC_VAULT_SPEND_PROOF` (`0x08` — Verifier-Decided SMT Inclusion vs All-Epoch Absence Across ALL Live Statuses, Closing `R5-M1` & `R6-L5`)**:
   - Proves finalized streamed tx `spendTxid` spent `vaultOutpoint` (`h_spend`) while `tv := TrackedVaultRecord[vaultOutpoint]` has `tv.status ∈ {ACTIVE, RELEASED, QUARANTINED}`:
     - **If `tv.status == QUARANTINED`**: ZERO valid spends exist prior to re-graphing (`0x0D`) ⇒ **immediate `ChainMeta.Halted = 1`**!
     - **If `tv.status ∈ {ACTIVE, RELEASED}` — Branch A (Registered Take)**: Valid `proof-format.md` V1 SMT **INCLUSION** proof that `SHA3-256(spendTxid)` is present in `e.takeTxidsSmtRoot` for ANY active epoch `e ∈ tv.activeEpochs`: if `tv.status == ACTIVE` → transitions `tv.status = PENDING_TRAP`, `tv.pendingTrapSpendHeight = h_spend` (NO halt!); if `tv.status == RELEASED` → valid reimbursement (no-op) if `spendTxid` belongs to `ReimbursementOperator`, else `PENDING_TRAP`!
     - **Branch B (Raw Unauthorized Sweep on `ACTIVE` OR `RELEASED` → Immediate `Halted = 1`)**: Proof **MUST supply valid `proof-format.md` V1 SMT ABSENCE proofs (`VerifyAbsenceByPath`) proving `SHA3-256(spendTxid)` is ABSENT from `e.takeTxidsSmtRoot` for EVERY active epoch `e ∈ tv.activeEpochs`** (constructible by anyone from the published `takeTxidsBlobHash` leaf DA!) → sets `ChainMeta.Halted = 1`!
     - **Branch C (Invalid/Omitted Proof)**: If NEITHER Branch A NOR Branch B validates, **REJECT (`stepError = 1`)**!
9. **`BTC_TRAP_TIMEOUT_HALT` (`0x0F`)**: If `tv.status == PENDING_TRAP && BestTipHeight >= tv.pendingTrapSpendHeight + 230` → sets `ChainMeta.Halted = 1`.
10. **`BTC_OPERATOR_SLASH_PROOF` (`0x09`)**: Verifies streamed tx spent `OperatorBondOutpoints[opId || roundId]` with `opReturnBurnMatched == 1` → sets `OperatorSlashed[opId] = 1`.
11. **`BTC_VAULT_RECOVERY_PROOF` (`0x0C`)**: Verifies streamed `WrongDepositDisproveTx^{T1|T2}` spent `OperatorBondOutpoints[opId || roundId]` (`opReturnBurnMatched == 1`) AND created `Out 0 = recoveryOutpoint` paying `99,899,000` sats to `Q_rec_d` while `tv.status ∈ {ACTIVE, PENDING_TRAP}` → sets `OperatorSlashed[opId] = 1`, `tv.status = RECOVERED`, inserts `TrackedVaultRecord[recoveryOutpoint] = {QUARANTINED, 0, activeEpochs=[]}`, and stores **`RecoveredVaultMap[oldOutpoint] = {recoveryOutpoint, offendingOperatorId: opId, offendingRoundId: roundId}` (`44 B`)**!
12. **`VAULT_GRAPH_EPOCH_ADDED` (`0x0D` — Strict Multi-Gen Update for `ACTIVE`, `QUARANTINED`, AND `RELEASED`, Closing `R6-M2` & `R6-L2`)**: Verifies `epochId (u16) < 4096`, `newBitmask != 0`, and 64 B `CommitteeIdentityKey` sig over `(cfg.ChainBindingHash || vaultOutpoint || newBitmask || u16BE(epochId) || newTakeTxidsSmtRoot || takeTxidsBlobHash)` while `tv.status ∈ {ACTIVE, QUARANTINED, RELEASED}`! First prunes any expired epoch `e'` whose `finalityEpochStartTs(e') + 58d < ChainMeta.BestTipBlockTime`. **STRICTLY REJECTS (`stepError = 1`) if `epochId` is ALREADY present in `tv.activeEpochs` (zero overwriting!) OR if `len(tv.activeEpochs) >= 2` (hard 2-epoch cap!)**. Appends `{epochId, newTakeTxidsSmtRoot}`, transitions `QUARANTINED → ACTIVE` (leaving `ACTIVE`/`RELEASED` unchanged), and writes `RegraphedVaultEpoch[vaultOutpoint || u16BE(epochId)]` (`0x10`)!
13. **`BTC_ROUND_RETIRED` (`0x10`)**: Proves finalized streamed `RoundRetireTx_{m,l,r}` (or `RoundRetireTx_{m,l,init}`) spent `OperatorBondOutpoints[opId || roundId]` (or `GenesisBond`) paying `3.6990 BTC` to `<pk_m>` (no `OP_RETURN` burn) → sets **`LaneRetired[opId || u16BE(epochId) || laneIndex] = 1`** (`0x11`).

---

## 5. Verifier State Layout (Domain L2 SMT — Field-Derived Sizes)

| Prefix | Key | Value (Field-Derived in Oracle) | Pruning Policy |
|---|---|---|---|
| `0x01` | singleton | `ChainMeta` (`238 B`) | Never pruned |
| `0x02` | `blockHashBE(32B)` | `HeaderNode` (`160 B`) | Pruned when `height < BestTip - 144 && height % 2016 != 0 && ReorgActive == 0` |
| `0x03` | `u64BE(height)` | `blockHashBE(32B) \|\| merkleRootLE(32B) \|\| blockTime(4B)` (`68 B`) | **NEVER PRUNED** |
| `0x04` | `BitcoinOutpointID(32B)` | `u64BE(rolloverHeight)` | Never pruned |
| `0x05` | `outboxId(32B)` | `ResolutionRecord` (`37 B`) | Never pruned |
| `0x06` | `u64BE(height)` | `admittedBlockHashBE(32B)` | Never pruned |
| `0x07` | `outboxId(32B)` | `PegOutState` (`190 B`, incl. `lastLapsedOperatorId` — **R6-M5**) | Never pruned |
| `0x08` | `vaultOutpoint(36B)` | `TrackedVaultRecord` (`78 B`: status, `pendingTrapSpendHeight`, up to 2 `{epochId, takeTxidsSmtRoot}`) | Never pruned |
| `0x09` | `frontingTxidBE \|\| vout` | `u8(1)` | Never pruned |
| `0x0A` | `depositOutpoint(36B)` | `u8(1)` (`ProcessedProvisionalDeposit`) | Never pruned |
| `0x0B` | `streamId(32B)` | `TxStreamState` (`175 B`) | Prunable after `144` blocks once consumed |
| `0x0C` | `u32BE(operatorId)` | `u8(1)` (`OperatorSlashed`) | Never pruned |
| `0x0D` | `u32BE(opId) \|\| u32BE(roundId)` | `OperatorBondRecord` (`52 B`: `bondOutpoint(36) \|\| anchorCutoffTs(8) \|\| anchorExpiryTs(8)`) | Never pruned |
| `0x0E` | `chainBindingHash(32B)` | `u8(1)` (`RecognizedBindings`, Governance-only) | Never pruned |
| `0x0F` | `oldOutpoint(36B)` | `RecoveredVaultRecord` (`44 B`: `recoveryOutpoint(36) \|\| opId(4) \|\| roundId(4)`) | Never pruned |
| `0x10` | `vaultOutpoint(36B) \|\| u16BE(epochId)` | `RegraphedVaultEpoch` (`40 B`: `bitmask(8) \|\| takeTxidsSmtRoot(32)`) | Never pruned |
| `0x11` | `u32BE(opId) \|\| u16BE(epochId) \|\| u8(lane)` | `u8(1)` (`LaneRetired` — **R5-M2**) | Never pruned |

---

## 6. Mandatory SPV Conformance Test Vectors (29 Vectors)

Vectors 1–24 from v2.3 PLUS:
25. **Verifier-Decided SMT Spend & Multi-Generation Rotation (`R5-M1`, `R5-H3`, `R6-L5`)**: Reject `BTC_VAULT_SPEND_PROOF` omitting both inclusion and all-epoch SMT absence proofs; verify rotated gen-`g+1` Take on an `ACTIVE` vault transitions to `PENDING_TRAP`; verify raw sweep with valid all-epoch SMT absence proofs halts immediately on BOTH `ACTIVE` AND `RELEASED` vaults, and ANY spend of a `QUARANTINED` vault halts immediately!
26. **Single-Authority Anti-Censorship Fronting Slot & Lane Retirement (`R6-M4`, `R6-M5`, `R5-M2`)**: Verify second `PEGOUT_SLOT_CLAIMED` during live slot is ignored (`stepError = 2`); verify consecutive re-claim by `lastLapsedOperatorId` is rejected; verify `BTC_ROUND_RETIRED` sets `LaneRetired = 1`.
27. **Decoupled `BTC_RELEASE_PROOF` on Trapped Vault (`R6-M3`)**: Verify valid `BTC_RELEASE_PROOF` is ADMITTED (`FOREIGN_RELEASE`) even after another operator's substituting `Take1` transitioned `TrackedVaultRecord` to `PENDING_TRAP` or `RECOVERED` (without overwriting `PENDING_TRAP`/`RECOVERED`).
28. **Strict `0x0D` Multi-Gen Guards (`R6-M2`, `R6-L2`)**: Verify `0x0D` succeeds on `ACTIVE`, `QUARANTINED`, AND un-claimed `RELEASED` vaults; verify `0x0D` REJECTS duplicate `epochId` AND REJECTS adding a 3rd unexpired epoch.
29. **Exact `0x0B` Epoch-Start Alignment (`R6-L6`)**: Verify `OPERATOR_ROUND_REGISTERED` REJECTS any `anchorExpiryTs != finalityEpochStartTs(epoch) + 58 days`.
