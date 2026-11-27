# Part 2: Direct-on-L1 Trimmed Bitcoin SPV Verifier (`vm/embedded/btcspv`)

**Document Class:** Normative Bitcoin SPV Verification Specification (`v1` / `v3.0.0-rfc`; supersedes `v0` `d_btc_asset` optimistic domain)  
**Shared Implementation Mandate:** Deterministic, pure-Go, **panic-recovered (`B1`)** package `vm/embedded/btcspv/` executed directly inside `SettlementContract` on Zenon L1 (no separate optimistic execution domain, no executors, no 48h challenge window).  
**Consistency Checker:** [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py)

---

## 1. Direct-on-L1 Architecture & `ChainBinding` (`D4` Locked)

In `v1`, Bitcoin header tracking and transaction inclusion verification run **directly on Zenon L1** as ABI methods on `SettlementContract`, paired with `>= k` federation co-signatures on sweep locks and batch intents. This eliminates `v0`'s optimistic `BatchCommitmentV3`, `StepTraceLeaf`, `zenon-executor`, Multi-Tx Witness Sessions, 48h (+12h) finalization lag, and findings **C-2 (case 1), M-5 (deposit spam), N-3, and N-4**.

```text
ChainBinding {
    foreignChainId        : ChainId   // u16(0x0001) || bytes30(SHA3-256("BTC_MAINNET_V1" || btcGenesisHashBE)[0:30])
    chainVerifierId       : bytes32   // SHA3-256("BTC_SPV_VERIFIER_V3.0" || reproducibleBuildDigest)  [L-4 fixed]
    genesisAnchor         : Bytes     // BitcoinAnchor { blockHashBE, height, header(80B), cumWork, retargetStartHash, retargetStartTime, retargetHeight, mtpWindow[11] }
    custodySpecHash       : bytes32   // SHA3-256(activated BTC-CUSTODY-F1 bytes); MUST be non-zero
    activeFederationSet   : Bytes     // { k(u8), n(u8), sortedPubkeys[n](32B each), recoveryCsvBlocks(u32=52560), recoveryScriptHash(32B) }
    finalityParams        : Bytes     // BitcoinFinalityParams below
}
```

### 1.1 `BitcoinFinalityParams`

```text
BitcoinFinalityParams :=
    confirmationDepthK         : u32   // Pilot: 14. Satisfies K >= max(12, ceil(2 * Cap_BTC / Subsidy(h))) across pre-2028 (12), post-2028 (12), and post-2032 (13) at 5.0 BTC cap!
    minimumPostAnchorWork      : u256  // Normative floor: K_pilot * blockWork(genesisAnchor.nBits) (must accumulate >= 14 blocks at anchor difficulty before any event proof is admitted)
    retainedReorgDepth         : u32   // 144 blocks (stale HeaderNode pruning ONLY; ActiveChainByHeight NEVER pruned)
    maximumHeaderBatch         : u32   // 2 headers per SubmitHeaderBatch call
    maximumMerkleBranchDepth   : u32   // 16 levels (65,536 txs/block)
    maximumFedStrippedTxBytes  : u32   // 6,144 B (stripped non-witness bytes for federation-built Sweep/Payout/Conflict txs; streaming 0x04 deleted!)
    depositRefundCsvBlocks     : u32   // 288 blocks (~48h)
    depositSweepCutoffBlocks   : u32   // 200 blocks (leaves >= 88 blocks safety buffer >> K=14)
    futureTimeGuardSecs        : u32   // 7,200 s
    equalWorkTieBreak          : u8    // 0 = LOWEST_BLOCK_HASH_BE (documented difference from Bitcoin Core first-seen; bounded by K=14)
```

> **Stage 0 Testnet Caveat:** On Bitcoin Signet (where block validity sits in the coinbase signature) and testnet4 (minimum-difficulty rules), header-only SPV does not resist an adversary. Stage 0 Signet SPV tests are explicitly labeled **conformance-only**; full PoW security applies only on Bitcoin Mainnet.

---

## 2. Direct-on-L1 SPV ABI Methods & Plasma Floor (`B1`, `B2`)

All `v0` BitVM-only input tags (`0x04` streaming, `0x08`–`0x0D`, `0x0F`, `0x10`) and `0x03` (`PEGOUT_CREATED` is now direct `SettlementContract` state) are **deleted**. Every SPV method executes directly on L1 with strict CPU, storage-access, and ABI bounds, and **MUST wrap execution in `recover()` converting any panic into a deterministic method error** so a crafted send can NEVER stall `SettlementContract`'s FIFO receive queue (`dev:verifier/account_block.go:508`, **B1**).

| ABI Method | Send Plasma Tier (`B2`) | Max Payload | Max ABI | Base Plasma (`QSR`) | Max Storage Ops | Purpose |
|---|---|---:|---:|---:|---:|---|
| `SubmitHeaderBatch(headers)` | `52,500` (Simple) | `197 B` | `324 B` | `74,260` (`36 QSR`) | `<= 8` | Validate `1..2` mainnet headers, 2016-block retarget, MTP, `ActiveChainByHeight`. |
| `StepReorg()` | `52,500` (Simple) | `0 B` | `4 B` | `52,500` (`25 QSR`) | `<= 6` | Walk 1 incremental reorg step; sets `Halted = 1` (mints paused ONLY) if an admitted event block is orphaned or `ReorgSteps > 144`. |
| `PruneStaleHeaders(hashes)` | `52,500` (Simple) | `65 B` | `196 B` | `65,556` (`32 QSR`) | `<= 4` | Delete `1..2` stale `HeaderNode`s (`height < BestTip - 144 && height % 2016 != 0 && ReorgActive == 0`). |
| `ReserveMintCapacity(...)` | `52,500` (Simple) | `64 B` | `164 B` | `63,380` (`31 QSR`) | `<= 4` | Reserve cap space before sweep (`M-7`); expires after `288` BTC blocks. |
| `PostBatchIntent(...)` | `52,500` (Simple) | `2,604 B` | `2,724 B` | `237,460` (`114 QSR`) | `<= 20` | Commit federation payout `inputs[]`, `outputs[]`, `feeCapSats`, `>= k` sigs before signing (`B4`). |
| `SubmitSweepLockProof(...)` | `73,500` (Heavy SPV) | `8,532 B` | `8,644 B` | `661,020` (`315 QSR`) | `<= 24` | Verify `K`-deep `SweepTx` (`<= 6 KiB` stripped) + coinbase midstate + `>= k` federation attestation → atomic mint. |
| `SubmitReleaseProof(...)` | `73,500` (Heavy SPV) | `7,344 B` | `7,460 B` | `580,508` (`277 QSR`) | `<= 20` | Verify `K`-deep `PayoutTx` matching `BatchIntent` → mark `PegOutRecord`s `RELEASED` (NO upper deadline!). |
| `SubmitConflictRefundProof(...)` | `73,500` (Heavy SPV) | `7,376 B` | `7,492 B` | `582,684` (`278 QSR`) | `<= 10` | Verify `K`-deep tx spending a `BatchIntent` input WITHOUT paying `outboxId` → atomic refund (`B4`). |

> **Mandatory B2 Plasma Floor:** Because `go-zenon` embedded receives cost `0` Plasma (`dev:vm/plasma.go:147`) and `SetPlasmaVariables` can currently lower `MaxBasePlasmaInMomentum` to `210,000` (`dev:vm/embedded/definition/plasma.go:66`), which blocks any call larger than `2,011 B` (`Heavy`) / `2,320 B` (`Simple`) in `pillar/content_selector.go:328`, the `v1` zBTC spork MUST enforce **`DynamicPlasmaSpork` active FIRST** and pin **`MaxBasePlasmaInMomentum >= 2,100,000`** (`>= 3×` the largest `661,020`-Plasma SPV call!). Direct L1 calls pay Plasma only (no `SubmitInput` ZNN deposit or refund machinery).

---

## 3. Deterministic Verification Rules (`vm/embedded/btcspv`)

### 3.1 Header Validation, Reorgs & `Halted` Semantics

- **`SubmitHeaderBatch`:** Exact Bitcoin mainnet `SetCompact`, 2016-block `[302400, 4838400]`s retarget, embedded `mtpWindow[11]`, `futureTimeGuardSecs = 7,200`, `LOWEST_BLOCK_HASH_BE` equal-work tie-break *(note: differs from Bitcoin Core's first-seen rule; any single-block tie resolves well within `K = 14`)*. Writes **`ActiveChainByHeight[height] = blockHashBE(32B) || merkleRootLE(32B) || blockTime(u32BE, 4B)` (68 B)** — **NEVER PRUNED**.
- **`ReorgActive` Guard:** Every event proof (`SubmitSweepLockProof`, `SubmitReleaseProof`, `SubmitConflictRefundProof`) MUST reject while `ChainMeta.ReorgActive == 1` OR `ChainMeta.PostAnchorWork < minimumPostAnchorWork`.
- **`Halted` Scope:** Deep reorg (`> 144` or orphaning an admitted block) sets `ChainMeta.Halted = 1`, which **pauses new mints ONLY** (`ReserveMintCapacity`, `SubmitSweepLockProof`). It **NEVER blocks `RequestPegOut`, `PostBatchIntent`, `SubmitReleaseProof`, or `SubmitConflictRefundProof`**.

### 3.2 Coinbase Midstate Proof (CVE-2017-12842 Without Streaming `0x04`)

Every transaction proof MUST verify:
1. `ActiveChainByHeight[blockHeight]` exists and `BestTipHeight >= blockHeight + K - 1`.
2. `len(strippedTx) <= 6,144` and `len(strippedTx) != 64` (CVE-2017-12842) and `txIndex != 0`.
3. Zero SegWit marker (`0x00 0x01`) in stripped bytes; `doubleSHA256(strippedTx)` matches `txBranch` against `merkleRootLE` with `len(txBranch) == len(coinbaseBranch)` and no duplicate-node CVE-2012-2459 padding.
4. **Coinbase Midstate Proof (`<= 616 B`):** Because mainnet coinbase transactions can pay hundreds of pool miners and exceed several KB, the verifier does NOT require raw coinbase bytes or `0x04` streaming. Instead, the caller supplies `(sha256Midstate(32B), finalChunkTail(<=64B), totalCoinbaseBytes(u32), coinbaseBranch)`: the verifier asserts `totalCoinbaseBytes != 64` (blocking 64-byte leaf forgery), completes the final SHA-256 compression + second SHA-256 round to recover `coinbaseTxid`, and verifies `coinbaseBranch` at index `0` with `len(coinbaseBranch) == len(txBranch)`.

### 3.3 Event Proof Rules

1. **`SubmitSweepLockProof`:**
   - Requires `Halted == 0`, `ReorgActive == 0`, and `K`-deep inclusion of `strippedSweepTx`.
   - Parses all outputs paying recognized `BTC-CUSTODY-F1` vault scripts; computes `totalVaultOutSats`.
   - Verifies `>= k` distinct valid BIP-340 Schnorr signatures from `activeFederationSet` (individual keys, NEVER aggregated `N`-of-`N` — closing **N-2**) over `SHA3-256("ZBTC_SWEEP_MINT_V1" || chainBindingHash || sweepTxid || canonical(mintAllocations[]))`.
   - Each allocation `(depositOutpoint, zenonRecipient, netMintSats, pegInFeeSats)` MUST satisfy: (i) `DepositOutpointUsed[depositOutpoint]` absent (permanent replay key), (ii) `pegInFeeSats >= ceil(input_vb * r_ref)`, (iii) `netMintSats + pegInFeeSats >= 100,000`, and (iv) `sum(netMintSats + pegInFeeSats) <= totalVaultOutSats` (bounding total mints on-chain by actual vault outputs!).
   - *Explicit Auditability Disclosure:* Because stripped Bitcoin transactions omit input amounts, on-chain SPV enforces the total vault-output upper bound and deposit-outpoint replay uniqueness, while per-recipient attribution is attested by `>= k` signers and independently auditable off-chain from Bitcoin's Taproot sighash input amounts.
2. **`SubmitReleaseProof` (No Upper Deadline!):**
   - Verifies `K`-deep inclusion of `strippedPayoutTx` spending `BatchIntent.inputs[]` and creating every `(spk, netSats)` output in `BatchIntent.outputs[]`.
   - **No upper height deadline:** A delayed or fee-starved payout can ALWAYS be proven once confirmed, marking each `PegOutRecord` `RELEASED` and decrementing `PendingForeignRelease`.
3. **`SubmitConflictRefundProof` (`B4` — Conflict-Only Refunds):**
   - Verifies `K`-deep inclusion of `strippedConflictTx` spending **at least one input** in `BatchIntent.inputs[]`, such that `strippedConflictTx` does **NOT** contain the `(spk, netSats)` output for `outboxId` (and `outboxId` is still `INTENT`).
   - Atomically marks `PegOutRecord[outboxId]` `REFUNDED`, decrements `PendingForeignRelease`, increments `RepresentationOutstanding`, and returns `grossAmountSats` `zBTC` to `refundRecipient`. Because Bitcoin inputs cannot be double-spent, a refunded peg-out can NEVER later confirm on Bitcoin.

---

## 4. Verifier Storage Layout (`SettlementContract` SPV Sub-Prefix)

| Prefix | Key | Value | Pruning Policy |
|---|---|---|---|
| `0x20` | singleton | `ChainMeta` (`BestTipHash`, `BestTipHeight`, `BestTipWork`, `PostAnchorWork`, `ReorgActive`, `Halted`) | Never pruned |
| `0x21` | `blockHashBE(32B)` | `HeaderNode` (`160 B`, incl. `mtpWindow[11]`) | Pruned via `PruneStaleHeaders` when `< BestTip - 144 && height % 2016 != 0 && ReorgActive == 0` |
| `0x22` | `u64BE(height)` | `ActiveChainByHeight` (`68 B`: `blockHashBE \|\| merkleRootLE \|\| blockTime`) | **NEVER PRUNED** |
| `0x23` | `u64BE(height)` | `AdmittedEventBlocks` (`admittedBlockHashBE`) | Never pruned |
| `0x24` | `depositOutpoint(36B)` | `u8(1)` (`DepositOutpointUsed`) | Never pruned |
| `0x25` | `sweepTxid(32B)` | `u8(1)` (`SweepProcessed`) | Never pruned |
| `0x26` | `chainBindingHash(32B)` | `ChainBinding` (`RecognizedBindings`, Governance + `>= k` fed) | Never pruned |

---

## 5. Mandatory SPV Conformance Test Vectors

1. All 24 Bitcoin header, difficulty retarget (`[302400, 4838400]`s), MTP, `futureTimeGuardSecs`, `LOWEST_BLOCK_HASH_BE` tie-break, `CVE-2012-2459`, and `CVE-2017-12842` (`len == 64` rejection) vectors.
2. **Coinbase Midstate Proof:** Valid multi-KB coinbase midstate acceptance; `totalCoinbaseBytes == 64` rejection; mismatched `len(coinbaseBranch) != len(txBranch)` rejection.
3. **`ReorgActive` & `Halted` Isolation:** Event proofs rejected while `ReorgActive == 1`; `Halted = 1` blocks `ReserveMintCapacity` / `SubmitSweepLockProof` while keeping `RequestPegOut`, `PostBatchIntent`, `SubmitReleaseProof`, and `SubmitConflictRefundProof` open.
4. **Sweep Bound & Replay:** `SubmitSweepLockProof` rejects when `sum(mints + fees) > totalVaultOutSats`, when `< k` distinct valid signer signatures are supplied, or on duplicate `depositOutpoint`.
5. **Conflict Refund vs Release (`B4`):** `SubmitConflictRefundProof` succeeds ONLY when a `K`-deep tx spends a `BatchIntent` input without paying `outboxId`; rejects timeout-only claims and rejects after `RELEASED`.
6. **Panic-Free Fuzz Gate (`B1`):** Randomized/malformed ABI payloads across all 8 methods MUST return deterministic method errors and NEVER panic or stall the FIFO receive queue.
