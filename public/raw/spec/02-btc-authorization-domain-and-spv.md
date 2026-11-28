# Part 2: Stage 0 Direct-on-L1 Bitcoin SPV Event Oracle & Stage 1A Bitcoin-L1-Canonical Authorization Domain

**Document Class:** Normative Bitcoin SPV Verification & L1 Authorization Domain Specification (`v1` / `v3.0.0-rfc` — Zero-Federation Phased Architecture; supersedes archived `v0` `v2.5.0-rfc`)  
**Philosophical Anchor:** Stage 0 implements Zenon's non-custodial verification thesis (`zenon-developer-commons`: `essays/Verify Bitcoin, Don't Bridge It.md` & `docs/specs/spv-event-oracle-spec.md`): **Event Validity only, zero custody authority**. Stage 1A moves canonical `zBTC` authorization, data availability, and forced exit directly onto **Bitcoin L1** so that `49%–100%` Zenon compromise cannot forge state or censor exits.  
**Consistency Checker:** [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py)

---

## 1. Two-Layer Separation: Stage 0 Event Oracle vs Stage 1A Canonical L1 Domain

This specification strictly separates two orthogonal verification surfaces with **zero federated signers** anywhere:

1. **Stage 0 — Direct-on-L1 Bitcoin SPV Event Oracle (`vm/embedded/btcspv`):**
   - Runs deterministically inside an embedded Zenon contract (`BtcSpvOracleContract`), wrapped in mandatory panic recovery (`recover()`, zero `common.DealWithErr` calls — closing upstream issue `#239` / **B1**).
   - Proves **Event Validity ONLY**: cryptographic evidence that a Bitcoin transaction `txid` is included at depth `>= K_oracle` on the heaviest cumulative-PoW Bitcoin header chain.
   - **Hard Non-Custody Invariant:** Stage 0 SPV has **ZERO minting, burning, sweeping, or vault-spending authority**. It powers Bitcoin-verified receipts, proof-of-payment triggers, and non-custodial PTLC/HTLC atomic swaps (`spec/03 §1`).
2. **Stage 1A — Bitcoin-L1-Canonical Authorization Domain (`vk_STF` Rollup Circuit):**
   - For pooled, fungible `zBTC` (`Stage 1A`), **Zenon L1 does NOT authorize mints, burns, or exits**.
   - Instead, the immutable RISC-V / ZK Rollup State Transition Function ($\mathcal{F}$, compiled to `RV32IM` for `BitVMX-CPU` `n = 8` bisection — `spec/01`) scans **complete stripped Bitcoin blocks** directly on Bitcoin L1, deriving the entire canonical `zBTC` state root $R_h$ strictly from Bitcoin's heaviest PoW chain (`0-of-N` Zenon trust; `0%` ZNN market-cap coupling).

---

## 2. Stage 0: Direct-on-L1 Bitcoin SPV Event Oracle (`vm/embedded/btcspv`)

### 2.1 `OracleChainConfig` & Finality Parameters

```text
OracleChainConfig {
    foreignChainId         : bytes32   // u16(0x0001) || SHA3-256("BTC_MAINNET_SPV_V1" || btcGenesisHashBE)[0:30]
    genesisAnchor          : Bytes     // BitcoinAnchor { blockHashBE(32B), height(u64), header(80B), cumWork(u256),
                                       //                 retargetStartHash(32B), retargetStartTime(u32), retargetHeight(u64), mtpWindow[11](u32) }
    admissionDepthN        : u32       // 6 blocks (provisional event admission; reversible on reorg)
    finalizationDepthK     : u32       // 12 blocks (oracle event finalization depth)
    minimumPostAnchorWork  : u256      // finalizationDepthK * blockWork(genesisAnchor.nBits)
    retainedReorgDepth     : u32       // 144 blocks (stale HeaderNode pruning ONLY; ActiveChainByHeight NEVER pruned)
    maximumHeaderBatch     : u32       // 2 headers per SubmitHeaderBatch call
    maximumMerkleDepth     : u32       // 16 levels (65,536 txs/block)
    maximumStrippedTxBytes : u32       // 6,144 B (per-call Stage 0 proof cap; fits 3x inside pinned 2.1M Plasma floor)
    futureTimeGuardSecs    : u32       // 7,200 s (Bitcoin consensus MAX_FUTURE_BLOCK_TIME)
    equalWorkTieBreak      : u8        // 0 = LOWEST_BLOCK_HASH_BE (deterministic across all Zenon full nodes)
}
```

> **Testnet / Signet Scope Caveat:** On Bitcoin Signet (where validity rests in the Signet challenge signature) and Testnet4 (minimum-difficulty block exception), header-only PoW SPV does not resist an adversary. Stage 0 Signet SPV tests are **conformance-only**; full PoW security applies strictly on Bitcoin Mainnet.

### 2.2 Stage 0 Embedded ABI Methods, Exact Sizes & Pinned Plasma Floor (`B1`, `B2`)

All 4 Stage 0 oracle methods are **panic-recovered (`B1`)**, require **zero federation signatures**, and stay strictly within the pinned **`MaxBasePlasmaInMomentum >= 2,100,000`** floor (`spec/05 §2.2`) and `dp.MaxContractBlocks = 40` per-Momentum contract-block cap (`origin/dev:dp/dp.go:259-264`). Base Plasma under `DynamicPlasmaSpork` equals `tier + 68 * (abiBytes - 4)` (`origin/dev:vm/plasma.go:185-200`):

| ABI Method | Send Plasma Tier | Exact Max Payload | Exact Max ABI (`32 B`-padded) | Exact Base Plasma (`QSR` @ floor `1,000`) | Max Storage Ops | Purpose |
|---|---:|---:|---:|---:|---:|---|
| `SubmitHeaderBatch(headers)` | `52,500` (Simple) | `160 B` (`2 × 80 B`) | `228 B` | `67,732` (`33 QSR`) | `<= 8` | Validate `1..2` mainnet headers, 2016-block `[302400, 4838400]`s retarget, MTP, update `ActiveChainByHeight`. |
| `StepReorg()` | `52,500` (Simple) | `0 B` | `4 B` | `52,500` (`25 QSR`) | `<= 6` | Walk 1 incremental reorg step; emits deterministic reorg state transition if an admitted `< 12`-deep event is orphaned; flags `DeepReorgAlert = 1` if `ReorgSteps > 144`. |
| `PruneStaleHeaders(hashes)` | `52,500` (Simple) | `64 B` (`2 × 32 B`) | `132 B` | `61,204` (`30 QSR`) | `<= 4` | Delete `1..2` stale `HeaderNode`s (`height < BestTip - 144 && height % 2016 != 0 && ReorgActive == 0`). |
| `ProveTxInclusion(...)` | `73,500` (Heavy SPV) | `7,279 B` | `7,620 B` | `591,388` (`282 QSR`) | `<= 8` | Verify `>= N`-deep `strippedTx` (`<= 6,144 B`) + 1-/2-block coinbase midstate + Merkle inclusion → record `VerifiedEvent[txid]`. |

*Exact `ProveTxInclusion` ABI Derivation (Full `32 B`-Padded Accounting):*
- Static head: `4 B` selector + `8 × 32 B` (`blockHeight`, `txIndex`, `totalCoinbaseBytes`, `sha256Midstate`, + 4 dynamic offsets) `= 260 B`.
- Dynamic bodies (`32 B` length prefix + `32 B`-padded bytes): `strippedTx` (`32 + 6,144 = 6,176 B`) + `txBranch` (`32 + 16 × 32 = 544 B`) + `coinbaseTail` (`32 + 64 = 96 B` for `<= 63 B` tail) + `coinbaseBranch` (`32 + 16 × 32 = 544 B`) `= 7,360 B`.
- Total ABI `= 260 + 7,360 = 7,620 B <= 16,384 B` (`MaxDataLength`). Base Plasma `= 73,500 + 68 × (7,620 - 4) = 591,388`. Up to **`3`** max-size `ProveTxInclusion` calls (`1,774,164 <= 2,100,000`) fit inside a single Momentum even at the pinned floor (`6` at default `4,200,000`).

### 2.3 Exact 1- and 2-Block Coinbase Midstate Proof (`CVE-2017-12842`)

Every `ProveTxInclusion` call MUST verify:
1. `ChainMeta.ReorgActive == 0` and `ChainMeta.PostAnchorWork >= minimumPostAnchorWork`.
2. `ActiveChainByHeight[blockHeight]` exists and `BestTipHeight >= blockHeight + admissionDepthN - 1`.
3. `len(strippedTx) <= 6,144`, `len(strippedTx) != 64` (**CVE-2017-12842**), `txIndex != 0`, and no SegWit marker (`0x00 0x01`) in stripped bytes.
4. `doubleSHA256(strippedTx)` verifies against `merkleRootLE` via `txBranch` at `txIndex` with `len(txBranch) == len(coinbaseBranch) <= 16` and zero duplicate-sibling **CVE-2012-2459** padding.
5. **1- and 2-Block SHA-256 Coinbase Midstate Verification:**
   - Caller supplies `(sha256Midstate: bytes32, finalChunkTail: bytes, totalCoinbaseBytes: u32, coinbaseBranch: bytes32[])`.
   - **Normative Constraints:**
     - `totalCoinbaseBytes >= 65` (rejects `totalCoinbaseBytes == 64` leaf forgery and impossibly short transactions).
     - **`len(finalChunkTail) == totalCoinbaseBytes % 64`** (strictly `< 64`; rejects any mismatched or unaligned tail!).
   - **Exact Final SHA-256 Padding (`100%` of valid Bitcoin coinbase lengths, avoiding the `12.5%` single-compression rejection bug when `rem ∈ [56, 63]`):**
     Let `rem = totalCoinbaseBytes % 64` and `bitLen = u64BE(uint64(totalCoinbaseBytes) * 8)`:
     - **Case 1 (`rem < 56` — 1-block final padding):** Build single `64 B` block `B_1 = finalChunkTail[0:rem] || 0x80 || 0x00^(55 - rem) || bitLen(8B)`. Compute `innerHash = SHA256_Compress(sha256Midstate, B_1)`.
     - **Case 2 (`56 <= rem <= 63` — 2-block final padding):** Build `B_1 = finalChunkTail[0:rem] || 0x80 || 0x00^(63 - rem)` and `B_2 = 0x00^56 || bitLen(8B)`. Compute `state_1 = SHA256_Compress(sha256Midstate, B_1)`, then `innerHash = SHA256_Compress(state_1, B_2)`.
   - Compute `coinbaseTxid = SHA256(innerHash)` and verify `coinbaseBranch` at index `0` against `merkleRootLE` with `len(coinbaseBranch) == len(txBranch)`.
   - *Explicit Auditability Disclosure:* A midstate proof proves that Merkle index `0` is a valid non-64-byte leaf at the same tree depth as `txIndex` (completely closing CVE-2017-12842 interior-node forgery); it does **not** parse the prefix of the coinbase transaction itself. In Stage 1A below, full coinbase bytes are directly verified inside the stripped-block scanner to extract the BIP-141 witness commitment.

### 2.4 Stage 0 Oracle Storage Layout (`BtcSpvOracleContract`)

| Prefix | Key | Value | Pruning Policy |
|---|---|---|---|
| `0x20` | singleton | `ChainMeta` (`BestTipHash`, `BestTipHeight`, `BestTipWork`, `PostAnchorWork`, `ReorgActive`, `DeepReorgAlert`) | Never pruned |
| `0x21` | `blockHashBE(32B)` | `HeaderNode` (`160 B`, incl. `mtpWindow[11]`) | Pruned via `PruneStaleHeaders` when `< BestTip - 144 && height % 2016 != 0 && ReorgActive == 0` |
| `0x22` | `u64BE(height)` | `ActiveChainByHeight` (`68 B`: `blockHashBE \|\| merkleRootLE \|\| blockTime`) | **NEVER PRUNED** |
| `0x23` | `txid(32B)` | `VerifiedEvent` (`blockHeight`, `blockHashBE`, `txIndex`, `finalized: bool`) | Never pruned |

---

## 3. Stage 1A: Bitcoin-L1-Canonical Authorization Domain (`0%` Zenon Trust)

For pooled, fungible `zBTC`, **Bitcoin L1 is the sole canonical ordering, data-availability, and forced-inclusion layer**. Zenon Pillars act strictly as **untrusted feeless soft-preconfirmation sequencers** (`spec/03 §2`, `spec/04 §2`). Even if **49%–100% of Zenon Pillars are Byzantine**, they cannot fork `zBTC`, mint 1 unbacked satoshi, or censor Bob's or Mike's exit.

### 3.1 Canonical Bitcoin L1 Tag Schema (`OP_RETURN "ZBTX"` `<= 80 B` + Taproot Witness)

All Stage 1A protocol events are tagged on Bitcoin L1 with a `4 B` magic prefix `"ZBTX"` (`0x5a 0x42 0x54 0x58`) and `1 B` `tag` inside an `OP_RETURN` output (`<= 80 B` standardness limit). Bulk payloads (`certBlob`, mutated SMT leaves, `π_batch`, signed forced transfers) sit inside the spending transaction's Taproot script-path witness, bound by SHA-256 commitment in the `OP_RETURN` and verified against the block's BIP-141 coinbase witness commitment.

| Tag | Name | `OP_RETURN` Layout & Exact Size | Taproot Witness / Additional Outputs | Purpose |
|---|---|---|---|---|
| `0x00` | `DEPOSIT` | `"ZBTX"(4) \|\| 0x00(1) \|\| recipientAcctHash(32) \|\| vaultParamsHash(32)` = **`69 B`** | Input witness carries acyclic `OP_DROP` `certBlob` (`104 B <= 520 B` BIP-342 push limit) + `<pk_depositor> OP_CHECKSIG`; outputs create `{0.50, 0.25, 0.25}` BTC deleted-key vaults (`spec/01 §2.2`, zero hash cycle — `txid_dep` is fixed before presigning). | Register `K`-deep multi-tier deposit vaults (`vaultId = txid_dep : vout`) and credit `recipientAcctHash` in the Rollup SMT. |
| `0x01` | `FORCED_EXIT` | `"ZBTX"(4) \|\| 0x01(1) \|\| exitCommitHash(32)` = **`37 B`** | Witness carries `(acctId, nonce, grossSats, maxOpFeeSats, destScriptPubKey, cancelPubKey, sig_user)`; additional output creates the **`(2M+1)`-leaf `ExitSlotUTXO`** (`546` sat dust anchor, `spec/01 §5`, `spec/03 §2.4`). | Uncensorable L1 exit for Bob (`0.50 BTC`) or Mike (`0.25 BTC`), bypassing 49%–100% Zenon censorship & Plasma spikes. |
| `0x02` | `BATCH_DA` | `"ZBTX"(4) \|\| 0x02(1) \|\| batchCommitHash(32)` = **`37 B`** | Witness carries `prevRoot(32B) \|\| newRoot(32B) \|\| mutatedLeaves[]` (**`16 B`** existing `{acctId(4), balanceSats(8), nonce(4)}` / **`48 B`** new `{acctId(4), pubkey(32), balanceSats(8), nonce(4)}`) `\|\| π_batch` (`~256 B` Groth16 or `~15–40 KB` transparent STARK/IPA). | Anchor feeless Zenon-sequenced transfers onto Bitcoin L1 with **100% self-contained state-diff DA** (zero Zenon node needed to reconstruct SMT!). |
| `0x03` | `FORCED_TRANSFER` | `"ZBTX"(4) \|\| 0x03(1) \|\| txCommitHash(32)` = **`37 B`** | Witness carries signed `110 B` rollup transfer (or `RollupHTLC`/`RollupPTLC` op). | Uncensorable L1 transfer fallback if Zenon censors or Dynamic Plasma spikes. |
| `0x04` | `CHALLENGE_CLAIM` | `"ZBTX"(4) \|\| 0x04(1) \|\| kickoffTxid(32) \|\| verifierAcctId(4)` = **`41 B`** | Emitted on every `ChallengeTx_{r,i}` opened in simultaneous window `[0, 144]` (`spec/01 §4`). | Registers honest challenger eligibility for atomic `0.55 BTC` `B_zbtc` split (`>= 0.0917 BTC` each) upon `Stake_r` slash. |
| `0x05` | `FRONT_CLAIM` | `"ZBTX"(4) \|\| 0x05(1) \|\| exitId(32) \|\| operatorId(4)` = **`41 B`** | Emitted when operator $O_j$ spends `ExitSlotUTXO` paying `destScriptPubKey` `>= grossSats - maxOpFeeSats` in `vout[0]`. | Credits `ReimbursementCredit[O_j] += grossSats` (or triggers `0.01 BTC` grief slash + refund if `vout[0]` fails payment!). |
| `0x06` | `EXIT_FEE_BUMP` | `"ZBTX"(4) \|\| 0x06(1) \|\| exitId(32) \|\| newMaxOpFeeSats(8)` = **`45 B`** | Witness carries user signature over `(exitId, newMaxOpFeeSats)` where `newMaxOpFeeSats > oldMaxOpFeeSats`. | Lets Bob/Mike raise fronting incentive during L1 fee spikes without re-queuing. |
| `0x07` | `RELEASE_ASSIGNMENT` | `"ZBTX"(4) \|\| 0x07(1) \|\| vaultId(32) \|\| operatorId(4)` = **`41 B`** | Witness carries explicit `O_j` signature voluntarily releasing an already-assigned vault (vault assignment itself is **deterministic FIFO inside $\mathcal{F}$** once `ReimbursementCredit[O_j] >= D_d`; zero passive-timeout slash, `spec/01 §6`). | Optional `O_j`-signed voluntary release returning `Vaults[vaultId]` to `UNASSIGNED` and restoring `ReimbursementCredit[O_j] += D_d`. |

### 3.2 Complete Stripped-Block Scan & BIP-141 Witness Binding

Inside the `RV32IM` Rollup verifier $\mathcal{F}$ (executed optimistically off-chain and disprovable via `BitVMX-CPU` `n = 8` bisection on any disputed single instruction):
1. **Complete Stripped Block Verification (`<= 1,000,000 B` Bitcoin consensus stripped-block cap):** For every confirmed block $h$ in the canonical range `[h_prev + 1, h_tip - K + 1]`, the prover feeds the **complete stripped block** (`tx_0 .. tx_{m-1}`) into $\mathcal{F}$. $\mathcal{F}$ computes every `txid_i = doubleSHA256(stripped_tx_i)`, reconstructs the full transaction Merkle root, and asserts equality with `header[h].merkleRoot`. **No transaction in block $h$ can ever be omitted or censored by a malicious prover.**
2. **BIP-141 Single-Branch Witness Inclusion:** For each stripped transaction $tx_i$ carrying an `OP_RETURN "ZBTX"` output requiring witness data (`0x00`, `0x01`, `0x02`, `0x03`, `0x06`, `0x07`), $\mathcal{F}$ parses the full `tx_0` coinbase outputs to extract the unique BIP-141 witness commitment `SHA256d(witnessRoot || witnessNonce)` (verifying `tx_0` is syntactically a coinbase with `vin[0].prevout == 0x00^32 : 0xffffffff`), verifies the single `wtxid_i` Merkle branch against `witnessRoot`, and checks `SHA256(witnessPayload) == opReturnCommitHash` (or verifies the `O_j` witness signature for `0x07`).
3. **Deterministic Skip on Invalid `0x02 BATCH_DA`:** Because `0x02` is permissionless, anyone can post a malformed `0x02` commitment on Bitcoin L1. If a `0x02` transaction fails witness parsing, `prevRoot != R_cur`, or `Verify(π_batch) == false`, $\mathcal{F}$ **deterministically skips** that `0x02` tx without halting state progression!

### 3.3 Canonical Intra-Block Ordering (Eliminating 49%–100% Zenon Forks)

Within each `K`-deep Bitcoin block $h$, $\mathcal{F}$ transitions $R_{h-1} \to R_h$ in strict deterministic order:
1. **Pass 1 — Deposits (`0x00 DEPOSIT`):** Process in Bitcoin block transaction-index order `i = 1..m-1`. Verify acyclic `certBlob` (`104 B`), valid `N`-of-`N` setup cohort binding, valid `{0.50, 0.25, 0.25}` BTC vault outputs, and `totalTVL + D_d <= Cap_TVL`. Credit `Accounts[recipientAcctHash].balanceSats += D_d`.
2. **Pass 2 — First Valid Sequenced Batch (`0x02 BATCH_DA`):** Scan block $h$ in tx-index order and apply **AT MOST ONE** valid `0x02` batch whose `prevRoot == R_after_pass_1` and whose `π_batch` verifies against the complete mutated SMT leaf list. **Any competing `0x02` batch (e.g., from a 49% Zenon fork!) automatically fails `prevRoot` matching and is deterministically ignored.**
3. **Pass 3 — Mandatory L1 Forced Inclusion (`0x03`, `0x01`, `0x06`):** Apply EVERY valid `0x03 FORCED_TRANSFER`, `0x01 FORCED_EXIT`, and `0x06 EXIT_FEE_BUMP` in tx-index order. Because these execute directly from Bitcoin L1, **100% hostile Zenon Pillars cannot delay or censor a single forced transfer or exit by even 1 Bitcoin block**.
4. **Pass 4 — Settlement, Deterministic FIFO Assignment & Slashing Events (`0x04`, `0x05`, `0x07`, `ExitSlotUTXO` spends, `Stake_r` slashes, `BurnBondTx_{r,k}`):** Process all `ExitSlotUTXO` spends (universal spend-or-refund rule, `spec/03 §2.4`), deterministic FIFO oldest-eligible-vault assignment whenever `ReimbursementCredit[O_j] >= D_d` (filtered by `opBitmask`), optional `O_j`-signed `0x07 RELEASE_ASSIGNMENT`, `ChallengeTx_{r,i}` (`0x04`), `DisproveTx`/`TimeoutSlashTx` dual-input slashes (`0.55 BTC` `B_zbtc` split across remaining challengers), and `BurnBondTx_{r,k}` Lamport equivocation slashes (`D_d` burned from `B_zbtc` + `0.05 BTC` bounty).

---

## 4. Launch-Time PoW Anchor, Retargeting & Halving-Indexed TVL-Scaled `K`

Because Bitcoin L1 scripts without covenants cannot inspect arbitrary future chain tips directly, each finite `BitVMX` `StakeChain` lane `(j, l)` (`R = 64` rounds, active horizon `<= ~1.5` years) verifies Bitcoin PoW inside $\mathcal{F}$ anchored at lane launch (`t = 0`, **before** `Q_lane_{j,l}` deletion — zero pre-broadcast hash cycle!):

1. **Launch-Time Lane Anchor `(h_lane_init, H_init, D_init)`:** Pins an **already-confirmed** Bitcoin mainnet block at lane creation, together with its 2,016-block retarget-period start header and `mtpWindow[11]`.
2. **Full 2,016-Block Retargeting & Difficulty Floor:** $\mathcal{F}$ validates every 80-byte Bitcoin header from `h_lane_init` to `h_tip` with exact mainnet `SetCompact`, `[302400, 4838400]`s 2,016-block retarget clamping, MTP monotonicity, and a normative difficulty-drop floor **`D(h) >= 0.50 * D(h_lane_init)`**.
   - *Explicit Difficulty-Growth Disclosure:* If mainnet difficulty grows `> 2×` during a finite lane's active lifetime, the effective private-fork difficulty ratio `α_diff = D(h_lane_init) / D_current` tightens proportionally (e.g., at `3×` growth, `α_diff = 0.33`, increasing required `K` by `1.5×`). Operators periodically retire old lanes (`RetireStakeTx` at `1,440` blocks) and launch fresh lanes re-anchored to current `D(h_lane_init)`.
3. **Halving-Indexed TVL-Scaled `K` Private-Fork Inequality:** To make a private PoW fork forging a fake `K`-deep state strictly unprofitable against honest mining opportunity cost, protocol TVL caps MUST satisfy:
   $$0.50 \times K \times \text{Subsidy}(\text{era}) > \text{Cap}_{\text{TVL}}$$

| Deployment Stage | `Cap_TVL` | `K` (2024–2028, `3.125 BTC` Subsidy) | `0.50 × K × Subsidy` | `K` (2028–2032, `1.5625 BTC` Subsidy) | `K` (2032–2036, `0.78125 BTC` Subsidy) |
|---|---:|---:|---:|---:|---:|
| **Stage 1A Pilot (`M = 3`)** | `<= 10 BTC` | **`14`** (`~2.3h`) | `21.875 BTC > 10` | `14` (`10.94 > 10`) | `28` (`10.94 > 10`) |
| **Stage 1A Expanded (`M = 5`)** | `<= 15 BTC` | **`14`** (`~2.3h`) | `21.875 BTC > 15` | `20` (`15.63 > 15`) | `40` (`15.63 > 15`) |
| **Stage 2 Scaled (`M = 10–20`)** | `<= 50 BTC` | **`36`** (`~6.0h`) | `56.250 BTC > 50` | `66` (`51.56 > 50`) | `130` (`50.78 > 50`) |
| **Stage 2 High-Cap (`M = 20+`)** | `<= 200 BTC` | **`144`** (`~24h`) | `225.000 BTC > 200` | `260` (`203.13 > 200`) | `516` (`201.56 > 200`) |

---

## 5. Mandatory SPV & Authorization Domain Conformance Test Vectors

1. **Stage 0 Header & Merkle Suite:** All 24 Bitcoin header, 2,016-block retarget (`[302400, 4838400]`s), MTP, `futureTimeGuardSecs = 7,200`, `LOWEST_BLOCK_HASH_BE` tie-break, `CVE-2012-2459`, and `CVE-2017-12842` (`len == 64` rejection) vectors.
2. **1- and 2-Block Coinbase Midstate Suite:** Valid coinbase proofs for BOTH `totalCoinbaseBytes % 64 ∈ [0, 55]` (1-block) AND `totalCoinbaseBytes % 64 ∈ [56, 63]` (2-block — e.g. `120 B`, `127 B`, `250 B`), plus rejection of `len(finalChunkTail) != totalCoinbaseBytes % 64` and `totalCoinbaseBytes == 64`.
3. **Panic-Free & Plasma-Floor Fuzz Gate (`B1`, `B2`):** Malformed ABI inputs across all 4 Stage 0 oracle methods MUST return deterministic errors (zero panics, zero FIFO sequencer stalls), and exact ABI sizing of `ProveTxInclusion` (`7,620 B`, `591,388` Plasma) fits `>= 3×` inside the `2,100,000` floor and `<= 40` contract blocks/Momentum.
4. **Stage 1A Stripped-Block & Tag-Ordering Suite:** Deterministic skip of malformed `0x02 BATCH_DA`, rejection of competing second `0x02` batch (49% Zenon fork simulation), mandatory inclusion of `0x03`/`0x01` even when all Zenon sequencers censor, and halving-indexed `K` PoW boundary enforcement across `2024–2036`.
