# Hostile Peer Review — Round 2 — zBTC Bitcoin↔Zenon Interoperability Specification `v2.0.0-draft`

**Reviewer posture:** adversarial, first-principles. Same rules as Round 1: the spec's own summaries were not trusted. Claims were re-derived from Bitcoin consensus and policy, from `go-zenon` source, and from upstream text.
**Review date:** 2026-11-24
**Baseline:** `HOSTILE_REVIEW.md` (Round 1: 12 C · 12 H · 15 M · 10 L · 18 U · 20 gates).

**Artifacts under review (SHA-256):**

| File | SHA-256 |
|---|---|
| `SPEC.md` | `f9904585…6e3d1e` |
| `spec/01` | `259d9268…a2` |
| `spec/02` | `c8d87a6e…69` |
| `spec/03` | `04f173be…3b` |
| `spec/04` | `550d9989…cc` |
| `spec/05` | `0e93b8fa…1e` |
| `scripts/verify_spec_bounds.py` | `4a5a0706…9df` |

**Ground truth:**
- `go-zenon`: `master` `e8986a6`, `origin/dev` `770e893`, `origin/release/0.0.11-rc1` `f19955f`. A `dev:` prefix means `git show origin/dev:<path>`.
- `zenon-developer-commons`: `HEAD` `3719452`. Aliases `S`, `M`, `PF`, `L2A` are as in Round 1 §4.

**Citation convention:** `spec/0N:L`, `SPEC.md:L`, `script:L` (= `scripts/verify_spec_bounds.py`).

---

## 1. Executive Verdict

### **HOLD — BLOCKING SPEC DEFECTS REMAIN**

v2.0 is a real redesign, not cosmetic edits. Most of Round 1's structural problems are gone:
- The pre-signed graph no longer signs over peg-out data.
- `OR anchored` is gone, and so is the custodial exit leaf.
- Vault outpoints are assigned to peg-outs.
- `PEGOUT_CREATED` replaces the L1-StateRoot race.
- The treasury pre-mint model matches the go-zenon VM.
- The three Round-1 swap bugs are fixed.
- The upstream conflicts are escalated rather than overridden.

Of the 67 Round-1 items, **45 are CLOSED, 3 are ESCALATED upstream (correctly), 18 are PARTIALLY CLOSED and 1 is STILL OPEN** (§3).

The redesign also introduces new defects. **Four are CRITICAL**, each giving loss of funds or unchallengeable minting as written:

1. **R2-C1 — The challenged path of the BitVM2 graph is causally impossible, and it can be griefed for about 1,000 sats.**
   - `ChallengeTx` has a dynamic txid: watchers add inputs under `ANYONECANPAY`, and the transaction commits a challenge-time `watcherBountyPubKey`. Yet `AssertStartTx`, `AssertTimeoutTx`, `DisproveTx` and `ChallengedPayoutTx` all spend its outputs or descendants under signatures that must be made at setup, before the key is deleted. This is C-01 again, one level down.
   - `VaultClaimConn` Leaf 2 is `<anyone>`. Anyone can burn an honest operator's happy-path connector. The operator has already fronted `D_bucket` and can never be reimbursed.
2. **R2-C2 — Batches are never chained.** `SubmitBatch` never checks `preStateRoot == previous postStateRoot`, and `ChallengeContinuity` only compares a batch against itself. An executor can start a batch from a fabricated state root, and every step is "correct".
3. **R2-C3 — The PTLC swap still loses funds.** Alice gives Bob her MuSig2 adaptor partial signature (step 3) **before** Bob locks zBTC (step 4). Bob completes the Bitcoin signature with `t` and takes the BTC without ever locking.
4. **R2-C4 — `ChallengeAggregation` is unbounded.**
   - Proving that `claimRoot`, `domainHalted` or `observedChainHeight` disagrees with `traceRoot` takes every step leaf. That is O(`inputCount`) and far above 16 KiB.
   - So an executor can add a fabricated `FOREIGN_LOCK` to `claimRoot`, and `RelayClaim` will mint it.
   - It can also inflate `observedChainHeight`, which only ratchets upward (`max`), and disable peg-outs permanently.

**Eight HIGH findings** remain. The most important:
- **Equivocation slashing does not cover the actual attack.** Certificates exist only every 30 momentums, so a forged certificate at any other height has no conflicting certificate. "Continuity from genesis" does **not** stop long-range attacks with retired Pillar keys (R2-H1).
- **The Groth16 circuit is undefined and unbounded.** It must verify an epoch-certificate chain that grows by one epoch every day, and there is no trusted-setup disclosure (R2-H2).
- **Header pruning lets anyone strand deposits** and shortens the real release deadline to about 133 blocks after fronting (R2-H3).
- **The 1,024 B coinbase cap** makes proofs impossible for blocks whose coinbase pays many outputs or carries large commitments (R2-H4).
- **Watcher economics are negative at every fee level, by the spec's own numbers** (R2-H5).
- **Any bonded executor can pause the whole bridge instantly**, and nothing ever unpauses it (R2-H6).
- **A binding migration strands all legacy vault UTXOs** (R2-H7).
- **The 10% priority lane can be filled with junk challenges** from roughly 300 QSR of fused plasma (R2-H8).

**The numeric oracle is not an oracle.** The BitVM2 weights (95 kvB / 220 kvB), the Zenon→BTC window (180 blocks) and the domain size (250k leaves) are hard-coded inputs. The SMT witness bound is average-case, not worst-case. Its economics section asserts nothing. G-2 and G-19 remain unmet (§5).

**New-finding census:** 4 CRITICAL · 8 HIGH · 12 MEDIUM · 8 LOW.

**What would move the verdict to CONDITIONAL PASS:**
- Fix R2-C1..C4 and R2-H1..H8 with re-reviewed diffs.
- Replace the hard-coded BitVM2 numbers with a published circuit description and measured Signet weights (G-2), or explicitly demote them to "Stage 0C targets".

---

## 2. New Findings (Round 2)

### 2.1 CRITICAL

---

#### R2-C1 — The challenged-path DAG is causally impossible again, and `VaultClaimConn` Leaf 2 = `<anyone>` lets anyone destroy an honest operator's reimbursement for about 1,000 sats

- **Spec:**
  - `spec/01:119` (causality rule)
  - `spec/01:125` (`VaultClaimConn` Leaf2 = `<anyone>`)
  - `spec/01:127` (`ChallengeTx`: `SIGHASH_SINGLE|ANYONECANPAY`, watcher funding inputs, `Out 0` "commits `watcherBountyPubKey`")
  - `spec/01:128` (`AssertTimeoutTx` "Pre-signed Committee…" spends `ChallengeTx:0`, pays `watcherBountyPubKey`)
  - `spec/01:129` (Assert chain consumes `ChallengeTx:0`)
  - `spec/01:130` (`DisproveTx` pays `watcherBountyPubKey`, spends `KickoffTx:2` Leaf2)
  - `spec/01:131` (`ChallengedPayoutTx` signed by `Q_ephem_d`, `SIGHASH_ALL`, spends `AssertEndTx:0`)
  - `spec/01:133-137` (mutual-exclusion claims)
  - `spec/01:225` (MUST-fail vector 5)
- **Ground truth:**
  - A txid commits to every input outpoint and every output.
  - With `ANYONECANPAY`, watchers add arbitrary funding inputs. With a dynamic `watcherBountyPubKey` output, the `ChallengeTx` txid is unknowable at deposit setup.
  - A `SIGHASH_ALL` signature over a transaction that spends `X:n` commits to `txid(X)`.
  - Without covenants (`OP_CTV`/`OP_CAT`/APO, none active), a Tapscript leaf cannot constrain the outputs of the spending transaction. An `<anyone>` leaf therefore lets any party spend the output to any destination.
- **Failure trace (causality):**
  1. `ChallengedPayoutTx_{d,m}` must be signed by `Q_ephem_d` before deletion. Its input 1 is `AssertEndTx:0`.
  2. `AssertEndTx` descends from `AssertStartTx`, which spends `ChallengeTx:0` (`spec/01:129`). `ChallengeTx`'s txid depends on watcher inputs and on `watcherBountyPubKey`. So `txid(AssertEndTx)` is unknown at setup and the signature cannot be produced.
  3. The same applies to:
     - `AssertTimeoutTx`: its input is `ChallengeTx:0`, and it pays a dynamic key.
     - `DisproveTx`: the committee must pre-sign it to bind the `BondOutput` slash to a disprove of `AssertEndTx:0`, and it pays a dynamic key.
  4. The challenged path, and with it the only sanctions against a fraudulent operator (assert-timeout slash and disprove slash), cannot be built.
- **Failure trace (griefing, assuming the happy path is built exactly as written):**
  1. Operator `m` fronts `recipientAmountSats` to the user. `PegOutRecord` becomes `RELEASED`, `outpoint_d` is `RELEASED`, and refund is now impossible.
  2. `m` broadcasts its one-shot `KickoffTx_{d,m}` (the slot UTXO is consumed).
  3. A griefer spends `KickoffTx_{d,m}:0` through Leaf 2 (`<anyone>`), paying the 330 sats to itself (about 110 vB, roughly 1,100 sats at 10 sat/vB).
  4. `PayoutTx_{d,m}` is now invalid forever, because its input 1 is spent. By the causality trace there is no `ChallengedPayoutTx` path. `m` cannot kick off again.
  5. `m` loses `D_bucket`, and `outpoint_d` is frozen on Bitcoin forever. That is accounting-neutral on Zenon (B was already decremented), but it is a pure operator loss.
  6. Rational operators stop fronting, redemption collapses to the refund loop, and zBTC becomes irredeemable in practice (M0).
- **Also false:**
  - "`ChallengeTx` supplying `< F_assert` MUST fail script validation" (`spec/01:225`) cannot be enforced. Leaf 2 has no signature, so nothing constrains its outputs.
  - "DisproveTx payout … strictly to `watcherBountyPubKey`" has the same causality problem. **M-03 is STILL OPEN.**
- **Minimal fix:** Adopt the actual BitVM2 shape.
  - `ChallengeTx` spends a dedicated kickoff connector through an **operator pre-signed** `SINGLE|ANYONECANPAY` signature committing to exactly one output that pays the operator `F_assert` (crowdfunding).
  - **Nothing pre-signed may spend `ChallengeTx` outputs.**
  - Assert, assert-timeout and disprove transactions spend only `KickoffTx` outputs (fixed txid).
  - Happy-path eligibility is gated by the challenge connector being unspent.
  - Disprove rewards must be either a fixed setup-time script or explicitly miner-capturable, with the residual M-03 risk disclosed.
  - Leaf 2 must never be `<anyone>`.
  - Re-derive the full table and have a second party rebuild it on Signet (G-1).

---

#### R2-C2 — Batches are not chained: `preStateRoot` is never bound to the previous batch, so an executor can fabricate the starting state

- **Spec:**
  - `spec/03:159-164` (the `SubmitBatch` checks: proposer, input contiguity, `inputRoot`, policy, caps, halt — no state-root check)
  - `spec/03:172` (`ChallengeContinuity` compares `curLeaf.PreRoot` only against **this** batch's `PreStateRoot`)
  - `spec/03:93-94`
  - `spec/02:288-289`
- **Ground truth:** In an optimistic rollup, a fraud proof is only meaningful relative to an authenticated pre-state. Upstream requires lineage: the referee rolls back "every later batch on that cursor lineage" (M:2176).
- **Failure trace:**
  1. A bonded executor submits batch `n` with `preStateRoot = X`, where `X` is an SMT root the executor built itself. It contains, for example:
     - a `HeaderNode` for a fabricated block whose `merkleRootLE` commits to a fake `RolloverTx`, marked active with ≥ K confirmations; or
     - a pre-populated `ResolutionSeenByOutboxId`.
  2. Every step in batch `n` is executed honestly relative to `X`. `ChallengeStep` finds nothing, and `ChallengeContinuity` passes, because step 0's `PreRoot == batch.PreStateRoot == X`.
  3. The batch finalizes, and `RelayClaim` mints `FOREIGN_LOCK`s against non-existent BTC (≤ `MaxBatchMint` per batch).
  4. The executor repeats this every batch. Total loss is unbounded.
- **Minimal fix:**
  - `SubmitBatch` MUST require `c.PreStateRoot == lineageHead(domainId).PostStateRoot`, where `lineageHead` is the last non-`REJECTED` batch, or the genesis domain root computed from `genesisAnchor` for batch 0.
  - After a successful challenge, `lineageHead` reverts to the last surviving batch.
  - Add a MUST-fail conformance vector.

---

#### R2-C3 — The PTLC swap still lets the secret holder take the BTC without locking zBTC

- **Spec:**
  - `spec/03:244-248` (step 3: "**Both** … exchange valid MuSig2 adaptor partial signatures whose sum is s̃"; step 4: "Once Alice's UTXO confirms and Alice verifies Bob's adaptor partial signature, **Bob locks zBTC**")
  - `spec/03:250-251`
  - `SPEC.md:168`
- **Ground truth:** Bob knows `t`. With Alice's adaptor partial signature `s̃_A` and his own `s̃_B`, he computes `s = s̃_A + s̃_B + g·t` (the parity rule at `spec/03:247` is correct). That is a valid BIP-340 signature on Alice's funding output.
- **Failure trace:**
  1. Alice funds the 2-of-2 output. The parties exchange nonces and adaptor partial signatures (step 3).
  2. Bob now holds everything needed to spend Alice's output. He broadcasts the spend immediately.
  3. Bob never executes step 4. Alice extracts `t`, but there is no Zenon PTLC to unlock.
  4. Alice loses the BTC. C-12 is regressed.
- **Minimal fix:**
  - Alice MUST withhold `s̃_A` until Bob's `PtlcContract.Create(T_znn, pointLock = compress(T), destination = Alice)` is confirmed. Before U2 that means at configured depth; after U2, finality-certified.
  - Alice MUST verify `T_znn ≥ T_btc_worst + Δ` from the confirmed entry before signing.
  - Equivalent alternative: Bob locks first.
  - Add conformance vector "(v) Alice's partial signature released only after the Zenon lock is confirmed".

---

#### R2-C4 — `ChallengeAggregation` is unbounded, so `claimRoot`, `domainHalted`, `observedChainHeight` and `claimEffectSummary` cannot be challenged

- **Spec:**
  - `spec/03:173` (`ChallengeAggregation(domainId, batchId, stepLeaves[], claimData[])`)
  - `spec/03:100-101` (`claimRoot`, `claimCount` separate from `traceRoot`)
  - `spec/03:181` (`RelayClaim` proves inclusion against `claimRoot`)
  - `spec/03:176` (`LastFinalizedTipHeight = max(…, batch.ObservedChainHeight)`)
  - `spec/03:188` (peg-out timeout bounds read that value)
  - `script:72` (`traceProof` depth 12 ⇒ up to 4,096 steps; `MaxBatchInputs` is never fixed)
- **Ground truth:**
  - A canonical `StepTraceLeaf` is 110 B, so 16 KiB holds fewer than about 140 leaves even with no claim data.
  - None of the batch-level aggregates is committed per leaf, so disproving them requires the whole leaf set.
- **Failure traces:**
  - **(a) Forged claim.**
    1. The executor submits a 500-input batch whose `traceRoot` is entirely honest, but whose `claimRoot` adds one extra `FOREIGN_LOCK(Subject = attacker, Amount = D_bucket)` and `claimCount += 1`.
    2. Disproving it needs all 500 leaves plus their claims, about 55 KB or more. That is unchallengeable.
    3. `RelayClaim` mints. This is C-08 reopened at the aggregation layer.
  - **(b) Tip poisoning.**
    1. The executor sets `observedChainHeight = 499,999,900`.
    2. After finalization, `LastFinalizedTipHeight` is permanently ≥ 499,999,900 because `max` never decreases.
    3. Every `RequestPegOut` now needs `tip + 144 ≤ timeoutHeight < 500,000,000`, which is impossible. Redemption is disabled forever.
  - **(c)** Likewise, a false `domainHalted = 0` on a batch that contains a halting step escapes the H-05 propagation, and the spec's main safety net disappears.
- **Minimal fix:** Put every aggregate inside the trace.
  - Each `StepTraceLeaf` carries running accumulators: `cumMint`, `cumClaimCount`, `haltedSoFar`, `observedTipAfter`, and a running claims-root (hash chain).
  - `claimRoot` becomes the final leaf's accumulator. `RelayClaim` proves claim → `stepClaimsRoot_i` → leaf `i` ∈ `traceRoot`.
  - Aggregation disputes become O(log n) "adjacent leaves disagree" challenges, like `ChallengeContinuity`.
  - Bound `MaxBatchInputs` normatively.

---

### 2.2 HIGH

---

#### R2-H1 — Finality-forgery residual: equivocation slashing misses non-checkpoint heights; "continuity from genesis" does not stop long-range attacks; slashable stake is tiny

- **Spec:**
  - `SPEC.md:181` ("(b) mandatory continuous certificate chain from pinned genesis … **defeating stale-key long-range attacks**")
  - `spec/01:146`
  - `spec/04:128` (equivocation = two certificates for the same `(epochIndex, height)`)
  - `spec/05:81` (certificates "every `30` Momentums")
  - `spec/05:84`
- **Ground truth:**
  - `PillarStakeAmount = 15,000 ZNN` (`vm/constants/embedded.go:41`). Delegated ZNN is not slashable.
  - A long-range attack is precisely the forging of a continuous chain from an old fork point using keys that are no longer bonded.
- **Failure traces:**
  - **(a) Non-checkpoint forgery.**
    1. 21 colluding members sign a `FinalityCertificate` for height `h` with `h mod 30 ≠ 0`, carrying a fabricated `stateRoot` that holds `PegOutRecord[x] = {RELEASED, assignedVaultOutpoint = outpoint_d}` and a matching batch root.
    2. No honest certificate exists at `h`, so `SubmitEquivocationProof` cannot fire.
    3. The SNARK (`spec/01:147`) accepts a certificate "at target height `h`" with no checkpoint restriction. The vault drains.
  - **(b) Long-range forgery.**
    1. Pillars that sat on epoch `E_k`'s committee years ago have since revoked and withdrawn their collateral. Their old producer keys are now worthless to them and can be bought.
    2. 21 of them sign a transition from `E_k` to an attacker committee. The attacker extends a fabricated chain to the present.
    3. The SNARK checks only signatures and continuity, so it is satisfied. No slashing is possible.
  - **(c) Economic bound.** The maximum slash per incident is 21 × 15,000 = 315,000 ZNN. `SPEC.md:181(d)` asks to size `MaxRepresentationSupply` below the corruption cost but gives no number or formula.
- **Minimal fix:**
  - Add an on-chain **invalid-certificate** fraud proof: any certified `(height, momentumHash)` that differs from the canonical momentum stored on-chain at that height is slashable. Covering only certificate-vs-certificate is not enough.
  - The SNARK accepts only checkpoint-height certificates.
  - Add a freshness or weak-subjectivity rule for the circuit, for example: the tip-epoch certificate must be Bitcoin-anchored within X blocks of `KickoffTx`, and the earliest anchor for that epoch wins, with a challenger able to present an earlier conflicting anchor.
  - Strike claim (b) from `SPEC.md:181`, and publish a numeric `MaxRepresentationSupply ≤ f(slashable stake)`.

---

#### R2-H2 — The Groth16 "VerifyReimbursementClaim" circuit is undefined, unbounded, and depends on an undisclosed trusted setup

- **Spec:** `spec/01:37`, `spec/01:129` (`L ≈ 32`, `~220 kvB`, `C ≈ 1,200`), `spec/01:143-157`, `SPEC.md:180-183` (says "THREE independent assumptions"), `script:146-147`.
- **Ground truth:**
  - Groth16 has a fixed circuit with a circuit-specific CRS.
  - Ed25519 verification and SHA3-256 (Keccak-f[1600]) are both non-native over BN254.
  - One depth-256 `proof-format.md` path is 256 SHA3 calls, and the predicate needs three such paths.
  - The epoch chain grows by 1 epoch (≥ 21 Ed25519 signatures) per day, without bound.
- **Failure traces:**
  - The vk is fixed per deposit at setup (`spec/01:8`). A deposit made today must prove a chain of `t` epochs years later, and no fixed circuit can do that. The spec has no recursion, IVC, STARK→Groth16 wrapping, or epoch cap.
  - **CRS compromise:** anyone holding the toxic waste can produce a valid proof of a false predicate. The Assert chain then verifies honestly, no `DisproveTx` exists, and every challenged reimbursement passes. This is a fourth trust assumption, and it is missing from §5.
  - **A single missing epoch-transition certificate** (fewer than 21/30 or ≤ 2/3 weight online at an epoch boundary) breaks "continuity" forever. No later SNARK can be proven, and the challenged path is dead for every vault UTXO.
  - The 95 kvB, 220 kvB and 1,200-leaf figures are hard-coded (`script:146-147`), not measured. G-2 ("publish circuit, chunk count, max chunk weight, assert sizes, Winternitz params") is unmet.
- **Minimal fix:**
  - Specify a recursive design: a per-epoch step proof folded into a fixed-size outer Groth16 verifier, with constraint counts.
  - Specify the MPC ceremony and disclose its trust.
  - Specify a liveness rule for missed transitions (e.g., the committee carries over when no handoff certificate exists).
  - Publish measured Signet numbers, or mark every BitVM2 number as a Stage 0C target, not a spec bound.

---

#### R2-H3 — `BTC_PRUNE_STEP` lets anyone strand rolled-over deposits and shortens the real release deadline to about 133 blocks after fronting

- **Spec:**
  - `spec/02:69` (`retainedReorgDepth = 144`)
  - `spec/02:214-215` (anyone may prune `HeaderNode`s deeper than `BestTip − 144`)
  - `spec/02:228` (every transaction proof needs the block's `HeaderNode`/`merkleRoot` and `ActiveChainByHeight`)
  - `spec/02:239` (lock window `h_rol < h_dep + 144`)
  - `SPEC.md:149` and `spec/02:83` ("grace" through `timeoutHeight + 264`)
  - `spec/03:151` (`SubmitInput` rejected while not `ACTIVE`)
- **Ground truth:** A lock proof needs **both** the deposit block's and the rollover block's `HeaderNode`. The lock proof becomes valid at `BestTip = h_rol + K − 1`. The deposit header becomes prunable at `BestTip = h_dep + 145`.
- **Failure traces** (computed in §6, item 5):
  - **Late rollover (`h_rol ≥ h_dep + 134`):**
    1. The deposit header becomes prunable **at or before** the moment the lock proof becomes valid.
    2. A griefer submits `BTC_PRUNE_STEP` first. The deposit fee is refundable, because the input is valid.
    3. The lock proof is now impossible forever. The BTC sits in a graph-complete vault UTXO, the depositor's Leaf B refund was consumed by the rollover, and no zBTC is ever minted. **The depositor loses `D_bucket`.**
  - **Normal rollover:** the relayer must land the lock proof within `145 − (lag + 11)` blocks. That is 128 blocks at a 6-block lag and 62 at a 72-block lag. A pause, congestion or relayer outage longer than that also strands the deposit.
  - **Release:**
    1. A `FrontingTx` at `h_front` must be proven by about `h_front + 133`, not by `timeoutHeight + 264`. With `timeoutHeight` up to `tip + 2016`, an early fronting has far less time than the spec promises.
    2. If the window is missed, the user files non-delivery after `timeoutHeight + 264 + K` and receives zBTC back **and** keeps the BTC. H-06 is reopened.
- **Minimal fix:**
  - Never prune the data that proofs need. Keep `merkleRootLE` in the never-pruned height index (`0x03`: `height → (blockHash, merkleRoot)`), or carry a header-MMR root in `ChainMeta` so old headers are proven by path.
  - Restrict `BTC_PRUNE_STEP` to fields that no proof reads.
  - Restate the release deadline as an explicit, enforced domain rule.

---

#### R2-H4 — `maximumCoinbaseTxBytes = 1,024` and attacker-sized vault-spend transactions make proofs impossible for real blocks

- **Spec:** `spec/02:75`, `spec/02:224-226` (the full non-witness coinbase must be supplied for depth binding), `spec/02:76` and `spec/02:177` (4,096 B cap on `spendTxBytes`), `script:102,106`.
- **Ground truth:**
  - Coinbase size is chosen by the miner, not by the depositor, operator or watcher.
  - Pools that pay hashers directly in the coinbase (e.g., OCEAN-style multi-output coinbases), and blocks carrying several merged-mining or commitment outputs, routinely exceed 1 KB of non-witness coinbase.
  - A vault-spend transaction is built by the **thief**, who can pad it with inputs past 4,096 B non-witness.
- **Failure traces:**
  - **Rollover mined in a large-coinbase block:** the lock proof is impossible, and the deposit is stranded (as in R2-H3).
  - **`FrontingTx` mined in such a block:** the release proof is impossible. The user files non-delivery and gets a double payout, so the operator loses.
  - **An unauthorized vault sweep** (for example, after an ephemeral-key leak, i.e. a failure of the 1-of-N deletion assumption) built over 4,096 B or landed in a large-coinbase block: `BTC_VAULT_SPEND_PROOF` cannot be formed, no halt occurs, and B is silently overstated. M-14 is reopened.
- **Minimal fix:**
  - Prove the coinbase with a SHA-256 midstate. Supply the 64-byte-aligned prefix containing the null prevout, then the midstate and the remaining length (the standard SPV technique). The depth binding needs only `cbTxid` and its branch.
  - Use the same technique to prove one input of an arbitrarily large spend transaction.
  - Never bound a proof by a size that the adversary or a third party controls.

---

#### R2-H5 — Watcher and operator economics fail by the spec's own numbers

- **Spec:**
  - `spec/01:55` ("watcher with fee capital `>= F_disprove`")
  - `spec/01:127` (the watcher pays `F_assert` **to the operator**)
  - `spec/01:128`
  - `spec/01:175-181` (`Min Bond = 2·F_disprove + 0.05`)
  - `spec/01:53` and `spec/01:180` (`Bond ≥ 1.0 BTC` **per (deposit, operator) slot**)
  - `spec/01:208` (`M ≥ 5`)
  - `spec/01:126`, `spec/01:170`
  - `SPEC.md:183`
- **Failure trace** (§6, item 3, using the spec's own 95 kvB / 220 kvB figures):
  - **Watcher net P&L on challenging fraud:**

    | Fee rate | Watcher net P&L |
    |---|---|
    | 50 sat/vB | **−0.014 BTC** |
    | 200 sat/vB | **−0.204 BTC** |
    | 500 sat/vB | **−0.585 BTC** |

    The watcher pays `F_assert + F_challenge + F_disprove`, while the bounty is capped by the bond. The fraudulent operator **keeps `F_assert`** (1.1 BTC at 500 sat/vB, more than the 1.0 BTC vault UTXO).
  - At 500 sat/vB, `AssertTimeoutTx` must pay `B_watch + F_assert = 1.15 BTC` out of a 1.0 BTC bond. As written, it is not even a valid transaction.
  - **Capital:** with `M = 5`, operators lock **5 BTC of bonds per 1 BTC deposit** for the deposit's whole life (500% of TVL). The "M ≥ 5" mitigation for permanent loss is therefore unaffordable.
  - **Reserve funding is unenforced.**
    - `PayoutTx` pays `D_bucket + Bond` entirely to the operator, with no reserve output.
    - `RequestPegOut` collects no ZNN fee.
    - "(or equivalent ZNN fee)" is never specified.
    - H-07 is only partially closed.
- **Minimal fix:**
  - Set the bond to at least `F_assert + F_challenge + F_disprove + B_watch` at the declared ceiling, and refund `F_assert` to the watcher on timeout or disprove.
  - Share one operator bond across deposits through BitVM2-style round/kickoff connectors.
  - Enforce `reserveFeeSats` either as a fixed `PayoutTx` output or as a ZNN/zBTC transfer inside `RequestPegOut`.
  - Make the script assert all of this (§6).

---

#### R2-H6 — Any bonded executor can pause the entire bridge instantly, nothing restores it, and pausing also blocks all relaying

- **Spec:**
  - `spec/03:163` (`domainHalted == 1` ⇒ `SubmitBatch` **immediately** sets `Status = PAUSED`, before any challenge)
  - `spec/03:151` (`SubmitInput` requires `ACTIVE`)
  - `spec/03:175` (`FinalizeBatch` requires `ACTIVE`)
  - `spec/03:160` (permissionless bonded proposer)
  - `spec/05:139` (governance exit windows ≥ 48h)
  - `spec/01:209` ("any party can post ZNN/QSR bond")
- **Failure trace:**
  1. The attacker registers an executor and, when it is the entitled or backup proposer, submits a batch with a fake halting step.
  2. The domain is `PAUSED` at once.
  3. A watcher's `ChallengeStep` succeeds: the batch is `REJECTED` and the bond is slashed. **No rule returns the domain to `ACTIVE`.**
  4. Unpausing needs governance (≥ 48h exit window).
  5. While paused, nothing can be relayed: no headers, release proofs, lock proofs or vault-spend proofs. Bitcoin keeps moving, and together with R2-H3 (prune) and peg-out timeouts this turns every pause into stranded deposits and operator losses.
  6. Cost to the attacker: one executor bond per ≥ 48h freeze, repeatable.
- **Minimal fix:**
  - A halt flag takes effect immediately **only for dispatch** (`RelayClaim` and `FinalizeBatch` of affected batches), and is automatically cleared when the halting batch is `REJECTED`.
  - `SubmitInput` stays open in every status. Input ordering is harmless; only dispatch is dangerous.
  - Specify the governance unpause path and its maximum delay.

---

#### R2-H7 — A binding migration strands every legacy vault UTXO, and users cannot redeem while draining

- **Spec:**
  - `spec/01:143` and `spec/01:152` (SNARK public input `activeChainBindingHash`; `PegOutRecord.ChainBindingHash == activeChainBindingHash`)
  - `spec/03:187` (`RequestPegOut` requires `BindingState == ACTIVE`)
  - `spec/03:192`
  - `spec/03:205-207` (drain phases; `VaultUtxoSet` preserved "byte-for-byte")
- **Failure trace:**
  1. Any binding change (operator set, `vk`, `enforcementSpecHash`, K) moves new peg-outs to the new binding hash.
  2. Legacy outpoints carried over in `VaultUtxoSet` get assigned to those peg-outs, but their per-deposit SNARK pins the old hash.
  3. Check 2 fails, so an honest operator can never pass the challenged path. Since a challenge is free under R2-C1, no rational operator fronts.
  4. All pre-migration TVL becomes unredeemable.
  5. Meanwhile, `DRAINING_*` blocks `RequestPegOut` (`spec/03:187`, `spec/03:205`), so R can never fall while draining. "Drain-before-switch" cannot drain the supply.
  6. A Guardian alone can enter `DRAINING_ROLLOVER_STOP` (`spec/03:205`), so a single multisig can freeze all redemptions indefinitely. That power is not on the forbidden-actions list (`spec/01:206`).
- **Minimal fix:**
  - Tag each `VaultUtxoSet` entry with its setup-time binding hash.
  - `PegOutRecord.chainBindingHash` must equal the **assigned outpoint's** binding, and the SNARK checks it against its own pinned value.
  - Allow `RequestPegOut` during draining; only new mints stop.
  - Bound Guardian draining by a governance timer.

---

#### R2-H8 — The fraud-proof "priority lane" can be filled with junk challenges cheaply and is not consensus-enforced

- **Spec:** `spec/03:223`, `spec/05:122`, `SPEC.md:178`. `ChallengeStep` and the other challenge methods take no bond or deposit (`spec/03:166-173`).
- **Ground truth:**
  - Plasma is a rate, not a cost: fused QSR is refundable (Round 1 H-10).
  - `chain/account_pool.go` is local mempool selection. `verifier/momentum.go` does not check momentum composition, so a "reserved lane" binds only honest Pillars.
- **Failure trace:**
  1. A minimal, failing `ChallengeStep` costs about 52,500 + ~100 × 68 ≈ 60k plasma.
  2. Filling 10 slots per momentum costs about 600k plasma per momentum, roughly 290 QSR fused (refundable) across Sybil accounts.
  3. Lane congestion now delays an honest challenger's 8 KB block, the same censorship the lane was meant to prevent. The fraudulent batch finalizes after 24h.
- **Minimal fix:**
  - Require a challenge deposit (a fixed fraction of the executor bond, forfeited on failure and refunded with the bounty on success).
  - Order the lane by deposit.
  - Make lane composition consensus-checked, or accept a weaker guarantee and lengthen the window.

---

### 2.3 MEDIUM

| ID | Title | Spec | Failure trace | Minimal fix |
|---|---|---|---|---|
| **R2-M1** | The "worst-case" Challenge witness is an average-case estimate, and attackers can grind keys to inflate it | `spec/02:77` ("measured worst case = 8,004 B"); `script:31-41` (`log2(N)+4`); `script:46` (fixed `N = 250,000`) | (1) Simulation (§6, item 1): 250k random keys give a **maximum of 23 non-empty siblings, which already exceeds the script's 22**. (2) Keys an attacker can grind: `FrontingOutpointUsed` (operator picks the txid), and `PegOutState`/`Resolution` (user grinds `sendBlock.Hash`, refunds make it free). A budget of 2⁴⁸ adds about 30 siblings to a target path; 2⁵⁶ adds about 38. (3) An 8-key step averaging ≥ 40 siblings breaks the 12 KiB cap, and ≥ about 57 breaks 16 KiB, which makes the step unchallengeable. (4) `0x03`/`0x06` are never pruned, so N grows forever. (5) The random-key fuzzer in G-9 cannot find ground trees. | Call it an estimate. Add multi-transaction challenge sessions (accumulate witnesses across blocks), or per-key bisection. Derive the cap with an explicit grinding budget. |
| **R2-M2** | `TokenContract.IssueMinted` as specified fails in `applySend` | `spec/03:34`; `spec/05:108` ("emits descendant ContractSend transferring 100% … to `SettlementContract`") | `Issue`'s descendant is a **data-less** `ContractSend` to the issuer (`token.go:143-152`). In `dev`, `applySend` looks up an embedded method for embedded recipients and returns an error on a miss (`dev:vm/vm.go:204-210`). The `isEmbeddedDeposit` exception applies only on the **receive** side, to refund sends (`dev:vm/vm.go:258-268,359`). So `IssueMinted` rolls back and 21M zBTC never reaches Settlement. Also, `spec/03:35` says "`Burn` already rejects every caller", which is false for the owner (`token.go:271`). | The descendant send must call a Settlement ABI method (e.g. `ReceiveTreasury()`). Add a go-zenon unit test (G-11 ⚙). Correct the Burn claim. |
| **R2-M3** | Consensus-critical fields are used but never defined | `spec/02:248` (`po.CreatedBtcHeight`) vs `spec/02:151-154` and `spec/02:279` (no such field); `spec/03:185` (`claim.FinalityRef` raw outpoint) vs `spec/02:241-243` (only the hashed `ForeignEventID`); `spec/03:154` (`inputHash` defined for kind 6 only) | Executor and referee implementations disagree on the primary-window rule, on `VaultUtxoSet` keys (the 36-byte outpoint cannot be recovered from the hashed id) and on the system-input hashes. That is a batch-rejection liveness failure, or a gap that can be exploited. | Add `createdBtcHeight` (the domain's `BestTipHeight` at ingestion) to `PegOutState`. Put the raw `rolloverOutpoint` in a committed claim field. Define `inputHash` for kind 7. |
| **R2-M4** | `BTC_LOCK_PROOF` does not constrain the rollover's shape; the identity-key blast-radius claim is overstated | `spec/02:239-242`; `spec/01:50`; `SPEC.md:182` | (a) Only the **rollover** outpoint is replay-tracked. If a `RolloverTx` ever spends deposits A and B into two vault outputs, a proof pairing `rolVin = A` with `rolVout = 1` mints B's bucket to A's recipient, and B is never credited. (b) `ephemPubKey` is any 32 bytes the relayer supplies. If the identity keys are compromised, every deposit during the compromise can be rolled over to attacker keys, and mints still succeed. The loss is all deposits for the duration of the compromise, not "< 24h of provisional deposits", and the unbacked zBTC is redeemed against honest outpoints by FIFO. | Require exactly one deposit input and one vault output. Track `ProcessedDeposit[depositOutpoint]`. Restate the blast radius honestly and add identity-key rotation / compromise response. |
| **R2-M5** | The peg-out timeout lower bound uses a stale tip | `spec/03:176,188` | `LastFinalizedTipHeight` is updated only at finalization (≥ 24h ≈ 144+ blocks behind). So `tip + 144` can be ≤ the real BTC height, leaving a zero fronting window. A user can then tie up FIFO outpoints for about 16 days per cycle at no cost (the refund returns the full `D_bucket`). | `timeoutHeight ≥ tip + 144 + W_zenon_btc_max + batchingMargin`. Accept the inflated-tip fix from R2-C4. |
| **R2-M6** | The spam deposit punishes honest redundancy | `spec/03:155` | Two relayers race the same header or proof. The second gets `stepError = 1` (already present) and forfeits. That discourages exactly the "≥ 1 honest relayer" redundancy the trust model needs. The refund mechanics (one L1 send per input competing for 100 blocks per momentum) are also unspecified. | A duplicate of an already-applied valid input is a refundable no-op. Specify the refund mechanics (pull-based claim). |
| **R2-M7** | Outpoint assignment ignores which operators hold graphs; losing fronters are uncompensated | `spec/03:189,199`; `spec/01:208` | (1) `preferredOperatorId` comes from a global round-robin and may have **no graph** for `outpoint_d` (it may have registered later). (2) Outpoints whose operators have exited are re-enqueued by FIFO after every refund, so users hit repeated 16-day refund loops. (3) After the 12-block window, operators racing to front lose `D − fee` if they don't win. | Assign only from operators holding graphs for the outpoint. Quarantine dead outpoints. Add an explicit fronting-intent lock on Zenon. |
| **R2-M8** | The BitVM2 graph is incomplete beyond R2-C1 | `spec/01:125,129,143` | (1) No disprove leaf binds the SNARK public inputs to the Kickoff's Winternitz-committed `(outboxId, frontingTxid, releaseBatchId)`. (2) `outpoint_d` and `operatorId_m` are not stated as per-graph constants. (3) Kickoff is one-shot per `(d, m)`, with no retry after a stray kickoff. (4) Winternitz parameters (`w = 4`, and "BLAKE3/SHA-256" is not a Tapscript opcode) and the chunking are unspecified. | Specify all of these in the DAG table (G-1, G-2). |
| **R2-M9** | `DeferredLockQueue` has no exit; `DRAINING_FINAL` strands late locks | `spec/03:79,184,206` | Deferred claims (cap or pause) are never dispatched or refunded: no method exists. Lock claims relayed after `drainGraceEndTs` (slow relayer, pause, R2-H3) are permanently stranded. | Add `DispatchDeferredLock` (permissionless, once headroom exists). Keep `MINTED_LOCK_V1` open for any rollover confirmed before the stop height, whatever the relay time. |
| **R2-M10** | Stage 1A shadow mode is impossible | `SPEC.md:228` (run "in `PAUSED` shadow mode"); `spec/02:28` (MUST initialize `PAUSED`); `spec/03:151` (`SubmitInput` requires `ACTIVE`) | A paused domain ingests nothing, so "≥ 30 days uninterrupted header tracking" cannot happen. | Define shadow mode as `ACTIVE` with `MaxRepresentationSupply = 0` and dispatch disabled, or allow `SubmitInput` while paused (R2-H6). |
| **R2-M11** | The PTLC challenge hash uses the untweaked key | `spec/03:245,247` | The funding output has a CSV script leaf, so the output key is `Q = P_swap + t_tweak·G`. BIP-340 `e` must use `x(Q)`. Signatures as written are invalid, so swaps always fail and refund (no fund loss, but the protocol does not work). Also, `T_btc` is relative to the funding confirmation, not "now". | Use BIP-327 tweaked aggregation. Express `T_btc` from the confirmation height. |
| **R2-M12** | The epoch-handoff signer is ambiguous | `spec/04:96,106,119`; `spec/05:81` | The digest commits `finalityCommitteeRoot` and `nextFinalityCommitteeRoot`, but which committee (E or E+1) signs the first momentum of E+1 is undefined. If no momentum lands in some 24h window, epoch E is never snapshotted and the chain's continuity rule has no defined successor. | State that committee E signs the handoff certificate over root(E+1). Define skipped-epoch carry-over. |

### 2.4 LOW / ERRATA

| ID | Erratum | Location | Correction |
|---|---|---|---|
| **R2-L1** | The release deadline `≤ timeoutHeight + ReleaseSubmissionGrace` is prose only; the domain never enforces it (release and non-delivery simply race on input order) | `SPEC.md:149` vs `spec/02:244-252` | Enforce it, or delete the claim (and see R2-H3) |
| **R2-L2** | Upstream enum conflict not escalated: `S:296` uses `domainClass = EXECUTION \| BRIDGE \| MESSAGING`, while `M:1417` uses `EXECUTION \| AUTHORIZATION`. `spec/02:20` silently picks M and assigns ordinals. `finalityModel` `PROOF` (`spec/02:27`) vs `PROOF_VERIFIED` (`S:309`) | `spec/02:18-29` | Add to the §7 amendment register (A-SPEC-6) |
| **R2-L3** | The non-delivery event id now pins `ActiveChainByHeight[timeoutHeight+264]`, but `M:3887` defines `finalizedCheckpoint` as "the selected `bestTipHashBE` … at verification time". The spec says it "matches `M:3881`"; it matches the shape, not the semantics | `spec/02:104,115-119` | Record it as an amendment (part of A-BTC-1) |
| **R2-L4** | `RolloverTx` has both reserve fee inputs **and** a 0-sat ephemeral anchor that requires a 0-fee parent. "RBF enabled" is misleading: any re-signature after key deletion orphans the graph | `spec/01:102-106` | Pick one fee model. State that `RolloverTx` is immutable once the ceremony completes |
| **R2-L5** | The `BTC_PRUNE_STEP` condition "NOT on any active pending reorg path" takes an unbounded walk to check | `spec/02:215` | Reject pruning while `ReorgActive == 1` |
| **R2-L6** | Overstated status: "Implementation-ready", "resolving all … findings", "measured worst case" | `SPEC.md:3-4`; `spec/02:77`; `SPEC.md:89` | Restate as draft, with open gates |
| **R2-L7** | `MaxBatchMint ≤ executorBond` bounds one batch only. Many concurrent unfinalized batches put up to (batches per 24h) × `MaxBatchMint` at risk against one bond | `SPEC.md:178`; `spec/03:146` | Add an in-flight exposure cap per executor |
| **R2-L8** | The 50% challenger bounty can be front-run by a producing Pillar that copies the `ChallengeStep` | `spec/03:171` | Commit-reveal, or bind the bounty to a pre-registered challenger |

---

## 3. Disposition of Round-1 Findings

Legend: **CLOSED** · **PARTIALLY CLOSED** · **STILL OPEN** · **ESCALATED** (correctly moved to the upstream amendment register; it blocks mainnet until ratified, but is not a spec defect).

### 3.1 CRITICAL (C-01..C-12)

| ID | Status | Evidence / residual |
|---|---|---|
| C-01 | **PARTIALLY CLOSED** | Fixed for the happy path: Winternitz witness, fixed Kickoff txid (`spec/01:119-126`). The challenged path is causally impossible again: **R2-C1**. |
| C-02 | **CLOSED** | Release is proven from an ordinary `FrontingTx` with `OP_RETURN`, non-witness (`spec/02:244-252`). Reimbursement is decoupled from Zenon accounting. |
| C-03 | **PARTIALLY CLOSED** | SNARK, chunked verifier, and non-TRUC Assert/Disprove adopted (`spec/01:129-130`). Circuit unspecified, unbounded and unmeasured: **R2-H2**. |
| C-04 | **CLOSED** (specific bug) | `OR anchored` deleted (`spec/01:145-147`; `spec/04:40-44`). Residual long-range / non-checkpoint forgery: **R2-H1**. |
| C-05 | **CLOSED** | `VaultUtxoSet` FIFO assignment (`spec/03:68,189`), plus the predicate's `AssignedVaultOutpoint == outpoint_d` and winning `operatorId` (`spec/01:148-156`). |
| C-06 | **CLOSED** | Per-deposit ephemeral `Q_ephem_d`, no sign-later templates (`spec/01:47-51`). Blast-radius wording overstated: **R2-M4**. |
| C-07 | **CLOSED** | Key-path-only terminal output, no exit leaf (`spec/01:22,105,208`). |
| C-08 | **PARTIALLY CLOSED** | `traceRoot` and step challenges added (`spec/03:95,114-122,166-172`). No cross-batch root chaining: **R2-C2**. Unbounded aggregation: **R2-C4**. |
| C-09 | **PARTIALLY CLOSED** | Two headers per input, incremental reorg and prune steps, per-tag key sets ≤ 8 (`spec/02:128-137`). The bound is average-case and attacker-grindable: **R2-M1**. |
| C-10 | **CLOSED** | `PEGOUT_CREATED` system input; the domain checks its own SMT (`spec/02:232-234`; `spec/03:193`). |
| C-11 | **PARTIALLY CLOSED** | Treasury model is correct in principle, and Settlement→user transfers are atomic (`dev:vm/vm.go:204-247`, non-contract recipient ⇒ `applyTransfer`). The `IssueMinted` descendant send fails: **R2-M2**. The G-11 ⚙ test is still pending. |
| C-12 | **PARTIALLY CLOSED** | (a) timeout order, (b) `hashType = 1`, (c) LN `ACCEPTED`-first ordering are all fixed (`spec/03:237-268`). New PTLC signature-ordering theft: **R2-C3**. |

### 3.2 HIGH (H-01..H-12)

| ID | Status | Evidence / residual |
|---|---|---|
| H-01 | **CLOSED** | `DepositTx` + `RolloverTx` proof; the CSV-impossibility argument is sound. BIP-112 fails CSV when the input's disable flag is set, or before 144 blocks (`spec/02:239`). |
| H-02 | **PARTIALLY CLOSED** | Bounded `[tip+144, tip+2016]` and `< 500M` (`spec/03:188`). Stale tip: **R2-M5**. Tip inflation: **R2-C4(b)**. |
| H-03 | **CLOSED** (structurally) | The SNARK trusts Zenon `RELEASED` and does not re-check the fronting transaction (`spec/01:158`). New coinbase-cap failure: **R2-H4**. |
| H-04 | **PARTIALLY CLOSED** | Grace window and deferral added (`spec/03:184,205`). Deferred queue has no exit, late locks are stranded: **R2-M9**. Prune strand: **R2-H3**. |
| H-05 | **CLOSED** | Every admitted event block is recorded (`spec/02:242,251,257`), and the halt propagates at `SubmitBatch` (`spec/03:163`). Abuse of the false-halt path: **R2-H6**. |
| H-06 | **PARTIALLY CLOSED** | A proven fronting forecloses refund. The fronting can still go unproven in time (prune / coinbase / pause): **R2-H3**, **R2-H4**, **R2-H6**. |
| H-07 | **PARTIALLY CLOSED** | Explicit `pegOutFeeSats` and a reserve gate. Reserve funding unenforced, watcher P&L negative, bond excludes `F_assert`: **R2-H5**. |
| H-08 | **CLOSED** | Time-epoch committee: `epochIndex` matches `consensus/consensus.go:55`, and timestamps are slot-bound (`consensus/consensus.go:73-86`; `verifier/momentum.go:117-131`). Handoff ambiguity: **R2-M12**. |
| H-09 | **PARTIALLY CLOSED** | Disclosed and slashing added. Slashing misses non-checkpoint forgery and long-range attacks: **R2-H1**. |
| H-10 | **PARTIALLY CLOSED** | Hash-only storage and a deposit added (`spec/03:149-155`). Lane can be filled with junk: **R2-H8**. Deposit punishes redundancy: **R2-M6**. |
| H-11 | **CLOSED** | `len != 64`, `txIndex != 0`, coinbase-depth binding (`spec/02:221-226`). Its coinbase cap is **R2-H4**. |
| H-12 | **CLOSED** | Invariant amended (`SPEC.md:25`); panic-free mandate (`spec/02:189`). |

### 3.3 MEDIUM (M-01..M-15)

| ID | Status | Note |
|---|---|---|
| M-01 | **CLOSED** | The parity rule `s = s̃ + g·t`, `t = g·(s − s̃)` is correct (`spec/03:247-251`). Separate issues: R2-M11, R2-C3. |
| M-02 | **CLOSED** | Unique tag at `paymentVout+1`, plus `FrontingOutpointUsed` (`spec/02:249-251`). |
| M-03 | **STILL OPEN** | The claimed fix (`spec/01:127,130,225`) cannot be implemented: R2-C1. |
| M-04 | **PARTIALLY CLOSED** | Purpose restated correctly; formula still wrong: R2-H5. |
| M-05 | **CLOSED** | `spec/01:83-86`. |
| M-06 | **PARTIALLY CLOSED** | `K ≥ f(…)` is stated but `f` is never defined; the pilot uses K = 12 (`spec/02:67`). |
| M-07 | **CLOSED** | Fronting only after a `FinalityCertificate` (`SPEC.md:145`); Stage 1B requires U2. |
| M-08 | **CLOSED** | `spec/02:287`. |
| M-09 | **CLOSED** | `SPEC.md:128`; `spec/03:216`. |
| M-10 | **CLOSED** | Timestamp windows are sound because momentum timestamps are slot-bound (code cited under H-08). The 180-block conversion is asserted, not derived (§6). |
| M-11 | **CLOSED** | `spec/03:174`; `spec/05:97`. |
| M-12 | **CLOSED** | `spec/01:197`. |
| M-13 | **CLOSED** | `spec/03:124-128` (tagged, no duplication, count committed). |
| M-14 | **PARTIALLY CLOSED** | `BTC_VAULT_SPEND_PROOF` added, but evadable through attacker-sized transactions and large coinbases: R2-H4. |
| M-15 | **CLOSED** (as a gate) | `spec/05:137-139`; `SPEC.md:227`. Governance design itself is not specified. |

### 3.4 LOW (L-01..L-10)

| ID | Status | Note |
|---|---|---|
| L-01 | **CLOSED** | |
| L-02 | **CLOSED** | |
| L-03 | **CLOSED** | |
| L-04 | **CLOSED** | |
| L-05 | **CLOSED** | |
| L-06 | **CLOSED** | |
| L-07 | **CLOSED** | Fee-model contradiction: R2-L4. |
| L-08 | **CLOSED** | With an unregistered upstream deviation: R2-L3. |
| L-09 | **CLOSED** | |
| L-10 | **CLOSED** | |

### 3.5 Upstream (U-01..U-18)

| ID | Status | Note |
|---|---|---|
| U-01 | **ESCALATED** | A-SPEC-1 (`SPEC.md:210`; `spec/02:15`). |
| U-02 | **CLOSED** | `globalInputIndex` (`spec/03:60-62,161`). |
| U-03 | **CLOSED / ESCALATED** | `MaxBatchMint` plus the identity (`spec/03:136-147`); A-SPEC-3. The identity's algebra checks out. |
| U-04 | **PARTIALLY CLOSED** | As H-06. |
| U-05 | **CLOSED** | As H-05. |
| U-06 | **CLOSED** | `cfg.ChainBindingHash` is committed (`spec/02:247,252`). |
| U-07 | **ESCALATED** | A-SPEC-4. Note that `M:3479` asks to **reuse** `kind=1` outbox; the amendment must say why it diverges. |
| U-08 | **CLOSED** | `spec/03:162,181`. |
| U-09 | **CLOSED** | `spec/02:89-95`. |
| U-10 | **CLOSED** | `spec/04:67-78` matches `PF §4` verbatim. L1 empty-as-delete vs L2 present-empty matches `L2A:23,106-108` and `S:674,720,735`. |
| U-11 | **PARTIALLY CLOSED** | A Zenon `OperatorBond_ZNN/QSR` is declared, but no slashing condition is ever defined for it. |
| U-12 | **PARTIALLY CLOSED** | Version header added. The `domainClass` S-vs-M conflict and `PROOF_VERIFIED` naming are not escalated: R2-L2. |
| U-13 | **CLOSED** | |
| U-14 | **CLOSED** | `spec/01:207`. |
| U-15 | **CLOSED** | `spec/05:158`. |
| U-16 | **CLOSED** | `SPEC.md:198`. |
| U-17 | **CLOSED** | `spec/04:4,144`; `spec/05:91`. |
| U-18 | **ESCALATED** | (i)–(v) in `SPEC.md:211-217`. |

**Tally (67 items):** 45 CLOSED · 3 ESCALATED (U-01, U-07, U-18) · 18 PARTIALLY CLOSED · 1 STILL OPEN (M-03). Two of the CLOSED rows (C-04, M-15) close only the specific defect and carry a noted residual. U-03 is counted under CLOSED.

---

## 4. Verified-Sound Mechanisms

These are recorded so they are not re-litigated in Round 3.

- **Leaf-A proof without witness parsing:** checking `(nSequence & 0x80000000) != 0` or `h_rol < h_dep + 144` is sufficient. BIP-112 fails `OP_CSV` when the input's disable flag is set, the key path is a NUMS-plus-tweak point, and the domain re-derives `ProvisionalDepositScript`.
- **Peg-out mutual exclusion inside the domain:** `ResolutionSeenByOutboxId` plus one-way `PegOutRecord` states give exactly one of `RELEASED`/`REFUNDED`.
- **`proof-format.md` V1** is reproduced byte-exact. L1 and L2 empty-value semantics match upstream.
- **Treasury pre-mint atomicity** for Settlement→user transfers (`dev:vm/vm.go:204-247`). R2-M2 concerns only the Token→Settlement issuance hop.
- **HTLC `hashType = 1`**, and the timeout directions for PTLC and both LN routes.
- **Time-based epoch index** and the use of slot-bound momentum timestamps for windows.
- **Event identifiers** are deterministic regardless of relay time.

---

## 5. Go / No-Go Gate Checklist (Round 2 Status)

**Status: NO-GO.**

| Gate | Status | Blocking items |
|---|---|---|
| G-1 (graph causality) | ❌ OPEN | R2-C1, R2-M8; ⚙ Signet build pending |
| G-2 (SNARK + chunked verifier, measured) | ❌ OPEN | R2-H2; numbers hard-coded |
| G-3 (finality proof) | ◐ PARTIAL | R2-H1 |
| G-4 (outpoint binding) | ✅ CLOSED | |
| G-5 (fresh keys) | ✅ CLOSED | (R2-M4 wording) |
| G-6 (no exit leaf) | ✅ CLOSED | |
| G-7 (fronting forecloses refund; fees) | ◐ PARTIAL | R2-H3, R2-H5 |
| G-8 (traceRoot challenge) | ❌ OPEN | R2-C2, R2-C4 |
| G-9 (witness bound) | ◐ PARTIAL | R2-M1; ⚙ CI fuzzer pending, and it must include adversarial trees |
| G-10 (`PEGOUT_CREATED`) | ✅ CLOSED | |
| G-11 (mint model) | ◐ PARTIAL | R2-M2; ⚙ go-zenon test pending |
| G-12 (lock-proof hardening) | ◐ PARTIAL | R2-H4, R2-M4 |
| G-13 (timeouts, sizes, eligibility, halt) | ◐ PARTIAL | R2-H3, R2-H6, R2-M5, R2-M9 |
| G-14 (input DoS) | ◐ PARTIAL | R2-H8, R2-M6 |
| G-15 (epoch committee) | ✅ CLOSED | (R2-M12) |
| G-16 (invariant + governance gate) | ✅ CLOSED | |
| G-17 (upstream) | ◐ PARTIAL | R2-L2, R2-L3; A-SPEC-1..5 and A-BTC-1 pending ratification |
| G-18 (peg-free rails) | ❌ OPEN | R2-C3, R2-M11; ⚙ tests pending |
| G-19 (numbers from scripts) | ◐ PARTIAL | §6 |
| G-20 (independent re-review) | ✅ this document; Round 3 required after fixes | |

---

## 6. Audit of `scripts/verify_spec_bounds.py`

The script ran cleanly (`python3 -I scripts/verify_spec_bounds.py`) and reproduces every number quoted in the spec: Challenge ABI ≤ 8,004 B, payloads ≤ 9,604 B ABI, plasma, and bond table. It is internally consistent, and the ABI envelope arithmetic is within ±32 B of an exact Solidity-ABI derivation. As an **oracle**, though, it is deficient:

| # | Defect | Location | Effect |
|---|---|---|---|
| S-1 | The BitVM2 weights are hard-coded inputs, not derivations: `disprove_max_vb = 95_000`, `assert_total_vb = 220_000` | `script:146-147` | Every fee, bond and watcher number inherits unmeasured guesses. G-2 and G-19 are unmet for Bitcoin. |
| S-2 | The SMT sibling bound `ceil(log2 N) + 4` is average-case. Random-key simulation at N = 250k gives a max of 23 (> 22). Grinding gives 40–60 | `script:31-41` | The "worst case" label is false (R2-M1). |
| S-3 | `N_DOMAIN = 250,000` is fixed, but `0x03`/`0x06` are never pruned and replay sets are permanent | `script:46` | The bound drifts upward over time and is not checked. |
| S-4 | The bond formula omits `F_assert` (which the watcher pays to the operator) and the challenge fee. There is no assertion that the watcher's P&L is ≥ 0 | `script:151` | Hides R2-H5: net −0.014 / −0.204 / −0.585 BTC at 50 / 200 / 500 sat/vB. |
| S-5 | `ChallengeAggregation` and `ChallengeContinuity` are not modeled | `script:69-98` | Hides R2-C4 (O(`inputCount`)). |
| S-6 | The `PegOutState` value omits `createdBtcHeight` | `script:53-54` | Off by 8 B, and hides R2-M3. |
| S-7 | `COINBASE_MAX = 1,024` and `VAULT_SPEND_MAX = 4,096` are treated as protocol-controlled, but they are chosen by the miner or the thief | `script:102,106` | Hides R2-H4. |
| S-8 | `release_sub_grace = K + 180 + 72` ignores the 144-block header-prune horizon (the actual binding constraint) and pause durations. 180 is asserted with no skew derivation | `script:156-158` | Hides R2-H3. |
| S-9 | No modeling of circuit size or epoch-chain growth | — | Hides R2-H2. |
| S-10 | Sections 4–5 contain **no assertions**. "ALL BOUNDS VERIFIED CLEANLY." prints unconditionally | `script:145-164` | The economic "verification" is a printout, not a check. |

**Required:** every economic inequality becomes an `assert`. Unmeasured inputs are labeled `ASSUMED` and listed as Stage 0C measurement obligations. Add an adversarial SMT generator to the G-9 fuzzer.

**Reproduction of this section's numbers:** `python3 -I <scratch>/r2_check.py`. The script is reproduced below (condensed). Its output, also condensed, was:

```text
N=250000: mean sib=18.27 p99=21 p99.99=22 max=23 | script assumes 22
grind budget 2^48: +30 siblings on one target path (+960 B)
grind budget 2^56: +38 siblings on one target path (+1216 B)
8 keys @ 40 siblings: ~13244 B Challenge ABI  (12 KiB cap False, 16 KiB cap True)
8 keys @ 60 siblings: ~18364 B Challenge ABI  (12 KiB cap False, 16 KiB cap False)
@50 sat/vB  watcher net -0.0135 BTC; @200 -0.2040; @500 -0.5850 (AssertTimeout payout 1.15 > Bond 1.0)
M=5: operator BTC bonds locked per 1-BTC deposit = 5.0 BTC (500% of TVL)
h_rol = h_dep+6:   lock-proof window before deposit header prunable = 128 blocks
h_rol = h_dep+72:  62 blocks
h_rol = h_dep+134: 0 blocks;  h_dep+143: -9 blocks (deterministic strand)
```

<details><summary>r2_check.py</summary>

```python
import random, math, sys
sys.setrecursionlimit(10000); random.seed(1)
def sib_counts(keys, depth, acc, out):
    if len(keys) == 1: out.append(acc); return
    bit = 63 - depth
    L = [k for k in keys if not (k >> bit) & 1]; R = [k for k in keys if (k >> bit) & 1]
    if L and R: sib_counts(L, depth+1, acc+1, out); sib_counts(R, depth+1, acc+1, out)
    else: sib_counts(L or R, depth+1, acc, out)
N = 250_000; ks = sorted(random.getrandbits(64) for _ in range(N)); out = []
sib_counts(ks, 0, 0, out); out.sort()
print(N, sum(out)/N, out[int(.99*N)], out[int(.9999*N)], out[-1], math.ceil(math.log2(N))+4)
for S in (22, 30, 40, 50, 60):
    print(S, 8*(1+32+32+32+2+32*S+4+160) + 900)
for fr in (50, 200, 500):
    Fd, Fa, Fc = 95_000*fr/1e8, 220_000*fr/1e8, 2_000*fr/1e8
    print(fr, min(1.0, 2*Fd+0.05) - (Fa+Fc+Fd), 0.05+Fa)
for lag in (6, 72, 133, 134, 143):
    print(lag, 145 - (lag + 12 - 1))
```
</details>

---

## 7. Required Actions Before Round 3 (Priority Order)

1. **R2-C1:** Re-derive the challenged path in the BitVM2 shape: nothing pre-signed spends `ChallengeTx` outputs, and no `<anyone>` leaves. Republish the DAG table with every txid dependency explicit.
2. **R2-C2:** Chain batches with `preStateRoot == lineageHead.postStateRoot`.
3. **R2-C4:** Move every batch aggregate into per-leaf accumulators, route claim inclusion through `traceRoot`, and bound `MaxBatchInputs`.
4. **R2-C3, R2-M11:** Fix PTLC message ordering and the Taproot tweak, and add the vectors.
5. **R2-H3, R2-H4:** Make proofs independent of pruning and of third-party transaction sizes (never-pruned `merkleRoot` index; midstate proofs).
6. **R2-H6, R2-H7, R2-M10:** Redefine pause semantics (dispatch-only, auto-clear, inputs always open), migration (per-outpoint binding, peg-outs during drain), and shadow mode.
7. **R2-H1, R2-H2:** Add invalid-certificate slashing and checkpoint-only SNARK certificates; specify the long-range freshness rule, the recursive circuit, the CRS ceremony, and the missed-epoch rule. Disclose the fourth trust assumption.
8. **R2-H5, R2-H8:** Fix the bond and fee algebra and assert it in the script; share bonds across deposits; enforce reserve fees; add challenge deposits for the lane.
9. Fix the MEDIUM and LOW items, and convert `verify_spec_bounds.py` into an asserting oracle with labeled assumptions (§6).
