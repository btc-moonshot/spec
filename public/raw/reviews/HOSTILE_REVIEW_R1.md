# Hostile Peer Review — zBTC Bitcoin↔Zenon Interoperability Specification `v1.0.0-draft`

**Reviewer posture:** adversarial, first-principles. Every claim was re-derived or checked against code/docs; nothing was taken from the spec's own summaries.
**Review date:** 2026-11-24
**Artifacts under review** (hashes from `HANDOFF_HOSTILE_REVIEW.md` §1): `SPEC.md` (`1abb7497…`), `spec/01` (`1c46c5d2…`), `spec/02` (`a46afd69…`), `spec/03` (`7f4ceedd…`), `spec/04` (`41e902ef…`), `spec/05` (`82c1c9a8…`).
**Ground truth inspected:**
- `go-zenon` `master` `e8986a6`, `origin/dev` `770e893`, `origin/release/0.0.11-rc1` `f19955f` (paths below are `master` unless prefixed `dev:`, meaning `git show origin/dev:<path>`).
- `zenon-developer-commons` `HEAD` `3719452` (paths below are relative to that repo).
- Bitcoin consensus/policy as of Bitcoin Core 28–29 (BIP-340/341/342, BIP-431 TRUC, P2A/ephemeral dust, `LOCKTIME_THRESHOLD`, CVE-2012-2459, CVE-2017-12842).

Citation convention:
- `spec/0N:L` = `spec/0N-*.md` line `L`; `SPEC.md:L` = master spec line `L`.
- Upstream aliases `M:`, `S:`, `PF:`, `L2A:`, `B01:`, `P15:`, `P2:`, `MSR:`, `BVB:` are defined at the top of §4.
- Spec-line citations (241) and go-zenon paths (81) were machine-checked to resolve.

---

## 1. Executive Verdict

### **REJECT — FUNDAMENTAL REDESIGN NEEDED**

1. **The Tier 1A Bitcoin vault cannot be built as drawn.** The graph has to be pre-signed at deposit time, but it commits to values that only exist at peg-out time (`outboxId`, `timeoutHeight`, the connector outpoint, and therefore the `AssertTx` txid). Its "single-transaction" disprove leaf would have to run 21 Ed25519 checks plus SHA3-256 SMT and SPV logic in Bitcoin Script, under a TRUC cap of 10,000 vB. On top of that, the predicate accepts a self-posted Bitcoin "anchor" instead of a quorum signature, and it blocks replay only within one operator's chain. Either gap lets an operator drain the vault with no zBTC burned.
2. **The optimistic layer on Zenon gives no real protection.** `Challenge` is undefined for any batch with more than one input. A 192-header input, or any reorg input, needs about 100–250 KiB of SMT witness against a 16 KiB cap. Release and refund proofs must be checked against a `StateRoot` the relayer cannot know when it builds them. The result: an executor can mint against fabricated Bitcoin state with no way to challenge it, while every honest peg-out stays `PENDING` forever.
3. **Several load-bearing `go-zenon` assumptions are false.** An embedded contract cannot write another contract's storage, so `SettlementContract` cannot atomically mint or burn through `TokenContract`, and the proposed "class guard" blocks Settlement's own only path. `CommitteeRoot` cannot stay fixed for an epoch, because go-zenon re-runs the election (15 random producer slots) every 300-second tick. All three peg-free swap recipes, which the spec calls "100% atomic", lose funds as written.

**Severity census:**
- §2 findings: 12 CRITICAL · 12 HIGH · 15 MEDIUM · 10 LOW.
- §4 upstream-alignment conflicts: 18 items (6 HIGH · 7 MEDIUM · 4 LOW · 1 INFO).
- Six handoff pressure points were tested and found **not** to be bugs (§2.5). Those are recorded so the redesign doesn't chase ghosts.
- The most consequential upstream conflict: under `SPEC.md` v1.6.0, `inputSource = L1_RELAYED` is **reserved, and Core MUST reject registering it** (S:352). `d_btc_asset` cannot be registered until upstream is amended.

---

## 2. Findings Register

### 2.1 CRITICAL / BLOCKER

---

#### C-01 — Pre-signed BitVM graph is causally impossible: it signs over peg-out data that does not exist at deposit time

- **Spec:** `spec/01:104`, `spec/01:140-176` (DAG), `spec/01:180-186` (connector mutual exclusion), `spec/01:183` (`nLockTime = PegOutRecord.Timeout.Height`), `spec/01:182` ("enforced by `SIGHASH_ALL` in the pre-signed BitVM graph"), `SPEC.md:119`, `SPEC.md:150`, `SPEC.md:158`.
- **Ground truth:**
  - BIP-341 signature messages commit to `nLockTime` for every sighash type, and with `SIGHASH_ALL` they also commit to every input outpoint and every output.
  - A transaction that spends an output of `AssertTx` has to name `AssertTx`'s txid. That txid depends on every input of `AssertTx`, `C_k` included.
  - The spec's own timeline puts the N-of-N signing at **rollover**, i.e. deposit time (`spec/01:104`, `spec/01:140`, `SPEC.md:119`). `outboxId`, `timeoutHeight` and `C_k` are created at **`RequestPegOut`** (`spec/03:265-272`), days or months later.
- **Failure trace:**
  1. Deposit `D` is rolled over into `V_i`. The committee must now sign `ReimburseTx_{m,s}` for every operator `m` and slot `s` (`spec/01:145`) and then delete its keys.
  2. `ReimburseTx` lists `C_k` ("unique per outboxId", `spec/01:151`) as an input and `OP_RETURN "ZBTC_REL"||outboxId||…` as an output (`spec/01:165-171`). Neither value exists yet, so there is nothing to sign.
  3. `TimeoutCancelTx` needs `nLockTime = timeoutHeight` (`spec/01:183`). The user picks that value later in `RequestPegOut`. Since `nLockTime` is under the signature, it cannot be pre-signed either.
  4. The DAG also contradicts itself on `C_k`. `AssertTx` consumes `C_k` (`spec/01:150-151`, and `SPEC.md:150` says "KickoffTx → AssertTx consuming the outboxId-unique Connector UTXO"), yet `ReimburseTx` **and** `TimeoutCancelTx` consume `C_k` too (`spec/01:165-167`). Two cases:
     - If Assert spends `C_k`, `ReimburseTx` is invalid forever.
     - If Assert does not spend it, the spec gives no binding between Assert and the slot.
  5. Griefing variant, reading Assert as the spender of `C_k`: a bonded operator posts a deliberately invalid `AssertTx` just before `timeoutHeight` and accepts being disproved. `C_k` is now spent, so `TimeoutCancelTx` is impossible forever, and so is `ReimburseTx`. `PegOutRecord` stays `PENDING` forever; the user's burned zBTC is gone and `pendingForeignRelease` never reaches 0 (drain-before-switch deadlocks, `spec/03:308`). Cost to the attacker: one bond.
- **Minimal fix:** Redesign the graph to the BitVM2/Clementine shape.
  - All pre-signed transactions bind only to **slot-static** objects that exist at setup: the vault outpoint, per-operator kickoff/round connectors, and bond outpoints.
  - Every dynamic value (`outboxId`, payout txid, `timeoutHeight`) is supplied by the operator as a **Winternitz-signed witness** in `KickoffTx`, and the disprove circuit checks it.
  - Refund-on-timeout cannot be a pre-signed `nLockTime` transaction. It has to be (a) a relative-timelock leaf on a per-kickoff connector, keyed off the kickoff confirmation, or (b) a Zenon-side refund rule that needs no Bitcoin event at all (see C-02 fix).
  - Write the full DAG with every input outpoint, sighash flag and timelock, and have a second party re-derive it before any code is written.

---

#### C-02 — `d_btc_asset` cannot authenticate releases or non-deliveries: `outboxId` can only live in witness data, and the verifier parses witness-stripped transactions

- **Spec:** `spec/02:163`, `spec/02:178` ("raw NON-WITNESS serialization"), `spec/02:289` (reject witness marker), `spec/02:360` (require `OP_RETURN "ZBTC_REL"||outboxId` in `ReimburseTx`), `spec/02:378` (`OP_RETURN "ZBTC_CNC"…` in `TimeoutCancelTx`).
- **Ground truth:**
  - After C-01's fix, the only place a pre-signed spend can carry a per-peg-out value is the witness, as Winternitz/Lamport-signed data. Outputs and `nLockTime` are fixed under the committee signature.
  - Witness bytes are not part of `txid`. Proving them takes the `wtxid`, the coinbase witness commitment (BIP-141), the coinbase transaction, and its own Merkle branch.
- **Failure trace:**
  1. Under a buildable graph, `ReimburseTx` has fixed outputs with no `outboxId`.
  2. `BTC_RELEASE_PROOF` step 3 (`spec/02:360`) requires an `OP_RETURN` carrying `outboxId`. That output cannot exist, so no `FOREIGN_RELEASE` is ever emitted.
  3. `PegOutRecord` stays `PENDING` while the vault UTXO has already left custody. `verifiedLockedCollateral` now overstates the BTC actually held: a silent solvency break, plus the drain deadlock from C-01.
  4. Same for `TimeoutCancelTx` (`spec/02:378`).
- **Minimal fix:** Pick one of two designs.
  - **(a)** Add a `wtxid`/witness-commitment proof path: coinbase tx, coinbase Merkle branch, witness Merkle branch, and BIP-141 commitment parse. The release payload grows, so check it against C-10 and H-03.
  - **(b) Preferred:** stop asking Zenon to recognize the reimbursement at all. Release is final on the Zenon side when the operator's **fronting payment** (an ordinary transaction the operator builds, with `OP_RETURN` allowed) is proven. Refund happens on Zenon purely by Bitcoin height (`blk.Height ≥ timeoutHeight` with no qualifying fronting payment proven before then). The vault-side race then becomes the operator's problem on Bitcoin and no longer affects Zenon accounting.

---

#### C-03 — "Single-transaction Tapscript `DisproveTx`" verifying 21 Ed25519 signatures plus SHA3-256 SMT plus SPV is infeasible, and contradicts the TRUC v3 mandate

- **Spec:** `spec/01:188-195` ("any single failed gate yields a single-transaction Tapscript `DisproveTx` leaf execution"), `spec/01:192-194`, `spec/01:207-208` (all graph txs MUST be TRUC v3), `spec/01:309` (MUST-fail vector 5: "disprovable in a single Tapscript execution"), `spec/01:217-219` (`F_disprove`).
- **Ground truth:**
  - Bitcoin Script has no Ed25519, SHA3/Keccak or 64-bit arithmetic. Each must be emulated in Tapscript with ≤ 4-byte numeric operands (stack elements ≤ 520 B, ≤ 1,000 stack items).
  - BIP-431 TRUC limits a v3 transaction to **10,000 vB**, and a TRUC child of an unconfirmed TRUC parent to **1,000 vB**.
  - Max standard transaction weight is 400,000 WU (100,000 vB).
  - Every BitVM2-family design verifies a **SNARK** (Groth16/BN254) of the off-chain predicate. The operator posts Winternitz-committed intermediate verifier values across **multiple** assert transactions (hundreds of KB in aggregate, non-TRUC). A disprove executes **one chunk** of the verifier, not the predicate.
- **Failure trace:**
  1. Verifying one Momentum hash takes SHA3-256 over the momentum preimage. A 256-level SMT inclusion takes 256 SHA3-256 calls. `FinalityCertificate` verification takes 21 Ed25519 verifications.
  2. Any one of these, emulated in Tapscript, is orders of magnitude larger than 10,000 vB.
  3. The DisproveTx therefore cannot exist. Without a disprove path, an operator can **assert anything**, and the "1-of-N honest watcher" assumption guards nothing.
- **Minimal fix:**
  - Respecify Tier 1A as (i) a zk-SNARK (Groth16/BN254 or an equivalent BitVM-supported verifier) proving `VerifyPegOutClaim`, plus (ii) a chunked BitVM2 verifier with Winternitz commitments.
  - Publish the circuit, chunk count, per-chunk weight, assert-tx count and size, and Winternitz parameters.
  - **Drop the TRUC v3 requirement** for Assert/Disprove (they cannot fit). Keep TRUC/P2A only for small transactions (Kickoff, Payout, Challenge) that are measured to be ≤ 10 kvB.
  - Recompute `F_disprove` from real chunk weights (see M-04).

---

#### C-04 — Disprove predicate accepts "anchored in a prior Bitcoin checkpoint" in place of a quorum certificate, so a self-posted `OP_RETURN` forges Zenon state and drains the vault

- **Spec:** `spec/01:192` ("…signed by ≥2/3 active Pillar quorum … **OR** anchored in a prior Bitcoin checkpoint"), `spec/04:31-45` (`ZenonCheckpointV1`), `spec/04:49-59` (Mode B: "permissionless community anchorers"), `spec/04:65` (First-Anchored-On-Bitcoin fork choice).
- **Ground truth:** Mode B anchoring is a plain `OP_RETURN` carrying `c_h = SHA256(ZenonCheckpointV1)` (`spec/04:54-56`). Anyone can publish any `c_h`. Nothing on Bitcoin, or in the predicate, ties an anchored digest to Pillar signatures.
- **Failure trace:**
  1. Operator `O` builds a fake `ZenonCheckpointV1` whose `stateRoot` is the root of a fabricated SMT. It contains `PegOutRecord[x] = {amount = D_bucket, recipient = O's own script, state = PENDING}`. `committeeRoot` and `quorumSigHash` are arbitrary.
  2. `O` broadcasts an `OP_RETURN "ZNNA"||…||c_h` (Mode B). That makes it "anchored in a prior Bitcoin checkpoint".
  3. `O` "fronts" `D_bucket` to **itself** (`FrontingTx` pays `O`'s script with `OP_RETURN "ZBTC_FNT"||x`). Check 3 passes.
  4. `O` asserts. Check 1 passes via the anchor branch, check 2 passes against the forged root, check 4 passes because `x` is fresh.
  5. Watchers cannot disprove. `ReimburseTx` pays `D_bucket` from `V_i` to `O`. Net result: `O` takes `D_bucket` of other users' BTC and burns no zBTC.
  6. Repeat once per vault UTXO.
  7. The light-client fork-choice rule "first anchored wins" (`spec/04:65`) is exploitable the same way: whoever anchors first decides, and anchoring is permissionless.
- **Minimal fix:**
  - Remove the `OR anchored` branch. Finality must **always** be a quorum certificate verified against a committee root whose lineage the circuit verifies (from a genesis/binding-time committee pinned in `enforcementSpecHash`).
  - Anchors may only add an extra constraint, e.g. "the certified checkpoint must also be anchored at depth ≥ X". They can never replace signatures.
  - Replace "first-anchored wins" with "certified **and** anchored; conflicting certified checkpoints ⇒ REFUSED + equivocation evidence".

---

#### C-05 — Cross-vault-UTXO double reimbursement: replay protection is per operator chain, and any `V_i` can reimburse any `outboxId`

- **Spec:** `spec/01:145` (pre-signed reimbursement "one per Operator O_m & Slot s" on **every** `V_i`), `spec/01:195` (Non-Replay: "not previously reimbursed in any prior slot **of the operator's** reimbursement chain"), `spec/02:363` (domain dedups `outboxId` only on the Zenon side).
- **Ground truth:**
  - Bitcoin enforces uniqueness per **outpoint**. Nothing in the graph ties `outboxId` to a specific `V_i`.
  - Operators are permissionless and bonded (`spec/01:51`), so Sybil identities cost nothing.
  - Production BitVM bridges prevent this by binding each withdrawal to exactly one deposit UTXO, so that UTXO uniqueness becomes replay protection.
- **Failure trace:**
  1. User `U` legitimately requests peg-out `x` (`D_bucket`). Sybil operators `O_1` and `O_2`, controlled by one party, both reference **the same** `FrontingTx` that pays `U` (paid once).
  2. `O_1` kicks off against `V_1`, `O_2` against `V_2`, both asserting `x` and the same `frontingTxid`.
  3. Check 4 is per-operator, so both assertions are valid. No one can disprove.
  4. Both `ReimburseTx`s confirm: the vault pays out 2 × `D_bucket` for one fronting.
  5. Zenon side: the domain accepts only the first release (`ResolutionSeenByOutboxId`, `spec/02:363`). `verifiedLockedCollateral` drops by one bucket while the vault lost two. Hidden insolvency of `D_bucket` per Sybil.
- **Minimal fix:**
  - At `RequestPegOut`, Settlement **assigns** a specific vault outpoint to the peg-out, e.g. FIFO over outpoints admitted by `FOREIGN_LOCK`, whose `ForeignEventID` is already the outpoint id (`spec/02:345`). Store it in `PegOutRecord` and `PegOutAuthorization`.
  - The SNARK predicate checks that the reimbursement spends exactly that outpoint.
  - Track vault outpoints on Settlement as `UNASSIGNED → ASSIGNED(outboxId) → SPENT`.

---

#### C-06 — A static `committeeAggPubKey` plus a public per-deposit tweak makes key deletion impossible for the whole life of the binding

- **Spec:** `spec/01:50` ("deletes per-UTXO / ephemeral committee signing keys"), `spec/01:72` (single `committeeAggPubKey` in `custodyConfig`), `spec/01:120-122` (`P_term = committeeAggPubKey + depositCommit·G` "…per-UTXO ephemeral nonce/key shares are destroyed"), `spec/01:148-151` (pre-declared Rebalance to "successor epoch vault key"), `spec/02:41` (`committeeAggPubKey` is in `releaseAdapterRef`, i.e. in `chainBindingHash`), `spec/03:309-311` (changing the binding requires full drain-before-switch).
- **Ground truth:**
  - The discrete log of `P_term` is `x_agg + depositCommit`, where `depositCommit` is public. Whoever can sign for `committeeAggPubKey` can sign for **every** `P_term`.
  - The same key also signs every future `RolloverLeaf` (`spec/01:92`).
  - The key is pinned in `chainBindingHash`, so rotating it means a full drain-before-switch migration (`pendingForeignRelease == 0`).
  - Upstream already flags this exact construction. Portal V2: "Any epoch key compromise can be applied uniformly to all UTXOs" (P2:361). BTC domain research: "no key combination can move BTC outside the pre-signed graph" (B01:208).
- **Failure trace:**
  1. The binding activates. The committee must keep `x_agg` shares **live** to roll over deposit #2, #3, … for as long as the binding exists, potentially years.
  2. "1-of-N deleted its key" is therefore never true for any vault UTXO. It degrades to "at least one of N keeps refusing, online, and is never compromised for the binding's entire lifetime".
  3. A single compromise event covering all N shares at any time (malware, coercion, insider collusion) key-path-spends **every** terminal vault UTXO at once. Total-loss blast radius.
  4. The "pre-declared RebalanceTx to the successor key" (`spec/01:148-151`) has to be signed after the successor key exists, so it also requires live keys.
- **Minimal fix:**
  - Use per-deposit (or per-setup-batch) **fresh** N-of-N keys: `committeeAggPubKey_d` generated, used to pre-sign deposit `d`'s graph, then provably deleted.
  - Remove the committee key from `chainBindingHash`. Pin instead a commitment to the committee-membership/attestation set, and have Settlement or the domain verify a per-deposit "graph complete" attestation (see H-01).
  - Remove all "sign later" templates (Rebalance, successor-key moves). Migration must use pre-signed paths created at deposit time, or wait for user-initiated redemption.

---

#### C-07 — The "Emergency Timelock Exit Leaf" is a custodial backdoor on every idle vault UTXO

- **Spec:** `spec/01:290` (row 4(b): CSV `26,280` blocks "of vault inactivity", spendable by "a pre-committed governed Wind-Down Multi-Party / Custodian liquidation script … NEVER accessible during normal operation"), and contradicting `spec/01:23` (Class P prohibition) and `spec/01:51` ("zero arbitrary spend power").
- **Ground truth:**
  - `OP_CHECKSEQUENCEVERIFY` measures the **age of the specific UTXO** since it confirmed. Bitcoin has no notion of "protocol inactivity". In a fungible pool, most vault UTXOs sit untouched for long periods by design; only peg-outs touch them.
  - Upstream requires the enforcement spec to enumerate "every … emergency key, threshold, and unilateral power" (M:4493). Every recovery path MUST state "its exact authority, exclusions, timelock …" (M:7525). An emergency power must not "silently grant seizure or arbitrary transfer authority" (M:7156). A script "disclosed at activation" fails all three.
- **Failure trace:**
  1. A vault UTXO `V_i` created at block `h` is not assigned to any peg-out for 26,280 blocks (~6 months). That is the normal case for a pool larger than the outflow over six months.
  2. At `h + 26,280` the wind-down key set can spend `V_i` to any destination its script allows. With the stated "Multi-Party / Custodian" script, that is effectively anywhere.
  3. Repeated for every UTXO older than six months, this hands the bulk of TVL to a governed key set. That is the Class P pooled custody the spec itself prohibits (`spec/01:23`).
  4. Avoiding it means re-rolling every UTXO every six months, which needs live committee keys (C-06) and miner fees per UTXO (H-07).
- **Minimal fix:**
  - Delete the leaf. If an emergency exit is required, it may pay **only** to a covenant-free, pre-signed distribution that is already fixed at deposit time (e.g., back to the depositor's refund key, accepting the fungibility consequences), or to nothing at all.
  - State honestly that Tier 1A has no governed exit and that permanent operator loss means waiting for `TimeoutCancel`-style refunds.
  - Any governed key path must be disclosed as `COMMITTEE`/custodial and labeled accordingly (`SPEC.md:185`).

---

#### C-08 — The optimistic fraud proof is undefined for any batch with more than one input

- **Spec:** `spec/03:68-88` (`BatchCommitmentV3`: one `preStateRoot` and one `postStateRoot` per batch; no per-input roots), `spec/03:176` (multi-input batches allowed, `≤ MaxBatchInputs`), `spec/03:181-194` (`Challenge(…, inputSeq, preRoot, postRootClaimed, claimRootClaimed, smtWitnesses)`, step 2: "…or per-input trace commitments in `DAHash`…"), `spec/05:216`.
- **Ground truth:** Nothing in `BatchCommitmentV3` commits the executor to the intermediate state root before or after input `inputSeq`. `daHash` is never defined to contain such a trace.
- **Failure trace:**
  - *Case A, the contract trusts the challenger's `preRoot` and `postRootClaimed`:*
    1. A griefer picks a correct batch.
    2. They supply any `preRoot'` for which they hold witnesses, re-execute, and claim the executor's (uncommitted) post-root differs.
    3. The honest executor is slashed and the honest lineage is rolled back. Bond theft.
  - *Case B, the contract refuses because it cannot verify those roots:*
    1. A malicious executor submits a 2-input batch whose second input fabricates claims.
    2. No challenger can pin the intermediate root, so the batch is unchallengeable and finalizes.
    3. Mint from nothing.
  - Step 5 also compares one input's emitted claims against the whole batch's `claimRoot`/`claimEffectSummary` (`spec/03:189`), which is meaningless for n > 1 inputs.
- **Minimal fix:**
  - Add `traceRoot` to `BatchCommitmentV3`: a Merkle root over `(inputSeq, preRoot_i, postRoot_i, claimsRoot_i)` per input.
  - `Challenge` proves inclusion of the step-`i` leaf against `traceRoot`, checks `preRoot_i == postRoot_{i-1}` (or the batch pre-root), re-executes, and compares `postRoot_i` and `claimsRoot_i`.
  - Define `claimRoot` as the ordered concatenation of the `claimsRoot_i`.
  - Alternative: force `MaxBatchInputs = 1`, which is ruinous for throughput.

---

#### C-09 — `BTC_HEADER_BATCH` and any reorg-carrying input cannot be challenged within 16 KiB, so the executor can poison header state and mint fake `FOREIGN_LOCK`s

- **Spec:** `spec/02:74` (`maximumHeaderBatch` 192), `spec/02:199-283` (per-header reads/writes: parent, existing-hash check, 10 MTP ancestors, `ActiveChainByHeight`, `ChainMeta`, LCA walk, pruning), `spec/02:395-405` (keys), `spec/02:406` ("~1–1.4 KB per key, fitting comfortably inside the 16 KiB account-block data cap"), `spec/03:185` (`smtWitnesses` supplied **in** the `Challenge` call).
- **Ground truth:**
  - `Challenge` data is capped at `MaxDataLength = 16,384` (`vm/constants/plasma.go:42`; enforced for embedded sends only under `DynamicPlasmaSpork`, `dev:vm/plasma.go:172-174,192-195`).
  - Reproducible estimate (Appendix A script; domain SMT ≈ 24k leaves, ≈ 513 B per proof):

    | Contested input | Keys touched | Naive witness | Optimistic multiproof |
    |---|---:|---:|---:|
    | 1 header (no reorg) | 16 | 10.1 KiB | 8.1 KiB |
    | 6 headers | 36 | 22.2 KiB | **16.6 KiB (over cap)** |
    | 192 headers (spec max) | 780 | 472 KiB | **253 KiB** |
    | 1 header causing a 144-deep reorg | 304 | 184 KiB | **108 KiB** |
- **Failure trace:**
  1. A malicious bonded executor processes a legitimate 192-header input. In its claimed post-state it writes one extra `HeaderNode` (`0xD1 0x02`) for a fabricated block `F` (no real PoW; `merkleRootLE` chosen to commit to a fake `RolloverTx` paying the terminal script for `zenonRecipient = attacker`), and marks it active at some height with ≥ K confirmations.
  2. The fraud is in input #1. Proving it needs ≥ 250 KiB of witnesses, so it is unchallengeable.
  3. A later `BTC_LOCK_PROOF` for the fake `RolloverTx` executes **correctly against the poisoned pre-state**, so no challenge on that input succeeds either.
  4. The batch finalizes and `RelayClaim` mints `MaxRepresentationSupply − verifiedLockedCollateral` of zBTC to the attacker, who redeems it against real BTC.
- **Minimal fix:**
  - Make every input's touched-key set bounded and small by construction: `maximumHeaderBatch ≤ 2`, a constant-size MTP ring stored in `ChainMeta`, no pruning inside header inputs (prune in a separate bounded "GC" input), and no reorg rewrites of the height index (index by `(height, branchId)` or store the best-chain hash as an MMR).
  - Or move to **interactive bisection** over a per-header trace (C-08 `traceRoot`), or to `ZK_VALIDITY`.
  - Publish a worst-case witness bound per input tag and enforce it in `SubmitInput`.

---

#### C-10 — Release and non-delivery proofs must cite a Zenon `StateRoot` the relayer cannot know, so every peg-out wedges `PENDING`

- **Spec:**
  - `spec/02:169`, `spec/02:183` (`authorizationProof` includes `smtProofAgainstL1StateRoot, zenonHeight`)
  - `spec/02:193` (`Apply(…, l1StateRoot, …)`, a single root)
  - `spec/02:358` ("against the L1 `StateRoot` passed in the batch context")
  - `spec/03:169` (`momentumHeight: frontier.Height` stamped at **receive** time)
  - `spec/03:184` and `spec/05:223` (`l1StateRoot := getHistoricalStateRoot(entry.MomentumHeight)`)
- **Ground truth:**
  - The proof is fixed inside the send block's `Data` when the relayer signs it.
  - `entry.MomentumHeight` is the frontier momentum **when the pillar later generates Settlement's receive block** (`vm/vm.go:251`; `dev:pillar/worker_contract_generator.go:20-44`, sequencer FIFO). That is always after the send was built.
  - Any state write anywhere changes the SMT root, and almost every momentum has writes.
  - Upstream only requires inclusion "under a Zenon state root accepted by the proof procedure" (M:1786; template M:7109). Which root is a choice the draft invented (spec/02:358), and the d_btc_asset release path never checks `state == PENDING`.
- **Failure trace:**
  1. A relayer builds `BTC_RELEASE_PROOF` with an SMT proof against `StateRoot(h0)` and submits it.
  2. The send confirms in momentum `h0+1`. Settlement's receive runs at frontier `h0+1` or later, so `entry.MomentumHeight = h ≥ h0+1`.
  3. The verifier checks the proof against `StateRoot(h) ≠ StateRoot(h0)` and fails. Every retry has the same race.
  4. `FOREIGN_RELEASE` is never emitted. `ReimburseTx` has already consumed `C_k`, so `TimeoutCancelTx` is invalid. The record is `PENDING` forever, B is overstated (vault UTXO gone), and drain deadlocks.
  5. The payload's own `zenonHeight` field (`spec/02:169`) is never used by `Apply`. The three documents disagree.
- **Minimal fix (preferred):** Delete the L1-SMT dependency entirely.
  - Have `RequestPegOut` **append a canonical `PEGOUT_CREATED{outboxId, amount, recipient, timeoutHeight, chainBindingHash, assignedVaultOutpoint}` input to `d_btc_asset`'s own L1 input stream**. Settlement owns the cursor (`spec/03:46`), so this is ordered by consensus for free.
  - The domain records it in its own SMT. Release and non-delivery proofs then check against domain state and carry no 1+ KB L1 proof.
  - *If* L1 proofs are kept: the payload must name `zenonHeight`, `Apply` must use `StateRoot(zenonHeight)` with `zenonHeight ≤ entry.MomentumHeight`, and the bound must be documented.

---

#### C-11 — VM impossibility: `SettlementContract` cannot atomically mint or burn zBTC; the proposed guard blocks Settlement's own path; the "internal helpers" cannot exist

- **Spec:**
  - `spec/03:28-31` ("Class-Level Rejection … regardless of caller"; "Only SettlementContract's internal VM execution may update `TokenInfo.TotalSupply`")
  - `spec/03:163`, `spec/03:263`, `spec/03:269`, `spec/03:291`
  - `SPEC.md:129` ("internal Settlement↔Token issuance authority")
  - `spec/05:189-202` (guard code runs "BEFORE any caller-permission check"; `token_minted_internal.go` helpers "atomically" mutate `TokenInfo`)
- **Ground truth (go-zenon):**
  1. An embedded method receives an `AccountVmContext` bound to **its own** address (`vm/vm_context/interfaces.go:12-37`). All writes go to `context.Storage()` and its own balance.
  2. Another account's committed state can be **read** through `context.MomentumStore().GetAccountStore(addr)` (`chain/store/momentum.go:51`; used in `vm/plasma.go:59`). It cannot be written.
  3. `TokenInfo` lives in **TokenContract's** storage (`vm/embedded/implementation/token.go:188,214-215`).
  4. The only way to mint is a descendant `ContractSend` to `TokenContract.Mint`. That send is executed later, in TokenContract's **own** receive block (`vm/vm.go:172-206`): asynchronous and non-atomic. `TokenContract` then pays the recipient through another descendant send (`token.go:227-236`).
  5. Burn works the same way: the owner sends tokens to `TokenContract.Burn`; `Owner` may burn even when `IsBurnable == false` (`token.go:271`).
  6. A failed TokenContract receive rolls back only TokenContract's state, and refunds only when `Amount > 0` (`vm/vm.go:208-237`). A failed **mint** (0-amount send) leaves Settlement's counters already updated.
  7. Upstream assumes a "reserved, non-signable Core-internal issuance identity" (M:3132) and an "internal path only" `creditOrMintZTS` (M:3225). The MINTED Extension never mentions `TokenContract`. The draft inherited an issuance primitive that go-zenon's VM does not have; it was never designed.
  8. `checkToken` rejects not only symbol `zBTC` (`token.go:38`) but also the name `"Zenon Bitcoin"`, because the name regex disallows spaces (`token.go:35`). The token id is `hash(issue send block)` (`token.go:70-72,117`), which Settlement cannot know inside the receive that creates it, since descendant hashes are computed afterwards in `finalizeEmbedded` (`vm/vm.go:254-265`).
- **Failure trace:**
  1. Implement the spec literally. `TokenContract.Mint` and `Burn` reject when `Owner == SettlementContract` "regardless of caller", **before** the permission check (`spec/05:194-197`).
  2. Settlement's only mint and burn channel, a descendant send to TokenContract, is rejected. `MINTED_LOCK_V1` updates `R` and `B` but no token is ever created. `RequestPegOut` moves R to P, and the received zBTC stays in Settlement's balance forever.
  3. The fallback, "internal helpers" writing `TokenInfo` from Settlement's context, has no API: the context cannot address TokenContract storage.
  4. Even with the guard fixed, mint is a three-hop asynchronous chain (Settlement receive → TokenContract receive → user receive) with no failure callback. `R` ≠ token supply is guaranteed transiently, and permanently after any TokenContract-side failure.
- **Minimal fix (pick one, specify it fully):**
  - **(a) Treasury model, atomic:**
    - At registration, Settlement (funded with 1 ZNN) issues zBTC through a new `TokenContract.IssueMinted` method callable only by `SettlementContract`. That method allows a lowercase symbol and spaces in the name, sets `TotalSupply = MaxSupply`, `IsMintable = false`, `Owner = Settlement`, and sends the whole supply to Settlement.
    - "Mint" becomes a descendant **transfer** from Settlement's own balance; "burn" becomes keeping the received tokens. Both happen inside Settlement's single receive (`applySend` at `vm/vm.go:197-201`), so they are atomic.
    - Bind the ZTS id in a second governance step that verifies `TokenInfo.Owner == Settlement` through the read-only cross-account store.
  - **(b) Asynchronous model:** keep Mint/Burn through TokenContract, make the guard allow `sendBlock.Address == SettlementContract` (which the existing owner check already enforces; the guard adds nothing), define the conservation invariant over Settlement counters only, and specify a reconciliation/compensation path for TokenContract-side failures.
  - Either way, delete `token_minted_internal.go` from `spec/05`.

---

#### C-12 — All three "100% atomic" peg-free routes lose funds as specified

- **Spec:** `spec/03:363-377` (PTLC), `spec/03:372`, `spec/03:383-388` (inbound submarine), `spec/03:385`, `spec/03:391`, `spec/03:394` ("100% atomic, zero vault trust"), `SPEC.md:165-166`.
- **Ground truth:**
  - `HashTypeSHA3 = 0`, `HashTypeSHA256 = 1` (`vm/embedded/definition/htlc.go:74-75`). Unlock hashes with the entry's type (`vm/embedded/implementation/htlc.go:252-260`).
  - HTLC/PTLC expiry is Unix seconds compared against the **frontier momentum timestamp at receive generation** (`htlc.go:241`; `dev:vm/embedded/implementation/ptlc.go:326,414,460`).
  - A failed unlock still publishes the preimage or scalar in the user's send block `Data`.
- **Failure traces:**
  - **(a) PTLC timeout inversion → Bob steals.**
    1. Bob holds the secret `t`, and Bob's lock is the zBTC PTLC. The spec sets `T_znn < T_btc − margin` (`spec/03:372`).
    2. After Alice funds and hands over her adaptor pre-signature, Bob waits until `T_znn` passes and calls `Reclaim` on Zenon.
    3. Then, still before `T_btc`, he completes `σ_btc = σ̃ + t` and takes Alice's BTC.
    4. Alice extracts `t`, but the PTLC is already reclaimed. **The secret holder's lock must have the longer timeout:** `T_znn > T_btc + Δ`.
  - **(b) Wrong `hashType`.** `HtlcContract.Create(…, hashType=SHA256(0), …)` (`spec/03:385,391`) selects **SHA3**.
    - Inbound: the user's `Unlock(r)` fails (`SHA3(r) ≠ SHA256(r)`) but publishes `r`. The gateway settles the user's held LN payment with `r` and later reclaims the zBTC. The user loses the LN amount.
    - Outbound: the gateway pays the merchant, learns `r`, `Unlock` fails, and the user reclaims. The gateway loses the amount.
  - **(c) Inbound ordering.**
    1. Step 2 has the gateway lock zBTC to the user under `h` **before** the user pays (step 3), and the user already knows `r`.
    2. The user calls `Unlock(r)` right away and never pays the hold invoice.
    3. The gateway's inventory is stolen at zero cost.
- **Minimal fix:**
  - (a) Invert to `T_znn ≥ T_btc + Δ_btc→znn`, where Δ covers the Bitcoin confirmation needed to observe `σ`, plus the Zenon receive-generation latency, plus the clock skew between BTC MTP/timestamps and momentum timestamps.
  - (b) `hashType = 1 (HashTypeSHA256)`.
  - (c) The gateway locks zBTC only after its LN node holds the user's incoming HTLC (hold invoice in `ACCEPTED` state), with `T_znn < T_ln − Δ`.
  - Add conformance vectors for all three.

---

### 2.2 HIGH

---

#### H-01 — Direct deposits to the terminal script mint zBTC against vault UTXOs that have no pre-signed graph

- **Spec:** `spec/01:116-135` (terminal script derivable from public data), `spec/01:132` ("verifies `BTC_LOCK_PROOF` ONLY against `RolloverTx` output 0"), `spec/02:340-346` (checks only `PkScript`, value, and outpoint freshness).
- **Ground truth:** The verifier never checks that the proven transaction spends a provisional deposit output, or that it is a `RolloverTx` at all. Coinbase outputs and arbitrary wallet transactions to `Q_term` pass.
- **Failure trace:**
  1. Anyone computes `Q_term(chainBindingHash, assetId, recipient, nonce, epoch)` and pays `D_bucket` straight to it.
  2. `BTC_LOCK_PROOF` passes and zBTC is minted.
  3. That UTXO has no pre-signed reimbursement graph. Operators cannot use it, so redeemable liquidity is less than `B`.
  4. Its only spend paths are the committee key path (C-06) and the exit leaf (C-07). The backing is fully custodial, yet it is counted in `verifiedLockedCollateral` as Tier 1A backing.
- **Fix:** `BTC_LOCK_PROOF` must also prove the parent `DepositTx` (provisional output with key `H_NUMS + depositCommit·G`, inclusion, depth). It must require the `RolloverTx` input to spend it through Leaf A, i.e. a committee signature, which an honest member gives only after the graph is complete. Reject coinbase transactions (`transactionIndex == 0`).

---

#### H-02 — `timeoutHeight` is unbounded and checked against a variable that does not exist; any user can deadlock drain-before-switch permanently

- **Spec:** `spec/03:268` (`timeoutHeight >= lastKnownBtcTipHeight + minimumReleaseTimeout`), `SPEC.md:143` (`bestKnownTipHint`), `spec/03:43-63` (no such storage key), `spec/03:122` (`height(u64)`), `spec/02:80`.
- **Ground truth:**
  - Settlement is chain-neutral and holds no Bitcoin tip (`SPEC.md:38`).
  - Bitcoin `nLockTime` is a u32, and values ≥ 500,000,000 are interpreted as **Unix time**, not height (`LOCKTIME_THRESHOLD`).
  - `d_btc_asset` requires `blk.Height ≥ timeoutHeight` (`spec/02:377`).
- **Failure trace:**
  1. A user calls `RequestPegOut(..., timeoutHeight = 2^64−1)`, or `4,294,967,295`, or `600,000,000`. There is no upper bound and no tip to compare against.
  2. No operator fronts it (check 3 cannot be satisfied in a sensible window). No `TimeoutCancelTx` can ever be valid at that height, so `FOREIGN_NON_DELIVERY` can never be proven.
  3. `pendingForeignRelease ≥ amount` forever, and `CompleteBindingMigration` (`spec/03:310`) is blocked forever, along with the Tier 2 migration (`SPEC.md:244`). Cost: one bucket of zBTC.
  4. The opposite case: `timeoutHeight` already in the past gives instant refunds and a free option against operators (H-06).
- **Fix:**
  - Store `btcTipObserved` in Settlement, updated only by a finalized domain claim type (`FOREIGN_TIP_OBSERVATION`, Amount = 0).
  - Enforce `tip + minTimeout ≤ timeoutHeight ≤ tip + maxTimeout` and `timeoutHeight < 500,000,000`.
  - Or make the timeout **relative**, with the domain fixing the absolute height when it ingests `PEGOUT_CREATED` (C-10 fix).

---

#### H-03 — Release-proof size and amount-binding wedges: the operator controls `FrontingTx` size, and Bitcoin checks `≥` while Zenon checks `==`

- **Spec:** `spec/02:76` (`maximumTransactionBytes = 8,192`), `spec/02:77`, `spec/02:361` (`Value == amountSats`), `spec/01:194` (predicate: pays `>= amountSats`).
- **Ground truth:** The calculation (Appendix A) shows a release proof with an 8,192 B fronting transaction is about 10.7 KB and fits. But the Bitcoin-side predicate sets **no** size bound, and the domain rejects anything over 8,192 B (about 195 legacy inputs).
- **Failure trace (size):**
  1. An operator fronts with a 9 KB consolidation transaction, or pays `amountSats + 1`.
  2. The Bitcoin predicate passes and the operator is reimbursed (`C_k` consumed).
  3. The Zenon release proof is rejected (too large, or `!=`), and `TimeoutCancel` is impossible. Permanent `PENDING`, B overstated, drain deadlock. Zero cost to the operator.
- **Fix:**
  - Make the predicate and the domain identical: the same max fronting size, exact `== amountSats` (or `≥` on both sides with the surplus ignored), and exactly one `ZBTC_FNT` output (M-02).
  - Add a governed "stuck release" escape: a proof that the assigned vault outpoint (C-05) was spent by this operator's payout ⇒ `RELEASED`.

---

#### H-04 — BTC already rolled over can be frozen indefinitely: caps, pauses, DRAINING and binding changes reject lock claims for deposits that no longer have a refund path

- **Spec:**
  - `spec/03:259-261` (lock requires `Status == ACTIVE`, `BindingState == ACTIVE`, cap headroom, and `ctx.ChainBindingHash == reg.ActiveChainBindingHash`)
  - `spec/03:306` (DRAINING "immediately rejects `MINTED_LOCK_V1`")
  - `spec/03:318-320` (Guardian: immediate pause, lower cap, enter DRAINING)
  - `spec/01:288` (pause sets `MaxRepresentationSupply = verifiedLockedCollateral`)
  - `spec/01:133` (rollover eliminates the depositor refund)
- **Failure trace:**
  1. Deposits roll over continuously. Lock claims reach Settlement about K blocks plus 24h later.
  2. During that pipeline, a Guardian pauses, lowers the cap, or enters DRAINING, or governance completes a migration that changes the binding hash.
  3. Every in-flight lock claim fails, and stays failed after migration because of the hash mismatch. The BTC sits in the vault with no zBTC, no refund leaf and no accounting entry (not in `B`).
  4. A compromised Guardian can do this to every in-flight deposit instantly.
  5. Same outcome for an invalid or embedded `zenonRecipient`, which nobody validates before rollover (`spec/03:261`).
- **Fix:**
  - A lock claim's eligibility should be decided by the binding and policy **at the deposit's rollover height**, not at dispatch time.
  - DRAINING keeps accepting old-binding lock claims for a grace period ≥ `provisionalTimeout + K + executionChallengeWindow`, and the committee must stop rollovers at DRAINING (published off-chain SLA).
  - Pauses and caps defer, never reject. Keep an explicit `PendingLock` queue that is dispatched or refunded through peg-out.
  - Validate `zenonRecipient` in `DeriveDepositScript` tooling and in the rollover policy.

---

#### H-05 — `HaltedForReorg` is not connected to Settlement: orphaned deposits still mint

- **Spec:** `spec/02:280-283` (halt sets a flag inside domain state and optionally emits a `FOREIGN_MISCONDUCT` claim), `spec/03:206` (`RelayClaim` checks Settlement `domain.Status`, not domain-internal state), `spec/03:293-296`.
- **Failure trace:**
  1. The lock claim for block `B` is emitted in batch `n`.
  2. A reorg deeper than K orphans `B` while batch `n` is still in its 24h window. The input that detects it sits in batch `n+1`.
  3. Batch `n` is not fraudulent, because it was correct given its inputs, so it finalizes first and mints against BTC that no longer exists.
  4. The `MISCONDUCT` claim in batch `n+1` finalizes later and pauses only after the damage.
  5. The handoff's worry that a 1-block reorg halts the bridge is unfounded, since admitted events need ≥ K confirmations (§2.5). The actual hole is the ordering race in steps 3–4.
  6. Worse case: `AdmittedEventBlocks` is written only for locks (spec/02:346), not for releases (:363) or non-deliveries (:379).
     - Suppose a deep reorg orphans a `TimeoutCancelTx` whose refund was already re-minted, and the operator's `ReimburseTx` confirms on the winning branch. The vault pays out **and** the user is refunded, so the system is insolvent.
     - That case does not halt anything.
  7. Both points violate M:4151-4153: a reorg removing "an already admitted foreign event" MUST halt, and the domain MUST "be paused before any further claim dispatch" (U-05).
- **Fix:**
  - The batch commitment carries `domainHalted`/`haltedAtInputSeq`. `FinalizeBatch` and `RelayClaim` for every batch at or after the earliest batch with an orphaned admitted block are frozen until governance review.
  - Or `RelayClaim` re-checks `FinalityRef` against the domain's latest **finalized** best chain.

---

#### H-06 — The timeout race turns every congested peg-out into a free option for the user against the operator

- **Spec:** `spec/01:183-186`, `spec/01:202` ("operator fronting loss is operator risk"), `spec/01:212-213`.
- **Failure trace:**
  1. A user requests peg-out with the minimal `timeoutHeight` and is fronted at tip+1.
  2. The operator's Kickoff, Assert, T_challenge (≥ 288 blocks) and Reimburse chain runs into a fee spike or targeted censorship and is not confirmed by `timeoutHeight`.
  3. The user, holding the fronted BTC, broadcasts `TimeoutCancelTx` (permissionless) with a high CPFP.
  4. The user receives `FOREIGN_NON_DELIVERY` (zBTC re-minted) **and** keeps the BTC. The operator loses `amountSats`. Repeatable whenever congestion is predictable.
  5. Rational operators price this in or decline service, so redemption degrades to the 4-day refund loop. zBTC becomes **irredeemable in practice** (M0).
  6. This is also a direct upstream MUST violation. A fronting design must prove payment "without permitting a second release **or a timeout refund**" (M:4063; M:4282) (U-04).
- **Fix:**
  - Cancellation must be impossible once the operator has **proven fronting** (C-02(b)): the Zenon-side refund requires "no qualifying fronting proven before `timeoutHeight`".
  - On Bitcoin, the operator's kickoff should disable the timeout path (kickoff consumes the per-slot cancel connector), not the other way round.

---

#### H-07 — No compensation for operators or watchers and no funding source for the Operations Reserve

- **Spec:** `SPEC.md:135-138` ("0 satoshis", "No Skimming"), `spec/01:206` (all BTC fees from the "Operations Reserve or Operator Fee Inventory"), `spec/01:216-221` (bond sized with `F_disprove` at 1,000 sat/vB), `spec/03:268-271` (peg-out burns exactly the bucket; no fee field), `spec/03:330`.
- **Failure trace:**
  - Operator P&L per peg-out: −`D_bucket` (front) + `D_bucket` (reimburse) − fees(Kickoff + Assert + Reimburse + CPFP) − cost of capital for ≥ 2 days − bond opportunity cost − H-06 risk. That is strictly negative.
  - Watcher P&L: a DisproveTx in the 100 kvB class at 1,000 sat/vB costs **1 BTC** (Appendix A), which is 10× a 0.1 BTC bucket.
  - Nobody funds the "Canonical Operations Reserve" (`SPEC.md:207`): not emissions, not users, not operators. Rollover CPFP, anchors and connectors (`spec/01:181`) all draw from it.
- **Fix:**
  - Specify an explicit, disclosed peg-out fee paid in zBTC (or ZNN/QSR) to the fronting operator and to the reserve. This is not collateral skimming: the fee is part of the user's burned amount above `D_bucket`, or a separate ZNN payment.
  - Specify reserve accounting and a minimum balance as an activation gate.
  - Size buckets so that `D_bucket ≫ F_disprove`.

---

#### H-08 — `CommitteeRoot` and `FinalityCertificate` do not match go-zenon's election; "O(1) per epoch" is false

- **Spec:** `spec/04:118-136` (CommitteeRoot fixed per epoch; `slotBitmask` "for current 30-momentum tick"; "O(1) per day"), `spec/04:139` ("top 30 active Pillars sign"), `spec/05:128` (`height % 8640 == 0` = epoch boundary), `SPEC.md:225`.
- **Ground truth:**
  - Producers are re-elected **every tick**: `ElectionByTick → generateProducers → ComputePillarDelegations()` (`consensus/election.go:90-137,147-165`).
  - Tick = `BlockTime × NodeCount` = 10 s × 30 = 300 s (`consensus/context.go:23`; `vm/constants/consensus.go:15-18`).
  - **`RandCount = 15`**: half of every tick's 30 slots go to pillars drawn randomly from outside the selected top set (`consensus/election_algorithm.go:78-117`).
  - Epochs are **time-based** (`consensus/consensus.go:20,55`, `EpochDuration = 24h`). Momentum heights drift from time whenever slots are missed, so `height % 8640` is not an epoch boundary.
- **Failure trace:**
  - A `CommitteeEntry` containing `slotBitmask` and `votingWeight` changes every 300 s, so `CommitteeRoot` changes about 288 times a day. The "one certificate per epoch" light client must then follow 288 committee transitions a day, or it will accept a stale committee.
  - The "top-30" signer set is a different set from the producer set. A light client checking `Momentum.PublicKey ∈ CommitteeRoot` has to use the per-tick producer set, while finality uses the top-30. That is two committees with two trust roots.
- **Fix:**
  - Separate them. `FinalityCommitteeRoot` = top-K by weight, snapshotted at a **time-based** epoch boundary and fixed for the epoch, signing with an explicit `epochIndex`. `ProducerScheduleRoot` = per tick, optional.
  - State the stake-weight vs count-weight threshold rule, and define epoch boundaries by timestamp/tick, never by `height % 8640`.

---

#### H-09 — Vault security silently reduces to 21-of-30 unslashed Pillar hot keys

- **Spec:** `SPEC.md:193` (Tier 1A: "1-of-N honest operator … 1-of-N honest watcher"), `spec/01:192`, `spec/04:138-162`, `spec/04:65`.
- **Ground truth:** go-zenon has no equivocation slashing for Pillars. `FinalityCertificate` exists only as off-chain gossip persisted per node (`spec/05:128-129`). Nothing on-chain penalizes signing two conflicting certificates.
- **Failure trace:**
  1. 21 Pillar producer keys (hot keys on internet-facing nodes) sign a certificate over a fabricated `stateRoot` containing an attacker `PegOutRecord`.
  2. A colluding operator asserts with it. Even after C-04 is fixed, the BitVM predicate is satisfied, so no watcher can disprove.
  3. The vault drains. There is no slashing, no on-chain evidence path, and no Bitcoin-side recourse.
- **Fix:**
  - Disclose it in §5 as a top-level trust surface: "Tier 1A custody ≤ Zenon finality-committee honesty".
  - Add equivocation evidence plus slashing of delegated or pillar stake via a ZNN bond.
  - Size `MaxRepresentationSupply` below the economic cost of corrupting 21 pillars.
  - Have the circuit require a certificate **chain** from a pinned genesis committee, so long-range keys cannot be replayed.

---

#### H-10 — `SubmitInput` writes full payloads into consensus state forever; plasma is renewable, so spam is free; bridge traffic competes for 100 blocks per momentum

- **Spec:** `spec/03:47` (`L1InputEntry` stores `payload`), `spec/03:167-169`, `spec/03:345` ("completely blocking free spam").
- **Ground truth:**
  - Fused plasma is a regenerating **rate**, not a cost (`vm/plasma.go:57-83`).
  - `MaxAccountBlocksInMomentum = 100` for the whole network (`chain/account_pool.go:25`), and contract receive blocks consume these slots too.
- **Failure trace:**
  - One account with about 525 QSR fused (refundable) submits a 15.4 KB junk input every momentum. That is about 133 MB/day of **permanent** Settlement storage, and all of it enters the L1 SMT (`StateRoot`).
  - N Sybil accounts multiply that. Every executor must also carry the junk in batches.
  - Separately, sustained momentum saturation (PoW-funded junk to user addresses) delays `Challenge` inclusion within the 24h window, with no inclusion guarantee anywhere in the spec.
- **Fix:**
  - Store only `inputHash` and read the payload from the send block (`MomentumStore().GetAccountBlockByHash`, already used at `vm/vm.go:155,176`).
  - Require a per-input deposit refunded on batch finalization if the input was non-erroring.
  - Reserve per-momentum capacity, or give priority, to `Challenge`/`FinalizeBatch`.
  - Publish a throughput budget (100 blocks/momentum ≈ 5 user transfers/s network-wide).

---

#### H-11 — SPV verifier lacks the 64-byte-transaction defense (CVE-2017-12842)

- **Spec:** `spec/02:285-329` (only the CVE-2012-2459 guard), `spec/02:441-443` (vectors).
- **Ground truth:**
  - A Bitcoin Merkle interior node is `SHA256d(left‖right)` over 64 bytes, and a 64-byte stripped transaction is consensus-valid. An attacker who gets a crafted 64-byte transaction mined can present its two 32-byte halves as an interior node and "prove" a fabricated transaction one level deeper.
  - The brute force is well within reach of a funded attacker. Mitigations: reject 64-byte stripped transactions (the proposed BIP-54 Consensus Cleanup would make them consensus-invalid, but it is not active, so the verifier must reject them itself), **and** bind branch length to the block's actual tree depth (e.g., require a coinbase proof of the same depth).
- **Failure trace:** A fabricated `RolloverTx` "proven" under a real, K-confirmed block passes `§4.2`, and a `FOREIGN_LOCK` is minted against nonexistent BTC.
- **Fix:** Reject `len(transactionBytes) == 64` for every proven transaction. Require each lock proof to carry the block's coinbase transaction plus branch, enforce `len(merkleBranch) == len(coinbaseBranch)`, and add both checks to the 14 vectors.

---

#### H-12 — The spec's own governing invariant is violated by its design

- **Spec:** `SPEC.md:38` (Settlement: "Strictly Prohibited: Parsing Bitcoin transactions/headers directly"), `SPEC.md:35` (Consensus: no "Running Bitcoin SPV"), versus `spec/03:185` and `spec/05:216-224` (`SettlementContract.Challenge` runs `btcspv.Apply`, which parses headers and transactions inside the L1 VM). `spec/03:268` also has Settlement validate Bitcoin `scriptPubKey`s.
- **Why HIGH:** It is not cosmetic. The upstream framework uses this separation to decide which component a fault lands in. If Settlement can parse Bitcoin, a btcspv bug becomes a **Settlement consensus fault** on every Zenon node: every full node re-executes `Challenge` and panics on `common.DealWithErr` paths. The blast radius expands from one domain to L1 liveness.
- **Fix:** Either amend the invariant explicitly ("Settlement may host a registered verifier plugin for fraud adjudication; plugin faults are contained by …"), or move adjudication to `ZK_VALIDITY` so that Settlement only verifies a proof.

---

*(Upstream normative conflicts that rank HIGH are listed in §4 and referenced as U-xx.)*

---

### 2.3 MEDIUM

| ID | Title | Spec | Ground truth | Failure trace | Minimal fix |
|---|---|---|---|---|---|
| **M-01** | PTLC/BIP-340 adaptor parity is not specified; the extracted scalar can be `−t` | `spec/03:366`, `spec/03:376` | `verifyPointScalar` compares the **compressed** encoding including the parity byte (`dev:…/ptlc.go:82-96`). With MuSig2 adaptors, if `R + T` has odd y the completed signature satisfies `s = s̃ − t` | Alice computes `t' = s − s̃ = −t`. `Unlock(−t)` gives `−T`, the prefix flips, `ErrInvalidPointScalar`, and Bob reclaims after expiry. Also, "Alice pre-signs" alone is wrong for a 2-of-2 MuSig2 key (needs both parties' nonces and partial signatures) | Specify the adaptor protocol (nonce exchange, `R' = R + T` parity rule, `t = g·(s − s̃)` with `g = ±1`), and require the client to check `t·G == T` before submitting |
| **M-02** | One fronting payment can satisfy two peg-outs | `spec/01:194`, `spec/02:361` | Consensus allows any number of `OP_RETURN` outputs (Bitcoin Core ≥ 30 also relays them by default); the spec only checks "commits `ZBTC_FNT‖outboxId`" | A user makes two identical peg-outs (same recipient and amount). The operator pays once, with two `ZBTC_FNT` tags, and is reimbursed twice. The user is underpaid by one bucket | Exactly one `ZBTC_FNT` per tx at `vout = paymentVout + 1`; record `FrontingOutpointUsed` in the domain and predicate |
| **M-03** | Free challenge trigger and MEV on the disprove bounty | `spec/01:157`, `spec/01:173` | In BitVM2 the challenger funds the operator's assert cost (`SINGLE\|ANYONECANPAY` crowdfunded challenge); disprove outputs are unconstrained | Any watcher forces the expensive Assert for free (griefing). Miners copy a watcher's disprove witness and redirect the bounty | Challenge fee ≥ assert cost; commit-reveal, or a bounty paid to a key committed in the challenge |
| **M-04** | Bond inequality has nothing to do with theft deterrence (handoff A.6) | `spec/01:216-221` | In BitVM2 theft is prevented only by a successful disprove; the bond pays challenge costs | `0.15·V_max` is arbitrary. If no watcher acts, the bond does not stop theft. If disprove is broken (C-03/C-04/C-05), the bond is irrelevant | Bond ≥ worst-case (challenge + assert-forcing + disprove-chunk) fees at a stated fee ceiling, plus bounty. State theft resistance as a watcher-liveness assumption only |
| **M-05** | Two contradictory internal keys for the provisional output | `spec/01:86` vs `spec/01:100` | Line 86: `committeeAggPubKey + depositCommit·G` (committee key-path). Line 100: `H_NUMS + depositCommit·G` | Implementers pick line 86, and the committee can key-path-spend un-rolled deposits with no script at all | Delete line 86's formula and keep the NUMS choice |
| **M-06** | `K` not tied to value at risk | `spec/02:71` (K = 12), `SPEC.md:243` | A 12-block fork costs roughly 12 × (subsidy + fees) | Once `MaxRepresentationSupply` exceeds the cost of a 12-block private fork plus a Zenon-side relay stall, minting against a minority fork pays | Require `K ≥ f(maxMintPerFinalityWindow)` as an activation and cap-raise gate |
| **M-07** | "Finalized" peg-out authorization undefined before U2 | `SPEC.md:146`, `SPEC.md:148` | go-zenon has no finality gadget; momentums can be truncated (`DeleteMomentum` paths exist) | An operator fronts against a burn that is later reorged out and cannot be reimbursed | Operators front only against a `FinalityCertificate` (U2) or ≥ N momentums of depth, stated in the enforcement spec |
| **M-08** | Executor input-ordering rule differs from Settlement's `seq` | `spec/02:421` | Order is defined by Settlement's per-contract sequencer FIFO (`chain/momentum/ledger_store.go:92`, `chain/account/sequencer.go`); content is sorted by header bytes (`chain/nom/momentum_content.go:41-55`), but descendant sends and receive-generation ordering are not "header bytes ascending" | Executor `inputRoot` ≠ on-chain, so batches are rejected (liveness) | The executor reads `L1InputEntry[seq]` from Settlement storage; ordering is defined by `seq` only |
| **M-09** | "Feeless ~1s PoW" is inaccurate | `SPEC.md:136` ("Argon2d"), `spec/03:336` | PoW is SHA3-256 (`pow/pow.go:18-23,74-78`); expected work is 31.5 M hashes per 21,000-plasma block (`vm/constants/plasma.go:39`); master caps PoW at 94,500 plasma per block (`vm/constants/plasma.go:47`) | Phones and WASM take seconds to tens of seconds. Under `DynamicPlasmaSpork` the work price rises with load. Relayers and challengers need about 525 QSR fused or heavy PoW | Restate UX numbers with benchmarks; state that "feeless" means "no BTC fee", not "no cost" |
| **M-10** | Momentum-count windows ≠ wall time ≠ Bitcoin blocks | `spec/02:78`, `spec/01:210-214`, `spec/03:321` | Slots are time-based and missed slots produce no momentum (`consensus/consensus.go:20,55`) | `8,640 momentums` can be much longer than 24h; the conversion `W_zenon` → BTC blocks is unspecified | Define windows in momentum **timestamps**, and derive BTC-block bounds with explicit skew margins |
| **M-11** | The `Update` crank is neither consensus-enforced nor frequent | `spec/05:151` | `pillar/worker_updater.go:20-42` sends **user** blocks from the pillar coinbase; rate limit `UpdateMinNumMomentums = 300` (~50 min) (`vm/constants/embedded.go:23`; `implementation/common.go:33`) | Finalization lag is at least 50 min after the window, and pillars that don't run it add more | Rely on permissionless `FinalizeBatch`; document `Update` as best-effort |
| **M-12** | The Tier 2 "stateless covenant" contradicts its own nullifier accumulator | `spec/01:272-276` | A covenant that updates a nullifier/SMT root is stateful, and one pooled UTXO serializes all peg-outs | About one peg-out per Bitcoin block per UTXO chain; accumulator proofs need `OP_CAT`-class opcodes not yet active | Mark as research; specify a UTXO-set or batched design when a covenant actually activates |
| **M-13** | `claimRoot` Merkle construction unspecified | `spec/03:80`, `spec/02:422` | No leaf or interior tagging and no odd-node rule (Bitcoin-style duplication would allow index aliasing) | Executor and Settlement implementations diverge, so honest batches fail `RelayClaim` | Specify a domain-separated tree (`0x00` leaf / `0x01` node, no duplication, explicit leaf count) |
| **M-14** | Vault UTXO set not tracked on Zenon | `spec/01:225`, `spec/01:295` | Only proven releases and locks are visible; unauthorized vault spends are never ingested | Proof-of-reserves (`spec/01:295`) and misconduct triggers depend on off-chain watchers; B can be silently stale | Add a `BTC_VAULT_SPEND_PROOF` input that marks the spent outpoint and emits `FOREIGN_MISCONDUCT` if unassigned |
| **M-15** | Governance is a prerequisite but is only delivered in U5 | `spec/03:318-321`, `spec/05:249-251`, `SPEC.md:243` | All sporks and Settlement governance are controlled by a single `SporkAddress` key until U5 (genesis `SporkAddress`, `chain/genesis/embedded_genesis_string.go:7`) | The Stage 1B pilot, with exit windows and guardians, would run on a single key | Make U5 governance (or an equivalent multisig) a hard gate for Stage 1B |

### 2.4 LOW / ERRATA

| ID | Erratum | Location | Correction |
|---|---|---|---|
| **L-01** | Non-hex prefix "`0xS0`–`0xS9`" | `spec/02:395` | The Settlement prefixes are `0x01`–`0x13` (`spec/03:43-63`), in a different tree anyway |
| **L-02** | Token name `"Zenon Bitcoin"` fails `checkToken`'s name regex (no spaces) as well as the symbol regex | `spec/03:17`; `token.go:35,38` | Use `"ZenonBitcoin"`, or exempt both regexes in `IssueMinted` (C-11) |
| **L-03** | `depositCommit` excludes `amountSats`, but `SPEC.md` says the vault commits to it | `spec/01:76-82` vs `SPEC.md:119` | Either add `u64(bucketIndex)` to the commit or fix `SPEC.md` |
| **L-04** | `math/rand` "blocks light clients" is overstated | `SPEC.md:225`, `spec/04:118` | Go's `rngSource` is deterministic and portable; the real blocker is that a delegation-state commitment is missing |
| **L-05** | Mode B `u32BE(height_mod)` is undefined | `spec/04:55` | Define it (e.g., `height mod 2^32`) or use `u64` |
| **L-06** | `FinalityCertificate` is non-canonical (any 21-of-30 subset) but `quorumSigHash` is anchored | `spec/04:42`, `spec/04:151-161` | Anchor `finalityDigest`, not a hash over the signer subset |
| **L-07** | Zero-value P2A ephemeral anchors need the Core **29** ephemeral-dust policy (0-fee parent, same-package spend), not "v28+" | `spec/01:208` | Correct the version; require zero-fee parents |
| **L-08** | `NON_DELIVERY` event id includes `bestTipHashBE`, so it is relay-time dependent | `spec/02:120-122`, `spec/02:380` | Use `(chainBindingHash, outboxId)`; replay is already enforced by `PegOutRecord.state` |
| **L-09** | Multiple vault epochs vs a single `vaultEpochId` in `releaseAdapterRef` | `spec/02:41` vs `spec/02:155,343` | Pin the epoch set in the binding; reject witness epochs not in the set |
| **L-10** | Baseline should name `release/0.0.11-rc1` (`f19955f`), which carries the same spork set as `dev`, including the real-hash `PtlcSpork` | `spec/05:1-30` | Baseline on the release branch; record `PtlcSpork` on-chain status (its id is a real CreateSpork hash, `dev:common/types/spork.go:12`) |

### 2.5 Handoff pressure points tested and **refuted** (do not "fix" these)

| Handoff item | Verdict | Reasoning |
|---|---|---|
| D.1 SMT leaf/interior with no domain tag when `len(value) = 32` | **Not exploitable as specified** | The verifier always walks exactly 256 levels from `SHA3(path‖value)`, and `path` both fixes the leaf position and is hashed into the leaf. Passing an interior node `SHA3(L‖R)` off as a leaf would need `path = L` **and** `L`'s 255-bit prefix to route to the position whose left child is `L`, a probability of about 2⁻²⁵⁵. Present-empty (`SHA3(path)`) ≠ absent (`zero32`). Still recommended: add a `0x00`/`0x01` tag for defense in depth and for any future variable-depth or compressed format. |
| B.3 A 1-block reorg halts the bridge | **No** | Admitted events require ≥ K confirmations, so only reorgs deeper than K orphan an admitted block. The real defect is H-05 (the halt does not reach Settlement in time). |
| B.4 192 headers do not fit in 16 KiB after ABI packing | **They fit** | Payload 15,397 B; ABI `SubmitInput(uint32, bytes)` = 15,524 B ≤ 16,384; ≤ `maximumProofBytes` 15,872. (Plasma is 1,107,860, not the spec's 1,099,428, a LOW-level arithmetic slip.) The size failure is the **challenge witness** (C-09), not the input. |
| B.1 17,380-momentum state-tree retention breaks old proofs | **Not the failure** | `StateRoot` lives in momentum headers forever; retention only limits proof *generation*. The real defect is C-10. |
| B.3 Retarget across forks, timespan clamp, `SetCompact` | **Correct** | Epoch start = block `h−2016` (Core's `nHeightFirst`); per-node `retargetStartTime` handles forks; the bounds `[302400, 4838400]` are right; the canonical round-trip is harmless on mainnet. |
| B.3 CVE-2012-2459 guard | **Correct for its case** | `idx` odd ∧ `cur == sib` exactly identifies a phantom duplicated right node. The open SPV hole is H-11 (64-byte txs), not this. |

---

## 3. Codebase Fact-Check Table (`spec/05` and other `go-zenon` claims)

| # | Spec claim (location) | Verdict | Evidence |
|---|---|---|---|
| 1 | `master` lacks `PtlcSpork`, `DynamicPlasmaSpork`, `Libp2pSpork`, `EmbeddedRefundSpork`, `EpochRewardTermsSpork`; `dev` has them (`spec/05:17-23`) | **CONFIRMED** | `common/types/spork.go:4-6` (master: three sporks); `dev:common/types/spork.go:8-84`. `release/0.0.11-rc1` has the identical set (not mentioned). |
| 2 | `PtlcSpork = e59f1e97…` (`spec/05:18,40`) | **CONFIRMED**; activation **UNVERIFIED** | `dev:common/types/spork.go:12`. It is a real tx hash, not a placeholder, so `CreateSpork` has likely already been broadcast. |
| 3 | Placeholder ids `…0001/0002/0004/0007` | **CONFIRMED** | `dev:common/types/spork.go:41,50,59,68`. Ids `…0003/0005/0006` are unused on every remote branch; the spec's `…0008`–`…000D` do not collide today. |
| 4 | Master bypasses 16 KiB and byte pricing for embedded sends at `vm/plasma.go:101` (`SPEC.md:223`) | **CONFIRMED** | `vm/plasma.go:93-101`: the length check exists only on the non-contract branch; the embedded branch returns `method.GetPlasma` flat. `ErrABDataTooBig` is used nowhere else. |
| 5 | Fixed by `EmbeddedSendBasePlasma` at `dev:vm/plasma.go:192` behind `DynamicPlasmaSpork` | **CONFIRMED** | `dev:vm/plasma.go:168-176,192-200` (tier + `(len−4)·68`, reject > 16,384). |
| 6 | Composable spork bitmask at `dev:vm/embedded/embedded.go:246` | **CONFIRMED** | `dev:vm/embedded/embedded.go:243-330`. |
| 7 | `checkToken` enforces `^[A-Z0-9]+$` at `token.go:38` (`SPEC.md:224`) | **CONFIRMED (incomplete)** | `token.go:38`; the name regex at `token.go:35` also rejects `"Zenon Bitcoin"` (L-02). |
| 8 | "Requiring an external issuer key" (`SPEC.md:224`) | **INACCURATE** | `Owner = sendBlock.Address` (`token.go:126`), and embedded contracts can be the sender. The problem is asynchrony and the token-id chicken-and-egg (C-11), not a key. |
| 9 | Settlement can mint/burn "atomically" via internal helpers (`spec/03:31`, `spec/05:199-202`, `SPEC.md:129`) | **INACCURATE (impossible)** | `vm/vm_context/interfaces.go:12-37`; `vm/vm.go:172-237`; `token.go:179-237,260-286` (C-11). |
| 10 | "go-zenon forbids an embedded contract from directly writing another contract's storage" (handoff C.1 premise) | **CONFIRMED for writes; INACCURATE for reads** | Reads of committed state: `chain/store/momentum.go:51`, used at `vm/plasma.go:59`. |
| 11 | `EmbeddedRefundSpork` fixes failed contract-to-contract refunds and is a Settlement prerequisite | **CONFIRMED** | `dev:common/types/spork.go:52-58` (data-less embedded→embedded sends were never received before the spork). |
| 12 | Election seeds `math/rand` with `proofBlock.Height` (`SPEC.md:225`) | **CONFIRMED** | `consensus/election_algorithm.go:38-40,54,89,100,112`. |
| 13 | Delegations are read per epoch (implied by `spec/04:122-136`) | **INACCURATE** | Per **tick** (300 s): `consensus/election.go:90-137,147-165`; `RandCount = 15` (`vm/constants/consensus.go:18`). |
| 14 | Epoch = `height % 8640` (`spec/05:128`) | **INACCURATE** | Time-based epochs: `consensus/consensus.go:20,55`. |
| 15 | `DeleteMomentum` is a no-op at `rpc/api/subscribe/api.go:162` | **CONFIRMED** | `rpc/api/subscribe/api.go:162-163`. |
| 16 | Genesis embeds BTC block hash `…4dd04059…`; genesis hash `9e2046…` | **CONFIRMED**; height `710,968` **UNVERIFIED offline** (consistent with timestamp 1637755200) | `chain/genesis/embedded_genesis_string.go:6`; `chain/genesis/embedded_genesis_test.go:11`; `chain/genesis/momentum.go:23` (written to `Momentum.Data`). |
| 17 | `ErrMDataMustBeZero` at `verifier/momentum.go:154` | **CONFIRMED** | `verifier/momentum.go:152-156`. |
| 18 | `ChangesHash` = hash of `goleveldb` batch dump | **CONFIRMED** | `common/db/patch.go:124-126`; `vm/vm.go:281`. |
| 19 | Protobuf tags 1–13 used; 14–16 free (`spec/05:69-73,108-114`) | **CONFIRMED** | `dev:chain/nom/protobuf.proto:39-53`. |
| 20 | `rlp:"optional"` convention for new momentum fields | **CONFIRMED** | `dev:chain/nom/momentum.go:76-77`; RLP is used for wire-size budgeting (`dev:chain/account_pool.go:1142-1167`). |
| 21 | Append new hash fields after v2 so v1/v2 hashes are unchanged | **CONFIRMED (pattern)** | `dev:chain/nom/momentum.go:104-123`. |
| 22 | `AccountBlock.ComputeHash` 16-field preimage at `account_block.go:177` | **CONFIRMED** | `chain/nom/account_block.go:177-195`. |
| 23 | `SporkMinHeightDelay = 6` | **CONFIRMED** | `vm/constants/embedded.go:80`. |
| 24 | Un-upgraded nodes halt on unknown enforced sporks | **CONFIRMED** | `dev:chain/momentum_pool.go:254-283` (exit status 2). |
| 25 | `btcec/v2` "already in origin/dev go.mod" | **CONFIRMED** | `dev:go.mod:7` (direct, v2.2.0); also `go.mod:32` on master (indirect). |
| 26 | `go-libp2p v0.33.2` | **CONFIRMED** | `dev:go.mod:17`. |
| 27 | Embedded address pattern / Bech32 charset for `z1qxemdeddedxsettlement…` | **CONFIRMED (feasible)** | `common/types/address.go:23-36,99-104`; every character is in the Bech32 charset. |
| 28 | Adding to `EmbeddedWUpdate` makes pillars "automatically" crank `Update` | **PARTIALLY ACCURATE** | `pillar/worker_updater.go:20-42` (pillar user-sends, best-effort); rate limit at `vm/constants/embedded.go:23` (M-11). |
| 29 | `MaxAccountBlocksInMomentum = 100` (`spec/03:349`) | **CONFIRMED** | `chain/account_pool.go:25`. |
| 30 | PoW is "Argon2d" (`SPEC.md:136`) | **INACCURATE** | `pow/pow.go:18-23,74-78` (SHA3-256). |
| 31 | `PoWDifficultyPerPlasma = 1500`, 31.5 M difficulty per base block | **CONFIRMED** | `vm/constants/plasma.go:39`; `vm/plasma.go:17-24`. |
| 32 | 10 QSR → 21,000 plasma | **CONFIRMED** | `vm/constants/plasma.go:35-37` (`PlasmaPerFusionUnit = 2100`, 1 QSR per unit). |
| 33 | HTLC `hashType = SHA256(0)` (`spec/03:385,391`) | **INACCURATE** | `vm/embedded/definition/htlc.go:74-75` (`SHA3 = 0`, `SHA256 = 1`). |
| 34 | PTLC `PointTypeSecp256k1Point = 2`, 33 B lock, 32 B scalar, destination mandatory | **CONFIRMED** | `dev:vm/embedded/definition/ptlc.go:111-138`; `dev:vm/embedded/implementation/ptlc.go:128-135`. Unlock checks compressed parity (`:82-96`), see M-01. |
| 35 | HTLC/PTLC expiry semantics | **CONFIRMED: Unix seconds vs frontier momentum time at receive** | `htlc.go:99,170,241`; `dev:…/ptlc.go:326,414,460`. |
| 36 | No `StateRoot`/`CommitteeRoot`/Settlement/btcspv code on any branch | **CONFIRMED** | `git ls-tree` on `master`, `dev`, and `release/0.0.11-rc1`: no `common/trie`, `state_tree`, `settlement`, `btcspv`, `committee`, `finality` paths. |
| 37 | Dynamic Plasma floor `MinResourcePrice = 1000`; PoW cap lifted under DP | **CONFIRMED** | `dev:dp/dp.go:58,66`. |

---

## 4. Upstream Alignment Audit

Path aliases (relative to `zenon-developer-commons/`):
- `M` = `Project Zeno/Research/Interoperability/ZENON-INTEROPERABILITY-MANUAL.md`
- `S` = `Project Zeno/spec/SPEC.md` v1.6.0
- `PF` = `Project Zeno/artifacts/proof-format.md`
- `L2A` = `Project Zeno/merkle-state/MERKLE_STATE_L2_ALIGNMENT.md`
- `B01` = `Project Zeno/Research/Interoperability/Authorization Domains/01_BTC_AUTHORIZATION_DOMAIN.md` (non-normative, superseded per M:3521)
- `P15` = `docs/specs/Zenon Portal/Zenon Portal Spec.md`
- `P2` = `docs/specs/Zenon Portal/Portal V2/zenon_portal_final.md`
- `MSR` = `Project Zeno/merkle-state/MERKLE_STATE_ROOT.md`
- `BVB` = `docs/architecture/bounded-verification-boundries.md`

The decisive lines were re-read by the reviewer. Precedence matters here: the MINTED Extension itself says *"On conflict with `SPEC.md`, `SPEC.md` controls"* (M:3099). The draft's own precedence order (`SPEC.md:56-63`) ranks its `spec/05` above upstream `SPEC.md`, which the upstream corpus does not permit.

| ID | Sev. | Conflict | Upstream (verbatim gist) | Draft | Required action |
|---|---|---|---|---|---|
| **U-01** | HIGH | `d_btc_asset` cannot be registered under SPEC v1.6.0 | S:352 "only `L1_NATIVE` MAY be activated. `L1_RELAYED` … reserved; Core MUST reject a `RegisterDomain` selecting a reserved `inputSource`". S:130: valid input types are "exactly" six (kinds 0–5) | `inputSource = L1_RELAYED` (spec/02:23); invented input kind `0x06` / `SubmitInput` (spec/03:169) | Get a Phase-2 profile amendment to `S` (L1_RELAYED activation, input kind, `inputHash` schema) **before** coding |
| **U-02** | HIGH | Input sequence numbering | S:172 "For `L1_NATIVE` and `L1_RELAYED` domains the input sequence number MUST equal the `globalInputIndex`"; S:188 per-domain subsequence, MUST NOT check raw contiguity | Dense per-domain counter `nextGlobalInputSeq++` and `FirstInputSeq == lastBatchedSeq + 1` (spec/03:46, :168, :176) | Adopt `globalInputIndex` as `seq`; contiguity is over the domain's subsequence |
| **U-03** | HIGH | Missing `MaxBatchMint`; MINTED counter model | S:889 "`MaxBatchMint` cap … MUST bound per-batch mint exposure, and the executor bond MUST be sized to cover it". S:881-882 use `mintedSupply ≤ provenForeignLocks`, `authorizedForeignRelease ≤ burnedSupply`, while M:3346 uses `R + P ≤ B`, and M:3099 says `S` controls | No `MaxBatchMint`; only `R + P ≤ B` (spec/03:142-161) | Add `MaxBatchMint` ≤ executor bond value. This is the only thing bounding the C-08/C-09 loss. Get upstream to reconcile the two counter models |
| **U-04** | HIGH | Fronting must not leave a timeout refund open | M:4063 enforcement spec MUST show "how it proves the payment without permitting a second release **or a timeout refund**"; M:4282 "`outboxId` cannot be released or refunded again" | spec/01:202 explicitly allows `FOREIGN_NON_DELIVERY` after a confirmed `FrontingTx` | See H-06 fix: proven fronting forecloses the refund |
| **U-05** | HIGH | Reorg halt must precede dispatch, for **every** admitted event | M:4151 halt on reorg removing "an already admitted foreign event"; M:4153 "MUST be paused before any further claim dispatch" | Halt is domain-internal and reaches Settlement late (H-05). `AdmittedEventBlocks` is written **only for locks** (spec/02:346), not for release (:363) or non-delivery (:379). An orphaned `TimeoutCancelTx` (refund already re-minted) followed by a confirmed `ReimburseTx` means vault paid **and** user refunded: insolvency | Record every admitted event block; propagate the halt synchronously (H-05) |
| **U-06** | HIGH | Release/non-delivery claims commit the wrong binding | M:3190 "An Authorization Domain MUST commit the binding under which it verified the foreign event" | `PayloadHash = SHA3(auth.ChainBindingHash)`, copied from the PegOutRecord proof (spec/02:370, :387), so the handler check `ctx == rec.ChainBindingHash` (spec/03:280, :288) is a tautology | Commit `cfg.ChainBindingHash` (the binding whose adapter rules verified the Bitcoin event) |
| **U-07** | MEDIUM | L1-initiated `outboxId` | S:1186 `outboxId = SHA3-256(domainId‖batchId‖input_index‖outbox_index)` "bound at batch construction"; M:3479 `RequestPegOut` MUST "reuse the Phase-1 `kind=1` outbox mechanism rather than introduce a parallel one"; M:1921 `ProcessedOutbox` = ids "already relayed"; M:2115 AUTHORIZATION `outboxRoot` MUST be empty | Nonce-based id reusing the batchId/index fields as constants (spec/03:271), written to `ProcessedOutbox` at creation | An upstream gap (M:3235/3254 leave it open). Get a normative L1-peg-out id with its own domain tag specified upstream; don't overload batch fields |
| **U-08** | MEDIUM | Policy-version pin | M:1632 "`PolicyVersion` MUST equal the immutable policy version pinned by the claim's batch" | `RelayClaim` looks up `claim.PolicyVersion` without checking it against the batch pin (spec/03:215-217) | Pin the policy version in `BatchCommitment`; reject mismatches |
| **U-09** | MEDIUM | Optional misconduct capability in policy v1 | M:3787 v1 "MUST authorize exactly these claim capabilities"; M:3817 misconduct "MAY only be introduced by a new policy version" | `FOREIGN_MISCONDUCT` optional in v1 (spec/02:94; spec/03:293-296), with an invented `Amount == 0` context payload | Remove it from v1, or amend upstream |
| **U-10** | MEDIUM | `SmtProof` wire format and empty-value semantics | PF:50-60 (`flags, key, leaf_hash, deepest-first bitmap, sib_count, siblings deepest-first, value`), with other encodings non-conformant; L2A:23 the L1 applier folds empty values into **deletion** | spec/04:102-109 invents a version-byte, root-first format and then walks it bottom-up (self-inconsistent); spec/04:84 claims present-empty ≠ absent on L1 | Adopt PF verbatim; restrict present-empty semantics to domain (L2) trees |
| **U-11** | MEDIUM | Bond denomination | M:1822 operator instances need "a bond in an asset uncorrelated with the bridged asset"; B01:458 "BTC is circular" | spec/01:221 says a BTC bond "solves" Open Questions #5–#6 | Either justify against M:1822 explicitly or use an uncorrelated or over-collateralized bond |
| **U-12** | MEDIUM | `BatchCommitmentV3` encoding and enum codes | M:2107-2112 field list begins with `protocol_version ; <other version fields §20>`; `S` numbers u8 enums from 0 (S:1180, S:1203-1208); the framework gives names only | spec/03:68-88 omits the version fields and invents `0x0003`; spec/02:20-27 invents 1-based codes; `BONDED_PERMISSIONLESS` is not in the upstream set (M:1429) | Take encodings from `S` §20/§27; no invented codes |
| **U-13** | MEDIUM | Custody key-power disclosure | M:4493 the enforcement spec must list "Every … emergency key, threshold, and unilateral power"; M:7525 every recovery path MUST identify "its exact authority, exclusions, timelock …"; B01:208 "no key combination can move BTC outside the pre-signed graph"; P2:361 an epoch key "can be applied uniformly to all UTXOs" | Wind-down liquidation script "disclosed at activation" (spec/01:290); epoch-wide `committeeAggPubKey` (spec/01:120-122) | See C-06, C-07 |
| **U-14** | LOW | Snapshot contents | M:284 snapshot includes "processed claim keys, and destination replay keys" | spec/01:289 omits destination replay keys | Add them |
| **U-15** | LOW | MINTED vector count | §13 has 15 MUST-fail bullets (M:3425-3439); §14 has 18 vectors (M:3445-3471) | "All 15 MUST-fail vectors from … §13–§14" (spec/05:272) | Cite 15 + 18 |
| **U-16** | LOW | Errata claims are mischaracterized | P15:961 NUMS hex `50929b74…` **is correct** (recomputed = SHA256(uncompressed G)); the wrong part is the derivation text at P15:949. `0x1800ff80` (P15:618) is a mislabeled NegativeMantissa vector (bit 23 clear), not an endianness bug. P15:633 has `8064000`, but no "4 * 1,209,600" literal. 6 s vs 10 s (P15:758) is confirmed. Bare `OP_RETURN` in a leaf is confirmed in `docs/research/bitcoin_anchoring.pdf` §4.1 (the `.md` is a 10-line stub) | `SPEC.md:227`, spec/01:40 call the hex "mistyped" and then mandate the same hex | Correct the errata text so readers don't distrust a correct constant |
| **U-17** | LOW | Misattributions and naming | `PROVEN/REFUSED/REJECTED` appears in neither `docs/specs/Minimum Verifier Spec.md` nor `docs/architecture/bounded-verification-boundries.md`; S:204 names the gate spork `OffchainExecutionSpork`; upstream domain status is `ACTIVE\|PAUSED` (M:1432) and `DRAINING` is a `bindingState` (M:3154) | spec/04:184 attributes the verdicts to the MVS; spec/04:4 and :193 cite a non-existent `docs/specs/bounded-verification-boundries.md`; `SettlementSpork`; `HALTED`/`DRAINING` as domain statuses (spec/03:167, :175, :206) | Fix the citations and names |
| **U-18** | INFO | Upstream gaps the draft papered over instead of escalating | (i) S:190 assumes per-index pre/post roots for fraud proofs, but the `Receipt` has none (S:1224-1227), which underlies C-08. (ii) No L1-initiated `outboxId`. (iii) `S` vs `M` MINTED counters. (iv) Direction of challengeWindow vs WithdrawalDelay: M:1504/M:2175 vs S:972. (v) M:3132/M:3225 assume a "Core-internal issuance identity" / `creditOrMintZTS` that go-zenon's VM does not provide, which underlies C-11 | Each one filled with invented normative text | Open upstream issues and resolve there first; the draft must not freeze guesses into an implementation spec |

**Alignment that does hold:** the MINTED handler semantics and `R + P ≤ B` (M:3207-3346), the lock-claim `PayloadHash` (M:3177-3185 vs spec/02:353), the BTC event-id formulas (M:3847-3889 vs spec/02:112-122), the confirmation-depth rule (M:4179 vs spec/02:335), the two-stage rollover for refund mutual exclusion (M:3941-3946 vs spec/01:62-136), the SMT hash rules and retention (MSR:28-39, :122-124 vs spec/04:76-95), Class R/Class P framing (P2:16, :985), and the O(k) bridge prohibition in substance (BVB:106-115).

---

## 5. Go / No-Go Gate Checklist (minimum before any production code)

**Status: NO-GO.** Every box below must be closed with a re-reviewed spec diff and, where marked ⚙, an executable artifact.

**Bitcoin enforcement (spec/01)**
- [ ] **G-1 (C-01, C-02):** Re-derive the Tier 1A graph so every pre-signed transaction binds only setup-time outpoints, and dynamic data enters only via Winternitz-committed witnesses. Publish the full DAG (inputs, outputs, sighash flags, timelocks). ⚙ Signet build of the graph from a real deposit.
- [ ] **G-2 (C-03):** Replace the "single Tapscript leaf" with a SNARK plus a chunked BitVM2 verifier. Publish circuit, chunk count, max chunk weight, assert-tx sizes, Winternitz params, and drop TRUC for Assert/Disprove. ⚙ Measured weights.
- [ ] **G-3 (C-04, H-09):** Delete the `OR anchored` predicate branch and the first-anchored fork choice. The finality proof is always a certificate chain from a pinned committee. Disclose Pillar-supermajority trust.
- [ ] **G-4 (C-05):** Bind each `outboxId` to one assigned vault outpoint on Settlement and in the predicate.
- [ ] **G-5 (C-06):** Fresh per-deposit committee keys; no binding-lifetime key; no sign-later templates.
- [ ] **G-6 (C-07):** Remove the Emergency Timelock Exit Leaf, or reclassify the binding as custodial.
- [ ] **G-7 (H-06, H-07):** Fronting proof disables refund; explicit operator fee and reserve funding model; buckets sized ≫ worst-case disprove fees.

**Zenon settlement and optimistic referee (spec/02, spec/03)**
- [ ] **G-8 (C-08):** Add per-input `traceRoot` to `BatchCommitmentV3`; rewrite `Challenge` against it.
- [ ] **G-9 (C-09):** Publish and enforce per-input worst-case witness bounds ≤ 12 KiB (headroom under 16 KiB). ⚙ Fuzzed maximum-witness generator in CI.
- [ ] **G-10 (C-10):** Replace L1-StateRoot proofs with a Settlement→domain `PEGOUT_CREATED` input, or pin `zenonHeight` semantics.
- [ ] **G-11 (C-11):** Choose the treasury or async mint model; specify `TokenContract.IssueMinted`; delete the "internal helpers". ⚙ go-zenon unit test showing mint/burn under the chosen model, including failure paths.
- [ ] **G-12 (H-01, H-11):** Lock proofs must prove provisional-parent spend via Leaf A, reject 64-byte and coinbase txs, and bind branch depth.
- [ ] **G-13 (H-02, H-03, H-04, H-05):** Bounded timeouts sourced from finalized domain observations; identical size and amount rules on both sides; grandfathered lock eligibility; halt propagates to Settlement before finalization.
- [ ] **G-14 (H-10):** Hash-only input storage, an input deposit, and challenge inclusion priority.

**go-zenon / light client (spec/04, spec/05)**
- [ ] **G-15 (H-08):** Separate a time-epoch `FinalityCommitteeRoot` from the per-tick producer schedule; remove `height % 8640`.
- [ ] **G-16 (H-12, M-15):** Amend the governing invariant or move adjudication to ZK; U5 governance (or equivalent) gates Stage 1B.
- [ ] **G-17:** Resolve every U-xx conflict in §4 (or amend upstream first).

**Peg-free rails**
- [ ] **G-18 (C-12, M-01):** Fix the PTLC timeout order, HTLC `hashType = 1`, inbound swap ordering, and adaptor parity. ⚙ Signet ↔ Zenon testnet adversarial swap tests (claim-then-reclaim, wrong hash type, early unlock).

**Process**
- [ ] **G-19:** Every numeric claim in the spec (sizes, plasma, timings, latencies) comes from a checked-in script or benchmark, not from prose.
- [ ] **G-20:** An independent second hostile review of the v1.1 diff, focused on G-1–G-10.

---

## Appendix A — Size and Fee Estimate Script (reproduces C-09, H-03, H-07, §2.5 numbers)

Run with `python3 -I appendix_a.py`. These are estimates under the stated assumptions (domain SMT ≈ 24k leaves; optimistic multiproof sharing of the top `log2(k)` levels). Even the optimistic column exceeds 16 KiB for any input touching more than about 30 keys.

```python
import math

MAX_DATA = 16384
MAX_PROOF = 15872

def abi_bytes_call(payload_len, static_words=1):
    # selector + static head words + offset word + length word + padded payload
    return 4 + 32 * static_words + 32 + 32 + 32 * math.ceil(payload_len / 32)

# ---- A. BTC_HEADER_BATCH with 192 headers
hb = 1 + 32 + 4 + 192 * 80
print("A. header batch payload:", hb, "B; ABI SubmitInput(domainId,payload):", abi_bytes_call(hb), "B; fits 16 KiB:", abi_bytes_call(hb) <= MAX_DATA)
print("   plasma (dev formula tier 52500 + (len-4)*68):", 52500 + (abi_bytes_call(hb) - 4) * 68)

# ---- B. SMT proof size for a tree with N leaves (random keys): expected non-empty siblings ~ log2(N)
def smt_proof_bytes(n_leaves):
    return 1 + 32 + 32 * math.ceil(math.log2(max(n_leaves, 2)))

# d_btc_asset state: retained headers (2 keys each: HeaderNode + height index) + outpoints + outbox + admitted
def domain_leaves(retained=144 + 2016, outpoints=10000, outbox=10000):
    return retained * 2 + outpoints + outbox + 1

N = domain_leaves()
p = smt_proof_bytes(N)
# value sizes
header_node_val = 8 + 4 + 4 + 32 + 32 + 32 + 4      # spec/02 §5 HeaderNode
key_path = 32
per_key_header = p + key_path + header_node_val
per_key_height = p + key_path + 32
print("\nB. domain leaves ~", N, "; single SMT proof ~", p, "B")

def header_input_keys(n_headers, mtp_ancestors=10, prune=True, reorg_depth=0):
    keys_header = n_headers            # absence + write of each new HeaderNode
    keys_header += 1 + mtp_ancestors   # parent + MTP ancestors preceding the batch
    keys_height = n_headers            # ActiveChainByHeight writes
    if prune:
        keys_header += n_headers       # prune one old HeaderNode per new tip height
        keys_height += n_headers       # and its height index
    keys_height += reorg_depth         # rewrite of orphaned heights
    keys_header += reorg_depth         # read orphaned branch nodes for LCA
    return keys_header, keys_height

for label, n, reorg in [("1 header", 1, 0), ("6 headers", 6, 0), ("192 headers", 192, 0), ("1 header triggering 144-deep reorg", 1, 144)]:
    kh, kt = header_input_keys(n, reorg_depth=reorg)
    total = kh * per_key_header + kt * per_key_height + (p + 32 + 32 + 8 + 32 + 1)  # + ChainMeta
    # optimistic multiproof: share top log2(k) levels
    k = kh + kt + 1
    shared_saving = k * 32 * math.floor(math.log2(k)) if k > 1 else 0
    multiproof = max(total - shared_saving, 0)
    print(f"   {label:38s}: keys={k:4d}  naive witness≈{total/1024:7.1f} KiB  multiproof≈{multiproof/1024:7.1f} KiB  (cap 16 KiB)")

# ---- C. BTC_RELEASE_PROOF worst case
merkle_depth = 13  # ~ 8k tx block
reimburse_stripped = 4 + 1 + 3 * 41 + 1 + (8 + 1 + 34) + (8 + 1 + 58) + (8 + 1 + 4) + 4
fronting_max = 8192
l1_smt = smt_proof_bytes(50_000_000)  # L1 NodeTree with tens of millions of keys
pegout_record = 32 + 4 + 32 + 32 + (4 + 34) + 20 + 32 + 32 + (1 + 32 + 8) + 1
auth_witness = 32 + 32 + 32 + (4 + 34) + 8 + (4 + l1_smt) + 8 + pegout_record
graph_witness = (4 + fronting_max) + 32 + 4 + (4 + 32 * merkle_depth) + 4 + 36
rel = 1 + (4 + reimburse_stripped) + 32 + 4 + (4 + 32 * merkle_depth) + 4 + 32 + (4 + auth_witness) + (4 + graph_witness)
print("\nC. release proof with 8,192 B FrontingTx:", rel, "B; ABI:", abi_bytes_call(rel), "B; payload<=15,872:", rel <= MAX_PROOF, "; ABI<=16,384:", abi_bytes_call(rel) <= MAX_DATA)
max_front = MAX_PROOF - (rel - fronting_max)
print("   largest FrontingTx that still fits maximumProofBytes:", max_front, "B (~", (max_front - 60) // 41, "legacy inputs)")

# ---- D. Disprove economics at 1,000 sat/vB
for vb in (10_000, 100_000, 400_000 // 4 * 4):
    print(f"\nD. DisproveTx {vb:,} vB @1,000 sat/vB = {vb*1000/1e8:.2f} BTC" if vb == 10_000 else f"   DisproveTx {vb:,} vB @1,000 sat/vB = {vb*1000/1e8:.2f} BTC")
```

Output at review time:

```text
A. header batch payload: 15397 B; ABI SubmitInput(domainId,payload): 15524 B; fits 16 KiB: True
   plasma (dev formula tier 52500 + (len-4)*68): 1107860

B. domain leaves ~ 24321 ; single SMT proof ~ 513 B
   1 header                              : keys=  16  naive witness≈   10.1 KiB  multiproof≈    8.1 KiB  (cap 16 KiB)
   6 headers                             : keys=  36  naive witness≈   22.2 KiB  multiproof≈   16.6 KiB  (cap 16 KiB)
   192 headers                           : keys= 780  naive witness≈  472.0 KiB  multiproof≈  252.6 KiB  (cap 16 KiB)
   1 header triggering 144-deep reorg    : keys= 304  naive witness≈  184.2 KiB  multiproof≈  108.2 KiB  (cap 16 KiB)

C. release proof with 8,192 B FrontingTx: 10736 B; ABI: 10852 B; payload<=15,872: True ; ABI<=16,384: True
   largest FrontingTx that still fits maximumProofBytes: 13328 B (~ 323 legacy inputs)

D. DisproveTx 10,000 vB @1,000 sat/vB = 0.10 BTC
   DisproveTx 100,000 vB @1,000 sat/vB = 1.00 BTC
   DisproveTx 400,000 vB @1,000 sat/vB = 4.00 BTC
```
