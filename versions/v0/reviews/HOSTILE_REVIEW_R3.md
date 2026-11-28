# Hostile Peer Review — Round 3 — zBTC Bitcoin↔Zenon Interoperability Specification `v2.1.0-draft`

**Reviewer posture:** adversarial, first-principles. Same rules as Rounds 1 and 2: the spec's own summaries were not trusted. Claims were re-derived from Bitcoin consensus and policy (BIP-68/112/341/342), from `go-zenon` source, and by independent recomputation of the oracle's numbers.
**Review date:** 2026-11-24
**Baseline:** `HOSTILE_REVIEW_R2.md` (Round 2: 4 C · 8 H · 12 M · 8 L · 10 script defects S-1..S-10).
**Mandate:** do not re-litigate the Round-2 §4 verified-sound mechanisms unless v2.1 broke them. Attack every new mechanism. Separate **blocking design-spec defects** from **legitimate execution gates** (Signet Stage 0C measurements, go-zenon unit tests, upstream ratification).

**Artifacts under review (SHA-256):**

| File | SHA-256 |
|---|---|
| `SPEC.md` | `b3cfde25…ac8d00` |
| `spec/01` | `c092818a…3ceebc` |
| `spec/02` | `49fcb30c…a68db` |
| `spec/03` | `6fdcbbfc…aef19` |
| `spec/04` | `07563f7f…0cb94` |
| `spec/05` | `4fd3bde8…eda8` |
| `scripts/verify_spec_bounds.py` | `0c58b2af…ba5ad` |

**Ground truth:**
- `go-zenon`: `master` `e8986a6`, `origin/dev` `770e893`, `origin/release/0.0.11-rc1` `f19955f`. A `dev:` prefix means `git show origin/dev:<path>`.
- `zenon-developer-commons`: `HEAD` `3719452`.

**Citation convention:** `spec/0N:L`, `SPEC.md:L`, `script:L` (= `scripts/verify_spec_bounds.py`).

---

## 1. Executive Verdict

### **HOLD — BLOCKING SPEC DEFECTS REMAIN (Bitcoin-side BitVM2 round design)**

v2.1 is a serious revision.

**What is now sound on the Zenon side.** All four Round-2 CRITICALs are fixed as specified, and the fixes check out on re-derivation:
- **Lineage chaining (R2-C2):** `PreStateRoot == lineageHead.PostStateRoot`.
- **Inductive per-leaf accumulators (R2-C4):** the base case plus the induction step cover every aggregate. `finalLeaf` is bound mechanically at `SubmitBatch`, and `RelayClaim` is routed through `traceRoot`.
- **PTLC ordering (R2-C3):** Bob locks first. `PointTypeSecp256k1Point` plus scalar unlock matches `dev:vm/embedded/definition/ptlc.go:114-120` and `dev:vm/embedded/implementation/ptlc.go:82-95`.
- **Pruning and coinbase size (R2-H3, R2-H4):** `ActiveChainByHeight` is never pruned, and streaming SHA-256 is used.
- **Pause semantics (R2-H6, R2-M10):** the halt freezes dispatch only and clears automatically.
- **Issuance hop (R2-M2):** `IssueMinted` → `ReceiveTreasury()` resolves the R2-M2 `applySend` failure. This was confirmed at `dev:vm/vm.go:204-226`: the method lookup runs for embedded recipients, and the `Issue` descendant is data-less at `dev:…/token.go:163-171`.

The numeric oracle now really asserts, and it labels its assumptions.

**What is broken: the new serial round-chain BitVM2 DAG (`spec/01 §3.3`).** It removes R2-C1's causality bug and the `<anyone>` connector, but it does so by placing **operator-only and signature-free leaves on the outputs that carry the slashing paths**. That creates three new CRITICAL defects, each a loss of funds:

1. **R3-C1 — The operator can escape every bond slash and pocket `F_assert`.**
   - `Conn_B` Leaf 2 (`AssertStartTx`) and Leaf 1 (`Take1Tx`) are `<pk_m>`-only (`spec/01:78`).
   - After being challenged, the operator spends `Conn_B` to itself. That kills `BurnBondTx` and the whole assert/slash subtree, and the operator keeps the watcher's `1.10 BTC`.
   - Every challenge therefore gives the attacker more than `D_bucket`. Challenging is −EV, so fake kickoffs go unchallenged and vault UTXOs are drained.
2. **R3-C2 — The anti-substitution trap is a free-for-all.**
   - `ReimburseEscrow` Leaf 2 is unsigned (`spec/01:79,86`). The substituting operator sweeps deposit `d`'s escrow itself, in the same block, with its bond intact.
   - It can then claim the released outpoint `X` **again** in a later round: double reimbursement.
   - Even the "intended" outcome pays `d`'s vault BTC to the watcher, so backing is destroyed.
3. **R3-C3 — Lifetime reimbursement capacity is finite and nothing caps supply to it.**
   - Each deposit is pre-signed only for rounds `0..R−1` of the current operators, and its keys are then deleted.
   - With `M = 5, R = 32` (`spec/01:45`), at most **160 reimbursements can ever happen** for all deposits combined, at about 0.91 BTC/day (one per lane per 792 blocks).
   - Every vault UTXO beyond capacity is permanently unredeemable.

**Root cause.** C1, C2 and C3 share one: **round-level connectors are fixed before a deposit exists, but the per-deposit keys that could constrain them are deleted after deposit setup.** No leaf on a round-level output can be pre-bound to a future deposit's `Take1Tx`, so v2.1 uses `<pk_m>` instead. The deployed precedent for round-shared BitVM2 (Clementine-style rounds) solves this either with a **live** N-of-N signer set (1-of-N honest in perpetuity, not deletion), or with **per-deposit kickoff transactions** that hang off round-level kickoff-connector outputs. v2.1 does neither (§2.1, fix guidance).

**Four HIGH findings:**
- **R3-H1:** `Take1Tx`/`Take2Tx` cannot be fee-bumped, and `BurnBondTx` needs no challenge, so honest operators get slashed in fee spikes.
- **R3-H2:** The bond slash keys (`SlashLeaf` "Committee+Op", `Q_ephem_bond`) are undefined. `WrongDepositDisproveTx` is per-deposit, so a **long-lived** bond key must sign it at every deposit.
- **R3-H3:** The R2-H1 long-range residual is still open:
  - the carry-over rule lets any retired committee extend the epoch chain in-circuit;
  - anchoring is permissionless, so the freshness rule is satisfied by fresh anchoring of a forged digest;
  - Leaf 4 ("earlier conflicting anchor") cannot be built in Script;
  - `SubmitInvalidCertProof` cannot reach future heights.
- **R3-H4:** The race between a Multi-Tx Challenge Session and `FinalizeBatch` is unspecified, and the depth-256 guarantee depends on it.

**New-finding census:** 3 CRITICAL · 4 HIGH · 9 MEDIUM · 11 LOW · 8 new script defects (S3-1..S3-8).

**Round-2 disposition (§3):**
- Of the 32 R2 findings: **21 CLOSED, 2 ESCALATED (correctly), 8 PARTIALLY CLOSED, 1 STILL OPEN (R2-L6 overclaims)**.
- Of the 10 R2 script defects: **9 CLOSED, 1 PARTIAL**.
- **M-03** is reclassified as a *disclosed residual*. Its disclosure text is still inaccurate (R3-C1).

**What would move the verdict to CONDITIONAL PASS / APPROVE (Design Spec):**
- Fix R3-C1..C3 and R3-H1..H4 in the spec (§7).
- Republish the DAG with **every leaf's signer set, every pre-signed transaction's signing epoch (round setup or deposit setup), and the fee source of every transaction** in explicit columns.
- Add capacity and fee-funding assertions to the oracle.
- The Signet measurements (G-1/G-2), go-zenon tests (G-11), fuzzer (G-9), swap tests (G-18) and upstream ratification (§6 register) **do not block the design sign-off**. They are honestly declared execution gates (`SPEC.md:126-130`).

---

## 2. New Findings (Round 3)

### 2.1 CRITICAL

---

#### R3-C1 — Operator-only leaves on round-level connectors let a challenged operator escape every slash and keep `F_assert`, which makes challenging −EV and vault theft unchallenged

- **Spec:**
  - `spec/01:78` (`Conn_A` Leaf1 = `<144> CSV <pk_m>`; `Conn_B` Leaf1 = `<144> CSV <pk_m>` for Take1Tx, **Leaf2 = `<pk_m>`** for AssertStartTx, Leaf3 = `<288> CSV <Q_ephem_bond>` for BurnBondTx)
  - `spec/01:82` (chunk/end connector leaves "Leaf1=`AssertChunkTx_i`", "Leaf1=`AssertEndTx`" with **no signer specified**; `Conn_C` Leaf 1 = `<144> CSV <pk_m>`; disprove Leaves 3..C+3 unsigned)
  - `spec/01:85` (`DisproveTx` "In 1 unsigned Tapscript")
  - `spec/01:65-67` (claimed invariants)
  - `spec/01:90` and `SPEC.md:92` ("fraudulent operator IS still slashed")
- **Ground truth:**
  - A Tapscript leaf `<pk> OP_CHECKSIG` lets the holder of `pk` sign **any** transaction spending that output. Pre-signing does not restrict the key holder; only a co-signer whose key is deleted (or who stays honest) can bind an output to one specific child.
  - A leaf with no signature check (a WOTS/hash/BitVM chunk verifier) can be spent in **any** transaction by anyone who can supply the witness. Witness data is not committed by any sighash.
  - BIP-341 `SIGHASH_SINGLE` on `BondOut` constrains only transactions that spend `BondOut`. It cannot stop a connector from being spent *without* `BondOut`.
- **Failure trace A (escape after challenge, zero timelock):**
  1. Operator `m` broadcasts `RoundKickoffTx_{m,r}`, claiming any outpoint `X` (fraudulently: it never fronted).
  2. A watcher broadcasts `ChallengeTx_{m,r}` (spends `Conn_A`) and pays `F_assert = 1.10 BTC` to `m` (`spec/01:80`).
  3. In the next block, `m` spends `Conn_B` through **Leaf 2 (`<pk_m>`)** in a transaction of its own choosing (330 sats to itself), not `AssertStartTx`.
  4. Effects:
     - `BurnBondTx` needs `Conn_B` Leaf 3, so it is invalid forever.
     - `AssertStartTx` never exists, so no `BurnBondChunkTx`, `BurnBondEndTx`, `BurnBondTake2Tx` or `DisproveTx` input exists.
     - `WrongDepositDisproveTx` needs an escrow, and there is none.
  5. `BondOut_{m,r}` is untouched. After 792 blocks `m` advances to round `r+1` or exits via Leaf 2.
  6. No `OP_RETURN` burn of `BondOut` ever occurs, so `BTC_OPERATOR_SLASH_PROOF` (`spec/02:154`) cannot fire and the Zenon bond is safe too.
  7. **Operator net: +1.10 BTC − ~200 vB of fee. Watcher net: −1.10 BTC − challenge fee.**
- **Failure trace B (alternative escape):** Even if Leaf 2 were fixed, `Conn_B` **Leaf 1** (`<144> CSV <pk_m>`) lets `m` sweep `Conn_B` at block 144, before `BurnBondTx` matures at 288. The same applies to any chunk/end connector whose Leaf 1 is operator-only (signer unspecified, `spec/01:82`). `Conn_C`'s unsigned disprove leaves let `m` spend `Conn_C` standalone (with a valid disprove witness against its own bogus assert) and so avoid `DisproveTx`'s `BondOut` input.
- **Failure trace C (theft):**
  1. Because of A, every challenge is a 1.10 BTC transfer from watcher to attacker, and 1.10 > `D_bucket` = 1.00.
  2. Unchallenged, the attacker's `Take1Tx_{X,m,r}` at block 144 steals `X`'s 1.00 BTC.
  3. Either branch is profitable, so the attacker repeats every round (and on every lane it runs).
  4. The trust model's "1-of-N watcher liveness" (`SPEC.md:92`) now needs watchers who rationally burn 1.10 BTC per round to protect 1.00 BTC.
  5. The asserted `fraud_op_net_timeout <= -1.50` and `SelfSlash <= -0.20` (`script:194-197`) model a DAG that cannot be built.
- **Also false:**
  - "ZERO `<anyone>` leaves" (`spec/01:66`). The disprove leaves, Leaf 3, Leaf 4 and the escrow trap are anyone-with-witness leaves, standalone-spendable.
  - "even under 100% miner MEV … the fraudulent operator strictly loses" (`spec/01:90`).
- **Minimal fix (pick one architecture; both are known-good):**
  - **(A) Per-deposit kickoff (Clementine-style round + kickoff connectors).**
    1. `RoundTx_{m,r}` carries the bond plus `k` *kickoff-connector* outputs (operator-key leaves are acceptable there: wasting one only burns a slot).
    2. Each deposit `d` pre-signs, with `Q_ephem_d`, a full graph rooted at `KickoffTx_{d,m,r,j}`, which spends kickoff connector `j`. That txid is fixed at deposit time.
    3. Every connector leaf of `KickoffTx_{d,m,r,j}` (Take1, Challenge, AssertStart, timeouts, Take2, disprove) is then **`Q_ephem_d`-co-signed** and bound to exactly one child. Disprove leaves become `<Q_ephem_d-sig over DisproveTx> CHECKSIGVERIFY <chunk verifier>`, so `Conn_C` cannot be spent without the bond.
    4. Bond slashing ties `RoundTx` collateral to an unresolved kickoff (e.g., a "kickoff-not-finalized" connector that the next `RoundTx` must consume).
  - **(B) Live graph-signing committee.**
    1. Replace deletion with "1-of-N honest **in perpetuity**" for a round-graph signer set `Q_round`.
    2. Every round-level leaf becomes `<Q_round> CHECKSIGVERIFY <pk_m> CHECKSIG`, and `Q_round` co-signs each new deposit's Take1/Take2 against existing rounds.
    3. Disclose this as a **5th trust assumption** that replaces Assumption 2 for the reimbursement path.
  - In both cases, add a DAG column "signer set + when signed", and a MUST-fail vector "operator spends any connector to a non-graph transaction ⇒ the bond is still slashable".

---

#### R3-C2 — The `ReimburseEscrow` trap is unsigned: the substituting operator sweeps deposit `d` itself, keeps its bond, and later double-claims `X`; even the intended outcome destroys `d`'s backing

- **Spec:**
  - `spec/01:79` (`Take1Tx` Out 0: `ReimburseEscrow` Leaf2 = "`OP_SHA256` WOTS+ trap", **no signature**)
  - `spec/01:84` (`Take2Tx`, same)
  - `spec/01:86` (`WrongDepositDisproveTx` "In 1 … unsigned Leaf2"; Out 1 = watcher payout `0.9990 BTC − fee`)
  - `spec/01:73` ("Operator loses `>= 2.0010 BTC` even if self-slashed")
  - `spec/02:153` (`BTC_VAULT_SPEND_PROOF` → `Halted`)
- **Ground truth:**
  - Leaf 2 has no CSV and no signature. Anyone holding the kickoff's WOTS signatures (public in `RoundKickoffTx`'s witness) can spend it in **any** transaction, including a child broadcast in the same package or block as `Take1Tx`.
  - Nothing on Bitcoin or on Zenon records that a `RELEASED` record has already been "used" by a kickoff. The SNARK predicate (`spec/01:99-101`) is stateless with respect to prior kickoffs.
- **Failure trace (theft):**
  1. Operator `m` legitimately fronts peg-out `P` whose assigned outpoint is `X` (`ResolutionSeen = {RELEASED, m}`).
  2. Round `r`: `m` kicks off claiming `X`. The claim is valid, so watchers do not challenge.
  3. At block 144, `m` broadcasts `Take1Tx_{d,m,r}` for a **different** vault UTXO `d`, together with a child that spends `ReimburseEscrow_{d,m,r}` through **Leaf 2**. The trap is satisfied because `claimedOutpoint = X ≠ d`, and the child pays `0.999 BTC` to `m`. `BondOut_{m,r}` is untouched.
  4. Round `r+1` (≥ 792 blocks later): `m` kicks off claiming `X` again. The SNARK is still satisfiable, since `RELEASED` and `AssignedVaultOutpoint == X` are both still true. `Take1Tx_{X,m,r+1}`, or `Take2` if challenged, pays `X`.
  5. **`m` collects about 2.0 BTC for one 1.0 BTC fronting.** `d` is now spent on Bitcoin while `TrackedVaultOutpoints[d] = ACTIVE`, so `BTC_VAULT_SPEND_PROOF` halts the domain. The halt does not stop Bitcoin-side reimbursements, so the attack repeats on alternating rounds.
- **Failure trace (intended path):** Suppose the trap is fixed so that only a `BondOut`-co-spending `WrongDepositDisproveTx` can use it. Out 1 still pays `d`'s `0.999 BTC` **to the watcher** (`spec/01:86`). The zBTC backing for `d` leaves custody. Each substitution makes 1 BTC of zBTC unbacked, and that loss is socialized by FIFO. A griefer-operator with a private miner pays about 2.0 BTC (bond burn minus recaptured Out 1) to destroy 1 BTC of backing and halt the bridge.
- **Minimal fix:**
  - Leaf 2 MUST be `<Q_ephem_d> CHECKSIGVERIFY <WOTS trap>`, with `Q_ephem_d` pre-signing exactly `WrongDepositDisproveTx_{d,m,r}` (`SIGHASH_ALL`, `BondOut` + escrow). This is feasible because the escrow script is fixed at deposit setup.
  - Do not let `d`'s BTC leave custody: Out 1 pays the escrowed `0.999` to a pre-committed **recovery vault** (a key-path-only key with its own depth-1 pre-signed graph, generated in the same ceremony). The watcher bounty comes from the bond only.
  - Make kickoffs single-use per `RELEASED` record. For example, the SNARK proves that `PegOutRecord.ReimbursementKickoff == (m, r)`, written on Zenon by a `ClaimReimbursementSlot(outboxId, m, r)` before the kickoff. A second kickoff for the same record then fails the predicate and is disproved.
  - Add MUST-fail vectors for the standalone trap spend and the double-claim.

---

#### R3-C3 — Finite round chains plus deleted per-deposit keys give a hard lifetime reimbursement capacity of `Σ_m R_m` that nothing ties to supply, so every UTXO beyond it is permanently unredeemable

- **Spec:**
  - `spec/01:42` (pre-signing "across active rounds `r ∈ {0..R-1}`", then `sk_{d,j}` deleted)
  - `spec/01:45-46` ("`R = 32` rounds per setup epoch"; `T_bond_cooldown = 792`; "15.00 BTC" across `M = 5`)
  - `spec/01:92` ("stray kickoff" note)
  - `SPEC.md:89` (cap rule mentions only Pillar stake)
  - `spec/01:133` (Wind-Down item 4)
- **Ground truth:**
  - A vault UTXO can be spent only by one of its pre-signed `Take1`/`Take2` transactions, which exist only for rounds `(m, r)` known at deposit time.
  - Each round reimburses **one** UTXO and needs `≥ 792` blocks before the next.
  - "Setup epoch" is undefined, and there is no rule for what happens to existing UTXOs when a round chain ends. Their keys are gone, so they cannot be re-graphed.
- **Failure trace** (reproduced in §6.2):
  - `M = 5`, `R = 32`: at most **160 reimbursements** can ever occur against all deposits made before the next setup epoch.
  - At `D_bucket = 1 BTC` with 1,000 deposits, **at least 840 BTC can never be reimbursed**. Operators will not front for them, peg-outs time out into the refund loop forever, and the zBTC is irredeemable (M0).
  - **Throughput:** `5 lanes / 5.5 days ≈ 0.91 BTC/day` for the whole bridge. A 30-day run on 100 BTC of TVL needs about 18 lanes (54 BTC of bonds), not 15 BTC. R2-H5's capital problem has become a throughput-and-capacity problem.
  - Raising `R` to cover supply multiplies the per-deposit pre-signing (`4·M·R` transactions, i.e. 40,000 at `R = 2,000`) and pushes lane lifetimes out by decades (`R × 5.5` days).
- **Minimal fix:**
  - Add a normative invariant, asserted in the oracle: `RemainingReimbursementCapacity = Σ_m (R_m − used_m) ≥ ceil(MaxRepresentationSupply / D_bucket) + safetyMargin`.
  - Gate `RelayClaim` mints on remaining capacity.
  - Specify the round-chain end-of-life (a new setup epoch MUST include graphs for every live UTXO, which is impossible after deletion), or adopt architecture (B) of R3-C1, where live signers re-graph.
  - Specify lane throughput against the peg-out queue, and have `ClaimFrontingSlot` check that the operator has a free round.

---

### 2.2 HIGH

---

#### R3-H1 — `Take1Tx`/`Take2Tx` cannot be fee-bumped and `BurnBondTx` needs no challenge, so honest operators are slashed (3 BTC plus 100% of the Zenon bond) in any fee spike

- **Spec:**
  - `spec/01:79,84`. Inputs: `1.0 BTC + 330 + 330` sats, all `SIGHASH_ALL`. Outputs: `0.9990 + 0.0010` BTC. There is **no CPFP anchor and no fee input**, so the fee is 660 sats.
  - `spec/01:70` ("minus 330-sat CPFP funded by operator fee input") contradicts the table.
  - `spec/01:68` (every operator-broadcast transaction carries a CPFP anchor) is not true of Take1/Take2.
  - `spec/01:81` (`BurnBondTx` spends `Conn_B` Leaf 3 at 288 with no dependency on `ChallengeTx`)
  - `spec/01:82` (`BurnBondTake2Tx` at 216 after `AssertEndTx`)
  - `spec/01:88` ("`Take1Tx` … must confirm `< 288`")
- **Ground truth:**
  - Under `SIGHASH_ALL`, nobody can add inputs or outputs after signing, and RBF needs new signatures from the deleted `Q_ephem_d`.
  - `ReimburseEscrow` is CSV-72, so it cannot CPFP. The reserve output is not the operator's.
  - 660 sats on a 3-input script-path transaction of about 250–300 vB is about 2.2–2.6 sat/vB.
- **Failure trace:**
  1. An honest operator kicks off and is not challenged.
  2. Mempool feerates are above about 3 sat/vB for 144 blocks (routine).
  3. `Take1Tx` cannot confirm.
  4. At block 288, any watcher broadcasts `BurnBondTx`. That burns 1.5 BTC and pays 1.5 BTC to the watcher.
  5. `BTC_OPERATOR_SLASH_PROOF` then slashes 100% of the Zenon bond, and the operator has already fronted `D_bucket`.
  6. `Take2Tx` has the same problem inside its `[144, 216)` window.
- **Minimal fix:**
  - Give Take1/Take2 an operator-only anchor output, and fund it by reducing `ReimburseEscrow`.
  - Or sign the operator connector inputs `SIGHASH_ALL|ANYONECANPAY` and the vault input `SIGHASH_SINGLE|ANYONECANPAY` (Out 0 = escrow), so that the operator can attach fee inputs.
  - Require `ChallengeTx` to have occurred before any assert-timeout burn (possible under R3-C1 architecture A).
  - Assert in the oracle that every pre-signed transaction has a fee source at the 500 sat/vB ceiling.

---

#### R3-H2 — Bond slash keys are undefined, and per-deposit `WrongDepositDisproveTx` forces a long-lived `BondOut` signing key

- **Spec:**
  - `spec/01:78` (`BondOut` Leaf1 "`SlashLeaf` (Committee+Op …)"; `Q_ephem_bond` is never defined)
  - `spec/01:86` (`WrongDepositDisproveTx_{d,m,r}`, In 0 = `BondOut_{m,r}` signed "Committee + Op")
  - `spec/01:42` (only `Q_ephem_d` is generated per deposit)
- **Ground truth:** `BondOut_{m,r}`'s script is fixed when the round chain is built. `WrongDepositDisproveTx_{d,m,r}` commits (through `SIGHASH_SINGLE` over all inputs) to `Take1Tx_{d,m,r}:0`, whose txid exists only after deposit `d`. The `SlashLeaf` key must therefore still be live at **every future deposit**.
- **Failure traces:**
  - If "Committee" in that leaf is `CommitteeIdentityKey` (the only long-lived committee key), then identity-key compromise plus operator collusion can sweep `BondOut` at will, which makes R3-C1's escape free even after it is fixed. This contradicts the blast-radius statement at `spec/01:43` ("CANNOT spend … already-rolled-over"), because the bonds that guard those UTXOs become spendable.
  - The operator holds a share of `SlashLeaf` and can **refuse to co-sign** `WrongDepositDisproveTx` for new deposits. Nothing says such an operator is excluded from `eligibleOperatorsBitmask`.
  - `Q_ephem_bond` (Leaf 3 / `Conn_C` Leaf 2) has no generation, holder or deletion rule.
- **Minimal fix:**
  - Define every key: holder, lifetime, deletion point.
  - Move substitution protection off `BondOut` (e.g., R3-C1 architecture A makes the kickoff per-deposit, so substitution becomes impossible by construction), or disclose a live bond-key assumption.
  - Make "operator co-signed all per-deposit transactions" a precondition for that operator's bit.

---

#### R3-H3 — The long-range residual of R2-H1 is still open: in-circuit carry-over, permissionless fresh anchoring, an unbuildable Leaf 4, and future-height certificates

- **Spec:**
  - `spec/04:71-73` (carry-over when quorum is missing)
  - `spec/01:29-30` (the epoch step circuit accepts "OR skipped-epoch carry-over")
  - `spec/04:41-43` and `spec/01:99` (anchor within ≤ 432 blocks "prior to `RoundKickoffTx`"; Leaf 4 "earlier conflicting anchor")
  - `spec/04:81` and `spec/05:58` (`SubmitInvalidCertProof` only for `h <= frontier.Height`)
  - `SPEC.md:86-90` ("mitigating retired-key long-range attacks!")
- **Ground truth:**
  - Pillar collateral is withdrawable after an 83-day lock cycle plus a 7-day revoke window (`dev:vm/constants/embedded.go:115-120`). Keys of Pillars retired ≥ 90 days ago carry **zero** slashable stake.
  - Anchoring is permissionless (`spec/04:16`). Anyone can put `c_h` of any digest in an `OP_RETURN` for one transaction fee.
  - A carry-over step is a *negative* claim ("no handoff quorum existed"). An IVC step cannot prove that a certificate does not exist.
  - The SNARK has no input that fixes the Bitcoin height of `RoundKickoffTx`. The kickoff commits only `(outpoint, outboxId, frontingTxid, releaseBatchId, depositBindingHash, pubInputHash)` (`spec/01:78`).
- **Failure trace:**
  1. The attacker buys 21 retired keys from any historical committee `E_k`.
  2. It proves `E_0 → … → E_k → carry-over → … → E_t` in-circuit, with no handoff ever signed after `E_k`.
  3. It signs a checkpoint certificate at a canonical-form height `h` with a forged `stateRoot` containing `RELEASED`/`ResolutionSeen` for its own operator.
  4. It anchors `c_h` today, which satisfies "≤ 432 blocks".
  5. Leaf 4 is meant to catch this, but it would have to verify ≥ 21 Ed25519 signatures, SHA3 digests and two Bitcoin SPV proofs, and compare intermediate committee roots that the constant-size `EpochChainReceipt` does not expose, all in Script. It is unspecified and, as described, cannot be built without a second SNARK verifier and its own disprove graph.
  6. With heights `h > frontier`, `SubmitInvalidCertProof` is unreachable until the chain catches up, by which time even current signers can have revoked.
  7. The activation cap (157,500 ZNN) is irrelevant to stakeless keys.
- **Minimal fix:**
  - Forbid in-circuit carry-over, or require a carry-over certificate signed by the outgoing committee and cap carry-over at ≤ 1 epoch.
  - Bind the target certificate's `timestampUnix` to the anchor block's header time (e.g., within 6 h).
  - Have the kickoff WOTS-commit a Bitcoin block hash, with a disprove path for a non-canonical or too-old commitment. A watchtower header-chain challenge is the standard approach.
  - Specify Leaf 4 as a concrete second verifier, or delete it and restate the trust assumption honestly ("2/3 of **any** historical committee").
  - Allow `SubmitInvalidCertProof` for future heights once they are reached, and hold slashed collateral past the revoke window.

---

#### R3-H4 — Multi-Tx Challenge Sessions do not stop finalization; the depth-256 guarantee depends on an unspecified race

- **Spec:**
  - `spec/03:151` (`OpenChallenge` → `UploadWitnessProof` ×k → `ExecuteChallenge`)
  - `spec/03:139` (`challengeDeadlineTs = now + 48h`)
  - `spec/03:143` (commit-reveal; reveal deadline unspecified)
  - `spec/03:177` (priority lane is local mempool policy)
- **Failure trace:**
  1. The executor grinds SMT keys so that a fraudulent step's witness exceeds 12 KiB, forcing a session.
  2. A `BTC_LOCK_PROOF` step can need up to 9 uploads of 8,676 B each, about 78 KB over ≥ 10 transactions.
  3. The challenger opens a session at `T − ε`.
  4. Neither `FinalizeBatch` nor any freeze rule refers to open sessions, so `FinalizeBatch` succeeds at `T` and the fraudulent mint is relayed.
  5. Conversely, if sessions *do* freeze finalization, sessions with no time bound give an unbounded freeze. The same holds for `CommitChallenge` with no reveal deadline.
- **Minimal fix:**
  - A session or commit opened before `challengeDeadlineTs` extends finalization of that batch, and of all successors, by a bounded `T_session` (e.g., 12 h). It expires if `ExecuteChallenge` is not called.
  - `ExecuteChallenge` MUST re-verify `leaf ∈ batch.TraceRoot` against the **current** batch record (see R3-M2).
  - Assert `T_session` in the oracle, and add a vector "session opened at T−1 blocks fraudulent finalization".

---

### 2.3 MEDIUM

| ID | Title | Spec | Failure trace | Minimal fix |
|---|---|---|---|---|
| **R3-M1** | `eligibleOperatorsBitmask` is unauthenticated | `spec/02:85,142-143`; `spec/03:161,165` | The relayer supplies the bitmask in `BTC_LOCK_PROOF`. Bitcoin contains nothing that proves which operators hold graphs. A malicious relayer (first to relay) sets bits for operators with no graph, which brings back R2-M7 (unreimbursable assignment), or sets 0 / dead operators to force quarantine. | Authenticate it: a committee-identity-key signature over `(rolloverOutpoint, bitmask, graphSetRoot)` verified in the lock proof (consistent with the existing identity-key assumption). Otherwise reject. |
| **R3-M2** | `batchId` is reused after rejection | `spec/03:130-136,152` | After rejection, `LineageHeadBatchId` reverts and the next batch must reuse `batchId = head+1`. Storage key `0x05‖domainId‖batchId` collides. A session opened against the rejected batch 5 can `ExecuteChallenge` against the honest replacement batch 5′ and slash its proposer, unless the leaf is re-verified. Rejecting batch 0 leaves `LineageHeadBatchId` with no sentinel. | Use never-reused monotonic batch ids with an explicit `parentBatchId`. Pin `(batchId, traceRoot)` in sessions and re-verify at execute. Define the empty-lineage sentinel. |
| **R3-M3** | `inputSeq` versus the global input index | `spec/03:38,66,122-123,148` | Inputs are keyed by `globalInputIndex`, which is global across domains (U-02). Leaves require `inputSeq = firstInputSeq + stepIndex` and Continuity requires `+1` adjacency. With more than one domain, a domain's global indices are not contiguous, so honest batches fail Continuity, or refunds look up the wrong `DomainInputIndex`. | Define a per-domain `domainInputSeq`, store the `domainInputSeq → globalInputIndex` mapping, and use it consistently in leaves, Continuity and refunds. |
| **R3-M4** | `ClaimFrontingSlot` cannot be enforced by the domain; there are two exclusivity rules that conflict | `spec/03:167`; `spec/02:147`; `SPEC.md:68` | The L1 slot lock (`frontingLockOperatorId`, timestamp expiry) lives in L1 `PegOutRecord`, which `d_btc_asset` never sees. The domain instead enforces "primary operator" for `h_front < po.CreatedBtcHeight + 12`, where `CreatedBtcHeight` is the domain tip when the input is processed and may already be 12+ blocks stale. A non-slot operator who fronts first and is proven first wins, so the slot holder loses `D − fee`. R2-M7(3) is still open. | Carry `slotOperatorId` / `slotExpiryBtcHeight` into the domain via a system input (`kind = 7` update), and enforce it in `BTC_RELEASE_PROOF`. Delete the `CreatedBtcHeight + 12` rule or derive it from the slot. |
| **R3-M5** | No operator→`BondOut` map for slash proofs | `spec/03:53` (single `btcRoundBondOutpoint`); `spec/02:154,158-173` | `BondOut_{m,r}` changes every round, and the domain SMT has no table of the R outpoints per operator. `BTC_OPERATOR_SLASH_PROOF` cannot attribute a burn for `r > 0`. U-11 is only partially closed. | Register the round-chain txid list at operator registration (prefix `0x0D`: `operatorId‖r → BondOut outpoint`) and check membership. |
| **R3-M6** | A late `RolloverTx` strands the deposit | `spec/01:57`; `spec/02:142` | `RolloverTx` is immutable and cannot be RBF'd. If it confirms at `h ≥ h_dep + 144` (fee spike, then CPFP), the lock-proof rule rejects it. The BTC sits in a graph-complete vault, Leaf B has been consumed, and nothing is minted: the depositor loses `D_bucket`. | Make reserve Input 1 **mandatory**. The committee MUST double-spend Input 1 (invalidating the rollover) if it is not confirmed by `h_dep + 144 − margin`, and the depositor then uses Leaf B. Alternatively, admit late rollovers with a witness-parsing Leaf-A proof (wtxid path). |
| **R3-M7** | `SubmitInvalidCertProof` slashes honest signers after a momentum reorg | `spec/04:81`; `spec/05:58`; `dev:chain/account_pool.go:694` (`DeleteMomentum` exists, so momentums can be popped) | Committee `E` signs a checkpoint at `h`, and the chain later reorganizes at `h` (e.g., a fork switch). Every honest signer loses 100% of 15,000 ZNN. Rational Pillars then stop signing, and certificate liveness collapses. | The U2 fork choice MUST NOT revert certified momentums (finality gadget), and certificates are signed only at depth ≥ X. Specify this before slashing activates. |
| **R3-M8** | `SpotPrice` cap has no oracle; `ExecutorBondValue` compares mixed units | `SPEC.md:89`; `spec/03:137` | `MaxRepresentationSupply × SpotPrice ≤ 157,500 ZNN` and `MaxInFlightMint ≤ ExecutorBondValue` mix BTC with ZNN/QSR. There is no price source, so a ZNN price drop silently breaks the cap. | Make the cap a governance parameter with a mandatory re-check cadence and a Guardian `LowerSupplyCap` trigger on a price-deviation report, or denominate bonds in zBTC. |
| **R3-M9** | M-03 disclosure is inaccurate; watcher economics under MEV are −`F_assert` | `spec/01:90`; `SPEC.md:92`; `script:175-177` | With miner capture of Out 1, the watcher always loses `1.10 BTC + fees`. So, under the disclosed residual, the "1-of-N watcher" assumption is purely altruistic. The text's "fraudulent operator IS still slashed" is also false under R3-C1. | Restate it: "Under miner capture, challenging is altruistic (−F_assert)". Model it in the oracle. Consider a committed-recipient watcher output via a pre-signed, watcher-key-registered variant. |

### 2.4 LOW / ERRATA

| ID | Erratum | Location | Correction |
|---|---|---|---|
| **R3-L1** | Line citations reference `master`, not the declared `release/dev` baseline: `token.go:35,38,271` are `40,43,330` on `release`/`dev`; `vm/constants/embedded.go:41` is `:108` on `dev`; `pillar.go` is actually `pillars.go` | `SPEC.md:101`; `spec/03:12`; `spec/04:82`; `spec/05:56,76` | Re-cite against `f19955f`/`770e893` |
| **R3-L2** | Overclaims remain (R2-L6): "ZERO `<anyone>` leaves", "addresses all Round-1 and Round-2 findings", "mathematically guaranteeing challengeability", "Every single inequality … asserted" | `spec/01:66,116`; `SPEC.md:3`; `spec/02:108` | Restate as design intent with gates |
| **R3-L3** | The Poisson quantile is off by one (conservative): the smallest `k` with `P(X>k) ≤ 1e-4` is **353**, and the script returns 354. Stationarity is unlabeled: with hashrate growing 10% faster than difficulty adjusts, the quantile is 386 | `script:54-63,209` | Fix the loop. Label the rate as `ASSUMED`, or size for `λ = 1.1 × 288` |
| **R3-L4** | The K formula uses a fixed `3.125 BTC` subsidy. After the ~2028 halving (1.5625), `ceil(2·10/1.5625) = 13 > 12`, so the pilot `K = 12` violates its own rule. The formula also uses the per-executor cap, while reorg profit scales with aggregate exposure | `spec/02:42`; `script:33,217-219` | Index the formula by epoch-height subsidy, and use aggregate in-flight mint |
| **R3-L5** | The BIP-327 adaptor sum omits the tweak term `e·g·tacc` (PartialSigAgg) | `spec/03:196-198` | Define `s̃` per BIP-327, including the tweak term |
| **R3-L6** | Release of `inFlightMintExposure` on `FinalizeBatch` is unspecified (only on rejection), so exposure ratchets up and blocks the executor | `spec/03:137,152` | Release on finalize |
| **R3-L7** | `FinalizeBatch` is "frozen" by `DispatchFrozenByBatch`, yet the halting batch itself must finalize to set `PAUSED`. Whether `FinalizeBatch` runs in shadow (`PAUSED`) mode is ambiguous | `spec/03:138`; `SPEC.md:129` | Exempt the freezing batch; state the shadow-mode finalization rule |
| **R3-L8** | ClaimPolicy payload is "Exact `cfg.ChainBindingHash`", but legacy releases emit `po.ChainBindingHash`. The "recognized binding set" is undefined | `spec/02:66-68,145,148` | Define a `RecognizedBindings` SMT set and amend the payload rule |
| **R3-L9** | Commit-reveal is optional. A Pillar can still copy an uncommitted `ChallengeStep` and front-run its bounty (R2-L8 residual). The reveal deadline is unspecified | `spec/03:143` | Give committed challenges priority for N momentums; set a reveal deadline |
| **R3-L10** | Refundable duplicate inputs make spam free in ZNN; only plasma prices it | `spec/02:116` | Cap refundable duplicates per submitter per batch |
| **R3-L11** | `ReceiveTreasury` does not check the ZTS id, the amount (`MaxSupply`), or that it runs only once | `spec/03:19` | Add those checks |

---

## 3. Disposition of Round-2 Findings

Legend: **CLOSED** · **PARTIALLY CLOSED** · **STILL OPEN** · **ESCALATED** (correctly placed in the upstream register: it blocks mainnet, not design sign-off).

### 3.1 CRITICAL / HIGH

| ID | Status | Evidence / residual |
|---|---|---|
| R2-C1 | **PARTIALLY CLOSED** | Causality is fixed: nothing spends `ChallengeTx` (`spec/01:65,80`), and round-level transactions have fixed txids. The `<anyone>` connector is removed. The slash paths are escapable: **R3-C1**. The trap is unsigned: **R3-C2**. |
| R2-C2 | **CLOSED** | `spec/03:94,128-136`. BatchId-reuse residual: R3-M2. |
| R2-C3 | **CLOSED** | Bob locks first, and Alice verifies the confirmed PTLC (`spec/03:191-196`). This matches the `dev` PTLC ABI (`Create(expirationTime, pointType, pointLock, destination)`; `PointTypeSecp256k1Point = 2`, scalar unlock). |
| R2-C4 | **CLOSED** | Re-derived: the base case plus the induction step over `Cum*`, the halted latch and `HaltedHeight` cover every aggregate. `finalLeaf` is bound at `SubmitBatch`. `observedTipAfter` is verified per step. `RelayClaim` goes via `StepClaimsRoot`. Continuity is 1,700 B ABI (recomputed). |
| R2-H1 | **PARTIALLY CLOSED** | Non-checkpoint forgery is closed by checkpoint-only acceptance plus `SubmitInvalidCertProof`. Long-range is still open: **R3-H3**. Reorg slashing hazard: R3-M7. The cap has no oracle: R3-M8. |
| R2-H2 | **PARTIALLY CLOSED** | Recursive IVC → fixed outer Groth16, 4th assumption (CRS `K ≥ 50`), and numbers labeled as targets are all done. The carry-over rule breaks soundness against long-range: **R3-H3**. Measurements are gate G-2 (not blocking). |
| R2-H3 | **CLOSED** | `ActiveChainByHeight = hash‖merkleRoot`, never pruned (`spec/02:118,122,164`). |
| R2-H4 | **CLOSED** | Streaming SHA-256 from the standard IV, ordered chunks, `isCoinbase` and `matchedOutpoint` latched (`spec/02:126-133`). Residual: plasma cost scales with miner/thief size (acceptable). |
| R2-H5 | **PARTIALLY CLOSED** | The fixed-amount algebra is correct as modeled, and the reserve output is enforced. The model does not match the DAG: **R3-C1**. Fee funding: **R3-H1**. 500% lockup is replaced by a capacity and throughput limit: **R3-C3**. |
| R2-H6 | **CLOSED** | Dispatch-only freeze, automatic clear, `SubmitInput` always open (`spec/03:120,138`). Ambiguity: R3-L7. |
| R2-H7 | **PARTIALLY CLOSED** | Per-outpoint binding, peg-out during drain, and the Guardian timer are all done. Legacy UTXOs remain subject to round exhaustion (**R3-C3**). Binding-set definition: R3-L8. |
| R2-H8 | **CLOSED** | `ChallengeDepositZnn` (10% of bond) prices junk. Lane composition is honestly disclosed as local policy, with a 48 h window. |

### 3.2 MEDIUM / LOW

| ID | Status | Note |
|---|---|---|
| R2-M1 | **CLOSED** (subject to R3-H4) | Single proof at depth 256 = 8,533 B; `UploadWitnessProof` ABI = 8,676 B (recomputed). |
| R2-M2 | **CLOSED** (design); G-11 ⚙ | Confirmed against `dev:vm/vm.go:204-226` and `dev:…/token.go:163-171`. Checks: R3-L11. |
| R2-M3 | **CLOSED** | `createdBtcHeight`, raw `rolloverOutpoint`, kind-7 `inputHash`. New sequencing ambiguity: R3-M3. |
| R2-M4 | **CLOSED** | 1-deposit-in shape plus `ProcessedProvisionalDeposit`; blast radius restated. |
| R2-M5 | **CLOSED** | `tip + 522`. Model caveat: R3-L3. |
| R2-M6 | **CLOSED** | Idempotent no-op plus pull refunds. Spam note: R3-L10. |
| R2-M7 | **PARTIALLY CLOSED** | Eligibility filter added, but the bitmask is unauthenticated (R3-M1) and the slot is unenforced (R3-M4). |
| R2-M8 | **PARTIALLY CLOSED** | Leaf-3 binding, `OP_SHA256` WOTS `w = 4`, and per-graph constants are done. Signers/keys are undefined: R3-C1, R3-H2. |
| R2-M9 | **CLOSED** | `DispatchDeferredLock` plus grandfathering by height. |
| R2-M10 | **CLOSED** | Shadow mode is feasible. |
| R2-M11 | **CLOSED** | Tweaked `x(Q_swap)`; `T_btc` measured from confirmation. Minor: R3-L5. |
| R2-M12 | **CLOSED** (signer) | Committee `E` signs the handoff. The carry-over consequence is in R3-H3. |
| R2-L1 | **CLOSED** | Enforced at `spec/02:146`. |
| R2-L2 | **ESCALATED** | A-SPEC-6. |
| R2-L3 | **ESCALATED** | A-BTC-1. |
| R2-L4 | **CLOSED** | One fee model; immutable. See R3-M6. |
| R2-L5 | **CLOSED** | Prune rejected while `ReorgActive`. |
| R2-L6 | **STILL OPEN** | R3-L2. |
| R2-L7 | **CLOSED** | `inFlightMintExposure`. See R3-L6. |
| R2-L8 | **PARTIALLY CLOSED** | R3-L9. |

**Round-2 tally (32):** 21 CLOSED · 2 ESCALATED · 8 PARTIALLY CLOSED · 1 STILL OPEN.

### 3.3 Remaining Round-1 Partials

| ID | Status | Note |
|---|---|---|
| C-01 | **PARTIALLY CLOSED** | Causality is fixed; enforceability is broken (R3-C1). |
| C-03 | **PARTIALLY CLOSED** → gate | The architecture is specified. Measurements are G-2 (execution gate). |
| C-08, C-09, C-11, C-12 | **CLOSED** | Via R2-C2/C4, R2-M1, R2-M2 and R2-C3 respectively. |
| H-02, H-04, H-06, H-10 | **CLOSED** | |
| H-07 | **PARTIALLY CLOSED** | The reserve is enforced, but Take1/Take2 fee funding is missing (R3-H1). |
| H-09 | **PARTIALLY CLOSED** | R3-H3. |
| M-03 | **ACCEPTED RESIDUAL — disclosure inaccurate** | R3-M9. |
| M-04, M-06, M-14 | **CLOSED** | Subsidy-indexing caveat: R3-L4. |
| U-04 | **CLOSED** | |
| U-11 | **PARTIALLY CLOSED** | R3-M5. |
| U-12 | **ESCALATED** | A-SPEC-6. |

---

## 4. Verified-Sound Mechanisms (new in v2.1; do not re-litigate)

- **Cross-batch lineage chaining and inductive `StepTraceLeaf` accumulators.** The 328 B leaf, depth-8 trace, Continuity base and induction cases, and `finalLeaf` binding were all re-derived. Under ChallengeStep plus Continuity, no aggregate is left unchallengeable.
- **The never-pruned `ActiveChainByHeight` merkle index and `BTC_PRUNE_STEP` rejection during reorgs.**
- **Streaming SHA-256 from the standard IV.** Ordered chunks, 64-byte alignment, `len != 64` and coinbase detection give the same `(txid, isCoinbase)` as inline parsing. Midstates cannot be forged.
- **The `IssueMinted` → `ReceiveTreasury()` hop** satisfies `applySend`'s embedded method lookup (`dev:vm/vm.go:204-226`). Descendant sends are applied through `applySend` at `dev:vm/vm.go:381`.
- **PTLC.** Bob locks first, and the ABI and point type match go-zenon `dev` (`PointTypeSecp256k1Point`, scalar unlock via `verifyPointScalar`).
- **Causality of the round-level DAG.** No pre-signed transaction spends `ChallengeTx`. All round-level transactions (`RoundKickoff`, `AssertStart/Chunk/End`, `BurnBond*`, `DisproveTx`) have setup-time-fixed txids. Witness-only WOTS data does not change txids.
- **Timelock ordering.** The asserted ordering (288/360/432/648/792) is internally consistent (re-derived).
- **`SIGHASH_SINGLE` (no ACP) on `BondOut` In 0 plus `SIGHASH_NONE` on In 1** correctly fixes the burn output and the inputs while leaving the watcher output free (BIP-341 semantics). The defect is elsewhere (R3-C1).
- **Upstream escalation.** A-SPEC-1..6, A-BTC-1 and A-MINT-1 are correctly escalated.

---

## 5. Go / No-Go Gate Checklist (Round 3)

**Status: NO-GO (design).** Execution gates marked ⚙ do not block design sign-off.

| Gate | Status | Blocking items |
|---|---|---|
| G-1 (graph causality and enforceability) | ❌ OPEN | R3-C1, R3-C2, R3-H1, R3-H2; ⚙ Signet build |
| G-2 (measured SNARK and chunk weights) | ⚙ GATE | Correctly labeled `ASSUMED_STAGE_0C_TARGET_*` |
| G-3 (finality proof) | ◐ PARTIAL | R3-H3, R3-M7 |
| G-4..G-6 | ✅ CLOSED | |
| G-7 (fronting and fees) | ◐ PARTIAL | R3-H1, R3-M4 |
| G-8 (traceRoot) | ✅ CLOSED | (R3-M2, R3-M3 are hygiene) |
| G-9 (witness bound) | ◐ PARTIAL | R3-H4; ⚙ adversarial fuzzer |
| G-10 | ✅ CLOSED | |
| G-11 (mint model) | ✅ design / ⚙ test | |
| G-12 (lock-proof hardening) | ◐ PARTIAL | R3-M1, R3-M6 |
| G-13 (timeouts, eligibility, halt) | ◐ PARTIAL | R3-M4, R3-L7 |
| G-14 (input DoS) | ✅ CLOSED | |
| G-15 (epoch committee) | ◐ PARTIAL | R3-H3 (carry-over) |
| G-16 | ✅ CLOSED | |
| G-17 (upstream) | ⚙ ESCALATED | Ratification pending (not a design blocker) |
| G-18 (peg-free rails) | ✅ design / ⚙ tests | |
| G-19 (numbers from scripts) | ◐ PARTIAL | S3-1..S3-8 |
| **G-21 (NEW) reimbursement capacity ≥ supply** | ❌ OPEN | R3-C3 |
| G-20 (independent re-review) | ✅ this document; **Round 4 required** | |

---

## 6. Audit of `scripts/verify_spec_bounds.py`

The script ran cleanly (`python3 -I scripts/verify_spec_bounds.py`, exit 0). Every printed number was independently recomputed and matches:
- depth-256 proof 8,533 B and `UploadWitnessProof` ABI 8,676 B;
- `StepTraceLeaf` 328 B;
- Continuity 1,700 B;
- payload and ABI sizes;
- economics rows;
- timelocks.

**S-1..S-10:**
- S-1, S-2, S-3, S-4, S-5, S-6, S-7, S-8 and S-10 are **CLOSED**: labeled assumptions, depth-256 hard bound, F_assert in P&L, Continuity modeled, `createdBtcHeight`, streaming, re-derived grace, real `assert`s.
- S-9 is **PARTIAL**: the constraint count (2M–5M), `L` and `C` appear only in prose and are not asserted.

### 6.1 New Script Defects

| # | Defect | Location | Effect |
|---|---|---|---|
| S3-1 | The economics model assumes slash paths that the DAG cannot enforce (no operator escape, no standalone connector/trap spend) | `script:174-199` | The assertions "prove" R3-C1 and R3-C2 away |
| S3-2 | No fee-source model for pre-signed transactions (Take1/Take2 fee is 660 sats with no anchor) | — | Hides R3-H1 |
| S3-3 | No capacity or throughput model (`Σ R_m`, 792-block lanes) against `MaxRepresentationSupply` | — | Hides R3-C3 |
| S3-4 | Watcher P&L under the disclosed M-03 miner capture is not modeled (it is −`F_assert` − `f_chal`) | `script:175-177` | Hides R3-M9 |
| S3-5 | Poisson quantile off by one (conservative), and stationary rate unlabeled | `script:54-63` | R3-L3 |
| S3-6 | Fixed 3.125 BTC subsidy in the K formula; per-executor cap only | `script:33,217-219` | R3-L4 |
| S3-7 | The honest-challenged-operator assertion is a knife edge (exactly 0.0 at 500 sat/vB) and excludes Take2 and CPFP costs | `script:189,199` | Negative in practice at the ceiling |
| S3-8 | The cap gate prints 157,500 ZNN but has no price input; `ChainMeta` (238 B) and `TxStreamState` (175 B) are not derived field by field | `script:68-72,243` | Unverified inputs to the witness bounds |

### 6.2 Reproduction of This Review's Numbers

```text
Poisson(288):   smallest k with P(X>k)<=1e-4 = 353  (P(X>353)=9.38e-5); script returns 354
Poisson(1.05*288)=370, (1.10*288)=386, (1.20*288)=418
K after 2028 halving (subsidy 1.5625, MaxInFlight 10 BTC) = max(12, ceil(12.8)) = 13 > 12
Lifetime reimbursements M*R = 5*32 = 160; round period 792/144 = 5.5 days
Bridge-wide reimbursement throughput (M=5 single lanes) = 0.909 BTC/day
Take1/Take2 fee = (1e8 + 330 + 330) - (0.9990e8 + 0.0010e8) = 660 sats (no anchor, all SIGHASH_ALL)
R3-C1 escape: operator +1.10 BTC (F_assert) - ~200 vB fee; watcher -1.10 BTC - challenge fee
```

```python
import math
from math import exp, log, lgamma
lam = 288
cdf = lambda k: sum(exp(-lam + i*log(lam) - lgamma(i+1)) for i in range(k+1))
print(1-cdf(353), 1-cdf(354))
print(max(12, math.ceil(20/1.5625)), 5*32, 792/144, 5/(792/144))
```

---

## 7. Required Actions Before Round 4 (Priority Order)

1. **R3-C1, R3-C2, R3-H2.**
   - Choose a BitVM2 round architecture:
     - **(A)** per-deposit `KickoffTx_{d,m,r,j}` hanging off round-level kickoff connectors, with all challenge-path leaves `Q_ephem_d`-co-signed; or
     - **(B)** a live round-graph signer committee, disclosed as a new trust assumption.
   - Republish the DAG with a "signer set / signing epoch / fee source" column for every leaf and transaction.
   - Sign the substitution trap, route recovered funds back into custody, and make kickoffs single-use per `RELEASED` record.
2. **R3-C3.** Add the capacity invariant `Σ remaining rounds ≥ supply / D_bucket`, gate mints on it, specify round-chain end-of-life, and model throughput.
3. **R3-H1.** Give every pre-signed transaction a bumpable fee source, and make the timeout burn conditional on a challenge.
4. **R3-H3.**
   - Remove or bound in-circuit carry-over.
   - Bind the certificate timestamp to the anchor header time.
   - Commit a Bitcoin block hash in the kickoff, with a disprove path.
   - Specify or delete Leaf 4.
   - Restate Assumption 1 honestly.
5. **R3-H4.** Bound sessions and commits so they extend finalization, and re-verify session leaves at execute.
6. Fix R3-M1..M9 and R3-L1..L11, and extend the oracle (S3-1..S3-8).

**Not blocking design sign-off (correctly gated in `SPEC.md §6–§7`):**
- Signet measurements (G-1 build, G-2);
- go-zenon `IssueMinted` test (G-11);
- adversarial SMT fuzzer (G-9);
- swap adversarial suite (G-18);
- CRS ceremony transcript;
- ratification of A-SPEC-1..6, A-BTC-1 and A-MINT-1.
