# Hostile Peer Review — Round 6 — zBTC Bitcoin↔Zenon Interoperability Specification `v2.4.0-draft`

**Reviewer posture:** adversarial, first-principles. Same rules as Rounds 1–5. I did not trust the spec's summaries, its change log, or the oracle's comments. I re-derived each claim from:
- Bitcoin consensus and policy (BIP-65/68/112/341/342; the 1,000-element limit, which BIP-342 also applies to the *initial* witness stack; the 400 kWU standardness limit);
- the public BitVM Winternitz construction, including how its digit-forwarding property interacts with checksums;
- SHA-256 (FIPS 180-4) padding and the compression-function chaining;
- `go-zenon` source at the declared baselines;
- my own recomputation of every oracle number used below.

**Review date:** 2026-11-24
**Baseline:** `HOSTILE_REVIEW_R5.md` (Round 5: 0 C · 3 H · 4 M · 9 L · script defects S5-1..S5-6).
**Mandate:**
- Grade every Round-5 item.
- Attack every new v2.4 mechanism.
- Do not re-litigate the mechanisms that R2–R5 §4 verified as sound, unless v2.4 broke them.
- Separate **blocking design-spec defects** from **non-blocking execution or upstream gates**.

**Artifacts under review (SHA-256, first and last 8 hex digits):**

| File | SHA-256 |
|---|---|
| `SPEC.md` | `d621e2cb…4ad05e3d` |
| `spec/01` | `48a4b42b…579a702d` |
| `spec/02` | `07732e07…7171d684` |
| `spec/03` | `a780cfbc…aad020a3` |
| `spec/04` | `e3494f63…d19ed59a` |
| `spec/05` | `3ad2f25a…872cbac8` |
| `scripts/verify_spec_bounds.py` | `bbed0ea1…c9e15cf5` |

**Ground truth:**
- `go-zenon`: `770e893` (`origin/dev`) and `f19955f` (`origin/release/0.0.11-rc1`), both resolved locally.
- I re-checked these citations on `770e893` and all of them match:
  - `pillars.go:132-138` (the `% (83d+7d)` revoke phase);
  - `pillars.go:395-412` (immediate `PillarStakeAmount` refund on `Revoke`);
  - `constants/embedded.go:108,115-120`;
  - `consensus.go:45,86`.
- `zenon-developer-commons`: `HEAD` `3719452`.
- Neither reference repository was modified.

**Citation convention:** `spec/0N:L`, `SPEC.md:L`, `script:L` (= `scripts/verify_spec_bounds.py`). My reproduction script is `<reviewer-scratchpad>/check.py` (§6.2).

---

## 1. Executive Verdict

### **HOLD — Design Spec (0 CRITICAL, 2 blocking HIGH)**

v2.4 is a substantial improvement. I re-derived each of the following and found it correct:
- **The cost model for certificate DA is now derived, not assumed.** This closes the 10–35× under-costing from R5-H1:
  - BLS12-381 `min-sig` certificate = `8+8+8+32+32+32+32+4+48 = 204 B`, a fixed size for any number of signers up to 30.
  - 30-day epochs with `E_anchor_ts = finalityEpochStartTs(E_anchor)` and expiry at 58 d < 60 d give at most 1 handoff.
  - `408 + 9` padding bytes = 7 SHA-256 blocks (the last block holds 24 data bytes, `len = 3264` bits), so there are 6 intermediate midstates.
  - Digits: `408·2 + 2·4` (a 4-nibble checksum on each 408-nibble certificate, since `6,120 < 16⁴`) `+ 6·(64+3)` (since `960 < 16³`) `= 1,226`.
  - Cost: `95.5 WU/digit` ⇒ **29,571 vB**. At 492 digits per input, 3 inputs are needed (cert₁ 412, cert₂ 412, midstates 402).
- **The economics are exact in integer satoshis:**
  - `F_assert = ⌈⌈125.5M·1.15⌉/5M⌉·5M = 1.45 BTC`;
  - burns of `1.65 / 1.85 / 2.70`;
  - `Bond = 165+145+1+47.5+11.5 = 370M sats = 3.70 BTC`;
  - `HonestOp(500) = +0.195`;
  - break-even `289.0 kvB`;
  - every value balance checks out (Disprove `1.65+2.05`, StaleBurn `1.85+1.85`, WDD `0.99899+2.70+1.00`, Retire `3.699+330 sats+99,670 sats`).
- **Bitcoin-side rotation and staggered CLTVs.**
  - The order `46d < 56d < 58d` holds, and the gap between `T_kill` and `T_bond` is 288 blocks, which exceeds the 72-block escrow trap. **R5-L3 is closed.**
  - With cutoff, kickoff and the latest Take2 (≤ 51.0 d), retirement can start at 51.5 d, leaving 936 blocks.
  - At most 2 generations overlap, because g+2's anchor (day 60) is later than g's expiry (day 58).
- **Verifier-decided halting in `0x08`.** It requires an inclusion proof or a set of all-epoch absence proofs, and otherwise rejects the input. **R5-M1 is closed.**
- **Lanes:** `BTC_ROUND_RETIRED` + `SyncRetiredLane`, serial `ReachableRounds`, and the `max(now, nextEligible) ≤ cutoff` kickoff gate. **R5-M2 (a)(b)(c) are closed.**
- **Domain and Settlement transition tables**, the non-overwriting `MINTED_REFUND_V1`, and a deterministic `SyncOrphanedVaultOutpoint`.
- **`A-PILLAR-1`:** `RegisterFinalityKey` + PoP, a 72-day lock measured from `finalityEpochEndTs`, and `RequestExitCommittee`.

The oracle runs clean (`python3 -I`, exit 0). Every number it prints that I recomputed matches.

**What still blocks design sign-off: two HIGH findings.** Both are defects inside the two mechanisms that v2.4 introduced to close R5-H1 and R5-H2. Both have small, local fixes.

1. **R6-H1 — The R5-H2 fix can be bypassed in two ways.**
   - **The "pinned transition-height handoff" cannot be enforced in the circuit.** The circuit has no oracle for `h_trans(E+1)` or `FinalityCommitteeRoot(E+1)`: it *learns* that root from the handoff itself.
   - **`SubmitInvalidCertProof` verifies the signature under `canonicalSigningCommitteeRoot(cert.Height)`** (`spec/04:80`). Suppose a committee-E cartel signs either:
     - a forged handoff at any **non-transition height inside epoch E+1**; or
     - a `CarryOverCertificate` followed by a target in epoch E+1.

     The signature then fails that *precondition*, because epoch E+1's canonical signer is committee E+1. Case A is never reached, so **nothing is slashed**.
   - This is the R5-H2 attack again, moved from "any height" to "any height in E+1 except the first".
2. **R6-H2 — Leaf 3B is either forgeable or cannot be built.**
   - The DA commits each 204 B certificate as **one** WOTS message with **one** checksum (`spec/01:29`). Each Leaf 3B chunk checks one 64-byte block.
   - Suppose a leaf checks only the block's digits, without the certificate's checksum. Winternitz chains can be hashed forward, so **any watcher can raise a digit** of an honest operator's commitment, make `compress(·) ≠ midstate`, and falsely disprove. That burns 1.65 BTC, pays the watcher 2.05 BTC, and kills Take2.
   - Suppose instead a leaf checks the full certificate including its checksum. It then needs 546 digits (blocks 0–2 and 4–6) or **958 digits (block 3 spans both certificates)**. By the spec's own model the cap is **492 digits per input** (`spec/01:30`, `script:256`), before the SHA-256 working set is even counted.

**New-finding census:** **0 CRITICAL · 2 HIGH · 5 MEDIUM · 9 LOW · 6 script defects (S6-1..S6-6).**

**Round-5 disposition (§3):**
- Of the 16 R5 findings: **10 CLOSED · 6 PARTIALLY CLOSED (R5-H1, R5-H2, R5-H3, R5-M3, R5-M4, R5-L7) · 0 STILL OPEN**.
- Of the 6 R5 script items: **4 CLOSED · 1 PARTIALLY CLOSED (S5-4) · 1 STILL OPEN (S5-6, non-blocking)**.

**Path to CONDITIONAL PASS (Design Spec).** Fix R6-H1 and R6-H2 (§7). Each is a few normative sentences plus a small re-derivation; neither needs an architecture change. R6-M1..M5 can be closed in the same pass or carried as named Stage-0B/0C conditions.

The following remain correctly declared **non-blocking** execution or upstream gates:
- G-1 (Signet build, 1p1c relay);
- G-2 (measured weights, *including* the script size of a SHA-256 compression without `OP_CAT` and its peak stack);
- G-9 (fuzzer);
- G-11 (`IssueMinted` test);
- G-18 (swap suite);
- the Groth16 CRS ceremony;
- §6 ratification (now including `A-PILLAR-1`).

---

## 2. New Findings (Round 6)

### 2.1 HIGH

---

#### R6-H1 — The circuit cannot enforce the transition-height pin, and `SubmitInvalidCertProof` checks the signature against the *canonical* committee at `cert.Height`. A committee-E cartel can therefore forge a handoff (or a `CarryOverCertificate`) at a non-transition height in epoch E+1 and never be slashed. R5-H2 is reopened.

- **Spec:**
  - `spec/04:72` (the epoch-step circuit "accepts a handoff `E → E+1` **ONLY** at `h = h_trans(E+1)` … with `cert.NextFinalityCommitteeRoot == FinalityCommitteeRoot(E+1)`, OR at most 1 … `CarryOverCertificate` (`next == Root(E)`)")
  - `spec/01:33`
  - `spec/04:70-71` (canonical signing root is `Root(E+1)` at every non-transition height of epoch E+1)
  - `spec/04:80` ("Requires `cert` to carry a valid dual-supermajority … signature **under `canonicalSigningCommitteeRoot(cert.Height)`**")
  - `spec/04:77` (the checkpoint restriction applies to *targets* only)
  - `spec/04:79` (equivocation is keyed on `(epoch, height)`)
  - `spec/05:60`
  - `SPEC.md:37,91`
- **Why the circuit cannot pin the height.**
  - The only trusted input baked into a round chain is `E_anchor_root` (Conn_C L3A, `spec/01:88`). The Q_round keys are deleted at setup, between day 0 and day 8 of the anchor epoch.
  - `h_trans(E+1)` (the first Momentum of epoch E+1) and `Root(E+1)` (snapshotted at day 30) do not exist at setup.
  - A fixed 204 B certificate carries no predecessor timestamp. The circuit can therefore check at most `cert.finalityEpochIndex == E+1` and `cert.FinalityCommitteeRoot == Root(E)`.
  - It cannot tell `h_trans` apart from `h_trans + k`, and "`next == Root(E+1)`" is a tautology, because the circuit adopts whatever `next` the handoff names.
- **Failure trace (forged handoff):**
  1. 21 of the 30 members of committee E (> ⅔ weight) sign `H*` at a height `h*` in epoch E+1, with `h* ≠ h_trans(E+1)` and `h* % 30 ≠ 0`. Its fields are:
     - `finalityEpochIndex = E+1`;
     - canonical `height`, `timestampUnix`, `momentumHash` and `stateRoot`;
     - `finalityCommitteeRoot = Root(E)`;
     - `nextFinalityCommitteeRoot = R_fake` (30 keys with no stake).
  2. The fake committee signs a forged target at a checkpoint height in epoch E+1. The circuit accepts the chain `Root(E) → H* → R_fake → target`.
  3. Under Assumption 3, the challenge publishes both certificates through `AssertCertDATx`.
  4. `SubmitInvalidCertProof(H*)` computes `canonicalSigningCommitteeRoot(h*) = Root(E+1)`. Committee E's aggregate signature does not verify under `Root(E+1)`, so the precondition fails ⇒ **the call is rejected, and no one is slashed.**
  5. `SubmitInvalidCertProof(target)` fails in the same way, and its signers have no stake anyway.
  6. `SubmitEquivocationProof` finds no canonical certificate at `(E+1, h*)`, because certificates are produced only at `%30` heights and at `h_trans`.
- **Failure trace (carry-over; simpler, with no fake keys):**
  - Committee E signs a `CarryOverCertificate` at a non-transition height in epoch E+1, then a forged target at a `%30` height in epoch E+1.
  - Both certificates fail the precondition, because they are signed by committee E but the canonical signer is E+1.
  - Equivocation catches only cartel members who **also** sit in E+1 **and** signed the canonical certificate at that exact height. Members who rotated out of E+1, or who abstained, are never caught.
- **Impact:** the reachable-slashing backstop of Assumption 1 (`SPEC.md:89-92`) is again worth an expected slash of 0 against the most direct cartel attack. The 72-day lock (`spec/04:87`) keeps the collateral in place but cannot be triggered. The new MUST-fail test in Stage 0A (`SPEC.md:130`, `spec/05:119`) uses a forged handoff *at the transition height*, which is the only shape that the fix does catch.
- **Minimal fix:**
  1. **Precondition:** verify the aggregate signature under the committee whose root equals `cert.FinalityCommitteeRoot`, requiring that root to be a historical Tag-15 root (`∃E': Root(E') == cert.FinalityCommitteeRoot`). Then apply the full 8-field Case A. A certificate signed by committee E at a height in epoch E+1 is then slashable through the `FinalityCommitteeRoot ≠ canonicalSigningCommitteeRoot(h)` term.
  2. **Delete `CarryOverCertificate`**, or define it as canonical only for an explicit Zenon "no-snapshot" event, recorded on-chain, at `h_trans(E+1)`. If it stays, define it so that a carry-over anywhere else is slashable under (1).
  3. **Stop claiming an in-circuit pin.** State that the pin is enforced *economically* by (1).
  4. **MUST-fail vectors:**
     - "committee-E-signed handoff at `h_trans(E+1)+1` with canonical momentum and state ⇒ slashable";
     - "committee-E-signed target in epoch E+1 after a carry-over ⇒ slashable".

---

#### R6-H2 — The DA is committed with one WOTS checksum per certificate, but Leaf 3B checks single 64-byte blocks. A leaf that skips the checksum lets any watcher forge digits and falsely disprove honest operators. A leaf that verifies the checksum exceeds the 1,000-element stack limit, for block 3 by about 2×.

- **Spec:**
  - `spec/01:26` (per-field WOTS, each field with its own checksum)
  - `spec/01:29` ("408 B cert bytes (`824` nibbles **incl. per-cert checksums**)")
  - `spec/01:30` ("`<= 492` digits/input")
  - `spec/01:31` and `spec/01:88` (`L3B_j`: "Single 64B SHA-256 Compression Check")
  - `script:251-258`
- **Ground truth (Winternitz):**
  - BitVM's W-OTS has no WOTS+ bitmasks; Script has no `OP_XOR`/`OP_CAT`. Anyone holding the signature on digit `d` can compute a valid signature on every digit reachable by hashing further along the chain.
  - Only the message's checksum digits prevent this, so a verifier that checks a *subset* of a message's digits without that message's checksum accepts forged values.
  - BIP-342 applies the 1,000-element limit to the initial witness stack. The BitVM verifier uses 2 elements per digit, which is the spec's own model (`script:255-256`, 492 digits).
- **Recomputation (`r6_check.py`):**

  | Leaf | Bytes | Certificates touched | Digits needed with checksums (cert(s) + 2 midstates) | vs. cap of 492 |
  |---|---|---|---:|---|
  | `L3B_0..2` | `[0,192)` | cert₁ | 412 + 134 = **546** | ✗ |
  | `L3B_3` | `[192,256)` | **cert₁ + cert₂** | 824 + 134 = **958** | ✗✗ (stack ≈ 1,916 elements) |
  | `L3B_4..6` | `[256,408)` | cert₂ | **546** | ✗ |

  This is before the SHA-256 compression's own working set (≈ 190 or more nibble elements for state, block and schedule window).
- **Failure trace A (leaf without the certificate checksum):**
  1. A griefing watcher challenges an **honest** operator (paying `F_assert = 1.45`).
  2. The operator posts a correct `AssertCertDATx`.
  3. The watcher takes the operator's revealed signature for one digit of `block_j` and hashes it forward once, which produces a valid signature for digit `+1`.
  4. It spends `DisproveTx` through `L3B_j` with the forged block. The leaf computes `compress(midstate_j, block'_j) ≠ midstate_{j+1}` ⇒ **the disprove succeeds.**
  5. Result:
     - the honest operator loses its 3.70 BTC bond (1.65 BTC burned, 2.05 BTC to the watcher);
     - Conn_C is consumed, so **Take2 is dead** and the 1 BTC reimbursement is lost;
     - the watcher nets about `+0.115` BTC at 500 sat/vB and about `+0.60` BTC at 1 sat/vB.

     That is profitable, repeatable theft from honest operators.
- **Failure trace B (leaf with the checksum):** the leaf cannot execute (stack exceeds 1,000 elements). No valid DA disprove exists, so an operator may publish DA bytes that do not hash to `certSetDigest`. Forged certificates then never become extractable, and R5-H1 / R4-H3(a) reopen.
- **Why this blocks, and is not G-2:** the WOTS *message granularity* is a design choice, fixed in the spec. G-2 measures weights; it cannot make a 958-digit leaf fit, or make a checksum-less leaf sound.
- **Minimal fix:**
  - Commit the DA as **7 independent WOTS messages, one per SHA-256 block**, each with its own checksum:
    - 6 × (128 + 3) digits for the full blocks;
    - 1 × (48 + 3) digits for the last block's 24 data bytes, with the padding hardcoded;
    - plus the 6 midstates.
  - That is **1,239 digits**, 13 more than now (about +311 vB, still ≤ 30 kvB at HASH160).
  - `L3B_j` then verifies exactly `block_j`, `midstate_j` and `midstate_{j+1}` (with `midstate_7` = the `W_certda` field), each with its own checksum. That is 131 + 67 + 67 digits, which fits.
  - Restate the slashing extractor as "reassemble the certificates from the 7 blocks".
  - **MUST-fail vector:** "disprove using a forward-hashed digit of an honest block ⇒ rejected".

---

### 2.2 MEDIUM

| ID | Title | Spec | Failure trace | Minimal fix |
|---|---|---|---|---|
| **R6-M1** | **The certificate set has variable length (1 or 2 certificates), but Leaf 3B is hardcoded for 408 bytes and 7 blocks.** An honest operator whose target falls in the first 30 days can be disproved. | `spec/01:28` ("at most … 2"), `spec/01:29,31` (7 blocks fixed), `spec/01:34` (`SHA256(targetCert ‖ handoffCert)`), `SPEC.md:90` ("`<= 2` certs"), `script:236-244` | A chain anchored at E pays out during days 0–30: the target is in epoch E and no handoff exists. `SHA256(targetCert)` covers 204 B, which is **4** blocks (12 data bytes in the last block, `len = 1632` bits). `L3B_0..6` hardcode 7 blocks and the 3264-bit length block. If the circuit hashes only the target, no midstate sequence can satisfy the leaves, and a watcher disproves the **honest** operator through `L3B_3..6`. The spec never defines what fills the "handoff" slot, nor which slot a `CarryOver` occupies. | Define a **fixed 408-byte encoding**: `targetCert ‖ (handoffCert or 204 zero bytes)`. The circuit hashes exactly those 408 bytes; a zero slot means "no handoff". Add the vector "chain with no handoff ⇒ honest assert is not disprovable". Have the oracle model both cases (S6-3). |
| **R6-M2** | **Reachability is checked at `now`, but reimbursement cannot start before about `now + 2.5–2.8 d`. Rounds are not reserved. `RELEASED` vaults cannot be re-graphed.** Honest fronting operators can be stranded (residual of R5-H3 trace B). | `spec/03:134,144,147`, `SPEC.md:69-71` (`ReachableRounds(e, now) >= 1`); `spec/02:152`, `spec/03:132` (`0x0D` only for `ACTIVE`/`QUARANTINED`); `spec/01:61` (rotation list excludes `RELEASED`); `SPEC.md:61` (48 h + 12 h finalization) | (a) Operator `m` is in `d`'s gen-`g` bitmask but not in its gen-`g+1` bitmask (it failed or skipped the g+1 Phase 1). At day 44.5 it passes `ClaimFrontingSlot` (`ReachableRounds(g, 44.5) ≥ 1`) and fronts. `RELEASED` is finalized at ≥ day 46.5 (K, then a 48–60 h batch). `ClaimReimbursementSlot`: `g` gives `max(now, ·) > 46` and is rejected; `g+1` has no bit set and is rejected ⇒ **1 BTC lost**. (b) The same operator can hold *k* slots, each checked against the **same** single reachable round. (c) Suppose `d` was released on the domain before its `0x0D` landed (day 38–44). `0x0D` then rejects (`RELEASED ∉ {ACTIVE, QUARANTINED}`), so `d` can never gain a g+1 graph, and its reimbursement dies at cutoff(g). | Evaluate `ReachableRounds(e, now + T_release)`, with `T_release = 4 h + K·600 s + 60 h + margin`, in `RequestPegOut` and `ClaimFrontingSlot`. **Reserve** a round per held slot (`pendingReservations` per lane), released when the slot expires or the round is claimed. Allow `0x0D` and `SyncVaultGraphEpoch` for `RELEASED` vaults whose `PegOutRecord.ReimbursementRoundId == 0`. |
| **R6-M3** | **A legitimate `BTC_RELEASE_PROOF` is *rejected* when the assigned vault has since been trapped by another operator's substitution.** The user is paid twice and the honest fronter loses `D_bucket`. This is the R5-M3(ii) residual: overwriting became rejecting, but there is still no re-pointing. | `spec/02:142` (`REQUIRES tv.status == ACTIVE`), `spec/03:135-138`, `spec/03:144` (`ClaimFrontingSlot` never checks vault status), `SPEC.md:75` | Peg-out `P` is assigned to `d`, and A legitimately fronts. Before A's proof reaches K, B (any operator) runs a substituting `Take1` on `d`. `0x08` sets `d` to `PENDING_TRAP`, and later to `RECOVERED`. A's `0x06` is now **rejected**. `P` times out, and `MINTED_REFUND_V1` refunds `D_bucket` in zBTC. **The user receives both A's BTC and the zBTC; A loses 1 BTC with no recourse.** Separately: (i) the `SyncPendingTrapVault` mirror still lags by K plus 48 h, so `d` can be assigned to a new `P2` during that window; (ii) `ClaimFrontingSlot` accepts slots on `PENDING_TRAP` vaults. A griefer who is also `P`'s user pays about 2.70 BTC plus the ZNN bond for 1 BTC, so this is not profitable. The honest-fronter loss, however, follows from *any* substitution. | Decouple *proof of payment* from *vault status*. `BTC_RELEASE_PROOF` must always admit a valid fronting for an unresolved `outboxId`. If the vault is `PENDING_TRAP` or `RECOVERED`, re-point `PegOutRecord.assignedVaultOutpoint` to the recovery outpoint once it has been re-graphed (R5's recommendation), or to the next `UNASSIGNED` vault. `ClaimFrontingSlot` and `RequestPegOut` must require the Settlement status `ASSIGNED`/`UNASSIGNED` respectively. |
| **R6-M4** | **The fronting slot expires on different terms in Settlement and in the domain.** Settlement can grant a slot that the domain ignores (residual of R5-M4). | `spec/03:144` (Settlement expiry is Zenon time only: `now < claimTs + 14,400`); `spec/02:138` (the domain ignores a new claim while `BestTip < H+24` **or** `ts < T+4h`); `spec/02:142` (exclusivity against the *domain's* `SlotOperatorId`); `SPEC.md:70` | A claims at `T`. At `T + 4 h + ε`, fewer than 24 Bitcoin blocks have arrived (probability ≈ 0.5). B calls `ClaimFrontingSlot`: **Settlement accepts it** and records B, while the domain ignores the `0x0A` (`stepError = 2`) and keeps A. B, trusting Settlement, fronts at `h < H + 24`. The domain's exclusivity check (`operatorId == A`) rejects B's release proof ⇒ **the honest B loses 1 BTC.** Conversely, if A's release is accepted, it is unspecified whether `MINTED_RELEASE_V1` checks the slot holder that Settlement recorded (B). If it does, the peg-out wedges with `ResolutionSeen` set, so it can be neither released nor refunded. | Make the domain the single authority. Settlement's `ClaimFrontingSlot` only appends the `0x0A`, and the winner is whatever the domain admits, exposed through a synced flag. Alternatively, Settlement also requires `lastFinalizedTipHeight ≥ SlotExpiryBtcHeight`. State explicitly that `MINTED_RELEASE_V1` keys on the domain's `operatorId`. |
| **R6-M5** | **Slot claims cost nothing and are unlimited.** A single malicious eligible operator can censor any peg-out until its timeout. | `spec/03:144`, `spec/02:138`, `SPEC.md:70` | The slot lasts 4 h / 24 blocks, with no bond and no penalty for letting it lapse, and the previous holder may re-claim. A malicious operator re-claims every `outboxId` at each expiry; it controls its submission timing and floods the momentum at the expiry. Peg-outs run to `timeoutHeight + 558`, then refund. The user retries and the operator repeats. **1 of M operators breaks peg-out liveness** (users keep zBTC, but cannot exit to BTC). | Bar the previous holder from re-claiming the same `outboxId`. Add a small `SlotBondZnn` that is forfeited when the slot lapses unfulfilled. Optionally rotate priority deterministically, e.g. `H(outboxId ‖ epoch) mod eligibleSet`. |

### 2.3 LOW / ERRATA

| ID | Erratum | Location | Correction |
|---|---|---|---|
| **R6-L1** | **The WOTS hash is inconsistent between prose and cost model.** <br>• The prose specifies `OP_SHA256` chains (32 B); the oracle prices `OP_HASH160` (20 B pubkey and preimage). <br>• With 32 B: `119.5 WU/digit` ⇒ **36,927 vB**, so `assert ≤ 30,000` fails and the re-derived `F_assert` becomes `1.50`. <br>• At the current 1.45, `HonestOp(500) = +0.16`, so the system stays solvent, but the "+39 kvB headroom" figure is wrong. <br>• "WOTS+" is also a misnomer: bitmasks cannot be implemented in Script. | `spec/01:26` vs `spec/01:30`; `script:85-90` | Pick HASH160, as BitVM does, and say so; or re-derive at 32 B. Rename to "W-OTS (BitVM, no bitmasks)". |
| **R6-L2** | **The `0x0D` handler under-specifies epoch-set updates:** <br>• no rejection of a **duplicate `epochId`**, which would overwrite a live root (`spec/01:61` forbids this, `spec/02:152` does not enforce it); <br>• no rejection of a **third** epoch while two are unexpired (the 78 B layout holds 2); <br>• no defined source for `T_bond_expiry(e')` when pruning; <br>• no stated mapping `roundChainEpochId ≡ E_anchor`. | `spec/02:152,168`; `spec/01:52,59` | Reject if the `epochId` is present or if two unexpired epochs exist. Define `roundChainEpochId := E_anchor` and `expiry(e) = finalityEpochStartTs(e) + 58 d`. |
| **R6-L3** | **The `unrotatedVaultCount` lifecycle is unspecified.** <br>• No decrement on `QUARANTINED → UNASSIGNED` (`SyncVaultGraphEpoch`) ⇒ **the mint pause becomes permanent**; or, if recovered vaults are not counted, it underflows. <br>• `QuarantineExpiredVault` covers only `UNASSIGNED`. An `ASSIGNED` vault that missed rotation neither pauses mints nor is quarantined until its peg-out refunds. | `spec/03:39,131-133`; `spec/01:62` | Specify the increment and decrement for every transition into or out of `QUARANTINED`. Extend `QuarantineExpiredVault` to `ASSIGNED`, re-checking after the refund. |
| **R6-L4** | **The rotation deadline is shorter than finalization latency.** <br>• A `0x0D` submitted at day 44 (the normative deadline) reaches Settlement at ≥ day 46–46.5, after a 48–60 h batch. <br>• At day 46, anyone may `QuarantineExpiredVault` a correctly rotated vault ⇒ a griefable, transient mint pause and quarantine. <br>• Nothing requires new deposits made after g+1 registration to be graphed into g+1. | `spec/01:61-62`; `SPEC.md:61,74`; `spec/03:133` | Make day 43 the deadline, or have `QuarantineExpiredVault` require `now ≥ cutoff + 60 h`. Mandate that deposits after day 38 carry a g+1 graph. |
| **R6-L5** | **Absence proofs may be impossible to construct, and the halt has a narrow scope.** <br>• The sorted Take-txid leaf set has no DA requirement, since only roots go on-chain. A withheld transcript makes Branch B (raw-sweep halt) unprovable. <br>• `0x08` requires `tv.status == ACTIVE`, so a raw sweep of a `RELEASED` vault (awaiting reimbursement) or a `QUARANTINED` recovery vault never halts. | `spec/02:144-148`; `SPEC.md:59`; `spec/01:70` | Publish the leaf set (Zenon calldata or a DA hash in `0x05`/`0x0D`). Apply the inclusion/absence rule to `RELEASED` (allowed: the registered Take of the `ReimbursementOperator`) and to `QUARANTINED` (no valid spends ⇒ any spend halts). |
| **R6-L6** | **Round expiry is not bound to the finality-epoch start.** <br>• `RegisterOperatorRound` and `0x0B` check only `anchorExpiryTs ≤ now + 58 d` and `cutoff == expiry − 12 d`, not `anchorExpiryTs == finalityEpochStartTs(epoch) + 58 d`. <br>• The 2-certificate bound (`spec/01:28`), Leaf 3B's fixed 7 blocks and the rotation calendar all rest on that alignment, which is guaranteed only by Setup Committee diligence. | `spec/03:145`; `spec/02:139`; `spec/01:28,54` | Enforce equality in both registries. |
| **R6-L7** | **Several BLS and circuit details are unspecified:** <br>• the PoP domain-separation tag (it must differ from the signing DST, per the IETF BLS `POP` scheme); <br>• the hash and tree for `FinalityCommitteeRoot(E)` that the circuit must recompute; <br>• where the 2–4 BLS12-381 pairings, the G2 aggregation of up to 30 keys and the hash-to-G1 run (in the inner STARK, since emulating them in BN254 R1CS alone would roughly consume the whole "~3.5M" outer budget); <br>• a prover-time bound against the 288-block `AssertStart` deadline. <br>Also, the Case-A `cert.ChainId` comparison is vacuous: the 204 B certificate has no `chainId` field. | `spec/04:63-65,82`; `spec/01:35`; `spec/01:7` | Specify these and add them to the G-2 targets. Drop `chainId` from Case A, or note that it is implicit through the signing digest. |
| **R6-L8** | **`ClaimReimbursementSlot` can be used only once, and the tolerance to slow blocks is undisclosed.** <br>• If the claimed round is lost without fault (fee ceiling breached, or `T_kill` reached because blocks are slow), there is no re-claim, so `D_bucket` is stranded and the vault stays `RELEASED` forever. <br>• The "Take2 by ≤ day 51.0" guarantee holds only for an average block interval ≤ 1.476 × 10 min (and retirement only for ≤ 1.59×). | `spec/03:147`; `spec/01:55` | Allow a Governance-gated (or deterministic) re-claim once `BurnBond`/`Kill` of the claimed round is proven. Document the block-rate tolerance as an impairment trigger. |
| **R6-L9** | **Remaining overclaims and numeric errata:** <br>• "slashing forged handoffs to stakeless keys", "every in-scope signer slashable" (false under R6-H1); <br>• `C = 1,207` omits the L3A binding disprove leaf (it should be 1,208); <br>• the "20–28-day" overlap is really ≈ 8/13.5–28 d (the peak of 74 BTC still holds); <br>• the periodic **G-21 mint stall** goes undisclosed. At supply ≥ 14 BTC, `Σ ReachableRounds` falls to 30 (< 40) after day 29.6, until g+1 registers (day 30–38), i.e. up to 8.4 d of every 30 d. | `SPEC.md:37,91,134`; `spec/04:41`; `spec/01:31,60,65` | Restate as conditional, correct the numbers, and disclose the stall (or register g+1 so that its capacity counts from day 30). |

---

## 3. Disposition of Round-5 Findings

Legend: **CLOSED** · **PARTIALLY CLOSED** · **STILL OPEN**.

### 3.1 HIGH

| ID | Status | Evidence / residual |
|---|---|---|
| **R5-H1** | **PARTIALLY CLOSED** | **Cost model: CLOSED.** <br>• 204 B fixed certificate (fields re-derived); ≤ 2 certificates because `58 < 60` and `E_anchor_ts` is aligned (`spec/01:28`); `408 + 9 ⇒ 7` blocks / 6 midstates (padding verified: last block holds 24 B, `len = 3264`). <br>• 1,226 digits (checksum widths 4/3 verified); 492 digits per input ⇒ 3 inputs, each aligned to a field boundary (412 / 412 / 402); 29,571 vB; one `AssertCertDATx` well under 400 kWU. <br>• `AssertStart` (3 + 32 outputs) → `AssertCertDA` → `AssertEnd` (`In 0..32`), plus a 72-block timeout `BurnBondCertDA`: wiring verified (`spec/01:88`). <br>• `F_assert`, `Bond` and the burns re-derived exactly. <br>**Leaf 3B: specified but unsound or infeasible → R6-H2.** <br>Residuals: R6-M1 (variable length), R6-L1 (hash-size mismatch), and G-2 (script size and peak stack of SHA-256 without `OP_CAT`, ≤ 380 kWU assumed). |
| **R5-H2** | **PARTIALLY CLOSED** | Case A now compares all 8 fields, and `canonicalNextCommitteeRoot(h)` is defined at every height (`spec/04:70-71,82`). That catches the R5-H2 trace exactly *at* `h_trans`. **Bypass:** the pin cannot be enforced in the circuit, and the precondition binds the signature to the canonical committee at `cert.Height`. A forged handoff or carry-over at any other height of epoch E+1 is unprovable → **R6-H1 (blocking)**. |
| **R5-H3** | **PARTIALLY CLOSED** (blocking part closed) | **Trace A (halt regression): CLOSED.** Per-epoch `activeEpochs ≤ 2` plus inclusion-or-absence across epochs; a g+1 Take ⇒ `PENDING_TRAP` (vector 25). <br>**Trace C (deadline semantics): CLOSED.** A normative schedule (registration by day 38, re-graph by day 44, cutoff at day 46), `QuarantineExpiredVault`, and a mint pause. <br>**At most 2 concurrent generations: verified.** g+2's anchor (day 60) is after g's expiry (day 58); pruning happens on add. <br>**Trace B (eligibility): residual → R6-M2** (checks at `now`, no reservation, `RELEASED` excluded from `0x0D`). Hygiene: R6-L2, L3, L4. |

### 3.2 MEDIUM / LOW

| ID | Status | Note |
|---|---|---|
| R5-M1 | **CLOSED** | Branch A (inclusion in any live epoch ⇒ `PENDING_TRAP`), Branch B (absence in *every* live epoch ⇒ halt), Branch C (anything else ⇒ reject). A submitter cannot force a halt by omitting the inclusion proof, and cannot hide a raw sweep (it has no inclusion proof). With 2 live epochs, the absence proof must cover both. I checked grinding: the payload cap of ~14 KB allows ≈ 220 siblings per proof, so grinding a ~40-bit prefix fits easily. Residual: leaf-set DA and status scope (R6-L5). |
| R5-M2 | **CLOSED** | (a) `0x10` → `LaneRetired` → `SyncRetiredLane` zeroes the lane (sync lag ≈ K + 48 h, acceptable). (b) Serial `ReachableRounds` (re-verified: t = 0/30/40 ⇒ 8/3/2). (c) `max(now, nextEligible) ≤ cutoff`, plus `idx == nextUnusedIdx`, plus `RoundUsed`: last kickoff ≤ 46 ⇒ Take2 ≤ 51.0 < 56, retirement from 51.5 < 58. The "16 ≥ 15" claim is now conditional on `t ≤ 7.5 d` (verified). Timing residual on the fronting and reimbursement path → R6-M2. |
| R5-M3 | **PARTIALLY CLOSED** | (iii) CLOSED (refund never overwrites `PENDING_TRAP`/`RECOVERED`). (iv) CLOSED (`RecoveredVaultMap.(opId, roundId)` equals the PegOutRecord's reimbursement pair; deterministic). (i) Mirroring exists, but the 48 h lag remains. (ii) Overwriting became **rejecting**, which strands honest fronters → **R6-M3**. |
| R5-M4 | **PARTIALLY CLOSED** | Within each store, a slot can no longer be overwritten while live. The two stores disagree on expiry → **R6-M4**. New: zero-cost re-claim censorship → **R6-M5**. |
| R5-L1 | **CLOSED** | `E_anchor_ts = finalityEpochStartTs(E_anchor)`; the 204 B certificate is fixed for 30 of 30 signers. Residuals: R6-M1, R6-L6. |
| R5-L2 | **CLOSED** | `anchorHeader` removed from the SNARK (`spec/01:34`, `spec/04:41`). |
| R5-L3 | **CLOSED** | `T_kill = 56 d` (Conn_B L4, Conn_C L4) and `T_bond = 58 d` (BondOut L5, GenesisBond L3). Any Take confirms by day 56, so its escrow trap closes by day 56.5 < 58. A fraudulent kickoff after day ≈ 54 cannot reach `AssertStart` before the kill. |
| R5-L4 | **CLOSED** | Fee UTXO L2 `<T_bond_expiry> CLTV <pk_m>` (`spec/01:81`). |
| R5-L5 | **CLOSED** | Assumption #4 (1-of-N Setup Committee) added, with a blast-radius row (`SPEC.md:95`, `spec/01:45`). |
| R5-L6 | **CLOSED** | `A-PILLAR-1` is in §6. Its interaction with the phase is specified: immediate withdrawal after `ExitCommitteeRequested` and 72 d. Verified against `pillars.go:132-138,395-412` (the baseline has an immediate refund, so the lock must override it, and it does). |
| R5-L7 | **PARTIALLY CLOSED** | The 5 listed overclaims are qualified ("when challenged", `t ≤ 7.5 d`, "prior to `T_kickoff_cutoff`", Kill-fee note). New overclaims follow from R6-H1 → R6-L9. |
| R5-L8 | **CLOSED** | `Q_graph` signs the release transcript, and the Setup Committee verifies it and attests a canonical sorted SMT of exactly the released Takes. Residual: leaf-set DA (R6-L5). |
| R5-L9 | **CLOSED** | `epoch < 4096` is enforced in `0x05`, `0x0B`, `0x0D` and `RegisterOperatorRound`; `cutoff == expiry − 12 d`; `OperatorBondRecord` is 52 B with the cutoff. Residual: expiry is not bound to the epoch start (R6-L6). |

**Round-5 tally (16):** 10 CLOSED · 6 PARTIALLY CLOSED · 0 STILL OPEN.

### 3.3 Script Items (S5-1..S5-6)

| ID | Status | Note |
|---|---|---|
| S5-1 | **CLOSED** | DA is derived from digits × (Script + witness), the stack-limit inputs and the midstates (`script:248-264`). Residual: the hash-size mismatch (S6-1) and the Leaf-3B stack (S6-2). |
| S5-2 | **CLOSED** | Comments now match the values (2.05 / 1.85 / 2.70 / 1.00, 37.0 / 74.0, 1.46 / 14.60); the status enum includes `QUARANTINED`. |
| S5-3 | **CLOSED** | Integer satoshis throughout §4B. Note: `min_bond_sats == 370,000,000` lands *exactly* on the 0.10 step, because the `11,500,000` margin was chosen to land there. It is deterministic now, but has zero slack. |
| S5-4 | **PARTIALLY CLOSED** | `reachable_rounds()` models serial reachability, retirement and the cutoff. Still tautological: `MAX_CONCURRENT_GENS = ceil(58/30)` (`script:405`) and the equality `(58−56)·144 ≥ 288` (`script:376`). Not modeled: release latency, slot reservation, the G-21 time series → S6-4. |
| S5-5 | **CLOSED** | Certificate count from `58 // 30`; size from fields. Residual: the 1-certificate case (S6-3). |
| S5-6 | **STILL OPEN** (non-blocking) | `L = 32` and the constraint count are still unchecked; `C` is printed but omits L3A (S6-6). Acceptable until G-2. |

---

## 4. Verified-Sound Mechanisms (new in v2.4; do not re-litigate)

- **SHA-256 chaining for Leaf 3B, as arithmetic.** `midstate_0 = IV`, `midstate_7 = W_certda` = the digest (no finalization step after the last compression). Block 6 hardcodes the padding (`0x80 ‖ 0³¹ ‖ u64BE(3264)`). Binding holds, by collision resistance, between the DA bytes, `certSetDigest`, the SNARK public input and the targets the SNARK verified. *(The WOTS granularity is the defect, R6-H2; the hash chaining is not.)*
- **Fixed-size BLS12-381 `min-sig` certificates.** G1 signature (48 B), G2 public keys (96 B), a G1 PoP (48 B), and a 32-bit bitfield for 30 signers.
- **Single-transaction `AssertCertDATx`.** The 3 inputs align to WOTS fields, it is ≈ 118 kWU (< 400 kWU), and it is part of the joint `F_assert` budget.
- **Exact economics and every slashing value balance** (§1). `HonestOp > 0` at all fee levels ≤ 500 sat/vB (break-even 577 sat/vB). The fraud-versus-watcher range `−2.25..−3.70` and the self-slash range `−0.20..−2.70` were recomputed.
- **Staggered CLTV ordering.** The trap closes before the bond burn. A stale or late fraudulent kickoff cannot reach `Take2`.
- **Generation overlap ≤ 2** and the add-and-prune semantics of `activeEpochs`.
- **Halting decided by the verifier in `0x08`** (R5-M1).
- **Lane retirement sync and serial reachability** (R5-M2).
- **Deterministic `SyncOrphanedVaultOutpoint`** through `RecoveredVaultMap`.
- **`A-PILLAR-1` lock arithmetic.**
  - An epoch-E signer stays locked until `end(E) + 72 d`: day 102 for a chain anchored at E.
  - DA evidence arrives by about day 59.5 and Case-A submission is possible immediately. The margin is ≥ 40 d *once the predicate is fixed* (R6-H1).
- **Oracle numerics (recomputed):**
  - structs 238 / 160 / 68 / 186 / 175 / 78 / 52 / 44 / 328;
  - depth-256 upload 8,676 B;
  - fast paths ≤ 10,212 B;
  - Continuity 1,700 B;
  - Poisson 353 / 472;
  - `K` 12 / 13 / 26 / 13;
  - timeouts 640 / 2,512;
  - grace 558;
  - `pendingTrapWindow` 230;
  - 29,571 vB;
  - `F_assert` 1.45;
  - bond 3.70;
  - break-even 289.0 kvB;
  - watcher capital 1.46 / 14.60;
  - minimum bond 31,500 ZNN;
  - cap `157,500 ≤ 157,500`.

---

## 5. Go / No-Go Gate Checklist (Round 6)

**Status: NO-GO (design) — HOLD.** Gates marked ⚙ do not block design sign-off.

| Gate | Status | Blocking items |
|---|---|---|
| G-1 (graph causality and enforceability) | ◐ PARTIAL | R6-M3, R6-L5; ⚙ Signet build and 1p1c relay |
| G-2 (measured weights) | ⚙ GATE, **plus a blocking design correction** | R6-H2 (WOTS granularity is not a measurement question); ⚙ SHA-256 chunk script size and peak stack |
| G-3 (finality proof) | ❌ OPEN | **R6-H1** |
| G-4..G-6, G-8, G-10, G-14, G-16 | ✅ CLOSED | |
| G-7 (fronting and fees) | ◐ PARTIAL | R6-M4, R6-M5 |
| G-9 | ✅ design / ⚙ fuzzer | |
| G-11 | ✅ design / ⚙ test | |
| G-12 | ✅ CLOSED | (R6-L5 hygiene) |
| G-13 (timeouts, eligibility, halt) | ◐ PARTIAL | R6-M2, R6-M3 |
| G-15 (epoch committee) | ◐ PARTIAL | R6-H1, R6-L7 |
| G-17 (upstream) | ⚙ ESCALATED | §6 now includes `A-PILLAR-1` |
| G-18 | ✅ design / ⚙ tests | |
| G-19 (numbers from scripts) | ◐ PARTIAL | S6-1..S6-4 |
| G-21 (capacity ≥ supply) | ◐ PARTIAL | R6-M2, R6-L3, R6-L9 (mint stall) |
| G-22 (round-chain lifecycle) | ✅ design (Bitcoin side and rotation) | R6-L2, R6-L4 hygiene |
| G-23 (certificate DA for slashing) | ❌ OPEN | **R6-H1, R6-H2**, R6-M1 |
| G-20 (independent re-review) | ✅ this document; **Round 7 required** | |

---

## 6. Audit of `scripts/verify_spec_bounds.py`

The script ran cleanly (`python3 -I`, exit 0). Independently recomputed: every value in §4, plus:
- the padding and block count for 204 B and 408 B;
- checksum widths for 408 / 128 / 64 / 48 nibbles;
- the digit total;
- the transaction overhead;
- `ceil(118,283 / 4) = 29,571`;
- `F_assert` and the bond chain in integer satoshis;
- watcher and operator P&L at 1 / 50 / 200 / 500 sat/vB;
- the reachability vectors.

### 6.1 New Script Defects

| # | Defect | Location | Effect |
|---|---|---|---|
| S6-1 | The WOTS cost function hardcodes a 20 B (HASH160) pubkey and preimage, while the prose says `OP_SHA256`. At 32 B, the derived figure is 36,927 vB and `assert ≤ 30_000` fails. | `script:85-90` vs `spec/01:26` | Hides R6-L1 |
| S6-2 | The stack limit is checked only for `AssertCertDATx` inputs, not for the Leaf-3B disprove leaves. By the script's own model (492 digits), a leaf needs 546–958 digits. | `script:255-258` | Hides R6-H2 |
| S6-3 | The certificate set is fixed at 408 B. The 1-certificate case (204 B ⇒ 4 blocks, `len = 1632`) is not modeled. | `script:236-244` | Hides R6-M1 |
| S6-4 | (S5-4 residual) No release-latency offset, no slot reservation, no G-21 time series (the stall from day 29.6). `MAX_CONCURRENT_GENS` and the 288-block gap remain constant tautologies. | `script:376,380-389,405` | Hides R6-M2 and R6-L9 |
| S6-5 | The fast-path key lists omit keys that are inserted: <br>• `0x0C`: the new `TrackedVault`, `RecoveredVaultMap`, `OperatorSlashed` ⇒ 8,388 → **11,172 B**; <br>• `0x0D`: `RegraphedVaultEpoch`, `OperatorBondRecord` ⇒ 3,204 → 5,124 B; <br>• `0x10`: `LaneRetired` ⇒ 7,364 → 8,292 B. <br>The `0x0D` payload encodes `epochId` as 4 B, against u16 elsewhere. | `script:165-173,210` | All still ≤ 12 KiB, but the printed figures are understated |
| S6-6 | (S5-6 carry-over) `L` and the constraint count are unchecked. `C = 1,200 + 7` omits the L3A binding leaf (it should be 1,208). | `script:246` | Non-blocking until G-2 |

### 6.2 Reproduction (`r6_check.py`, abridged)

```python
cd=lambda a,b:(a+b-1)//b
print(cd(408+9,64), cd(204+9,64))                     # 7 blocks (408 B) ; 4 blocks (204 B)  -> R6-M1
wu=lambda h:(2.5*15+35+(h-20))+(23+(h-20))
for h in (20,32): print(h, cd(int(1226*wu(h)+1200),4))   # 29,571 vB ; 36,927 vB          -> R6-L1/S6-1
cert,mid=408+4,64+3
for j in range(7):                                       # Leaf-3B digits incl. checksums
    a,b=64*j,min(64*j+64,408); n=len({0 if x<204 else 1 for x in range(a,b)})
    print(j, n*cert+2*mid)                               # 546 x6, 958 at j=3  (> 492 cap)  -> R6-H2
print(6*(128+3)+(48+3)+6*67)                             # 1,239 digits with the per-block fix (+311 vB)
for t in (29.5,29.6,30,38): print(t, 10*min(8,int((46-t)//5.5)+1))  # 40,30,30,20 -> mint stall (R6-L9)
print(15.5/10.5, 17.5/11)                                # 1.476x / 1.59x block-time tolerance (R6-L8)
```

```text
spec/04:80   SubmitInvalidCertProof precondition: sig valid "under canonicalSigningCommitteeRoot(cert.Height)"
             -> a committee-E signature at any epoch-(E+1) height fails the precondition (R6-H1)
spec/04:72   "ONLY at h = h_trans(E+1) ... next == Root(E+1)": circuit has no oracle for h_trans or Root(E+1)
spec/01:29   "824 w=4 nibbles incl. per-cert checksums" vs spec/01:31 single-block L3B_j (R6-H2)
spec/02:142  BTC_RELEASE_PROOF "REQUIRES tv.status == ACTIVE" -> honest fronter stranded (R6-M3)
spec/03:144  vs spec/02:138  Settlement expiry = Zenon time only; domain = height AND time (R6-M4)
```

---

## 7. Required Actions Before Round 7 (Priority Order)

1. **R6-H1, the slashing predicate:**
   - verify the signature under `cert.FinalityCommitteeRoot` (which must be a historical Tag-15 root), then apply the full Case A;
   - delete `CarryOverCertificate`, or make it slashable everywhere except a recorded no-snapshot event;
   - restate the "pin" as economic, not enforced in the circuit;
   - add the two MUST-fail vectors (handoff at `h_trans+1`; target after a carry-over).
2. **R6-H2, Leaf 3B:**
   - commit the DA as 7 per-block W-OTS messages, each with its own checksum (1,239 digits);
   - have `L3B_j` verify exactly `block_j + midstate_j + midstate_{j+1}`;
   - re-derive the DA weight;
   - add the MUST-fail vector for forward-hashed digits;
   - extend the oracle's stack check to the disprove leaves.
3. **R6-M1..M5:**
   - a fixed 408 B encoding with a zero handoff slot;
   - reachability evaluated at `now + T_release`, with reservations and re-graphing of `RELEASED` vaults;
   - admitting a release proof regardless of vault status, with re-pointing;
   - a single authority for slot expiry;
   - anti-censorship rules for slot re-claims.
4. R6-L1..L9 and S6-1..S6-6.

**Not blocking design sign-off (correctly gated in `SPEC.md §6–§7`):**
- G-1 Signet and 1p1c relay;
- G-2 *measured* weights (SHA-256 chunk ≤ 380 kWU, peak stack ≤ 1,000, outer constraints);
- G-9 fuzzer;
- G-11 `IssueMinted` test;
- G-18 swap suite;
- the Groth16 CRS ceremony (`K ≥ 50`);
- ratification of A-SPEC-1..6, A-BTC-1, A-MINT-1 and `A-PILLAR-1`.
