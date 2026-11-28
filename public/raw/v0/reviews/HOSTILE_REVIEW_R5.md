# Hostile Peer Review — Round 5 — zBTC Bitcoin↔Zenon Interoperability Specification `v2.3.0-draft`

**Reviewer posture:** adversarial, first-principles. Same rules as Rounds 1–4. I did not trust the spec's own summaries or the change log in the review request. I re-derived each claim from:
- Bitcoin consensus and policy (BIP-65/68/112/341/342, the 1,000-element stack limit, the 400 kWU standard transaction weight);
- the public BitVM Winternitz verifier construction;
- `go-zenon` source at the declared baselines;
- my own recomputation of every oracle number used below.

**Review date:** 2026-11-24
**Baseline:** `HOSTILE_REVIEW_R4.md` (Round 4: 0 C · 3 H · 7 M · 12 L · script defects S4-1..S4-7).
**Mandate:**
- Do not re-litigate the Round-2/3/4 §4 verified-sound mechanisms unless v2.3 broke them.
- Attack every new v2.3 mechanism.
- Give a disposition for every Round-4 item.
- Separate **blocking design-spec defects** from **non-blocking execution or upstream gates**.

**Artifacts under review (SHA-256, first and last 8 hex digits):**

| File | SHA-256 |
|---|---|
| `SPEC.md` | `43caacc5…54c35e83` |
| `spec/01` | `3c647966…e06802e6` |
| `spec/02` | `66cf540b…a48f185b` |
| `spec/03` | `5ac5f5c1…e70783cb` |
| `spec/04` | `f69ac8dc…1d3d20ce` |
| `spec/05` | `c5137745…104cffbd` |
| `scripts/verify_spec_bounds.py` | `622060a5…5a2ff16d` |

**Ground truth:**
- `go-zenon`: `origin/release/0.0.11-rc1` `f19955f`, `origin/dev` `770e893`, `master` `e8986a6` (all resolved locally). A `dev:` prefix means `git show origin/dev:<path>`.
- `zenon-developer-commons`: `HEAD` `3719452`.

**Citation convention:** `spec/0N:L`, `SPEC.md:L`, `script:L` (= `scripts/verify_spec_bounds.py`).

---

## 1. Executive Verdict

### **HOLD — Design Spec (0 CRITICAL, 3 blocking HIGH)**

v2.3 closes most of the Bitcoin-side defects from Round 4. I re-derived each of the following and found it sound:
- **Bitcoin-side round-chain closure:**
  - `RoundRetireTx` on `GenesisBond` L2 and `BondOut` L4. Value balance: `4.20 − 4.199 − 0.0000033 = 99,670` sats of fee.
  - `OP_CLTV` `StaleChainBurnTx` / `StaleConn{B,C}KillTx` at `T_anchor_expiry`.
  - `R = 8`: the last kickoff is at day 38.5, retirement at 44 ≤ 48, and the window between cutoff and expiry is `[53.5, 58)` = 648 blocks.
- **Trap variants:** both `WrongDepositDisproveTx^{T1,T2}`, the normative Phase-1-before-Phase-2 ceremony, and independent per-field WOTS checksums.
- **Assumption-1 hardening:**
  - the `72`-day post-committee-service stake lock, which is the correct construction against the per-Pillar `% 90d` phase (`dev:pillars.go:132-138,395-412`, verified);
  - deletion of the `recentBtcBlockHash` claim;
  - `SubmitInvalidCertProof` scoped to dual-supermajority certificates.
- **Zenon-side fixes:**
  - `CommitteeIdentityKey`-authenticated round registration, with the Governance-only binding writer split out;
  - globally unique `roundId` plus `RoundUsed`;
  - `QUARANTINED` recovered vaults;
  - fronting-slot expiry computed in the domain;
  - joint fee budgets;
  - an honest restatement of watcher economics against a self-slashing fraudster.

The oracle runs clean (exit 0), and every number it prints that I recomputed matches.

**What still blocks design sign-off: three HIGH findings.** Two are in the mechanisms that close R4-H3, and the third is a lifecycle gap that v2.3 opened by deleting the v2.2 rotation rule.

1. **R5-H1 — The certificate data availability in G-23 is under-costed about 10–35×, and its disprove leaf is unspecified.**
   - The 66 kvB `AssertCertDATx` figure is `9 × 1,460 B × 20 B / 4`. It counts the WOTS *preimages* and leaves out the *verifier Script*, which dominates.
   - With the BitVM unrolled-chain verifier (≈ `2.5·(2^w−1) + 35` B of Script per digit), I get:
     - **≈ 2,285 kvB at the specified `w = 8`**;
     - ≈ 627 kvB at `w = 4`.
   - Fed through the oracle's own formulas at `w = 4`, that gives `F_assert ≈ 4.90 BTC` and a bond of ≈ 10.60 BTC per lane (106 BTC steady state, 212 BTC peak).
   - "Disprove Leaf 3B" must hash 13,140 committed bytes in Script **with no `OP_CAT`**, so it needs an arithmetic SHA-256 split into chunks, with about 206 committed midstates. None of that is specified or costed.
2. **R5-H2 — The slashing predicate can be bypassed through a forged *handoff*.**
   - `SubmitInvalidCertProof` Case A compares only `(MomentumHash, StateRoot, FinalityEpochIndex)` (`spec/04:81`, `spec/05:58`).
   - A cartel can sign a handoff certificate whose momentum and state are canonical but whose `nextFinalityCommitteeRoot` is attacker-chosen. It hands off to keys with no stake, and those keys then sign the forged `targetCert`.
   - No proof path accepts that handoff certificate, even after G-23 publishes it. Equivocation does not catch it either, because the epoch-step circuit does not pin the handoff height (`spec/01:32`, `spec/04:77`).
   - Result: the Assumption-1 backstop is still unreachable for the exact attack R4-H3(a) named ("a forged handoff to a fake committee").
3. **R5-H3 — Routine round-chain rotation and re-graphing of live vaults is unspecified, and the domain and Settlement state cannot represent it.**
   - Every vault's graphs die at most 58 days after its chain's `E_anchor`. Yet v2.3 has:
     - no rotation trigger (the v2.2 "70% / 50 d" rule is gone);
     - no re-graph procedure for `ACTIVE` vaults;
     - no update of `graphTakeTxidsRoot`, bitmask or epoch for them. The `VAULT_REGRAPH_ATTESTATION` handler is scoped to `QUARANTINED → ACTIVE` (`spec/02:156`, `spec/03:154`).
   - After the first rotation, every trapped substitution on a new-generation graph is a "raw sweep" and **halts immediately** (`spec/02:152`), which reopens R4-H2(b).
   - Assignment and G-21 eligibility also have no notion of which epoch a vault is graphed into.

**New-finding census:** 0 CRITICAL · 3 HIGH · 4 MEDIUM · 9 LOW · 6 script defects (S5-1..S5-6).

**Round-4 disposition (§3):**
- Of the 22 R4 findings: **15 CLOSED · 7 PARTIALLY CLOSED (R4-H1, R4-H2, R4-H3, R4-M1, R4-L2, R4-L7, R4-L11) · 0 STILL OPEN**.
- Of the 7 R4 script items: **6 CLOSED · 1 STILL OPEN (S4-7, non-blocking)**.

**Path to CONDITIONAL PASS (Design Spec).** Close R5-H1..H3 in the spec (§7). All three have bounded fixes and need no change of architecture:
- re-derive the DA cost model and specify Leaf 3B (or restructure the DA);
- compare the full `finalityDigest` preimage in Case A and pin handoff heights;
- write a normative rotation procedure, with per-epoch vault graph state.

R5-M1..M4 should be closed in the same pass, or carried as named conditions.

The following **do not block design sign-off**; they remain correctly declared execution or upstream gates:
- G-1 (Signet build, 1-parent-1-child package relay);
- G-2 (*measured* weights, as opposed to the analytic error in R5-H1);
- G-9 (fuzzer);
- G-11 (`IssueMinted` test);
- G-18 (swap suite);
- the Groth16 CRS ceremony;
- §6 upstream ratification (which should add the U2 stake lock; see R5-L6).

---

## 2. New Findings (Round 5)

### 2.1 HIGH

---

#### R5-H1 — The `AssertCertDATx` cost (G-23) omits the WOTS verifier Script. The real cost is roughly 10× (`w = 4`) to 35× (`w = 8`) the 66 kvB assumed, which invalidates `F_assert = 1.70`, `Bond = 4.20`, the "+53 kvB headroom" and the watcher-capital figures. Disprove Leaf 3B requires an in-Script hash over 13 KB without `OP_CAT`, which is unspecified and uncosted.

- **Spec:**
  - `spec/01:30` ("`w = 8` `OP_SHA256` WOTS+ … `~264 KB` witness ⇒ `~66 kvB`"; Leaf 3B checks "published certificate bytes match … `certSetDigest`")
  - `spec/01:7,84,93`
  - `SPEC.md:73,90`
  - `script:33-35` (the constant `66_000`, derived in the comment as `20B/byte … / 4`) and `script:203-209`
- **Ground truth (Bitcoin Script):**
  - Tapscript has no loops. A Winternitz digit of `w` bits is verified by unrolling `D = 2^w − 1` hash steps. The BitVM `winternitz` verifier emits, per digit:
    - `D × (OP_DUP OP_HASH160)`, a pick, a 20-byte public-key compare, and `(D+1)/2 × OP_2DROP`;
    - in total ≈ `2.5·D + 35` bytes of Script, plus about 23 WU of witness.
  - The leaf Script is revealed in the witness, so it is paid for at 1 WU/byte.
  - Consensus caps the stack plus altstack at 1,000 elements. Each `w = 8` digit pushes 256 temporary items.
- **Recomputation** (`/private/tmp/…/scratchpad/r5_check.py`; §6.2 reproduces it):

  | WOTS `w` | WU per certificate byte | DA for 13,140 B | Spec value | Ratio |
  |---|---:|---:|---:|---:|
  | 8 (specified) | ≈ 696 | **≈ 2,285 kvB** | 66 kvB | **34.6×** |
  | 4 | ≈ 191 | **≈ 627 kvB** | 66 kvB | 9.5× |

  - At `w = 8`, the 1,000-element limit forces at least **36 DA inputs** (≈ 372 digits per input). `AssertStartTx` therefore needs about 36 DA outputs, not "`D = 2..4`".
  - Feeding the `w = 4` figure through the oracle's own formulas (`script:205-217`):
    - honest cost ≈ 4.24 BTC at 500 sat/vB;
    - **`F_assert = 4.90`**;
    - **`Bond = 10.60 BTC/lane`**, i.e. 106 BTC steady state and 212 BTC peak for a 15 BTC pilot;
    - watcher capital ≈ 4.91 BTC per lane.
  - At the specified `F_assert = 1.70`, the honest challenged operator breaks even at **≈ 200 sat/vB** (w = 4) or **≈ 68 sat/vB** (w = 8), far below the 500 sat/vB design ceiling. Between those fee levels, a griefer can push honest operators into losses at a cost of 1.71 BTC per challenge.
- **Failure trace (Leaf 3B):**
  1. The SNARK's public input `certSetDigest = SHA256(targetCert ‖ handoffCerts…)` (`spec/01:33`) covers about 13,140 bytes, which is about 206 SHA-256 compressions.
  2. Disprove Leaf 3B must show that the WOTS-published bytes do not hash to the committed digest.
  3. Without `OP_CAT`, the decoded digits cannot be assembled into a stack element for `OP_SHA256`. The hash has to be computed arithmetically in Script, split into chunks, with each 32-byte midstate committed in the assert. That is about 206 extra WOTS-committed values (≈ 300 kvB more at w = 4) plus about 206+ extra disprove leaves.
  4. None of this appears in `C = 1,200`, `L = 32`, `W_assert` or the DAG table. As written, Leaf 3B cannot be built.
- **Why this blocks and is not G-2:**
  - G-2 covers *measurement* of plausible targets. This target is not plausible: the derivation in `script:33-35` drops the dominant term.
  - The spec presents `F_assert`, `Bond`, break-even and watcher capital as *derived invariants with headroom* (`spec/01:93`, `SPEC.md:39`).
  - R4-H3 (blocking) is "closed" by a mechanism whose cost, once corrected, changes the pilot's capital requirements by more than 2.5×.
- **Minimal fix:**
  1. Replace the constant `ASSUMED_STAGE_0C_TARGET_CERT_DA_VB` with a derived lower bound: `digits(w) × (verifier_script(w) + witness)`. Assert `w ∈ {3, 4}`. Count the inputs implied by the stack limit.
  2. Specify Leaf 3B concretely:
     - a Script-implementable hash (SHA-256 or BLAKE3 over committed limbs);
     - the chunk size and the midstate commitments;
     - the number of leaves;
     - then add the midstate commitments to `W_assert`.
  3. Re-derive `F_assert`, the burns, `Bond`, the watcher capital and the Stage 1B capital from the corrected weight, or lower `FeeCeil` and state the trade-off.
  4. Alternatively, shrink the DA set and state the residual honestly. Examples:
     - publish only the `(epoch, height, signerBitfield, signatures, digest fields)` that slashing needs;
     - publish full bytes through a cheap witness envelope bound to a Script-friendly per-chunk digest.

---

#### R5-H2 — `SubmitInvalidCertProof` Case A ignores `nextFinalityCommitteeRoot` (and `finalityCommitteeRoot` and `timestampUnix`), so a forged handoff to stake-less keys is unslashable even after G-23 publishes it

- **Spec:**
  - `spec/04:81` and `spec/05:58` (Case A: `(cert.MomentumHash, cert.StateRoot, cert.FinalityEpochIndex) != canonicalMomentum[cert.Height]`)
  - `spec/04:19-29` (`finalityDigest` also commits `finalityCommitteeRoot` and `nextFinalityCommitteeRoot`)
  - `spec/04:69` (a handoff certificate sets `nextFinalityCommitteeRoot = FinalityCommitteeRoot(E+1)`)
  - `spec/01:32` (the epoch-step circuit accepts "an explicit Committee-`E` dual-supermajority handoff cert", with no height constraint)
  - `spec/04:77` (the checkpoint-height restriction applies only to *target* certificates)
  - `spec/04:79` (equivocation is keyed on `(finalityEpochIndex, height)`)
- **Failure trace:**
  1. 21 colluding members of the in-scope committee `E` sign handoff certificate `H*`:
     - at height `h*`, where no canonical certificate exists (any non-checkpoint height);
     - with **canonical** `momentumHash` and `stateRoot`;
     - with `nextFinalityCommitteeRoot = R_fake`, the root of 30 attacker-generated keys with no stake.
  2. The fake committee signs a `targetCert` claiming `State == RELEASED` for a non-existent peg-out. The SNARK accepts the chain `E_anchor … E → fake`.
  3. A watcher challenges. `AssertCertDATx` publishes `H*` and the forged target (assuming R5-H1 is fixed).
  4. `SubmitInvalidCertProof(H*)`: Case A compares momentum, state and epoch, which all match, so **nothing is slashed**. `SubmitInvalidCertProof(target)` is signed by non-Pillars, so there is nothing to slash.
  5. `SubmitEquivocationProof`: no canonical certificate exists at `(E, h*)`, so no conflict exists.
  6. Even if the circuit pinned `h*` to the canonical transition height, the 21-member cartel can **withhold** the canonical handoff. Finality then stalls publicly, but abstaining is not slashable, so again there is no conflict.
  7. Net: G-23 publishes evidence that no slashing path accepts. The cap rule (`SPEC.md:92-97`) is still backed by an expected slash of 0 against the most direct long-range or cartel attack.
- **Minimal fix:**
  1. Case A MUST compare the **entire** `finalityDigest` preimage against canonical values:
     - `chainId`, `finalityEpochIndex`, `height`, `timestampUnix`, `momentumHash`, `stateRoot`;
     - `finalityCommitteeRoot` (momentum tag 15 for that epoch);
     - `nextFinalityCommitteeRoot`, whose canonical value MUST be defined at *every* height (for example, it equals the current root except at the transition height, where it is the consensus snapshot for `E+1`).
  2. The epoch-step circuit MUST accept a handoff only at the canonical transition height (or as the single allowed `CarryOverCertificate`), so that a forged handoff conflicts with a canonical certificate whenever one exists.
  3. MUST-fail vector: "handoff with canonical momentum and state but non-canonical `nextFinalityCommitteeRoot` ⇒ slashable".

---

#### R5-H3 — Rotation of live vaults onto the next round-chain generation has no normative procedure, and neither `TrackedVaultRecord` nor `VaultUtxoSet` can represent multi-generation graphs. After day 58, trapped substitutions halt immediately and assignment eligibility no longer means anything.

- **Spec:**
  - `spec/01:29` ("Every `RoundChain` pins a fresh … `E_anchor`")
  - `spec/01:45` (`Q_graph` "re-graphs live & recovered vaults onto new `<58d` round chains")
  - `spec/01:60` ("`10`-day handoff overlap")
  - `SPEC.md:98`
  - v2.2's "re-graph at 70% utilization or `E_anchor` 50 d" rule, which is **absent** from v2.3 (grep finds no trigger or schedule)
  - `spec/02:151-152` (spend of an `ACTIVE` vault by a txid ∉ `graphTakeTxidsRoot` ⇒ immediate `Halted = 1`)
  - `spec/02:156` and `spec/03:154` (`0x0D` and `ActivateRegraphedVault`: `QUARANTINED → ACTIVE/UNASSIGNED` only)
  - `spec/02:171` (`TrackedVaultRecord` holds **one** root)
  - `spec/03:43` (`VaultUtxoSet` holds one bitmask, epoch and root)
  - `spec/03:148,151` (`RequestPegOut` and `ClaimReimbursementSlot` never check that the claimed `roundId`'s epoch has graphs for the assigned vault)
- **Ground truth:** `Take1Tx`/`Take2Tx` spend `Conn_A`/`Conn_B`/`Conn_C` of a specific chain. Their txids change with every generation. A vault minted in generation `g` that is still in custody after `g`'s `T_anchor_expiry` can be reimbursed only through generation-`g+1` graphs. Those must be produced with:
  - all `N` members of `Q_graph`;
  - a Phase-1 trap from every operator;
  - a Phase-2 Take.
- **Failure trace A (halt regression):**
  1. Day 45: `Q_graph` re-graphs `d` onto generation `g+1` off-chain. The domain still holds generation `g`'s `graphTakeTxidsRoot[d]`.
  2. Day 60: operator `m` substitutes `d` through `Take1Tx^{g+1}_{d,m,l,r}`. A watcher traps it correctly with `WDD^{T1}`.
  3. A relayer submits `BTC_VAULT_SPEND_PROOF(d)`. The txid is not in the stored root, so it is treated as a "raw unauthorized sweep" ⇒ **immediate halt**, then `PAUSED` with a 14-day governance SLA.
  4. R4-H2(b) is therefore reopened for every vault older than one generation, which in steady state is almost all of them.
- **Failure trace B (meaningless eligibility and capacity):**
  - `RequestPegOut` picks `d` if "≥ 1 eligible operator has `RemainingFreshRounds ≥ 1`". Eligibility comes from `d`'s generation-`g` bitmask; the rounds are generation `g+1`.
  - An operator that failed the generation-`g+1` Phase 1 for `d` may still be eligible. It can claim and front `d`, but no `Take^{g+1}_{d,m,…}` exists, so it cannot be reimbursed (an R2-M7 recurrence).
  - G-21 counts generation-`g+1` rounds as capacity for vaults that may have no generation-`g+1` graphs.
- **Failure trace C (no deadline semantics):** nothing says what happens to a vault that has not been re-graphed when generation `g` passes its cutoff or expiry.
  - Is it `QUARANTINED`?
  - Is minting of new vaults blocked?
  - Is a wind-down triggered?
- **Minimal fix:**
  1. A normative rotation schedule:
     - generation `g+1` is registered at the latest by `E_anchor(g) + 41 d`;
     - `E_anchor(g+1)` is the newest finalized weekly root;
     - every live non-terminal vault is re-graphed (Phase 1, then Phase 2) before generation `g`'s cutoff;
     - a vault not re-graphed by then is moved to `QUARANTINED` and G-21 admission stops.
  2. Generalize `0x0D` into `VAULT_GRAPH_EPOCH_ADDED` for any `ACTIVE`, `UNASSIGNED` or `QUARANTINED` vault, signed by `CommitteeIdentityKey`. Store **per-epoch** roots (at most 2 live), and add to them rather than replace them. The graph-aware spend proof checks the union of live epochs.
  3. In `VaultUtxoSet`, keep `eligibleOperatorsBitmask` per epoch. `RequestPegOut`, `ClaimFrontingSlot` and `ClaimReimbursementSlot` MUST require that `epoch(roundId)` holds a graph for the assigned vault and that the operator's bit is set for that epoch.
  4. MUST-fail vectors:
     - "Take on a generation-`g+1` graph of a rotated vault ⇒ `PENDING_TRAP`, not halt";
     - "claim on a round whose epoch has no graph for the assigned vault ⇒ rejected".

---

### 2.2 MEDIUM

| ID | Title | Spec | Failure trace | Minimal fix |
|---|---|---|---|---|
| **R5-M1** | Whether a vault spend halts or pends depends on whether the *submitter* chose to attach the optional inclusion proof (R4-H2(b) reopened) | `spec/02:151-152` ("If the proof supplies a valid Merkle inclusion … Otherwise IMMEDIATELY `Halted = 1`") | The substituting operator wants the halt. After a correctly trapped `Take1`/`Take2` substitution, it submits `BTC_VAULT_SPEND_PROOF(d)` **without** the inclusion proof. The deterministic verifier takes the "raw sweep" branch ⇒ immediate halt, then `PAUSED`. Cost to the attacker: ≈ 3.2 BTC net bond (it self-traps to collect the 1.00 bounty) plus the unreimbursed `D_bucket` plus the Zenon bond. That buys a bridge pause of up to 14 days on demand, which is exactly the R4-H2(b) outcome the fix was meant to remove. A plain Merkle root cannot prove *non*-membership, so honest relayers cannot pre-empt it either. | Make membership something the verifier decides, not the submitter. Store the registered Take txids for each vault in an SMT keyed by txid, so absence is provable. The raw-sweep halt then requires a **verified absence proof**, and an inclusion proof yields `PENDING_TRAP`. Alternatively, send *every* spend of an `ACTIVE` vault through `PENDING_TRAP` and halt only through `0x0F`. Add the MUST-fail vector "spend proof without an inclusion proof for a registered Take ⇒ no halt". |
| **R5-M2** | G-21 and `RemainingFreshRounds` count rounds that cannot be used. Zenon's cutoff limits the *claim*, not the Bitcoin *kickoff*, so the "4.5-day retire window" is not enforced. | `spec/01:54-55,59`; `spec/01:77` (`GenesisBond` L2 immediate exit); `spec/03:147,149,151`; `SPEC.md:61,98`; `script:313` | (a) **Retired lanes stay counted.** An operator can retire every lane right after registration through `GenesisBond` L2 (no CSV) and get its 4.20 BTC back. Zenon is never told, and keeps counting 16 rounds per operator. G-21 then admits mints against phantom capacity, and `RequestPegOut` assigns to dead lanes. (b) **Rounds run strictly one after another.** If a lane's first kickoff happens on day 30 or 40, only 4 or 2 rounds respectively can start by day 48, yet all 8 count. "1 surviving operator: 16 ≥ 15" (`spec/01:59`, `script:313`) is true only if that survivor's first kickoff is at day ≤ 9.5, since the 15 reimbursements need at least 38.5 days. (c) **Late kickoff can cost an honest operator its bond.** Round `k−1` kicks off at day 47.9. Round `k` is claimed at day 47.95, which is allowed (`now < cutoff`), but its kickoff can come no earlier than day 53.4. Retirement then opens at 58.9, and `StaleChainBurnTx` fires at 58.0 and **burns the bond of an honest operator**. If round `k` is challenged, `Take2` also races `StaleConnCKill`. | Add a permissionless `BTC_ROUND_RETIRED` input: an SPV proof of the deterministic `RoundRetireTx` txid that zeroes the lane's remaining rounds. Track the earliest kickoff time per lane (SPV of `RoundKickoffTx`, or a lower bound from claim times). Count a round as fresh only if `earliestKickoff(idx) + 792 blocks + margin ≤ T_anchor_expiry`, and make `ClaimReimbursementSlot` enforce the same rule. Restate the survivor claim. Have the oracle model reachability (S5-4). |
| **R5-M3** | The vault state machines on the domain side (`TrackedVaultRecord`) and the Settlement side (`VaultUtxoSet`) are incomplete and can overwrite each other | `spec/02:147` (`BTC_RELEASE_PROOF` sets the assigned vault to `RELEASED` with no status precondition); `spec/02:155` (recovery requires `ACTIVE` or `PENDING_TRAP`); `SPEC.md:75` (non-delivery "re-enqueues `outpoint_d` as `UNASSIGNED`"); `spec/03:153,155`; `script:102` (status enum lacks `QUARANTINED`) | (i) `PENDING_TRAP` is never reported to Settlement. Between the Take confirming and `SyncRecoveredVaultOutpoint` (Bitcoin K plus a ≥ 48 h batch), `d` is still `UNASSIGNED` and can be given to a new peg-out `P2`. (ii) If `P2` is fronted, `BTC_RELEASE_PROOF` overwrites `PENDING_TRAP → RELEASED`. The later `BTC_VAULT_RECOVERY_PROOF` then fails its precondition, so the recovered 0.99899 BTC is **never registered** (it remains `QUARANTINED`-less custody), and the fronting operator for `P2` cannot be reimbursed from the spent `d`. (iii) A `P2` timeout re-enqueues `d` as `UNASSIGNED` and overwrites `RECOVERED`. (iv) `SyncOrphanedVaultOutpoint` takes no evidence and requires that `X` "remained unspent", which SPV cannot prove. | Specify complete transition tables for both stores. Mirror `PENDING_TRAP` into Settlement (non-assignable). `BTC_RELEASE_PROOF` and `MINTED_REFUND_V1` act only on vaults that are `ACTIVE` or `ASSIGNED`. When an in-flight `ASSIGNED` vault is recovered, point its peg-out at the recovery outpoint once that has been re-graphed, or refund the peg-out. `SyncOrphanedVaultOutpoint` must require the domain's `RecoveredVaultMap` entry whose `(operatorId, roundId)` equals `PegOutRecord(X).{ReimbursementOperatorId, ReimbursementRoundId}`. That is deterministic and needs no proof of an unspent output. |
| **R5-M4** | The fronting slot can be overwritten, so R3-M4's "loser pays `D_bucket`" trace comes back through a hostile competitor | `spec/03:149` (`ClaimFrontingSlot` checks only that the caller is eligible and has rounds); `spec/02:137` (`0x0A` handler recomputes expiry unconditionally); `spec/02:146`; `SPEC.md:70` | Honest operator A claims the slot and broadcasts `FrontingTx` (paying the user `D_bucket`). Before A's `BTC_RELEASE_PROOF` is admitted (K = 14 confirmations plus relay ≈ 2.5 h), competitor B calls `ClaimFrontingSlot`. `PEGOUT_SLOT_CLAIMED(B)` overwrites `SlotOperatorId` and resets expiry. A's release proof is rejected (`operatorId ≠ po.SlotOperatorId` while unexpired). B fronts and is reimbursed, and A has paid the user unreimbursably. A cannot defend itself, because the overwrite can land at any point before its proof. | Settlement rejects `ClaimFrontingSlot` while `slotOperatorId ≠ 0 && now < slotClaimZenonTs + 14,400`. The `0x0A` handler ignores (`stepError = 2`) a claim while the previous slot has not expired by both height and time. Add a MUST-fail vector "second claim during a live slot ⇒ rejected". |

### 2.3 LOW / ERRATA

| ID | Erratum | Location | Correction |
|---|---|---|---|
| **R5-L1** | **The certificate count and size rest on undefined parameters.** `E_anchor_ts` is undefined. If it is not the start of the weekly epoch (offset δ ≥ 5 d into the week), a 58-day chain spans **9 handoffs + 1 target = 10** certificates. The 1,460 B per certificate assumes exactly 21 signatures, but the weight condition (`> 2/3`) can need more signers, up to 30 (≈ 2.1 KB). The worst case is about 21 KB, not 13,140 B. | `spec/01:29-30`; `spec/04:64`; `script:33-34` | Define `E_anchor_ts = finalityEpochStartTs(E_anchor)`. Bound the certificate size with 30 signers, or require minimal signer subsets in the DA. Feed the result into R5-H1. |
| **R5-L2** | **The SNARK's anchor check is now unanchored.** With the `recentBtcBlockHash` link deleted, `anchorHeader` in circuit item (iii) is chosen by the prover and has no difficulty floor, so it carries no security. The spec no longer claims it as a defense (`spec/04:43`), but it still costs constraints. | `spec/01:33` | Either delete item (iii), or pin an `nBits` floor and disclose that its security is about one block of PoW. |
| **R5-L3** | **`StaleChainBurnTx` can pre-empt the trap.** `StaleChainBurnTx` (`BondOut` L5) and `WDD^{T}` (`BondOut` L3) unlock at the same `T_anchor_expiry`. A substituting `Take1` that confirms within 72 blocks of expiry lets the operator burn its own bond through L5, collecting the 2.10 BTC watcher output itself. That kills `WDD` and lets it sweep the escrow, with a net bond cost of 2.10 instead of 3.20. The outcome is a trap escape plus a `0x0F` halt. | `spec/01:56,78,80,87` | Stagger the CLTVs: `StaleConn{B,C}Kill` at `T_anchor_expiry − 2 d`, and `StaleChainBurn` at `T_anchor_expiry`, so every trap window closes before the bond can be burned. Honest Takes are finished by about day 52.5 (given R5-M2). |
| **R5-L4** | **No exit is specified for fee UTXOs.** The Scripts and exits of `RoundFeeUTXO`/`AssertFeeUTXO` (`RoundGenesisTx` Out 1..R) are unspecified. After a retirement or a stale burn they are either stranded (if gated by `Q_round`) or can be pre-empted by the operator (if `pk_m`-only), which is harmless but undefined. | `spec/01:77` | Give each a `<T_anchor_expiry> CLTV <pk_m>` exit, or sweep them inside `RoundRetireTx`. |
| **R5-L5** | **The authority of `CommitteeIdentityKey` grew, but its blast radius was not updated.** It now also signs round registrations, `graphTakeTxidsRoot` and re-graph attestations. If all N members are compromised, it can inflate G-21 with fake rounds, attest roots that turn raw sweeps into halts delayed by 230 blocks, or activate quarantined vaults with fake graphs (assignments that cannot be reimbursed). The "FOUR explicit assumptions" (`SPEC.md:87`) do not mention the Setup Committee at all, even though it can already divert in-flight deposits. | `spec/01:44`; `SPEC.md:87-101` | Update the registry row. Add "1-of-N honest Setup Committee (deposit-window and attestation integrity)" as an assumption. |
| **R5-L6** | **The U2 lock changes Pillar staking terms but is not in the amendment register.** The 72-day post-service lock means a Pillar that stays in the top 30 can never exit. Whether the `% 90d` revoke window still applies once the lock expires is unspecified (effective lock up to 72 + 83 days). This needs community ratification, yet it is absent from the §6 register. | `spec/04:85`; `spec/05:60`; `SPEC.md` §6 | Add `A-PILLAR-1` to §6 and specify how the lock interacts with the phase. |
| **R5-L7** | **Overclaims remain (R4-L2 residual):** <br>• "every in-scope signer remains 100% slashable" (false under R5-H2, and for unchallenged `Take1`) <br>• "making any forged … certificate publicly extractable" (only when challenged) <br>• "even 1 surviving operator has 16 ≥ 15" (R5-M2) <br>• "all already-minted vaults remain redeemable within … G-21" (R5-M2 / R5-H3) <br>• "zero challenge cost" (the `Kill` fallback needs watcher fee inputs) | `spec/04:43`; `SPEC.md:90,98`; `spec/01:56,59` | Restate each as conditional design intent |
| **R5-L8** | **Phase 2 conflates the two committees.** The text says `Q_graph` "sign[s] the `CommitteeIdentityKey` eligibility attestation". These are distinct committees, and nothing guarantees that `graphTakeTxidsRoot` equals exactly the set of Takes that were released. An omitted Take causes a false immediate halt; an extra Take delays a raw-sweep halt. | `SPEC.md:59`; `spec/01:65` | The Setup Committee signs only over a `Q_graph` release transcript, and the root is defined as a canonical sorted set of exactly the released Takes. |
| **R5-L9** | **Round-registration details are underspecified:** <br>• the derivation of `anchorCutoffTs` (`= anchorExpiryTs − 10 d`?) is not written down; <br>• the domain-side `OperatorBondRecord` has no cutoff field; <br>• `roundChainEpochId` is `u32` in storage but 12 bits in `roundId`, with no range check. | `spec/03:51,150`; `spec/02:138,176`; `spec/01:51` | State the derivation, enforce `epochId < 4096`, and keep the two registries consistent |

---

## 3. Disposition of Round-4 Findings

Legend: **CLOSED** · **PARTIALLY CLOSED** · **STILL OPEN**.

### 3.1 HIGH

| ID | Status | Evidence / residual |
|---|---|---|
| **R4-H1** | **PARTIALLY CLOSED** | **Bitcoin side: CLOSED.** <br>• `RoundRetireTx` is on `GenesisBond` L2 and `BondOut` L4. <br>• `OP_CLTV` L5, `Conn_B` L4 and `Conn_C` L4 force death at `T_anchor_expiry`. <br>• `R = 8`: 44 ≤ 48 < 58, and the 648-block window was recomputed. <br>• Overlap capital is ≤ 2 generations (`ceil(58/48) = 2`; at the weekly cadence the overlap is about 16 d, not 10 d, but the peak still holds). <br>• Long-range trace A is dead: a stale-anchor `Take1` needs `144` CSV after the kickoff, so a kickoff at day ≥ 57 loses the race to `Kill_B`. <br>Residuals: **R5-H3** (the rotation half of the lifecycle is unspecified, and the v2.2 trigger was deleted) and **R5-M2** (G-21 counts retired and unreachable rounds; late kickoffs burn honest bonds). |
| **R4-H2** | **PARTIALLY CLOSED** | (a) **CLOSED**: both `WDD^{T1}` and `WDD^{T2}` exist. In 0 is `Take1:0` or `Take2:0`; `SIGHASH_SINGLE` without ACP binds each to its escrow. Value balance: `0.99899 + 4.20 − (0.99899 + 3.20 + 1.00) = 0`. <br>(c) **CLOSED**: the Phase-1-before-Phase-2 order is normative (`spec/01:64-65`). <br>(b) **PARTIAL**: `PENDING_TRAP` plus `0x0F` with a 230-block window is the right shape, but whether it halts depends on the submitter (**R5-M1**), and the root is never updated on rotation (**R5-H3**). |
| **R4-H3** | **PARTIALLY CLOSED** | (b) **CLOSED**: the `72`-day lock from the end of service is independent of `RegistrationTime % 90d` (`dev:pillars.go:132-138` phase and `:395-412` immediate refund both verified). A worst-case signer from week `E_anchor` stays locked until day ≥ 79, while evidence is available by about day 61. <br>(c) **CLOSED**: the claim was deleted (residual: R5-L2). <br>(a) **PARTIAL**: certificate DA exists in principle, but it is under-costed by about 10–35× and Leaf 3B is unspecified (**R5-H1**). Case A also cannot slash a forged handoff (**R5-H2**). The Assumption-1 restatement (`SPEC.md:90` caveat about unchallenged `Take1`) is honest. |

### 3.2 MEDIUM / LOW

| ID | Status | Note |
|---|---|---|
| R4-M1 | **PARTIALLY CLOSED** | Expiry is now computed in the domain from `BestTipHeight + 24` and `slotClaimZenonTs + 14,400`, with `blockTime` in `ActiveChainByHeight` (68 B, never pruned). `FreeLaneCount` was deleted. Slot overwrite remains: **R5-M4**. |
| R4-M2 | **CLOSED** | `CommitteeIdentityKey` BIP-340 signature over `(binding, opId, roundId, bondOutpoint, anchorExpiryTs)`. `RecognizedBindings` is now written only by `0x0E`, from Governance. Blast-radius update: R5-L5. |
| R4-M3 | **CLOSED** | Recovered vaults are `QUARANTINED` until `0x0D` and `ActivateRegraphedVault`. The false "depth-1 graph" claim was removed (`SPEC.md:72`). The all-N re-graph dependency is disclosed (`SPEC.md:98`). Cross-store residual: R5-M3. |
| R4-M4 | **CLOSED** | `roundId = epoch[12] ‖ lane[4] ‖ idx[16]` (bit layout verified), hardcoded in `Conn_C` L3, plus `RoundUsed`. Range check: R5-L9. |
| R4-M5 | **CLOSED** (disclosure) | Assumption 3 restated: challenge EV is `−(F_assert + f_chal)`, giving 1.71 BTC/lane and 17.10 BTC total. `MinOperatorBondZnn = 1.5 × L × D × price = 31,500 ZNN`. The values must be re-derived after R5-H1. |
| R4-M6 | **CLOSED** | Independent per-field WOTS keys and checksums (36 B ⇒ 72 + 4 nibbles; 3 nibbles suffice). A double-signed WOTS value only hurts the operator who signed it. MUST-fail vector (e) is present. |
| R4-M7 | **CLOSED** (structure) | `F_assert` is parametric (`×1.15`, rounded up to 0.05). The joint assert/DA/Take2 budget and the per-chunk CPFP anchors are in place. **The DA input is wrong: R5-H1.** |
| R4-L1 | **CLOSED** | I spot-checked about 25 citations on `770e893`: <br>• `pillars.go:132-138,395-412` <br>• `consensus.go:45,86` <br>• `htlc.go:92` <br>• `api.go:355-358` <br>• `momentum.go:198` <br>• `account_block.go:283` <br>• `constants/embedded.go:108,115-120` <br>• `plasma.go:192` <br>• `embedded.go:246` <br>• `constants/plasma.go:67` <br>• `token.go:40,43,163-172,330` <br>• `vm.go:204-226` <br>• `ptlc.go` (definition `:114-120`, `PointTypeSecp256k1Point = 2`; implementation `:82-95`) <br>• `go.mod:7` <br>• `embedded_genesis_string.go:6-7` <br>All match. |
| R4-L2 | **PARTIALLY CLOSED** | Several overclaims were fixed, but new ones were introduced: R5-L7. |
| R4-L3 | **CLOSED** | `qGraphXOnly`, `committeeSizeN ≥ 7` and the tweak tags are in `releaseAdapterRef`. `Q_vault_d`/`Q_rec_d` are computed in the domain. |
| R4-L4 | **CLOSED** | Pre-2032 rule: `K ≥ 26` or cap ≤ 5 BTC (recomputed 26 / 13). |
| R4-L5 | **CLOSED** | Global cap of ≤ 16 duplicate refunds per batch. (Nit: first-come allocation lets a cheap Sybil take the 16 slots; the amounts are negligible.) |
| R4-L6 | **CLOSED** | Reserve-liveness monitor, plus the depositor's Leaf-B replace-by-fee at `h_dep + 144` (`0xfffffffd` is signaled). |
| R4-L7 | **PARTIALLY CLOSED** | The `ORPHANED` status and a 7-day governance step exist, but the trigger cannot be verified: R5-M3(iv). |
| R4-L8 | **CLOSED** | 1-parent-1-child relay is explicitly gated under G-1 (`spec/01:72`). |
| R4-L9 | **CLOSED** | `RefundRejectedBatchChallenge` covers descendants. |
| R4-L10 | **CLOSED** | Writers split (`0x0B` vs `0x0E`). |
| R4-L11 | **PARTIALLY CLOSED** | Re-graph state is updated only for `QUARANTINED` vaults. Routine rotation: **R5-H3**. |
| R4-L12 | **CLOSED** | Dual supermajority (`≥ 21/30` and `> 2/3` weight) required. Equivocation remains unconditional. |

**Round-4 tally (22):** 15 CLOSED · 7 PARTIALLY CLOSED · 0 STILL OPEN.

### 3.3 Script Items (S4-1..S4-7)

| ID | Status | Note |
|---|---|---|
| S4-1 | **CLOSED** | Lifetime ≤ cutoff < expiry and fresh capacity are now asserted. Residual reachability issue: S5-4. |
| S4-2 | **CLOSED** | `RealWatcherVsSelfSlash/MEV = −1.7000..−1.7100` (recomputed). |
| S4-3 | **CLOSED** | Joint `Assert+CertDA+Take2` row is 1.435 < 1.70. |
| S4-4 | **CLOSED** | Steady-state and peak bond capital are modeled. |
| S4-5 | **CLOSED** | Break-even of 339.0 kvB printed and `F_assert` derived. Its input is wrong: S5-1 / R5-H1. |
| S4-6 | **CLOSED** | The 72-day lock is asserted against 58 + 14. This is a constant comparison, which is acceptable because the lock is measured from the end of service. |
| S4-7 | **STILL OPEN** (non-blocking) | `L`, `C` and the constraint count are still printed but never checked. Acceptable until G-2. |

---

## 4. Verified-Sound Mechanisms (new in v2.3; do not re-litigate)

- **Value balances of the retirement and stale-chain transactions.**
  - `RoundRetireTx`: 4.20 → 4.1990 + 330 sats, fee 99,670 sats.
  - `StaleChainBurn`: 2.10 burned + 2.10 to the watcher.
  - `DisproveTx`: 1.90 + 2.30.
  - `WDD`: 0.99899 + 3.20 + 1.00 against 0.99899 + 4.20.
  - Every slash path sums to the 4.20 bond.
- **Closure of stale anchors on Bitcoin.**
  - `Conn_B` L4 and `Conn_C` L4 kill both Take paths at `T_anchor_expiry` (MTP-based CLTV, which is compatible with the time-type CLTV used in the burn variants).
  - Because of the `144` CSV on `Take1` and `Take2`, any stale kickoff after day 57 loses to `Kill`.
  - Under Assumption 3, a forged kickoff before day 57 is in the fresh-anchor regime, where the 72-day lock and (once fixed) DA and slashing apply.
- **Trap-window timing still holds after the new leaves.** `AssertCertDA` runs in parallel with the chunks, so `AssertEnd` ≤ 432, `Take2` ≤ 648, and trap windows close by 720, all before the retire / next-kickoff leaves open at 792. Only the CLTV interaction is a residual (R5-L3).
- **Per-field WOTS with independent checksums.** No griefing by digit-forwarding without inverting the hash.
- **The two-phase ceremony order and the two trap variants.**
- **The `72`-day post-committee-service lock.** It is the correct construction against the per-Pillar revoke phase and immediate refund of `dev:pillars.go`.
- **Dual-supermajority scoping (R4-L12)** and Case B for future heights.
- **Authenticated round registration, unique `roundId`, `RoundUsed`.**
- **Slot expiry computed in the domain** from the domain's own `BestTipHeight` and the Zenon claim timestamp. To break exclusivity, both the height and `nTime` must pass expiry, and height cannot be faked. Overwrite residual: R5-M4.
- **Joint fee budgets and CPFP anchors on every operator-broadcast pre-signed transaction.** Relay policy is gated under G-1.
- **Oracle numerics (recomputed):**
  - depth-256 `UploadWitnessProof` 8,676 B;
  - fast paths ≤ 10,180 B;
  - Continuity 1,700 B;
  - Poisson 353 / 472;
  - `K` 12 / 13 / 26 / 13;
  - timeouts 640 / 2,512;
  - grace 558;
  - `pendingTrapWindow` 230;
  - break-even 339.0 kvB *for the stated input*.

---

## 5. Go / No-Go Gate Checklist (Round 5)

**Status: NO-GO (design) — HOLD.** Gates marked ⚙ do not block design sign-off.

| Gate | Status | Blocking items |
|---|---|---|
| G-1 (graph causality and enforceability) | ◐ PARTIAL | R5-M1, R5-L3; ⚙ Signet build and 1p1c relay |
| G-2 (measured weights) | ⚙ GATE, **plus a blocking analytic correction** | R5-H1 (DA lower bound and Leaf 3B are not a measurement question) |
| G-3 (finality proof) | ◐ PARTIAL | R5-H2 |
| G-4..G-6 | ✅ CLOSED | |
| G-7 (fronting and fees) | ◐ PARTIAL | R5-M4 |
| G-8 (traceRoot) | ✅ CLOSED | |
| G-9 (witness bound) | ✅ design / ⚙ fuzzer | |
| G-10 | ✅ CLOSED | |
| G-11 (mint model) | ✅ design / ⚙ test | |
| G-12 (lock-proof hardening) | ✅ CLOSED | (R5-L8 hygiene) |
| G-13 (timeouts, eligibility, halt) | ◐ PARTIAL | R5-M1, R5-M3 |
| G-14 (input DoS) | ✅ CLOSED | |
| G-15 (epoch committee) | ✅ CLOSED (design) | (R5-L1, R5-L6 hygiene / ratification) |
| G-16 | ✅ CLOSED | |
| G-17 (upstream) | ⚙ ESCALATED | Ratification, now including the U2 lock (R5-L6) |
| G-18 (peg-free rails) | ✅ design / ⚙ tests | |
| G-19 (numbers from scripts) | ◐ PARTIAL | S5-1, S5-4, S5-5 |
| G-21 (capacity ≥ supply) | ◐ PARTIAL | R5-M2, R5-H3 |
| G-22 (round-chain lifecycle and bond exit) | ◐ PARTIAL | Bitcoin side ✅; rotation ❌ R5-H3 |
| G-23 (certificate DA for slashing) | ❌ OPEN | R5-H1, R5-H2 |
| G-20 (independent re-review) | ✅ this document; **Round 6 required** | |

---

## 6. Audit of `scripts/verify_spec_bounds.py`

The script ran cleanly (`python3 -I`, exit 0). Independently recomputed:
- `poisson(288) = 353` and `poisson(396) = 472`;
- `F_assert`: `ceil(1.435 × 1.15 × 20)/20 = 1.70`;
- break-even `(1.70 − 0.005)·1e8/500 = 339.0` kvB;
- bond `ceil(41.99999999999999) = 42` ⇒ 4.20;
- watcher P&L at 1 / 50 / 200 / 500 sat/vB;
- `−1.7000..−1.7100`;
- lifecycle 44 / 48 / 58 / 648 blocks;
- capacity 80, steady-state / peak capital 42 / 84;
- `K` 12 / 13 / 26 / 13.

### 6.1 New Script Defects

| # | Defect | Location | Effect |
|---|---|---|---|
| S5-1 | The cert-DA weight is a hardcoded constant derived from preimage bytes alone (`9 × 1,460 × 20 / 4`). It omits the WOTS verifier Script (≈ `2.5·(2^w−1) + 35` B per digit), the inputs forced by the stack limit, and the Leaf-3B midstate commitments. | `script:33-35` | Hides R5-H1. Every number derived downstream (`F_assert`, bond, watcher capital, Stage 1B capital) is understated by about 2.5–7× |
| S5-2 | Stale comments contradict the computed values: <br>• `# 2.05 BTC` / `# 1.85` / `# 2.70` (actual 2.30 / 2.10 / 3.20) <br>• `# 37.0` / `# 74.0` (actual 42 / 84) <br>• `# 1.4600` / `# 14.60` (actual 1.71 / 17.10) <br>• the status enum lacks `QUARANTINED` | `script:102,219-221,316,319,324-325` | Misleads reviewers and implementers |
| S5-3 | The bond is derived with a floating-point `ceil` that lands exactly on a boundary (`41.99999999999999`). Changing any input by 1e-15 BTC changes the bond by 0.10 BTC. | `script:216` | Fragile. Use integer satoshis or `Decimal` |
| S5-4 | The lifecycle assertions are constant tautologies (`44 ≤ 48`, `72 ≥ 72`, `ceil(58/48) = 2`, `2×8 ≥ 15`). They do not model serial reachability, a kickoff after the cutoff, retirement being invisible to Zenon, or the overlap at a weekly cadence. | `script:297-302,313,317-318` | Hides R5-M2 |
| S5-5 | The certificate count (9) and size (1,460 B) are assumed rather than derived from `E_anchor_ts` alignment and the worst-case signer count. | `script:33-34` | Hides R5-L1 (10 certificates, up to 2.1 KB each) |
| S5-6 | (S4-7 carry-over) `L`, `C` and the constraint count are never checked. Leaf 3B's roughly 206 extra leaves are absent from `C`. | `script:28-30` | Acceptable until G-2, apart from the R5-H1 part |

### 6.2 Reproduction

```python
import math
def per_byte_wu(w):                       # BitVM unrolled Winternitz verifier
    D = 2**w - 1
    return (8 / w) * ((2.5 * D + 35) + 23)   # script + witness, per digit
B = 9 * 1460
for w in (4, 8):
    print(w, round(B * per_byte_wu(w) / 4 / 1000))          # 627 kvB ; 2285 kvB  (spec: 66)
print(B * 20 / 4 / 1000)                                     # 65.7 -> the spec's derivation
print(math.ceil(B / ((1000 - 256) // 2)))                    # 36 DA inputs at w=8 (stack limit)
tot = (220_000 + 627_000 + 1_000) * 500 / 1e8                # w=4 honest cost @500
F = math.ceil(tot * 1.15 * 20) / 20
print(tot, F, math.ceil(((F + .2) + F + .01 + .475 + .115) * 10) / 10)   # 4.24 4.9 10.6
print(1.70e8 / (220_000 + 627_000 + 1_000))                  # ~200 sat/vB break-even at F=1.70
for d in (0, 4.9, 5.0): print(d, math.floor((d + 58) / 7) + 1)          # 9, 9, 10 certs
for t0 in (0, 30, 40): print(t0, min(8, math.floor((48 - t0) / 5.5) + 1))  # 8, 4, 2 reachable rounds
print(47.9 + 5.5 + 5.5)                                      # 58.9 > 58 -> honest bond burned (R5-M2c)
```

```text
dev:vm/embedded/implementation/pillars.go:132-138  epochTime = (now - RegistrationTime) % (83d + 7d)   (per-Pillar phase; v2.3 72d lock correctly overrides)
dev:vm/embedded/implementation/pillars.go:395-412  Revoke: RevokeTime=now; Amount=0; ContractSend PillarStakeAmount to StakeAddress (immediate)
spec/04:81 / spec/05:58                            Case A compares (MomentumHash, StateRoot, FinalityEpochIndex) only -> nextFinalityCommitteeRoot unchecked (R5-H2)
spec/02:151-152                                    halt vs PENDING_TRAP decided by an optional submitter-supplied inclusion proof (R5-M1)
```

---

## 7. Required Actions Before Round 6 (Priority Order)

1. **R5-H1, certificate DA cost and Leaf 3B:**
   - derive the DA weight from per-digit verifier Script plus witness, use `w ≤ 4`, and count the inputs forced by the stack limit;
   - specify Leaf 3B (hash function, chunking, midstate commitments, leaf count) and add its commitments to `W_assert`;
   - re-derive `F_assert`, the burns, `Bond`, watcher capital and Stage 1B capital, or restructure or shrink the DA and state the residual.
2. **R5-H2, the slashing predicate:**
   - compare the full `finalityDigest` preimage in Case A, with a canonical `nextFinalityCommitteeRoot` defined at every height;
   - pin handoff certificates to the canonical transition height (or the single carry-over);
   - add the MUST-fail vector.
3. **R5-H3, rotation:**
   - a normative schedule and re-graph procedure (Phase 1 then Phase 2) for every live vault before generation `g`'s cutoff;
   - per-epoch graph roots and bitmasks that are added to, not replaced (generalize `0x0D` and `ActivateRegraphedVault`);
   - epoch-coverage checks in `RequestPegOut`, `ClaimFrontingSlot` and `ClaimReimbursementSlot`;
   - a rule for vaults not re-graphed by the deadline;
   - the MUST-fail vectors.
4. **R5-M1..M4:**
   - a halt decided by the verifier, through SMT absence proofs;
   - a `BTC_ROUND_RETIRED` input and reachability-aware fresh capacity and claims;
   - complete cross-store vault transition tables;
   - a fronting slot that cannot be overwritten.
5. R5-L1..L9, and S5-1..S5-5.

**Not blocking design sign-off (correctly gated in `SPEC.md §6–§7`):**
- G-1 Signet build and 1p1c relay tests;
- G-2 *measured* weights (once R5-H1's analytic model is in place);
- G-9 adversarial SMT fuzzer;
- G-11 `IssueMinted` test;
- G-18 swap suite;
- the Groth16 CRS ceremony (`K ≥ 50`);
- ratification of A-SPEC-1..6, A-BTC-1, A-MINT-1, plus the U2 Pillar-lock amendment (R5-L6).
