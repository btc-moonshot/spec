# Hostile Peer Review — Round 4 — zBTC Bitcoin↔Zenon Interoperability Specification `v2.2.0-draft`

**Reviewer posture:** adversarial, first-principles. Same rules as Rounds 1–3: the spec's own summaries and the change log in the review request were not trusted. Claims were re-derived from Bitcoin consensus and policy (BIP-68/112/341/342), from `go-zenon` source at the declared baselines, and by independent recomputation of every oracle number used below.
**Review date:** 2026-11-24
**Baseline:** `HOSTILE_REVIEW_R3.md` (Round 3: 3 C · 4 H · 9 M · 11 L · script defects S3-1..S3-8 + S-9).
**Mandate:**
- Do not re-litigate the Round-2 §4 or Round-3 §4 verified-sound mechanisms unless v2.2 broke them.
- Attack every new v2.2 mechanism.
- Give a disposition for every Round-3 item.
- Separate **blocking design-spec defects** from **non-blocking execution or upstream gates**.

**Artifacts under review (SHA-256, first and last 8 hex digits):**

| File | SHA-256 |
|---|---|
| `SPEC.md` | `55e9e815…8edda987` |
| `spec/01` | `ca9ec480…271bad8c` |
| `spec/02` | `69d1bddb…0f426ecc` |
| `spec/03` | `b0621668…7e31e99a` |
| `spec/04` | `05ef3a14…6eab475c` |
| `spec/05` | `0346b36e…5d741442` |
| `scripts/verify_spec_bounds.py` | `0b57e47d…37875576` |

**Ground truth:**
- `go-zenon`: `origin/release/0.0.11-rc1` `f19955f`, `origin/dev` `770e893`, `master` `e8986a6`. A `dev:` prefix means `git show origin/dev:<path>`.
- `zenon-developer-commons`: `HEAD` `3719452`.

**Citation convention:** `spec/0N:L`, `SPEC.md:L`, `script:L` (= `scripts/verify_spec_bounds.py`).

---

## 1. Executive Verdict

### **HOLD — Design Spec (0 CRITICAL, 3 blocking HIGH)**

v2.2 is the strongest revision so far. The Round-3 root cause has been dealt with. Round-level connectors were fixed before any deposit existed, yet were guarded by operator-only or unsigned leaves. Architecture (B) replaces that with:
- a **live 1-of-N `Q_graph`**, honestly elevated to Trust Assumption #2; and
- **per-round deleted `Q_round_{m,r}`**.

I walked every output in the republished DAG (`spec/01:79-87`). **No leaf on `Conn_A`, `Conn_B`, `AssertStart:i`, `AssertChunk_i:0`, `Conn_C` or `BondOut` can be spent by the operator alone, or by anyone without a `Q_round`/`Q_graph` signature**, apart from the intended `ReimburseEscrow` Leaf 1 and the 330-sat anchors. **R3-C1 is CLOSED.**

The rest of the Round-3 work also holds up on re-derivation:
- Take1/Take2 fee arithmetic: 1,330 / 1,000 sats.
- The dual-`SIGHASH_SINGLE` value balance of `WrongDepositDisproveTx`: 0 sats unaccounted.
- Bounded challenge sessions (R3-H4).
- Never-reused `batchId` lineage (R3-M2) and per-domain `domainInputSeq` (R3-M3).
- Authenticated eligibility (R3-M1).
- Exact Poisson: 353 stationary, 472 at λ = 396.
- Halving-indexed `K`: 12 / 13 ≤ 14.
- Hardened `ReceiveTreasury`.

The oracle runs clean (`python3 -I scripts/verify_spec_bounds.py`, exit 0), and every number I recomputed matches.

**What still blocks design sign-off: three HIGH findings, all on the new v2.2 mechanisms.**

1. **R4-H1 — The round-chain lifecycle has no end.** There is no idle round, no bond exit and no way to retire a superseded chain.
   - Rounds cannot advance without a valid reimbursement claim.
   - `BondOut_{m,R−1}` has no exit.
   - A lane lives **≥ 352 days** (64 × 5.5 d), with no upper time bound.
   - Consequences:
     - The "every `RoundChain` rotates `E_anchor` < 60 d" defense against long-range attacks cannot retire stale-anchor graphs. A malicious operator simply keeps kicking off its old chain.
     - Rotating every 50 d with locked bonds needs about **8 concurrent bond generations (~248 BTC) to back a 15 BTC pilot**.
     - If G-21 counted only rounds under a fresh anchor, it would admit **0** mints (10 lanes × 10 rounds − 100 margin = 0 < 16).
2. **R4-H2 — The custody-preserving substitution trap is incomplete and races the halt.**
   - (a) Only one `WrongDepositDisproveTx` is pre-signed per `(d, m, r)`, but `Take1Tx_{d,m,r}:0` and `Take2Tx_{d,m,r}:0` are **different escrow outpoints**, so substitution through the Take2 path is untrapped.
   - (b) `BTC_VAULT_SPEND_PROOF` on `d` (status ACTIVE) can be relayed after 14 confirmations of the Take, well before the trap's 72-block window completes. Every substitution therefore halts and pauses the bridge for up to 14 days, trapped or not.
   - (c) The order of the signing ceremony is unspecified. If `Q_graph` releases its Take signatures before the operator countersigns both trap variants, the operator ends up holding untrapped graphs. Leaving it out of the Zenon-side bitmask does not revoke them on Bitcoin.
3. **R4-H3 — The Assumption-1 slashing backstop cannot be reached.**
   - (a) The forged `FinalityCertificate` and handoff certificates are **private SNARK witnesses**. The kickoff publishes only `pubInputHash`, and the anchor publishes only `c_h`. `SubmitInvalidCertProof` and `SubmitEquivocationProof` therefore never receive the evidence they need. The new future-height Case B is moot for BitVM2 forgeries.
   - (b) The "`E_anchor` < 60 d < 83 d lock ⇒ 100% slashable collateral" argument is wrong. A Pillar's revoke window is phased per Pillar (`(now − RegistrationTime) mod 90 d`, `dev:vm/embedded/implementation/pillars.go:132-138`) and refunds immediately (`:395-400`). A committee member can revoke on the day it signs, so only the new 14-day hold is guaranteed.
   - (c) `W_kick.recentBtcBlockHash` has no disprove path, so the "≤ 432-header PoW link" is chosen by the prover and proves nothing.
   - Net effect: the 157,500 ZNN cap rule (`SPEC.md:92`) deters nothing.

**New-finding census:** 0 CRITICAL · 3 HIGH · 7 MEDIUM (R4-M7 is a non-blocking sensitivity tied to G-2) · 12 LOW · 7 script defects (S4-1..S4-7).

**Round-3 disposition (§3):**
- Of the 27 R3 findings: **18 CLOSED · 7 PARTIALLY CLOSED · 2 STILL OPEN (R3-M4, R3-L2)**.
- Of the 9 R3 script items: **6 CLOSED · 3 PARTIAL**.

**Path to CONDITIONAL PASS (Design Spec).** Close R4-H1..H3 in the spec (§7). All three have bounded, known fixes and need no change of architecture:
- a pre-signed retire / bond-exit transaction, plus an absolute-CLTV stale-chain burn;
- two trap variants, a graph-aware vault-spend rule, and normative signing order;
- publication of certificates with data availability, plus a post-committee-service stake lock.

The following **do not block design sign-off**; they remain correctly declared execution gates:
- G-1 (Signet build, package relay and TRUC viability);
- G-2 (measured assert, chunk and disprove weights);
- G-9 (fuzzer);
- G-11 (`IssueMinted` test);
- G-18 (swap suite);
- the CRS ceremony;
- §6 upstream ratification.

---

## 2. New Findings (Round 4)

### 2.1 HIGH

---

#### R4-H1 — The round-chain lifecycle is never closed (no idle round, no bond exit, no retirement), so `< 60 d E_anchor` rotation is not achievable, bonds stay locked indefinitely, and G-21 counts rounds that cannot be used safely

- **Spec:**
  - `spec/01:50-51` (`R = 64` rounds/lane, `T_bond_cooldown = 792` ⇒ 5.5 d/round)
  - `spec/01:57` (re-graph at 70% utilization **or** `E_anchor` age 50 d: "launch `RoundChain_{next}`")
  - `spec/01:28` and `SPEC.md:87` ("Every `RoundChain` pins … `E_anchor` strictly `< 60` days old")
  - `spec/01:79` (`BondOut_{m,r}` leaves: L1 = `Q_round` burns/disprove only; L2 = 792-CSV next `RoundKickoffTx`; L3 = `Q_graph`+`pk_m` "`WrongDepositDisproveTx` ONLY")
  - `spec/01:53-56`, `spec/03:175` (G-21)
  - `script:271-296`
- **Ground truth (Bitcoin):**
  - Relative timelocks give a *lower* bound only. Nothing forces `RoundKickoffTx_{m,r+1}` to occur by any deadline.
  - Pre-signed `Take1`/`Take2` signatures from `Q_graph` cannot be revoked once handed out.
  - `BondOut` has no leaf that releases the bond to the operator. `BondOut_{m,63}` → `RoundKickoffTx_{m,64}` does not exist.
- **Failure trace A (stale-anchor chain stays live, so the long-range residual is open):**
  1. Lane `(m, l)` is set up at day 0 with `E_anchor` pinned in `Conn_C` Leaf 3 (`spec/01:83`).
  2. At day 50, `Q_graph` launches `RoundChain_next` and re-graphs every live UTXO onto it (`spec/01:57`).
  3. The old chain's graphs for those same UTXOs remain valid. The old lane still has about 54 rounds left, at ≥ 5.5 d each.
  4. The operator keeps kicking off the **old** chain at day 90, 180, 300 and so on. Each such round's SNARK accepts any epoch chain starting from the old `E_anchor`.
  5. The disclosure at `SPEC.md:87` says trust degrades only "if `Q_graph` ever fails to rotate". In fact it degrades on **every** lane past about day 60–90, whether or not rotation happens.
- **Failure trace B (rounds cannot be skipped, and bonds are locked):**
  1. A round advances only through `BondOut_{m,r}` Leaf 2, which is the next kickoff.
  2. A kickoff with no valid claim either:
     - leaves `Conn_B` unspent until `BurnBondTx` at 288 (`spec/01:82`), which pays any watcher 1.55 BTC for free; or
     - spends `Conn_B` via `Take1_{d}`, which triggers the trap; or
     - spends it via `AssertStart`, which leads to a disprove.
  3. Every round that does not burn the bond therefore needs a **genuine reimbursement claim**. Recovering a lane's 3.10 BTC needs 64 real reimbursements on that lane (≥ 352 days). Even then, the final `BondOut` has no exit.
  4. Rotation every 50 d with locked bonds means `ceil(352/50) = 8` concurrent lane generations × 31 BTC ≈ **248 BTC of bonds backing a 15 BTC pilot**. Without that, operators cannot both rotate and keep their old lanes' capacity.
- **Failure trace C (G-21 is either insecure or blocks every mint):**
  - Under a < 60 d anchor, each lane can run at most `floor(60/5.5) = 10` rounds (recomputed).
  - Pilot fresh-anchor capacity = 10 lanes × 10 = **100**.
  - G-21 then requires `ActiveVaultUTXOs + 1 ≤ 100 − 100 = 0`, so **no mint is ever admitted**.
  - The oracle's 640 counts rounds 11..63 of every lane, which are exactly the stale-anchor rounds of trace A.
  - `script:291-292` asserts only the constant comparison `60 < 83`. It never combines that with `ROUNDS_PER_LANE × days_per_round = 352`.
- **Minimal fix:**
  1. **Retire path.** Pre-sign at round setup, with `Q_round_{m,r}`, a `RoundRetireTx_{m,r}` that spends `BondOut_{m,r}` through a new Leaf 4 `<792> CSV <Q_round_{m,r}> CSVFY <pk_m> CS`. It returns the bond (minus a fixed reserve) to `pk_m` and ends the chain.
  2. **Forced expiry.** Add a `BondOut` leaf `<T_anchor_expiry> CLTV <Q_round_{m,r}> CS` that spends through a pre-signed `StaleChainBurnTx`, using the existing burn plus free watcher output pattern. Set `T_anchor_expiry = E_anchor_time + 60 d`. An operator who does not retire before expiry is burned, so stale-anchor chains die on Bitcoin.
  3. **Size `R`** so that `R × 5.5 d ≤ 60 d − margin` (`R ≤ 10`). Make G-21 count only rounds whose `T_anchor_expiry` is in the future, decremented on Zenon from `OPERATOR_ROUND_REGISTERED` metadata.
  4. **Oracle:** assert `R × T_bond_cooldown/144 ≤ E_anchor_max_age`, fresh-anchor capacity ≥ supply + margin, and the concurrent bond capital.
  5. **MUST-fail vector:** "kickoff on a chain past `T_anchor_expiry` ⇒ `StaleChainBurnTx` valid first".

---

#### R4-H2 — The substitution trap covers only the Take1 escrow, races `BTC_VAULT_SPEND_PROOF`, and the signing order that makes it binding is unspecified

- **Spec:**
  - `spec/01:80` and `spec/01:85` (both `Take1Tx` and `Take2Tx` pay Out 0 = "`ReimburseEscrow_{d,m,r}`")
  - `spec/01:87` (one `WrongDepositDisproveTx_{d,m,r}`, In 0 = `ReimburseEscrow_{d,m,r}` Leaf 2, `SIGHASH_SINGLE` no ACP)
  - `spec/02:151` (`BTC_VAULT_SPEND_PROOF`: ACTIVE outpoint spent "without `RELEASED` or `RECOVERED`" ⇒ `Halted = 1`)
  - `spec/02:153` (recovery proof)
  - `spec/03:146,150` (halting batch ⇒ `PAUSED`, governance resume, 14 d SLA)
  - `spec/01:46` and `SPEC.md:57` (co-signing as the eligibility precondition)
- **Ground truth:**
  - BIP-341 `SIGHASH_SINGLE` without ACP commits to `sha_prevouts` of **all** inputs. Each pre-signed `WrongDepositDisproveTx` is therefore bound to exactly one escrow outpoint.
  - `Take1Tx_{d,m,r}` and `Take2Tx_{d,m,r}` have different txids, so they produce two distinct escrow outpoints.
  - `Q_graph` is live, but `BondOut` Leaf 3 also needs `pk_m`. A trap transaction created after the fact therefore needs the operator's cooperation, which a substituting operator will not give.
- **Failure trace (a), untrapped Take2 substitution:**
  1. Operator `m` legitimately fronts `P` (assigned `X`) and claims its slot `(m, r)`.
  2. It kicks off the valid claim `X` and self-challenges. `ChallengeTx` is `SIGHASH_SINGLE|ACP`, so the operator can fund it itself, net 0.
  3. It asserts honestly. No disprove exists.
  4. At `AssertEnd + 144` it broadcasts `Take2Tx_{d,m,r}` with `d ≠ X`. No `WrongDepositDisproveTx` spends `Take2Tx_{d,m,r}:0`.
  5. After 72 blocks the operator sweeps `d`. Its bond is intact and its Zenon bond is never slashed (no `OP_RETURN` burn).
  6. `d` is spent while ACTIVE ⇒ `BTC_VAULT_SPEND_PROOF` ⇒ the domain halts.
  7. `X` stays in custody, orphaned (see R4-L7). The cost to the attacker is about `f_assert` (~0.0022 BTC at 1 sat/vB) for a halt of up to 14 days, repeatable once per lane-round.
- **Failure trace (b), the race defeats "custody-preserving":**
  1. Even on the Take1 path, `Take1Tx_{d,m,r}` reaches `K = 14` confirmations about 58 blocks **before** the trap's 72-block window closes.
  2. A relayer submits `BTC_VAULT_SPEND_PROOF(d)` as soon as `d` has 14 confirmations. The proof is valid because `d` is ACTIVE and not yet RECOVERED, so `Halted = 1`, then `PAUSED`, and governance is needed to resume.
  3. `BTC_VAULT_RECOVERY_PROOF` arrives later and cannot un-halt the domain.
  4. So every substitution attempt, even a fully trapped one, halts the bridge. The attacker's cost is about 2.10 BTC of burn plus its fronted `D_bucket`, recapturing 1.00 BTC by self-trapping.
- **Failure trace (c), ceremony order:**
  1. `Take1`/`Take2` need **two** signatures: the aggregate `Q_graph` signature on the key-path vault input and on the connector leaves, plus `pk_m`. Leaf 3 of `WrongDepositDisproveTx` needs `pk_m`.
  2. If `Q_graph` hands its Take signatures to `m` before `m` has delivered valid `pk_m` signatures on **both** trap variants, `m` holds spendable, untrapped graphs.
  3. "Excluded from `eligibleOperatorsBitmask`" (`spec/01:46`) only stops Zenon from *assigning* `d` to `m`. It does not stop `m` from substituting `d` on Bitcoin with a different valid claim.
- **Minimal fix:**
  1. Pre-sign **two** `WrongDepositDisproveTx` variants per `(d, m, r)`, `…^{T1}` and `…^{T2}`, one for each escrow outpoint, in setup and in re-graphing.
  2. Make the ceremony order normative: `Q_graph` releases no `Take1`/`Take2` partial signature to `m` until `m`'s `pk_m` signatures on both trap variants have been verified. Abort the rollover otherwise.
  3. Make `BTC_VAULT_SPEND_PROOF` graph-aware:
     - Add a registered graph txid set: `GraphTakeTxids[d]`, committed with the CommitteeIdentityKey eligibility attestation, or derivable from `(RolloverTx, round registry)`.
     - A spend of `d` by a registered `Take*Tx_{d,·,·}` moves `d` to `PENDING_TRAP`, not to `Halted`.
     - Halt only if neither `BTC_VAULT_RECOVERY_PROOF` nor a matching RELEASED assignment is admitted within `72 + K + margin` blocks.
  4. MUST-fail vectors: "Take2-path substitution ⇒ trap^{T2} valid" and "VAULT_SPEND_PROOF on a trapped Take within the window ⇒ no halt".

---

#### R4-H3 — The Assumption-1 slashing backstop cannot be reached: forged certificates are private SNARK witnesses, the 60 d / 83 d slashability argument ignores per-Pillar revoke phase, and `recentBtcBlockHash` is unconstrained

- **Spec:**
  - `SPEC.md:86-93` (Assumption 1: slashing plus the cap rule `MaxRepresentationSupply × price ≤ 157,500 ZNN`)
  - `SPEC.md:87` and `spec/01:28` ("every in-scope committee `E ≥ E_anchor` retains `100%` locked slashable collateral")
  - `spec/04:83-86` (`SubmitInvalidCertProof` Cases A and B, 14-day hold)
  - `spec/01:79` (`W_kick` commits `pubInputHash` only)
  - `spec/01:100` (the ≤ 432-header link to `W_kick.recentBtcBlockHash`)
  - `spec/04:30` (only `c_h` is anchored)
- **Ground truth:**
  - `dev:vm/embedded/implementation/pillars.go:132-138`: `epochTime = (now − RegistrationTime) mod (83 d + 7 d)`, and the Pillar is revocable while `epochTime ≥ 83 d`. **The phase differs for each Pillar.** About 7/90 ≈ 7.8% of Pillars are inside their revoke window at any given moment.
  - `:395-400`: `Revoke` zeroes `pillar.Amount`, and the descendant send refunds the stake **immediately**. Under U2, the only guaranteed slashability after signing is the new 14-day hold.
  - A Groth16/IVC proof reveals only its public inputs. The `FinalityCertificate` signatures and epoch-handoff certificates are private witnesses.
- **Failure trace (a), certificates are never published:**
  1. 21 colluding members of the **current** committee `E_t` (inside the `< 60 d` window, fully staked) sign a forged checkpoint certificate, or a forged handoff to a fake committee.
  2. They anchor `c_h` (a hash only) within 6 h of the certificate timestamp.
  3. An operator kicks off a forged reimbursement. A watcher challenges.
  4. The operator asserts with a valid SNARK. No disprove is possible, so `Take2` steals `D_bucket`.
  5. At no point is any certificate byte published: not in the kickoff (`pubInputHash`), not in the assert (WOTS intermediates of the Groth16 verifier), not in the anchor (`c_h`).
  6. `SubmitInvalidCertProof(cert)` and `SubmitEquivocationProof` need the certificate, and nobody but the cartel has it. **No Pillar is slashed.** The cap rule rests on an expected slash that never happens.
- **Failure trace (b), the slashing window is shorter than claimed:**
  1. Even if certificates were published, a cartel can wait until each of its 21 members is inside its own revoke window (worst case ≤ 90 d, best case same-day for some members).
  2. Each member revokes and withdraws 14 days later.
  3. A certificate signed on day `t` by a member who revokes on day `t` is unslashable from day `t + 14`.
  4. So "`E_anchor` < 60 d ⇒ all signers since `E_anchor` slashable" is false for any signer older than 14 days.
- **Failure trace (c), the anchor link is chosen by the prover:**
  - `recentBtcBlockHash` is WOTS-committed by the kickoff's own operator, and no leaf checks that it is canonical or recent. R3-H3 fix item 3 (a disprove path) was not adopted.
  - The "≤ 432-header PoW link" therefore only proves that the anchor lies within 432 blocks of *some* real block that the prover chose.
- **Minimal fix:**
  1. **Data availability for certificates.**
     - `W_kick` (or `AssertStartTx`) MUST commit `certSetDigest = H(targetCert ‖ handoffCerts[E_anchor..E_t])`.
     - The full certificate set MUST be published, either in `AssertStartTx` witness or `OP_RETURN` chunks, or by a `PublishReimbursementCerts` call on Zenon before the kickoff.
     - Add a disprove leaf for "published bytes ≠ `certSetDigest`", and a disprove leaf for "certificate data never published", using the `AssertStart` timeout as the burn.
     - Then any forged certificate signed by real keys becomes evidence for `SubmitInvalidCertProof`.
  2. **Post-service stake lock (U2).** A Pillar that sat on finality committee `E` cannot complete `Revoke` until `E_time + E_anchor_max_age + T_round_max + 14 d`. Restate the bound in the oracle as `min post-signing slashability ≥ E_anchor_max_age + lane lifetime`.
  3. Either add a disprove leaf on `recentBtcBlockHash` (non-canonical, or older than `X` blocks before the kickoff confirmed, using a watchtower header chain), or delete the "≤ 432 link" claim and the defense attributed to it.
  4. Restate Assumption 1 honestly until (1) and (2) are specified: "no 21-of-30 collusion in any committee from `E_anchor` onward; slashing is ex-post only if certificates become public."

---

### 2.2 MEDIUM

| ID | Title | Spec | Failure trace | Minimal fix |
|---|---|---|---|---|
| **R4-M1** | The fronting-slot expiry is always in the past, so R3-M4 is still open | `SPEC.md:68` (`slotExpiryBtcHeight = tip + 24`); `spec/03:36` (Settlement's only BTC height is `lastFinalizedTipHeight`); `spec/03:177`; `spec/02:147` | `ClaimFrontingSlot` runs on Settlement, so `tip` there is `lastFinalizedTipHeight`. That trails the real Bitcoin tip by ≥ the 48 h window (~288+ blocks; `script:306-308` itself sizes the lag at 472). So `slotExpiry = staleTip + 24 < h_front` for every real fronting, and `spec/02:147`'s exclusivity branch is never taken. Two operators race to front; the loser pays `D_bucket` to the user unreimbursably (R2-M7(3) / R3-M4 trace). Separately, **`FreeLaneCount` (`spec/03:53,177`) is never incremented or decremented by any specified operation**: Zenon has no information about Bitcoin-side lane cooldown. | Compute the expiry **inside the domain** when `PEGOUT_SLOT_CLAIMED` is processed (`ChainMeta.BestTipHeight + 24`), or compare the fronting header's `nTime` with a Zenon-timestamp expiry (`slotExpiryTs`). Define how `FreeLaneCount` is maintained (decrement on slot claim, increment on `ClaimReimbursementSlot` + 792 blocks), or delete the check. |
| **R4-M2** | `RegisterOperatorRound` is unauthenticated, so the Zenon slash and vault recovery can be evaded | `spec/02:109,139`; `spec/03:178`; `spec/05:91` | The operator registers `OperatorBondOutpoints[m‖r]` itself. Registering bogus outpoints means a real `BondOut` burn on Bitcoin never matches `0x0D`: `BTC_OPERATOR_SLASH_PROOF` fails, so the "100% Zenon bond" deterrent is void. `BTC_VAULT_RECOVERY_PROOF` fails too, so `d` is never synced, which makes R4-H2(b) a permanent halt. The same input also writes `RecognizedBindings` (`spec/02:139`), so any operator can extend a set that should be governance-controlled. | Registration MUST carry a `CommitteeIdentityKey` (or `Q_graph`) signature over `(operatorId, roundId, bondOutpoint, T_anchor_expiry)`, or an SPV proof of `RoundGenesisTx` together with the deterministic pre-signed txid chain. Move `RecognizedBindings` writes to governance or binding migration. |
| **R4-M3** | The `RecoveryVaultUTXO_d` graph cannot be pre-signed, and recovered outpoints are made assignable without graphs | `SPEC.md:57` ("depth-1 `RecoveryVaultUTXO_d` graph" co-signed at deposit setup); `spec/01:87` (Out 2 is *watcher-added*); `spec/03:180` (inserted as `UNASSIGNED`) | `WrongDepositDisproveTx`'s txid depends on the free Out 2, so `RecoveryVaultUTXO_d`'s outpoint is unknown until it is broadcast. No `Take1`/`Take2` for it can exist beforehand. `SyncRecoveredVaultOutpoint` makes it `UNASSIGNED`, so `RequestPegOut` can assign it to a peg-out. The fronting operator holds no graph and can never be reimbursed (an R2-M7 recurrence). Re-graphing needs **all N** `Q_graph` members: one lost member freezes the recovered BTC forever. | Insert the recovered outpoint as `QUARANTINED` until a signed re-graph attestation (CommitteeIdentityKey over `(recoveryOutpoint, bitmask, epoch)`) is relayed. Alternatively, fix the txid by making Out 2 a pre-committed watcher-pool key; this also addresses R4-M5. Correct `SPEC.md:57`. |
| **R4-M4** | The `roundId` namespace is undefined across lanes and round-chain epochs | `spec/01:50` (`RoundKickoffTx_{m,l,r}`, `r ∈ 0..R−1` per lane); `spec/01:83,99` (Leaf 3 hardcodes `(operatorId_m, roundId_r, E_anchor)`); `spec/01:101`; `spec/03:178` | If `roundId_r` is the per-lane index (as the notation reads), lane 0 round 5 and lane 1 round 5, or epoch 1 round 5 and epoch 2 round 5, share the hardcoded `(m, 5)`. The record bound to `(m, 5)` then satisfies **both** SNARKs: two reimbursements for one fronting, regressing R3-C2. The `0x0D` key `opId‖roundId` implies uniqueness, but no text defines it. | Define `roundId` as a u32 unique per operator over all lanes and epochs, e.g. `epoch(8b)‖lane(4b)‖index(20b)`. Hardcode it at setup. `ClaimReimbursementSlot` MUST require a registered round (R4-M2) and keep a `RoundUsed[m‖roundId]` set. |
| **R4-M5** | Watcher P&L is −`F_assert` against **every** rational fraudster, not only under miner MEV; the watcher capital requirement and Zenon bond size are undisclosed | `SPEC.md:96`; `spec/01:93,108-113`; `script:220-229` | A challenged fraudster compares losing to a watcher disprove (`F_assert − f_asrt − 3.10` ≈ −1.95 BTC) with self-disproving (`−0.20`) or self-timeout (`−0.40`). It always self-slashes, front-running with `AssertEnd`+`DisproveTx` as a package to a private miner, and captures Out 1. The challenger's net is then **−(1.15 + f_chal)** in every fraud case (recomputed −1.1500 / −1.1600). The positive figures `WatcherDis +0.115..+0.599` and `WatcherTO +0.385..+0.400` are unreachable against an adversary. Safety therefore rests on an *honest* (altruistic) watcher with ≥ 1.16 BTC × concurrently-fraudulent lanes of liquid capital (**≈ 11.6 BTC** for the pilot's 10 lanes), which is not stated. `OperatorBond_ZNN/QSR` (`spec/03:53,179`) is **never quantified**, so "100% Zenon bond" cannot be evaluated. After a slash, the operator's *other* lane keeps live Bitcoin graphs, and later fraud on it risks only 0.2–0.4 BTC. | Restate Assumption 3 ("1-of-N altruistic, capitalized watcher; challenge EV = −F_assert"). Specify the minimum `OperatorBond_ZNN` (≥ `D_bucket` × lanes × price × safety factor). Better still, fix the watcher's payout: pre-commit Out 1 of every burn or disprove to a registered watcher-pool key (making it `SIGHASH_SINGLE`-locked), and refund `F_assert` to the challenge's funding script. This also cures M-03. |
| **R4-M6** | The scope of the WOTS message encoding and checksum is unspecified where Script compares fields | `spec/01:26` (generic `w = 4` + checksum); `spec/01:80` (trap `W_kick != outpoint_d`); `spec/01:83` (Leaf 3 binding verifier); `script:37` ("76-nibble") | The trap and Leaf 3 fire when a committed **field** differs from a constant or another commitment. If the checksum covers the whole 204 B `W_kick` rather than each compared field, a griefer can hash-forward any digit of the honest operator's revealed `claimedOutpoint` chain. That yields a valid-looking signature on a *different* outpoint, so the "mismatch" makes the trap or Leaf-3 disprove fire against an **honest** operator: its bond is burned and its escrow diverted. | Normatively require independent WOTS keys with a **per-field checksum** for every field that Script compares (`claimedOutpoint`, and each Leaf-3-bound public input). Add a MUST-fail vector: "digit-forwarded field ⇒ checksum rejects". |
| **R4-M7** *(non-blocking; G-2-linked)* | The assert economics are a knife edge on an optimistic assumed weight | `spec/01:7,83`; `script:34,202,231` | `HonestChallengedOp = F_assert − W_assert·500 sat/vB − 0.005 BTC` breaks even at **229 kvB** against an ASSUMED 220 kvB (4% headroom). At w = 4 with 20 B preimages, 220 kvB ≈ 650 WOTS-committed 256-bit values, which is low for a 1,200-chunk Groth16 split (each chunk boundary commits intermediates). Consensus limits each input's stack to 1,000 elements (≈ 14 committed values per input), which constrains the chunk layout. The DAG table gives `AssertChunk_i` no CPFP anchor (`spec/01:83`), contradicting invariant 3 (`spec/01:73`). | Make `F_assert` a **parametric invariant**: `F_assert ≥ 1.1 × (W_assert_measured + W_take2) × FeeCeil`, with `DisproveBurn`/`TimeoutBurn` derived from it. Have the oracle print the break-even weight. Add the chunk anchors to the table. This is settled at G-2. |

### 2.3 LOW / ERRATA

| ID | Erratum | Location | Correction |
|---|---|---|---|
| **R4-L1** | R3-L1 is only partly fixed. `master` line numbers are still cited as `release`/`dev` ground truth: `consensus/consensus.go:20,55` (`dev` 45, 86); `htlc.go:75` (`dev` 92); `rpc/api/subscribe/api.go:162` (`dev` 357); `verifier/momentum.go:154` (`dev` 198/204); `chain/nom/account_block.go:177` (`ComputeHash` is at `dev` 283). `spec/05:6` claims they were all verified. | `SPEC.md:106`; `spec/03:213`; `spec/04:64,97`; `spec/05:21,51,109,111` | Re-cite against `770e893`/`f19955f`, or prefix with `master:` |
| **R4-L2** | Overclaims remain (R3-L2): "cannot escape" with no assumption qualifier; "ZERO backing loss" (false under R4-H2(b)); "100% redeemable via G-21"; "every in-scope committee retains 100% locked slashable collateral" (R4-H3(b)); "depth-1 `RecoveryVaultUTXO_d` graph" (R4-M3); "Every operator-broadcast tx carries … CPFP anchor" (no anchor on AssertChunk) | `SPEC.md:57,71,87,95-96`; `spec/01:44,73-74,93,133`; `spec/03:180` | Restate each as conditional design intent |
| **R4-L3** | The `Q_graph` output key, the vault and recovery tweak derivation, and `N` are absent from `releaseAdapterRef`. The domain cannot check "pays to key-path-only `Q_graph` tweak". The relationship between the `Q_graph` membership and the Setup Committee is undefined. | `spec/02:32,142`; `spec/01:44` | Add `QGraphXOnly(32B)` and the tweak rule; state `N` and the membership rule |
| **R4-L4** | `K ≥ max(12, ceil(2·10/S(h)))` becomes **26** at the ~2032 halving (S = 0.78125). `K` lives in the immutable `ChainBinding.finalityParams`. | `spec/02:42`; `script:311-315` | Add a halving-triggered binding migration, or lower `MaxAggregateInFlightMint` ahead of each halving |
| **R4-L5** | The R3-L10 cap applies per submitter address, so duplicate refunds remain Sybil-able. | `spec/03:126` | Cap per batch globally (e.g., ≤ 16 refundable duplicates per batch) |
| **R4-L6** | Late-rollover protection depends on one Reserve key acting by `h_dep + 120`. | `spec/01:64` | Specify the depositor fallback: broadcast a Leaf-B refund at `h_dep + 144`, since the rollover is RBF-signaled. Add a Reserve-liveness monitor. |
| **R4-L7** | After a trapped substitution, `X` remains in custody but is RELEASED on Zenon and its slot is consumed: orphaned BTC with no defined disposition. | `spec/02:153`; `spec/03:178` | Define an `ORPHANED` status and a governance-gated surplus re-enqueue |
| **R4-L8** | Fee bumping of pre-signed low-fee parents (7 kvB `AssertChunk`, a 32-input `AssertEnd`) relies on 1-parent-1-child package relay. The anchors are `<pk_m>`, not P2A, and the TRUC size limits (10 kvB / 1 kvB child) apply if v3 is used. | `spec/01:73,83` | Execution gate G-1: state the relay policy assumed and test it on Signet |
| **R4-L9** | The fate of the `ChallengeDepositZnn` of sessions or commits opened against descendants of a batch later rejected through its ancestor is unspecified. | `spec/03:168-169` | Refund when `State` became `REJECTED` through an ancestor |
| **R4-L10** | `OPERATOR_ROUND_REGISTERED` doubles as the `RecognizedBindings` writer. | `spec/02:139` | Separate them (see R4-M2) |
| **R4-L11** | `VaultUtxoSet.{eligibleOperatorsBitmask, roundChainEpochId}` is never updated on re-graphing. | `spec/03:45,175`; `spec/01:57` | Add a `RegraphAttestation` system input |
| **R4-L12** | `SubmitInvalidCertProof` slashes "any Pillar signing a SINGLE valid-signature FinalityCertificate". If a *sub-quorum* certificate counts, an honest signer of a not-yet-quorate depth-6 certificate is unprotected by the gadget (which protects only quorum-backed momentums), so R3-M7 reopens. | `spec/04:79,83`; `spec/05:55,58` | State that only dual-supermajority certificates are slashable, or extend the gadget to any momentum the local signer has signed |

---

## 3. Disposition of Round-3 Findings

Legend: **CLOSED** · **PARTIALLY CLOSED** · **STILL OPEN**.

### 3.1 CRITICAL / HIGH

| ID | Status | Evidence / residual |
|---|---|---|
| **R3-C1** | **CLOSED** | Leaf-by-leaf walk of `spec/01:79-87`. `Conn_A` L1/`Conn_B` L1/`Conn_C` L1 need `Q_graph` (signed only for `Take*` with `SIGHASH_ALL`, which binds the other connector). `Conn_A` L2/`Conn_B` L2/`AssertStart:i`/`AssertChunk_i:0` need `Q_round` (deleted; pre-signed children only). `Conn_C` L3..C+2 = `<Q_round> CSVFY <verifier>`. `BondOut` L1/L2 need `Q_round`, and L3 needs `Q_graph`. After `ChallengeTx` spends `Conn_A`, `Take1` is dead, and `Conn_B` can go only to `AssertStart` or to `BurnBondTx` at 288. The escape trace of R3 (`Conn_B` Leaf 2 to self) is impossible. This depends on Assumption 2 (live 1-of-N `Q_graph`), which is honestly disclosed. Residual: R4-M7 (chunk anchors). |
| **R3-C2** | **PARTIALLY CLOSED** | The signed trap (`<Q_graph> CSVFY <WOTS>`), custody routing to `RecoveryVaultUTXO_d`, the bond-only watcher bounty, value balance 0 and single-use `ReimbursementRound` are all done. Residuals: **R4-H2** (Take2 variant, halt race, ceremony order), **R4-M3** (recovery graph), **R4-M4** (`roundId` namespace), **R4-M6** (WOTS field checksum). |
| **R3-C3** | **PARTIALLY CLOSED** | Live `Q_graph` re-graphing, the G-21 invariant on `MINTED_LOCK_V1`, `ClaimFrontingSlot` capacity checks, and throughput modeling (1.82 BTC/day, recomputed) are done. The lifecycle is not closed, stale chains survive, and fresh-anchor capacity is 100: **R4-H1**. |
| **R3-H1** | **CLOSED** | Recomputed: Take1 fee = 1,330 sats, Take2 = 1,000 sats, each with an operator-only `<pk_m>` 330-sat anchor. All operator transactions have bumpable fees (budget table asserted, `script:253-266`). The `BurnBondTx`-without-challenge design is kept, with a 144-block CPFP window, which is acceptable. Residual: R4-L8 (relay policy, G-1). |
| **R3-H2** | **CLOSED** | Four-key registry with holder, lifetime and deletion (`spec/01:41-46`). `Q_ephem_bond` is gone. The `BondOut` slash leaves are `Q_round` (deleted) or `Q_graph`+`pk_m` (live, disclosed). Co-signing is stated as an eligibility precondition. Residual: ceremony ordering (R4-H2(c)) and the `Q_graph` parameters (R4-L3). |
| **R3-H3** | **PARTIALLY CLOSED** | Silent carry-over is removed (signed `CarryOverCertificate`, max 1), and so is the in-circuit carry-over. The 6 h timestamp binding is added. Leaf 4 is honestly deleted. Future-height Case B and the 14 d hold are added. Still open: rotation cannot retire stale chains (**R4-H1**); slashing cannot be reached and the 60 d argument is wrong (**R4-H3**); there is no disprove path for `recentBtcBlockHash` (**R4-H3(c)**). |
| **R3-H4** | **CLOSED** | `OpenChallenge` and `CommitChallenge` must occur before the deadline. Sessions are bounded to +12 h and commits to +1 h. `FinalizeBatch` rejects while either count is > 0 or the parent is unfinalized. `ExecuteChallenge` re-verifies `(State, traceRoot, leaf)` against the current record. Expiry is permissionless. `W_zenon_worst = 60 h` is folded into the timeout and grace values (640 / 2,512 / 558, recomputed). Max delay = deadline + 12 h, not cumulative. |

### 3.2 MEDIUM / LOW

| ID | Status | Note |
|---|---|---|
| R3-M1 | **CLOSED** | BIP-340 signature under `CommitteeIdentityKey` over `(bindingHash, rolloverOutpoint, bitmask, epochId)`; a zero bitmask is rejected (`spec/02:143`). |
| R3-M2 | **CLOSED** | `NextBatchId` is never reused, `parentBatchId` is explicit, and the genesis sentinel is 0 (`spec/03:132-144`). |
| R3-M3 | **CLOSED** | Contiguous `domainInputSeq` with a `DomainInputBySeq` mapping, used in leaves, Continuity and refunds. |
| R3-M4 | **STILL OPEN** | The slot exists, but its expiry is computed from a lagging tip, so it never applies: **R4-M1**. |
| R3-M5 | **PARTIALLY CLOSED** | `0x0D` registry and round-indexed slash proof added. Unauthenticated registration: **R4-M2**. Namespace: **R4-M4**. |
| R3-M6 | **CLOSED** | Mandatory `In 1` plus a double-spend at `h_dep + 120`. Single-key residual: R4-L6. |
| R3-M7 | **CLOSED** (design) | Finality gadget plus ≥ 6-momentum signing depth. Quorum-scope clarification: R4-L12. |
| R3-M8 | **CLOSED** (process) | Weekly governance check plus Guardian TWAP trigger. The rule it serves is hollow until R4-H3 is fixed. |
| R3-M9 | **PARTIALLY CLOSED** | The MEV row is modeled and disclosed. Watcher loss against a self-slashing fraudster (the general case), the capital requirement and the bond size: **R4-M5**. |
| R3-L1 | **PARTIALLY CLOSED** | `token.go:40,43,163-172,330`, `vm.go:204-226`, `embedded.go:108,115-120` and `ptlc.go` were verified on `dev`/`release`. Five `master` cites remain: **R4-L1**. |
| R3-L2 | **STILL OPEN** | **R4-L2**. |
| R3-L3 | **CLOSED** | `poisson_upper_quantile(288) = 353`; `λ = 360×1.10 = 396 ⇒ 472` (both recomputed). 1.10 labeled `ASSUMED`. |
| R3-L4 | **CLOSED** | Aggregate in-flight with halving index: `K_req` = 12 / 13 ≤ 14. 2032 note: R4-L4. |
| R3-L5 | **CLOSED** | `s̃ = s̃_A + s̃_B + e·g_key·t_acc`, matching BIP-327 `PartialSigAgg`. Completion `s = s̃ + g_R·t` and extraction `t = g_R(s − s̃)` are consistent. |
| R3-L6 | **CLOSED** | Exposure is released on finalize and on rejection. |
| R3-L7 | **CLOSED** | The freezing batch is exempt, and Shadow-mode `FinalizeBatch` is permitted. |
| R3-L8 | **CLOSED** | `RecognizedBindings` (`0x0E`) added. Writer coupling: R4-L10. |
| R3-L9 | **CLOSED** | 6-momentum commit priority plus `T_reveal = 1 h`. |
| R3-L10 | **PARTIALLY CLOSED** | Sybil-able per address: R4-L5. |
| R3-L11 | **CLOSED** | Caller, single-use, amount and recorded ZTS checks (`spec/03:19`). |

**Round-3 tally (27):** 18 CLOSED · 7 PARTIALLY CLOSED · 2 STILL OPEN.

### 3.3 Script Items (S3-1..S3-8, S-9)

| ID | Status | Note |
|---|---|---|
| S3-1 | **PARTIAL** | The DAG is now enforceable as modeled. Watcher P&L under operator self-slash front-running is not modeled: S4-2. |
| S3-2 | **CLOSED** | Nine fee-source rows asserted at 500 sat/vB. Minor double-count: S4-3. |
| S3-3 | **PARTIAL** | Capacity and throughput are modeled, but not against the `E_anchor` / lane-lifetime interaction: S4-1. |
| S3-4 | **CLOSED** | `MEVWatcher = −1.1500..−1.1600` (recomputed). |
| S3-5 | **CLOSED** | 353. |
| S3-6 | **CLOSED** | Two halving epochs (see R4-L4). |
| S3-7 | **CLOSED** | +0.0450 BTC at 500 sat/vB, including Take2 and CPFP. Sensitivity: S4-5 / R4-M7. |
| S3-8 | **CLOSED** | Field-by-field derivation of `ChainMeta` 238, `HeaderNode` 160, `PegOutState` 182, `TxStream` 175, leaf 328 (re-summed). Price input labeled `ASSUMED`. |
| S-9 | **PARTIAL** | The constraint count, `L` and `C` are printed but not checked against anything. Acceptable until G-2. |

---

## 4. Verified-Sound Mechanisms (new in v2.2; do not re-litigate)

- **The escape-proof connector set (R3-C1).** Every round-level leaf is `Q_round`- or `Q_graph`-gated, and `ChallengeTx` is a terminal `SIGHASH_SINGLE|ACP` sink. Self-funded challenges are harmless (net 0) and only force the assert path.
- **Trap-window timing.** Take1 must confirm before 288 (otherwise a free `BurnBondTx` pays any watcher 1.55 BTC). Take2 must confirm before `AssertEnd + 216 ≤ 648`. Trap windows therefore close by 360 and 720 respectively, both before `BondOut` Leaf 2 opens at 792. The operator cannot consume `BondOut` inside a trap window.
- **The `WrongDepositDisproveTx` dual `SIGHASH_SINGLE` (no ACP) construction.** In 0 → Out 0 (recovery), In 1 → Out 1 (burn), Out 2 free. Value balance: `0.99899 + 3.10 − (0.99899 + 2.10 + 1.00) = 0`. Fix only the variant count and race (R4-H2).
- **Fee arithmetic.** Take1 = 1,330 sats and Take2 = 1,000 sats base fee; `Burn + Watcher = 3.10` on every slash path (1.35 + 1.75, 1.55 + 1.55, 2.10 + 1.00).
- **Bounded challenge sessions and commits (R3-H4)**, never-reused lineage (R3-M2) and `domainInputSeq` (R3-M3).
- **The hardened `ReceiveTreasury`** and **the BIP-327-tweaked PTLC aggregation**.
- **Signed, bounded `CarryOverCertificate`.** No silent in-circuit skips.
- **Oracle numerics:** depth-256 `UploadWitnessProof` 8,676 B; fast paths ≤ 10,148 B; Continuity 1,700 B; Poisson 353 / 472; `K` 12 / 13 ≤ 14; timeouts 640 / 2,512; grace 558.

---

## 5. Go / No-Go Gate Checklist (Round 4)

**Status: NO-GO (design) — HOLD.** Gates marked ⚙ do not block design sign-off.

| Gate | Status | Blocking items |
|---|---|---|
| G-1 (graph causality and enforceability) | ◐ PARTIAL | R4-H2, R4-M6; ⚙ Signet build and relay policy (R4-L8) |
| G-2 (measured weights) | ⚙ GATE | R4-M7 sensitivity |
| G-3 (finality proof) | ◐ PARTIAL | R4-H3, R4-L12 |
| G-4..G-6 | ✅ CLOSED | |
| G-7 (fronting and fees) | ◐ PARTIAL | R4-M1 (fees ✅) |
| G-8 (traceRoot) | ✅ CLOSED | |
| G-9 (witness bound) | ✅ design / ⚙ fuzzer | |
| G-10 | ✅ CLOSED | |
| G-11 (mint model) | ✅ design / ⚙ test | |
| G-12 (lock-proof hardening) | ✅ CLOSED | (R4-L3 hygiene) |
| G-13 (timeouts, eligibility, halt) | ◐ PARTIAL | R4-M1, R4-M3 |
| G-14 (input DoS) | ✅ CLOSED | (R4-L5 hygiene) |
| G-15 (epoch committee) | ◐ PARTIAL | R4-H3(b) |
| G-16 | ✅ CLOSED | |
| G-17 (upstream) | ⚙ ESCALATED | Ratification (not a design blocker) |
| G-18 (peg-free rails) | ✅ design / ⚙ tests | |
| G-19 (numbers from scripts) | ◐ PARTIAL | S4-1, S4-2, S4-5 |
| G-21 (capacity ≥ supply) | ❌ OPEN | R4-H1 |
| **G-22 (NEW) round-chain lifecycle and bond exit** | ❌ OPEN | R4-H1 |
| **G-23 (NEW) certificate data availability for slashing** | ❌ OPEN | R4-H3 |
| G-20 (independent re-review) | ✅ this document; **Round 5 required** | |

---

## 6. Audit of `scripts/verify_spec_bounds.py`

The script ran cleanly (exit 0). Independently recomputed:
- `poisson(288) = 353`, `poisson(396) = 472`, `poisson(360) = 433`;
- Take fees 1,330 / 1,000;
- WDD balance 0;
- self-disprove −0.2032 at 1 sat/vB and −1.775 at 500;
- break-even assert weight 229.0 kvB at 500 sat/vB;
- lane lifetime 352 d;
- fresh-anchor rounds per lane = 10 (60 d) and 9 (50 d);
- concurrent generations 8, giving 248 BTC.

### 6.1 New Script Defects

| # | Defect | Location | Effect |
|---|---|---|---|
| S4-1 | The capacity model ignores `E_anchor` against lane lifetime. `ROUND_ANCHOR_MAX_AGE_DAYS < PILLAR_LOCK_DAYS` is a constant tautology, and 640 includes stale-anchor rounds. | `script:271-296` | Hides R4-H1 (fresh-anchor capacity = 100, G-21 headroom = 0) |
| S4-2 | Watcher P&L assumes the watcher captures Out 1. Operator self-slash front-running, where the watcher gets −(F_assert + f_chal), is labeled "MEV" only. | `script:220-229` | Overstates watcher incentives (R4-M5) |
| S4-3 | `F_assert` is charged independently as the budget for both the Take2 and Assert rows. | `script:257-258` | Double-count. The combined 1.105 ≤ 1.15 still holds, but should be asserted jointly. |
| S4-4 | No bond-capital model for rotation, and no bond-exit model | — | Hides R4-H1(B) |
| S4-5 | No break-even output for the assert weight; `F_assert` is a constant rather than derived | `script:202,231` | R4-M7 sensitivity is invisible |
| S4-6 | Slashability is modeled as an 83 d lock, not as per-Pillar phase plus the 14 d hold | `script:291-292` | Hides R4-H3(b) |
| S4-7 | `L`, `C` and the constraint count are printed, never checked (S-9 carry-over) | `script:195` | Acceptable until G-2 |

### 6.2 Reproduction

```python
import math
def q(lam,p=1e-4):
    c=0;k=0
    while True:
        c+=math.exp(-lam+k*math.log(lam)-math.lgamma(k+1))
        if 1-c<=p: return k
        k+=1
print(q(288), q(396))                                   # 353 472
print(64*792/144, math.floor(60/(792/144)))             # 352.0 10
print(10*math.floor(60/(792/144)) - 100)                # 0  (G-21 headroom under fresh-anchor accounting)
print((1.15-0.005)*1e8/500/1000)                        # 229.0 kvB break-even
print(1.15-220000*1/1e8-1.35-95000*1/1e8, -(1.15+2000*500/1e8))  # -0.2032 ; watcher -1.16 vs self-slasher
print(math.ceil(352/50)*31.0)                           # 248.0 BTC concurrent bonds
```

```text
dev:vm/embedded/implementation/pillars.go:132-138  epochTime = (now - RegistrationTime) % (83d+7d); revocable iff epochTime >= 83d  (per-Pillar phase)
dev:vm/embedded/implementation/pillars.go:395-400  Revoke: RevokeTime=now; Amount=0; descendant send refunds PillarStakeAmount immediately
```

---

## 7. Required Actions Before Round 5 (Priority Order)

1. **R4-H1, the round-chain lifecycle:**
   - add a `RoundRetireTx` bond exit;
   - add an absolute-CLTV `StaleChainBurnTx` at `E_anchor + 60 d`;
   - set `R ≤ 10`;
   - make G-21 count only fresh-anchor rounds;
   - add oracle assertions for lifetime ≤ anchor age, fresh capacity and concurrent bond capital.
2. **R4-H2, the trap:**
   - two `WrongDepositDisproveTx` variants (T1 and T2);
   - normative ceremony order (trap signatures before Take signatures);
   - a graph-aware `BTC_VAULT_SPEND_PROOF` with a `PENDING_TRAP` window;
   - MUST-fail vectors.
3. **R4-H3, Assumption 1:**
   - certificate-set digest in `W_kick`/`AssertStart`, plus publication with data availability and disprove leaves;
   - a post-committee-service stake lock in U2;
   - a `recentBtcBlockHash` disprove path, or deletion of the claim;
   - restate Assumption 1.
4. **R4-M1..M6:**
   - domain-computed slot expiry;
   - authenticated round registration;
   - quarantine recovered UTXOs until re-graphed;
   - a unique `roundId` namespace with a `RoundUsed` set;
   - restate the watcher assumption and quantify `OperatorBond_ZNN`;
   - per-field WOTS checksums.
5. R4-L1..L12, and S4-1..S4-6.

**Not blocking design sign-off (correctly gated in `SPEC.md §6–§7`):**
- G-1 Signet build and relay-policy tests;
- G-2 measured weights (including R4-M7);
- G-9 adversarial SMT fuzzer;
- G-11 `IssueMinted` test;
- G-18 swap suite;
- the Groth16 CRS ceremony (`K ≥ 50`);
- ratification of A-SPEC-1..6, A-BTC-1 and A-MINT-1.
