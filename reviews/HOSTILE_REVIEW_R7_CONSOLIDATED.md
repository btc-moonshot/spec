# zBTC v2.5.0-rfc: consolidated hostile review

Nov 26, 2026 · @trev

## Verdict

**NO-GO for a Signet build (Stage 0C) or any pilot with real BTC.** More parameter tuning won't fix this. The BitVM2 mechanics are carefully engineered and internally consistent, but three things are wrong underneath them:

- **What the vault trusts.** BitVM2 pays out whenever Zenon's state root says `RELEASED` and a 21-of-30 Pillar BLS committee has signed it. The vault's security ceiling is therefore Zenon itself: its Pillars, its optimistic-batch challengers and its upgrade keys.
- **What that trust is worth.** Every slashing and bond deterrent is priced in ZNN at an assumed 10,500 ZNN/BTC. Market quotes this week put it at 400,000–727,000 ZNN/BTC, so each deterrent is worth 1.4–2.6% of its stated value.
- **What it costs on Bitcoin.** The assert and disprove sizes behind every fee and bond figure are 4–10× below published BitVM2 measurements. If the published numbers hold, an honest operator who gets challenged loses money even at moderate fee rates.

The custody key is also weaker than claimed. `Q_graph` is an N-of-N key (N ≥ 7) that is never deleted and has key-path control of every vault. All N signers can sweep everything, and losing any one of them bricks every vault not redeemed within about 56 days.

**What the spec actually is**, stated honestly: a 7-of-7 federation with fraud-proof-constrained reimbursement, whose payout rule is "a 2/3 committee of a small proof-of-stake chain signed this state". That is closer to a PoS-validated sidechain peg than to trust-minimized BitVM2.

**To its credit**, the spec is unusually candid. It says Tier 1A is not trustless, prints the watcher's negative expected value and labels its unmeasured inputs `ASSUMED`. Much of this review follows those admissions to their consequences.

**Basis.** This review merges three hostile reviews of the spec (Nov 24–26, 2026), checks their arithmetic, settles where they disagree, and spot-checks their key outside claims. Scope and limits are at the end.

## Findings at a glance

There are 31 findings: 4 Critical, 8 High, 15 Medium and 4 Low. The "Source" column shows which input review raised each one: R1 is "Feeless Settlement Lattice" (Nov 24), R2 is "vs go-zenon 0.0.11-rc2" (Nov 26) and R3 is "R7" (Nov 26). "New" marks points this consolidation added.

| ID | Severity | Finding | Spec ref | Source |
| --- | --- | --- | --- | --- |
| C-1 | Critical | Security is paid in ZNN at an assumed price 40–70× too high; a 21-signer forging cartel risks about 0.4–0.8 BTC against a 15 BTC cap | SPEC §4, §9; oracle :51 | R1, R3 (R2 as a note) |
| C-2 | Critical | Fraudulent but canonical Zenon state (an unchallenged batch, censorship or an upgrade) is certified honestly, and the vault pays out against it | Part 1 §2; Part 3 §3.2; Part 4 §3.3 | R3 |
| C-3 | Critical | The BitVM2 assert (220 kvB) and disprove (≤ 95 kvB per leaf) sizes are 4–10× below published measurements, which breaks the bond and fee economics | Part 1 §3.4–3.5 | R2 |
| C-4 | Critical | `Q_graph` is a never-deleted N-of-N with key-path control of every vault: all N can sweep, one loss bricks unredeemed vaults, and there is no recovery path | Part 1 §1, §3.1, §7 | R1, R2, R3 |
| H-1 | High | Committee seats go by delegated ZNN at one snapshot; delegation is free and instant, but only the 15k self-stake is slashable | Part 4 §3.1 | R3 |
| H-2 | High | ≥ 10 committee seats can withhold certificates and profitably burn an honest operator's bonds; withholding isn't slashable | Part 4 §3.3; Part 1 §3.4 | R3 |
| H-3 | High | Upgrade and Plasma authority is custody authority: two single spork keys today, with no on-chain Pillar vote, and none of it listed in §4 | Part 5; Part 1 §8; Part 3 §5 | R1, R3 |
| H-4 | High | The challenger fronts 1.45 BTC and may never be repaid; safety rests on altruistic watchers with 14.6 BTC on hand | Part 1 §3.4–3.5 | R1, R2, R3 |
| H-5 | High | Exit liveness is missing from the threat model; exits run at about 1.8 vaults/day, and a failed exit is refunded in zBTC | SPEC §3.3, §4; Part 3 §4 | R1, R2, R3 |
| H-6 | High | Bitcoin fees and block times already broke the design envelope (2024, 2021); a fully used lane tolerates only 1.287× slow blocks | Part 1 §8, §10 | R1, R3 |
| H-7 | High | Long-range defense depends on timely anchoring of every epoch handoff, which is unpaid and not a listed assumption | Part 4 §1, §4 | R1 |
| H-8 | High | All 21M zBTC is pre-minted into an embedded contract; one dispatch bug can release up to the full supply, and the fix needs a spork | Part 3 §1 | R1 |
| M-1 | Medium | Settlement and the Bitcoin domain expire fronting slots on different clocks, so an operator can front 1 BTC and never be reimbursed | Part 2 §4.3; Part 3 §3.4 | R2, R3 |
| M-2 | Medium | Two colluding operators can alternate slot lapses and hold a peg-out for its whole timeout for about $6–8k | Part 3 §3.4 | R2, R3 |
| M-3 | Medium | The pinned node release is superseded, rc2 ships a hash-verification regression, and embedded-failure provenance is still open upstream | Part 5 U0 | R2 |
| M-4 | Medium | The PTLC swap has a 12-block refund window, a "broadcast" rule where "confirmed" is needed, and free options for both sides | Part 3 §5.1, §7 | R1, R2, R3 |
| M-5 | Medium | Valid but useless inputs are refunded, and unconsumed stream state is never pruned | Part 2 §5; Part 3 §3.1 | R2 |
| M-6 | Medium | Leaf 3B (a full SHA-256 compression without `OP_CAT`, in ≤ 95 kvB and 470 free stack slots) is unproven, and the R6-H1 fix depends on it | Part 1 §3.4 | R3 |
| M-7 | Medium | Admission control runs after irreversible custody, so deferred deposits can be stranded | Part 1; Part 3 | R3 |
| M-8 | Medium | If Zenon censors a release proof, an honest fronter pays twice: the user keeps the BTC and is also refunded in zBTC | Part 3 §4 | R3 |
| M-9 | Medium | "Feeless" capacity is about 9 tx/s by default and 4,400 tx/s at the ceiling, and one key can throttle it | SPEC §3.2; Part 5 U0 | R1 |
| M-10 | Medium | Momentum time is about 11.4 s, not 10 s; finality today is a node-local 30-Momentum rollback limit | Parts 3–5 | R1 |
| M-11 | Medium | Certificates for heights in `(frontier, frontier + 60]` are unslashable while the chain stalls | Part 4 §3.3 | R1, R3 |
| M-12 | Medium | The Setup Committee can divert in-flight deposits and inflate G-21 with phantom rounds | SPEC §4 #4 | R1 |
| M-13 | Medium | Precedence ranks Bitcoin enforcement (Part 1) below the Zenon contract parts | SPEC §2.1 | R1 |
| M-14 | Medium | Safety-critical parameters are TBD or `ASSUMED`, and the oracle only checks the spec against itself | Parts 1–5; oracle | R1, R2, R3 |
| M-15 | Medium | v2.5.0 has had no independent review, and all R6 closures are self-declared | Reviews index | R1, R3 |
| L-1 | Low | Behavior is undefined with fewer than 21 BLS-registered Pillars, and so is U2 fork choice between certified branches | Part 4; Part 5 U2 | R3 |
| L-2 | Low | The disclosed mint-stall window is 5.5 days per cycle, not about 5.0 | Part 3 (G-21) | R3 |
| L-3 | Low | Stale-acknowledgement evaluation is fixed in `dev`, but only once `DynamicPlasmaSpork` enforces | Part 3 §1; Part 5 | R1 |
| L-4 | Low | Errata, plus public claims the spec doesn't support | Various; bigidea page | R1, R2, R3 |

## Critical findings

### C-1. Security is paid in ZNN at a price 40–70× too high

The spec sizes every ZNN-denominated safeguard at an `ASSUMED` 10,500 ZNN/BTC (`verify_spec_bounds.py:51`), and says "the whole governance cap derives from this." Market quotes from this week give a different picture:

- ZNN at $0.0877 on CoinMarketCap (Nov 26), with no recorded 24 h volume, and $0.12–0.16 on CoinGecko, with essentially one active market.
- BTC at about $64,000.
- That gives a rate of **about 400,000–727,000 ZNN/BTC**.
- ZNN's whole market cap is about $1.6–2.1M, roughly 25–33 BTC. The 15 BTC pilot cap alone is half of it or more.

| Safeguard | ZNN | BTC at the spec's 10,500 | BTC at 400,000 | BTC at 727,000 |
| --- | --- | --- | --- | --- |
| One Pillar's slash for a forged certificate | 15,000 | 1.43 | 0.038 | 0.021 |
| Minimum forging cartel (21 signers) | 315,000 | 30 | 0.79 | 0.43 |
| Operator bond ("≥ 3.0 BTC equivalent") | 31,500 | 3.0 | 0.079 | 0.043 |
| Fronting slot bond | 500 | 0.048 | 0.0013 | 0.0007 |
| Supply cap rule (`MaxRepresentationSupply × price ≤ 157,500 ZNN`) | 157,500 | 15 | 0.39 | 0.22 |

**Attack.** A 21-seat cartel signs a forged `RELEASED` certificate for each vault and has a colluding operator assert it. The circuit accepts, and `Take2` pays out. The cartel's worst case is losing about 0.4–0.8 BTC of stake against 15 BTC stolen.

The real penalty is lower still, for three reasons:

- **Wrong-way risk.** Slashing lands after the theft is public, when ZNN has likely collapsed.
- **Shorting.** A cartel can short ZNN, or wait for a drawdown, before it acts.
- **No restitution.** The spec says where bonds are forfeited, not where slashed ZNN goes, so zBTC holders get nothing back.

**The safeguards can't be measured either.** The guardian TWAP "across ≥ 3 venues" can't be satisfied with one market and near-zero volume. No price feed from such a market can safely drive a circuit breaker.

**Required change.**

- Remove the constant. Set the cap from measured slashable value with a stress haircut: `supply ≤ α · slashableStake · price_min`. Applied honestly today, that caps the bridge well under 1 BTC.
- Or denominate finality-signer and operator bonds in BTC, and stop counting ZNN in the security case.
- Route any slashed value into a restitution pool for zBTC holders.
- Publish an operator P&L at realistic fee and capital-cost assumptions. `minOperatorFeeSats` is never defined.

### C-2. Honest certificates over a dishonest canonical state

The BitVM2 circuit never re-executes Zenon. It proves that a record (`PegOutRecord`, `BatchCommitmentV3`, `ResolutionSeenByOutboxId`) says `RELEASED`, or that a lock happened, inside a state root that ≥ 21 Pillars signed. `SubmitInvalidCertProof` slashes only a certificate that disagrees with *canonical* Zenon state.

Any way of making canonical state itself wrong therefore bypasses all of the slashing:

1. **No challenger online.** An executor posts a batch with a fake `FOREIGN_LOCK` (unbacked zBTC) or a fake `FOREIGN_RELEASE` (no fronting). Nobody calls `CommitChallenge` within 48 h, and it finalizes.
2. **An upgrade.** A spork changes Settlement semantics (see H-3).
3. **Censorship.** Producers exclude the challenge for 48 h. This path is weaker than the source review assumed: a 21-of-30 cartel produces only about 35–40% of Momentums (see "Where the reviews disagreed"). It still needs analysis, because the 10-slot priority lane is each producer's local mempool rule, and the Momentum verifier doesn't check what was included.

In each case honest committee members sign accurate certificates, and nothing is slashable.

- **A fake release** lets a colluding operator reimburse itself from a victim's vault.
- **A fake mint** lets the attacker peg out real BTC, which honest operators front and then recover from the vaults.

The 10 BTC in-flight cap limits mints only per 48 h window, and it resets on finalization. Releases aren't mint-capped at all, so repeated windows can drain the whole vault set. Threat-model item #6 names optimistic admission but never states this consequence on the Bitcoin side, and no R1–R6 fix addresses it.

**Required change.**

- Add the explicit assumption: "1-of-N live Zenon challenger, *and* 48 h censorship resistance of Zenon," with a producer-selection analysis behind it.
- Move to ZK validity proofs (the spec's Phase 3) *before* any BTC is at risk, not after.
- Have the circuit verify the fronting payment against Bitcoin headers directly, so a fake `RELEASED` can't reimburse an operator who never paid.

### C-3. The BitVM2 cost model is 4–10× below published measurements

The operator's assert allowance (`F_assert` = 1.45 BTC), the per-round bond (3.70 BTC) and the whole incentive table (Part 1 §3.5) rest on two `ASSUMED` sizes: a 220 kvB Groth16 assert over 32 chunks, and ≤ 95 kvB for each of the 1,200 disprove leaves. At the spec's own 95.5 WU per W-OTS digit, 220 kvB is about 9,215 digits, or roughly 138 committed field elements.

Published BitVM2 figures are far larger:

- [Alpen (Oct 2024)](https://www.alpen.org/blog/state-of-snark-verification-with-bitvm2): 611 bit-commitments, an assert of about 4.8 MB and a disprove of 3.5–4 MB.
- [Citrea](https://www.blog.citrea.xyz/clementine-v2-with-garbled-circuits-and-toop/): BitVM2 asserts of about 1.3 MB.
- [USENIX '26 mainnet run](https://www.usenix.org/system/files/usenixsecurity26-woll.pdf): 14.9M sat in total, 10.99M sat of it in the disprove.

Re-pricing Alpen's 611 commitments with the spec's own W-OTS cost (611 × 67 digits × 95.5 WU) gives **about 977 kvB, 4.4× the assumption**. I re-ran this arithmetic and it checks out.

| Quantity | Spec (220 kvB assert) | Re-priced (977 kvB assert) |
| --- | --- | --- |
| Assert + certificate data + Take2 | 251 kvB | 1,008 kvB |
| Fee rate where `F_assert` = 1.45 BTC breaks even | 578 sat/vB | 144 sat/vB |
| Honest challenged operator, net @ 200 sat/vB | +0.95 BTC | −0.57 BTC |
| Honest challenged operator, net @ 500 sat/vB | +0.20 BTC | −3.59 BTC |
| `F_assert` under the spec's +15% rule @ 500 sat/vB | 1.45 BTC | 5.80 BTC |
| Per-round bond under the spec's formula | 3.70 BTC | about 12.40 BTC |
| Peak BTC bonds (10 lanes × 2 generations) | 74 BTC | about 248 BTC |

**On the disprove side the gap is narrower than R2 claimed.** Alpen's 3.5–4 MB disprove comes from an unchunked design, about 10× Bitcoin's 400 kWU standardness limit. The spec deliberately splits disproves into 1,200 leaves of ≤ 95 kvB each to stay standard. So the honest framing is: *no published BitVM2 build shows leaves that small; it's unproven, and the hardest leaf is M-6.* If leaves end up non-standard, disproving fraud depends on a few mining pools, as [Bitlayer's mainnet](https://blockworks.co/news/bitvm-implementation-stage) did, and the spec has no non-standard submission path.

**Caveat.** Alpen's count is from October 2024, and newer BitVM2 work may have lowered it. The field has meanwhile moved toward garbled circuits: the [BitVM3 paper](https://bitvm.org/bitvm3.pdf) reports an assert of about 2.4 kvB and a disprove of about 93 vB.

**Required change.**

- Re-cost Part 1 from published data now, rather than waiting for Gate G-2. Choose between BitVM2 and a garbled-circuit design.
- Either prove every disprove leaf is standard, or specify a non-standard submission path and its censorship model.

### C-4. `Q_graph` is a standing pooled key that can sweep everything, or brick everything

Part 1 defines each vault as key-path-only:

`Q_vault_d = Q_graph + H("zBTC/VaultTweak/v1", x(Q_graph) ‖ depositOutpoint)·G`

`Q_graph` is N-of-N MuSig2 over the verifier committee (N ≥ 7), and its lifetime is "NEVER deleted." Only the per-round `Q_round` keys are deleted. The tweak is public, so the N holders can jointly sign any spend of any vault. "Daemons ONLY sign valid BitVM2 graphs" is a software policy, not a script constraint. Standard BitVM2 ([ePrint 2025/1158](https://eprint.iacr.org/2025/1158)) needs one honest signer *at setup*, who then deletes their key. zBTC needs 1-of-N honesty "in perpetuity," in the spec's own words.

**Safety failure: sweep.** All N together, or anyone who compromises all N, can key-path-spend every vault at any time without touching the graph. The domain only detects it after the fact (`0x08` → `Halted`). That is a multisig with an alarm, not a covenant. The key also stays online and rotating for the life of every vault, because it re-graphs every 30 days.

**Liveness failure: brick.** Round chains expire on Bitcoin by day 56–58, so all N must re-graph every vault every 30 days. If one member's key is lost for good, no new graph can be signed. After `T_kill` (day 56), the only spend path left on an unredeemed vault is a key that can no longer sign. **The BTC is gone.**

Three things make the liveness failure worse:

- **The wind-down has nothing to distribute.** Item #8 pays out "Governance-released `ORPHANED` vaults," but releasing one needs the very `Q_graph` signature that is lost. When `Q_graph` is intact, a governance release is exactly the custodial sweep C-07 forbids.
- **The forced-exit window is narrow.** Only peg-outs reimbursed before `T_kickoff_cutoff` (day 46) escape. At pilot scale, 80 rounds per generation cover 15 vaults if users act fast and operators front. At any larger scale, every vault beyond lane capacity bricks.
- **The signing load is heavy.** Each vault needs Take1, Take2 and `WrongDeposit^{T1,T2}` for each of 80 operator rounds: 320 N-of-N co-signed transactions per vault per month. That is 4,800 at 15 vaults and 320,000 at 1,000.

**It also contradicts the spec's own claims.** Part 1 calls custodial pooled multisigs "STRICTLY FORBIDDEN" (C-07). The bigidea page says "the network never holds a pooled key." SPEC §4 Assumption 2 describes only the liveness case ("rotations… stop") and not the safety case, which appears only in Part 1 §8.

**Required change.** Pick one model and say so:

- **(a) True BitVM2.** Script-path-only vault outputs with a NUMS internal key, per-deposit or per-generation keys deleted after pre-signing, and graphs that don't expire with finality epochs.
- **(b) An honest federation.** A t-of-N threshold key (for example FROST with resharing) for liveness, plus a long-timelock, non-custodial recovery leaf, explicitly dropping C-07. Then publish signer identities, jurisdictions, HSM attestations and rotation evidence, and make "no full compromise of `Q_graph`, ever" Assumption 1.

Today the spec takes the safety of (a) and the liveness of neither. At minimum, state the permanent-loss consequence in §4, and quantify how many vaults can exit if one key is lost.

## High findings

### H-1. Committee seats can be rented through free, instant delegation

The finality committee is the top 30 Pillars by `totalDelegatedZnn`, snapshotted at a single Momentum `h_trans(E)` (Part 4 §3.1). In go-zenon, `DelegateMethod.ReceiveBlock` only records `DelegationInfo{Backer, Name}`. There is no lock and no slashing. So committee weight is borrowed, while the only slashable amount is each Pillar's 15,000 ZNN self-stake.

**Attack.** Register Pillars (15,000 ZNN locked, plus a QSR burn of 150,000 + 10,000 per Pillar beyond the initial set). Gather delegation for the one snapshot Momentum, from your own coins, exchange-held coins or rented coins, then undelegate. The seats are yours for 30 days. With about 100 Pillars and a token worth about $2M, this is cheap, and C-1 makes the penalty trivial.

The committee (the top 30 by delegation) and the producer set (all Pillars) are different groups, so capturing the committee doesn't require dominating block production.

**Required change.** Weight seats by slashable, time-locked stake: either lock delegations for the epoch plus 72 days and make them slashable, or count self-bond only. Average weight over the whole epoch instead of one snapshot.

### H-2. A certificate stall lets ≥ 10 seats burn honest operators, profitably

A certificate needs popcount ≥ 21 **and** more than 2/3 of the weight. Ten seats can therefore block every certificate, and withholding a signature isn't slashable.

**Attack.**

1. An honest operator fronts 1 BTC to a user and kicks off reimbursement.
2. A watcher allied with ≥ 10 seats challenges, paying `F_assert` = 1.45 BTC to the operator.
3. The 10 seats withhold signatures, so no certificate covering `RELEASED` exists, and the operator can't assert.
4. After 288 blocks, `BurnBond` pays the watcher 1.85 BTC and burns 1.85 BTC.

**Outcome.** The watcher nets about +0.40 BTC, minus fees, if it collects the watcher share (see H-4). The operator loses the 1 BTC it fronted and its 3.70 BTC bond, but keeps the 1.45 BTC challenge payment: **net about −3.25 BTC, plus its full ZNN bond**, and all its lanes are deactivated. (R3 put the loss at 4.70 BTC by leaving out the challenge payment.)

Ordinary Pillar downtime triggers the same outcome with no attacker at all. `ResetFailedReimbursementSlot` covers only stale-kill and retirement, not this case.

**Required change.**

- Define "no certificate covering `RELEASED` within X" as a fault that pauses challenges or extends the assert deadline.
- Exclude a `BurnBond` caused by certificate unavailability from ZNN slashing.
- Add committee liveness to the threat model.

### H-3. Upgrade authority is custody authority

The circuit trusts whatever canonical state Settlement code produces. Whoever can change that code can authorize arbitrary BTC releases, which is a governed emergency exit in all but name. C-07 claims to forbid exactly that.

**Who holds that power today.** In go-zenon `dev`, `CreateSpork`, `ActivateSpork` and `SetPlasmaVariables` accept only two senders:

| Key | Holder | When it may act |
| --- | --- | --- |
| `types.SporkAddress` (`z1qpxswrfnlll355wrx868xh58j7e2gu2n2u5czv`) | Set from genesis | Any time; no window |
| `types.CommunitySporkAddress` (`z1qqvwzz2xq7q5gwk6uhcddgrpxlfcyzc8rsu82s`) | The Mariposa01 Pillar, "a temporary measure until an embedded governance contract is taken into use" | Heights 10,109,240–13,243,712 (2025-04-16 to 2026-04-16) and 14,567,887–19,791,986 (2026-11-03 to about 2028-09-19); the renewal works only on nodes running a release that includes it |

**There is no on-chain Pillar vote.** Pillars influence a spork only by choosing whether to run the release that recognises it. A node that hasn't upgraded halts when the spork enforces. A draft governance ZIP exists (go-zenon PR #47, still open), with one vote per Pillar: a standard spork needs more than 66% participation and more than 50% Yes, and an emergency spork needs Yes from more than 66% of active Pillars within 7 days. The spec's own U5 `GovernanceContract` is instead Pillar *stake-weighted* (≥ 33% quorum, > 66% approval), whose weight comes from the free delegation in H-1.

Either way, **the upgrade path and the finality committee are not independent trust roots.** Depending on the threshold, a cartel able to forge certificates may also be able to vote through a code change.

**The spec's own governance and guardian powers are also unlisted.** None of them appears in §4:

- Governance initiates Wind-Down.
- Governance can release `ORPHANED` vaults in the shortfall allocation.
- Governance sets operator bonds weekly.
- Governance can invoke `ResetFailedReimbursementSlot`.
- A guardian can start `DRAINING_ROLLOVER_STOP`, behind a 7-day governance timer.

`PeripheryConfig` names a `guardianMultisig` and a `governanceContract` without assigning either, and no actor is named for pause. Stage 0C is gated on "no single-key SporkAddress," which today's code does not meet.

**One attack runs through the rotation calendar.** Gen g+1 registers by day 32, re-graphing finishes by day 43, quarantine triggers at day 48.5 and the kill expiry is day 56. Anyone who can freeze rollover signing in that window can force quarantine and then wind-down, whatever the operators do.

To its credit, the spec forbids governance from fabricating `RELEASED` or `REFUNDED` records or adding custodial sweep keys. That instinct needs a complete list behind it.

**Required change.**

- Add a privileged-powers table: each power, its holder, threshold, timelock and maximum effect. List both spork keys and the community key's windows in §4, and make legitimate spork authority a Stage 0 gate.
- Freeze vault-relevant semantics (the `RELEASED`/`LOCK` handlers and the `vk_bitvm` inputs) per vault: have the circuit check a `settlementCodeHash` pinned at vault creation, so an upgrade can't touch existing vaults.
- Make any custody-relevant spork wait at least the 72-day exit lock after creation, so finality signers can leave before the rule lands.
- Forbid pause during days 30–46 of a generation unless a deterministic impairment proof is presented.
- Model the Sybil cost of Pillar voting once it exists.

### H-4. The watcher may never be repaid

**How a challenge is funded (Part 1 §3.4).** The watcher funds `ChallengeTx` with 1.45 BTC, plus a fee of up to 0.010 BTC. Its only output pays `F_assert_fixed` = 1.4500 BTC to the operator, to cover the assertion chain. It isn't a bond, and the spec never refunds it. The watcher is meant to get it back from a share of the operator's 3.70 BTC bond when it burns: 1.85 BTC from `BurnBondTx`, 2.05 BTC from `DisproveTx`, or 1.00 BTC from `WrongDepositDisproveTx`, each minus fee.

**The spec's own table (§3.5) prints two outcomes for the watcher, in BTC:**

| Fee rate | Watcher collects the share (disprove / timeout / sub) | Someone else collects it (self-slasher or MEV) |
| --- | --- | --- |
| 1 sat/vB | +0.5990 / +0.4000 / +1.0000 | −1.4500 |
| 500 sat/vB | +0.1150 / +0.3850 / +0.9850 | −1.4600 |

The spec calls the second case "altruistic" but never says which one actually holds. The burn and disprove transactions are pre-signed at graph setup, before any challenger exists, so it isn't clear how their watcher output could be locked to whoever later funds `ChallengeTx`. If the share goes to whoever broadcasts first, the cheating operator (who knows exactly when the burn becomes valid) or a miner will usually take it.

**If the share can be front-run:**

- **The defender loses more than the attacker.** On the timeout path the watcher is down 1.45–1.46 BTC. The fraudulent operator is down about 0.40 BTC plus a ZNN bond worth about 0.04–0.08 BTC (C-1).
- **The cost scales with lanes.** Covering all 10 lanes concurrently takes 14.6 BTC of altruistic capital to protect a 15 BTC cap. C-3's re-pricing makes it worse.
- **Watchers can be ground down.** Deliberately failed fraud attempts drain watchers until nobody challenges, and then the next fraud succeeds.

Assumption 3 then means "someone willing to give away up to 1.46 BTC per lane, per challenge," not "one honest watcher."

**Required change.**

- State in Part 1 who can broadcast `BurnBondTx`, `DisproveTx` and `WrongDepositDisproveTx`, and who can spend their watcher outputs. Publish the scripts and sighash flags.
- If anyone can, add a refund that can't be front-run: bind the watcher's payout into the burn's sighash, or register the `ChallengeTx` on Zenon (proved by SPV) and repay from the slashed bond or the Reserve. Or use a retained, bonded watcher set paid from protocol fees.
- Until then, remove "one honest watcher can stop a bad payout" from public materials and restate Assumption 3.

### H-5. Exit liveness is missing from the threat model, and exits are throttled

§4 lists six assumptions, all about safety. It never states that at least one operator is online, holds BTC and is willing to front each peg-out, the 1-of-m operator liveness assumption standard in the [BitVM2-bridge](https://eprint.iacr.org/2025/1158) model. Without it, the only guarantee is the non-delivery refund, which pays zBTC, not BTC.

**Throughput.** Each lane can claim one reimbursement per 5.5 days (the 792-block cooldown), with at most 8 rounds per epoch. The pilot has 5 operators × 2 lanes, so:

- 10 lanes give **about 1.82 vaults/day**, the spec's own figure.
- A run on 15 BTC needs about 8.2 days of reimbursement capacity, even if operators front instantly.
- Scaling to 1,000 BTC with 5%/day outflow would need about 275 lanes and about 1,000 BTC of bonds.

**Operator float.** Fronters wait through the 48 h batch window, the 144-block happy path and the 72-block escrow. In a run they carry up to the whole supply in fronted BTC, on top of 37–74 BTC of bonds.

**Unfronted users.** A user whose peg-out isn't fronted waits until `timeoutHeight` (up to tip + 2,512 blocks) plus 558 blocks of grace, about 21 days, and is then refunded in zBTC.

**Required change.**

- Add the liveness assumption to §4.
- Publish exit-throughput and worst-case wait math next to the supply cap, and size `MaxRepresentationSupply` from it.
- Add a parallel exit path, or size the caps to the serial one. State the bucket rule plainly: the terminal vault is a fixed 1.0000 BTC UTXO, and `D_bucket` = 1.0 BTC in the pilot.

### H-6. Bitcoin has already broken the design envelope

Part 1's safety rests on two bounds: a 500 sat/vB design fee rate (impairment after more than 72 blocks above it), and block intervals of up to 1.476× nominal for Take2 and 1.591× for retirement. Both were exceeded recently:

- **Fees, April 2024.** At the halving and the Runes launch, the median fee reached about 1,805 sat/vB, the minimum to get into a block topped 1,050 sat/vB, and fees stayed high for about 200 blocks, well past the 72-block trigger.
- **Block times, June 2021.** After China's mining ban, the daily average reached 23 minutes (2.3×) and the 7-day average was about 19.5 minutes (about 1.95×).

**The block-time bound is also overstated.** The 1.476× and 1.591× figures assume only the *last* round runs late. Under a sustained slowdown, a lane used serially from day 0 stretches every 792-block CSV:

- The 8th round's Take2 needs 7 × 5.5f + 5f ≤ 56, so **f ≤ 1.287×**.
- Retirement needs 8 × 5.5f ≤ 58, so **f ≤ 1.318×**.

Settlement also schedules `nextEligibleKickoffTs` in wall-clock time (+5.5 days) rather than blocks, so Zenon's view of what's reachable drifts ahead of what Bitcoin allows. Multi-week slowdowns of 1.3–1.5× have followed large hashrate exits.

**There is no fee headroom either.** `Take1Tx` carries 1,000 sats of fee and a CPFP cap of ≤ 0.005 BTC. At an `ASSUMED` \~1 kvB for Take plus CPFP, 500 sat/vB uses the cap exactly. Past the bounds, the spec offers only a dispatch freeze, a downgrade to M0 and a voluntary pro-rata wind-down, and it never says how much users lose.

**Required change.**

- Use 1.287× as the impairment trigger, or compute `nextEligibleKickoffTs` from the prior kickoff's confirmed Bitcoin height plus 792 blocks.
- Size the bounds to at least 2,000 sat/vB sustained for 300 blocks and 2.0× block intervals for 2 weeks, or show the deadline arithmetic that survives them.
- Put a wind-down loss model in the spec.

### H-7. Long-range defense depends on anchoring nobody is paid to do

A light client checks three things: a chain of 30-day BLS certificates from a trusted checkpoint; that each Bitcoin anchor matches a certificate within 6 hours; and that no conflicting certified anchor exists, with the earliest Bitcoin block winning. That last rule is the only thing stopping long-range attacks. An old committee's stake unlocks 72 days after its epoch, after which it can sign an alternative history for free. The forgery loses only if the *real* handoff was anchored first.

The spec assigns anchoring to "permissionless anchorers" every 360 Momentums and at each handoff. It gives no incentive, no fee budget and no consequence if an epoch goes unanchored. One missed handoff anchor, plus 72 days, lets a former committee anchor a forged branch that light clients accept as earliest. That is an unlisted seventh assumption.

Two more gaps:

- **No Bitcoin side of the proof.** Part 4 defines no SPV inclusion proof for the anchor transaction, no header source for a phone and no minimum chainwork. `minimumPostAnchorWork` has no value.
- **No proof availability.** The state tree keeps 17,380 Momentums, about 2.3 days at the observed 11.4 s per Momentum. Older proofs depend on someone keeping archives.

**What a phone actually trusts.** The bigidea page says proofs "end at Bitcoin's proof-of-work." In the spec, *validity* comes from the 21-of-30 committee, and Bitcoin only provides *ordering and timestamps*. The accurate statement is: "Your phone checks that a 21-of-30 Pillar committee signed this state, and that the commitment was timestamped on Bitcoin before any competitor."

**Required change.**

- Make anchoring each epoch handoff a duty of the committee, with a fallback bounty from the Reserve, and halt BitVM2 targets for any epoch whose handoff anchor is missing.
- Specify the client's Bitcoin header source and minimum work.
- Add anchoring liveness and proof availability to §4, and correct the public wording.

### H-8. The pre-mint makes the whole supply the blast radius

`IssueMinted` creates all 21,000,000 × 10⁸ zBTC base units at once, owned by `SettlementContract`, and `ReceiveTreasury()` puts them in its treasury. Every cap (`MaxRepresentationSupply`, `MaxAggregateInFlightMint`, and the per-executor and batch caps, which have no values yet) is enforced inside the same contract that holds the tokens. One dispatch bug can release unbacked zBTC up to the full supply, not just up to the 15 BTC cap.

`SettlementContract` would be a go-zenon embedded contract, which is consensus code. A bug in it can be fixed only by a spork: today a single key (H-3), and under the draft governance a 45-day standard track or a track of up to 7 days for emergencies. In-flight exploitation can't be stopped on any useful timescale unless the guardian pause can halt the contract, and the spec doesn't say who holds that pause. The [Liquid incident of Sep 6, 2026](https://www.certik.com/blog/liquid-network-incident-analysis) is the cautionary case: a software bug minted about 4,000 unbacked L-BTC that was pegged out for real BTC, with every federation key intact.

**Required change.** Hard-code the supply cap at the `TokenContract` level, so it holds even if `SettlementContract` misbehaves. Or keep treasury tokens in a separate account that releases tranches of at most the cap, behind a timelock. Define an emergency halt and its holder.

## Medium findings

### M-1. Fronting slots expire on two different clocks

When a user withdraws, one operator claims an exclusive fronting slot for 24 blocks (about 4 h). The spec names the Bitcoin domain as the single authority on that slot, but Settlement also enforces expiry on its own clock:

- **Settlement** (Part 3 §3.4) sets `SlotExpiryBtcHeight = LastFinalizedTipHeight + 24`.
- **The domain** (Part 2 §4.3 #2) sets `po.SlotExpiryBtcHeight = ChainMeta.BestTipHeight + 24`.

`LastFinalizedTipHeight` trails the live tip by at least the 48 h batch window. So Settlement counts 24 blocks mined two days ago, while the domain counts 24 blocks mined now. The two counts are independent, and they disagree often:

- At a fixed 4 h after the claim, each says "expired" about 53% of the time, and they split the dangerous way about 25% of the time (about 10% at 5 h, 1.4% at 6 h).
- Among re-claims Settlement grants at the earliest allowed moment, about 35% are still bound to the old holder in the domain (R3's simulation).

The two figures measure different things, and both are plausible. Batch-sized jumps in the finalized tip make it worse.

**When they split,** Settlement records operator B and slashes A's 500 ZNN while A is still the domain's exclusive holder. If B fronts, the domain rejects B's release proof under `0x06` exclusivity, so B pays the user 1 BTC, is never reimbursed and is then slashed by `SlashLapsedSlot`. If A fronts, A is reimbursed but has already lost its bond, and the spec doesn't say which bond `MINTED_RELEASE_V1` releases.

**Required change.** Make the domain the only slot authority: `ClaimFrontingSlot` only appends the claim (`0x0A`), and the winner and any slash come from the domain's finalized output. Alternatively, carry Settlement's computed expiry inside the `0x0A` payload and have the domain use that value for both tests.

### M-2. Two colluding operators can censor a peg-out cheaply

A lapse forfeits only the 500 ZNN slot bond, about $44–80 today. The re-claim ban applies only to the same operator, so two colluders can alternate, as long as they claim first after each expiry. Holding one peg-out for its whole timeout takes 27 lapses at the 640-block minimum, or 105 lapses at the 2,512-block maximum: about $5–8k. Every held slot also consumes a lane reservation, shrinking G-21 capacity for everyone.

**Required change.**

- Drop slot exclusivity after two lapses on one peg-out, so the first valid fronting from any eligible operator wins.
- Escalate the bond per lapse on the same `outboxId`, and rotate priority deterministically (`H(outboxId ‖ n) mod eligibleSet`).
- Price the bond in BTC terms (C-1).

### M-3. The node baseline is superseded, and rc2 ships a regression

Phase U0 says "Ship `release/0.0.11-rc1` (`f19955f`)." Since then:

- **rc2 has shipped.** `release/0.0.11-rc2` (`b85ee94`, Nov 25) adds 42 commits and 1,366 non-test lines on top of the spec's `dev` pin `770e893`. Several are consensus-adjacent: Momentum signature and producer checks before applying extension blocks, `ContractSend` hash authentication, bounded embedded receive retries, and panic recovery in `VerifyBlockInMomentum`. Settlement's whole design rides on descendant `ContractSend` chains through exactly this path.
- **rc2 carries a regression.** Commit `ad3b729` skipped post-VM verification for externally supplied blocks. But embedded `ValidateSendBlock` methods re-pack `block.Data` in place, so a block whose `ComputeHash() != Hash` could enter the pool and be gossiped to peers that reject it. [Commit `0aa299e`](https://github.com/zenon-network/go-zenon/commit/0aa299e0484ee69130f14b34bf1348dbd622aa35) on `dev` fixes it (I confirmed this; its parent is `b85ee94`), but rc2 doesn't include the fix. Neither rc1 nor rc2 is a safe U0 target.
- **Embedded-failure provenance is still open upstream.** rc2's `AutoReceiveFailedGenerationMismatchError` notes that embedded methods "do not yet" report whether a failure was deterministic (issue #239). The spec adds the largest embedded contract Zenon has seen, including a full SPV verifier, on top of that gap.
- **Neighbouring logic is still moving.** Stake cancellation became one-shot, gated on `DynamicPlasmaSpork` (`7a019ec`), while A-PILLAR-1 rewrites Pillar revocation next to it.

The spec's citations were exact at their pins: 20 of 23 cited files are byte-identical on rc2. Four citations have drifted: `vm/vm.go:204-226` and `:204-247` (`applySend` is now at `:287`), `consensus/consensus.go:86` (now `:94`), `verifier/momentum.go:198` (now `:207`) and `consensus/consensus.go:45` (now `:46`).

**Required change.** Pin U0 to a tag that contains `0aa299e` (an rc3 or v0.0.11 final). Cite code by symbol and content hash, re-checked in CI on every release branch. Hold the bridge-contract phases (U3–U4) until #239 is closed. Stop describing the spec as based on v0.0.10; that release only renewed the community spork window.

### M-4. The PTLC swap's refund race

In the PTLC swap, Alice's refund leaf is `<12> OP_CSV`, spendable at `h_conf + 12`. Bob must *broadcast* his claim before then, and broadcasting reveals the adaptor secret `t`, which unlocks his zBTC on Zenon for Alice. If Bob's claim isn't *confirmed* by `h_conf + 12`, Alice can RBF her refund and still use `t` to take the zBTC. Bob loses both sides.

Twelve blocks is short. They arrive within 60 minutes about 2% of the time, and within 90 minutes about 20% of the time.

**Both sides hold a free option.** Alice chooses when to release her adaptor partial signature, and can wait until block 11 to see how the price moves. Bob, once he has it, chooses whether to claim at all. Meanwhile his zBTC stays locked until `T_znn`. `T_btc_worst` maps heights to wall time but is never defined. Boltz-style swaps use timeouts of about 24 h.

**Required change.**

- Require Bob's claim to be *confirmed* at least one block before the refund matures, and give it a CPFP anchor.
- Lengthen the refund CSV to at least 72 blocks and scale `T_znn` with it.
- Require Alice to release her partial signature within a few blocks of the Zenon lock confirming, or Bob aborts. Add a minimum remaining-window check before Bob broadcasts.
- Define `T_btc_worst` in blocks, at a stated worst-case interval multiple.
- **Lightning gateway:** specify `Δ_safety`. The inbound flow holds a hold invoice until the zBTC lock, a known channel-jamming vector, so it needs a timeout and a gateway-side rate limit.

### M-5. Useful-looking spam is free, and stream state is never pruned

`SubmitInput` refunds every input with `stepError == 0` (Part 3 §3.1). Streaming any real Bitcoin transaction as `BTC_TX_STREAM_CHUNK` is valid, so its deposit comes back. `TxStreamState` (175 B) can be pruned only "after 144 blocks once consumed" (Part 2 §5), so a stream nobody consumes stays in domain state forever. Because `domainInputSeq` is contiguous, every real input waits behind the spam. Plasma is the only cost, and fused QSR regenerates. The cap of 16 refundable duplicates per batch covers duplicates only.

**Required change.** Refund only inputs a later step consumes, or headers that extend the best chain. Prune unconsumed streams after a fixed TTL. Add a per-submitter quota per batch.

### M-6. Leaf 3B may not be buildable

Each `L3B_j` must verify 265 W-OTS digits (530 initial stack elements) and also run a full SHA-256 compression in Script, without `OP_CAT`, in ≤ 95 kvB (380 kWU), using only the 470 remaining stack slots. Public BitVM work has favoured cheaper in-script hashes because SHA-256 is expensive in Script. The R6-H1 closure depends on this leaf entirely: if it can't execute, certificate-DA disproves fail and forged certificates can't be extracted.

**Required change.** Make a measured Leaf 3B a design gate *before* Stage 0A work, not a Stage 0C measurement. Have a fallback ready, such as a different DA hash or a DA commitment via the STARK.

### M-7. Admission control runs after irreversible custody

`RolloverTx`, which has no refund path, confirms before `RelayClaim` checks G-21, the supply cap, the in-flight cap and `unrotatedVaultCount == 0`. Under a key loss (C-4) or a permanent quarantine, `DeferredLockQueue` never drains. The depositor's BTC then sits in a vault with no zBTC minted against it. This is a residual of R1 H-04.

**Required change.** Have the Setup Committee sign `RolloverTx` only after an on-Zenon *reservation* of mint capacity, and refund through Leaf B if the reservation fails.

### M-8. Zenon censorship makes an honest fronter pay twice

A fronter has about `timeoutHeight + 558 + K` blocks (about 4 days) to get `BTC_RELEASE_PROOF` into a finalized batch. If Pillars colluding with the user censor the proof or its batch, `FOREIGN_NON_DELIVERY` refunds the user's zBTC on top of the BTC already received.

**Required change.** Let a valid fronting proof admitted any time before the refund *executes* override it, and make the refund reversible against a later valid proof by clawing the zBTC back from escrow, not from the user's free balance.

### M-9. "Feeless" capacity is small, and one key can throttle it

The spec's "100 account blocks per Momentum" (about 5 transfers/s) is `MaxAccountBlocksInMomentum`, which go-zenon marks "Not used after Dynamic Plasma spork." Under Dynamic Plasma, capacity is a setting, `MaxBasePlasmaInMomentum / 21,000`, plus a separate cap for contract blocks:

| Setting | Base blocks per Momentum | Transfers/s at 11.4 s per Momentum |
| --- | --- | --- |
| Default (4,200,000) | 200 | about 9 |
| Hard ceiling (2,100,000,000) | 100,000 | about 4,400 |
| Lowest allowed | 10 | about 0.4 |

Each transfer costs 21,000 Plasma: 10 fused QSR at the floor price, or about 31.5M SHA3-256 hashes (0.1–0.3 s on a desktop, 2–10 s on mobile or WASM). Resource prices move up to `MaxPriceChangePercent` per Momentum (default 10%, settable to 100%), with a floor of 1,000 and **no ceiling**. At 10% per Momentum, about 11 minutes of sustained overload raises the price about 300×.

So even at the ceiling the network is three orders of magnitude short of the pitch's "millions of transactions per second," and a phone paying per second by PoW would hash for 2–10 s per second of stream. The bigidea page's "0.5–5×" spam multiplier exists in neither the spec nor the code. `SetPlasmaVariables` is callable only by the two spork keys (H-3), and challenge, fronting and peg-out transactions near a deadline compete for that capacity. The spec's "10 of 100 Momentum slots reserved for settlement" is planned new code, not a property of today's Plasma rules.

**Required change.** Publish a capacity budget for zBTC against other Zenon traffic. Bound the Plasma variables in the zBTC sporks (a minimum capacity and a maximum step), or give settlement-critical calls capacity `SetPlasmaVariables` can't reduce. Specify PoW difficulty and any load multiplier as consensus constants. Rescope the public claims to tips, payouts and periodic settlement unless there's a real scaling path.

### M-10. Momentum time runs about 14% slow, and finality is node-local

go-zenon's own comments record about 11.46 s per Momentum at height 14,310,887 (2026-09-30) and about 11.35 s at 14,228,943 (2026-09-19). `ConsensusConfig` says 10 s. Every conversion in the spec drifts accordingly:

- 360 Momentums is about 68 minutes, not 1 hour.
- Case B's +60 heights is about 11.4 minutes.
- 17,380 Momentums of state retention is about 2.3 days.
- Zenon-time windows (the 4 h slot claim, the 12 h session, the 48 h finalization) drift by the same \~14% against height-based ones.

**Finality today is only node-local.** The chain bridge refuses any rollback more than 30 Momentums below the frontier (`protocol/chain_bridge.go`); otherwise fork choice prefers the longer chain. Until U2 ships, nothing exists that a light client or BitVM2 verifier could check as objective finality.

**Required change.** Express each deadline in one unit, with a stated worst-case interval. List the U2 dependency for every component that relies on finality.

### M-11. Certificates in a height gap can't be slashed

`SubmitInvalidCertProof` covers Case A (`cert.Height ≤ frontier.Height`) and Case B (`cert.Height > frontier.Height + 60`). Heights in `(frontier, frontier + 60]` are covered by neither. Normally the gap closes within about 11 minutes as the chain advances. But a cartel that also stalls Momentum production can sign a certificate for a near-future height that is a multiple of 30, which is a valid BitVM2 target, and it stays unslashable for as long as the stall lasts.

**Required change.** Define a Case C for the gap, or forbid using any certificate as a BitVM2 target until a later certified Momentum covers its height. Optionally, make equivocation evidence enforceable on Bitcoin, for example by publishing it through `AssertCertDA` to kill the graph.

### M-12. The Setup Committee can divert deposits and fake capacity

The provisional deposit's Leaf A is the committee key, with a 144-block CSV refund on Leaf B. SPEC §4 #4 already admits that a compromised committee can "divert in-flight deposits, inflate G-21 with phantom rounds, or manipulate SMT roots." Phantom rounds are the worse half: they make G-21 report reimbursement capacity that doesn't exist, so mints continue past what operators can actually honour.

**Required change.** Recompute G-21 reachability from on-chain operator-round registrations alone. Cap the time between deposit and rollover below 120 blocks, or show why it can't be lower.

### M-13. Precedence puts Bitcoin custody last but one

SPEC §2.1 ranks, highest first: Zenon L1 rules; the bridge framework and MINTED extension; Parts 3 and 5; Part 2 (SPV); Part 1 (`BTC-ENFORCEMENT-V1`); Part 4. So when they conflict, Zenon contract semantics override the part that protects the BTC.

**Required change.** Make Part 1's invariants (no sweep key, graph-only spends, the burn splits) a non-overridable layer, and treat any conflict with them as a spec bug.

### M-14. Safety-critical values are missing or assumed, and the oracle is circular

| Parameter | Status | Why it matters |
| --- | --- | --- |
| `minimumPostAnchorWork` | No value | Floor for SPV bootstrap and anchor security |
| `maxBatchMint`, `maxInFlightMintPerExecutor` | No value | The only per-actor mint bounds |
| `ChallengeDepositZnn` | No value | Decides who wins the challenge priority lane |
| `f_chal` | Not derived (implied about 0.01 BTC) | Part of the watcher's funding requirement |
| `minOperatorFeeSats` | Not defined | Operator viability |
| `Δ_safety`, PoW difficulty, Plasma fusion rate | No value | Swap safety and the feeless model |
| Wind-Down Plan | Listed as 11 items, not enumerated | The only stated outcome for users in a failure |
| `DeferredLockQueue` beyond about 5 days | Undefined | Mint liveness during stalls |
| `SlashEquivocation` amount | Not stated | The penalty for double signing |
| G-21 constants (−25, 3.0-day lookahead) | Unexplained | Mint gating |
| BitVM2 weights, about 3.5M constraints, prover ≤ 15 min, 10,500 ZNN/BTC | `ASSUMED` | Every fee and deadline derives from these |

**"Oracle verified" means internally consistent, not measured.** `verify_spec_bounds.py` imports only `math` and recomputes the spec's formulas from hard-coded inputs, so it confirms the spec agrees with constants the spec itself chose. Every risky input is an `ASSUMED` constant, including an unsourced 200-element SHA-256 working stack. R3's independent re-derivation passes all 45 of its consistency checks, which confirms the arithmetic and says nothing about the premises.

**Required change.** Fix each value or mark it as a blocking gate. Relabel the oracle a consistency check, and feed it measured, sourced inputs.

### M-15. v2.5.0 has had no independent review

The review index lists R1–R6. R6 reviewed v2.4.0-draft and returned HOLD with two High findings (the transition-height pin, and WOTS checksum soundness). The index marks every R6 item closed in v2.5.0-rfc, without a verifying round. R3's regrading found 9 of R6's 16 findings fully closed, 5 partly closed and 2 closed on paper but dependent on unmeasured gates. The fixes to WOTS digit budgets and Script stack limits are exactly the kind that need measuring, not asserting.

The three reviews merged here don't fix this either: all three come from one reviewer within 48 hours (see Scope).

**Required change.** Have reviewers with BitVM implementation experience, outside the R1–R7 loop, review v2.5.0, including Signet measurements for Gate G-2, before the document is called RFC-ready.

## Low findings, errata and public claims

### L-1. Undefined committee and fork-choice edge cases

- `popcount ≥ 21` is absolute. If fewer than 21 active Pillars register BLS keys, or fewer than 30 are eligible, the finality gadget never finalizes, and the spec doesn't say what happens.
- U2 fork choice ("refuse `DeleteMomentum` across certified momentums") doesn't say what an honest node does when a certified competing branch appears. That gap is the opening for C-2's censorship path.

### L-2. The mint-stall window is understated

At 15 BTC of supply, generation-g capacity drops below the 40-round G-21 threshold once t + 3 days > 43 days, at **day 26.5**. Generation g+1 registers by day 32, so the worst-case stall is **5.5 days** per 30-day cycle, not "about 5.0". The spec's own "day 26.6 .. 32.0" is 5.4 days, and any used or reserved rounds lengthen it further. Either state 5.5 days plus the usage dependence, or move g+1 registration earlier so its capacity counts from day 26.

### L-3. The stale-acknowledgement fix applies only after `DynamicPlasmaSpork`

go-zenon `dev` now rejects a user account block whose acknowledged Momentum doesn't enforce every spork enforced at the confirming Momentum's parent (`chain/acknowledgement_recency.go`, issue #227). The rule applies only from the Momentum whose parent enforces `DynamicPlasmaSpork`, and embedded-contract blocks are exempt. Make `DynamicPlasmaSpork` enforcement a hard precondition for every zBTC spork in Part 5, and add MUST-fail vectors for a stale-acknowledgement mint, burn and update.

### L-4. Errata

- **Assumption count.** §4 says "5 explicit" assumptions but numbers six. It also omits five assumptions this review shows are load-bearing: Zenon censorship resistance and challenger liveness (C-2), committee liveness (H-2), upgrade and governance authority (H-3), exit liveness (H-5) and anchoring liveness (H-7).
- **Take1 fee.** `Take1Tx` outputs sum to 0.99999 BTC from a 1.0000 BTC vault, so it relies entirely on CPFP. Say so explicitly.
- **Version label.** `chainVerifierId` still says `BTC_SPV_VERIFIER_V2.4`.
- **Fork tie-break.** Equal work resolves to the lowest block hash. That differs from Bitcoin Core's first-seen rule, so during a tie the contract can follow a different tip than most nodes. Document it and bound it with K.
- **Ambiguous window.** "48h (+12h session)" appears in Parts 3 and 5 without a definition.
- **Part 2 table.** The "Typical" ABI sizes exceed "Max ABI" for several tags, for example `0x0C`.

### Public claims vs the spec

The bigidea page makes claims the spec doesn't support. Fix the page, or change the design until it does.

| Public claim | What the spec actually says | See |
| --- | --- | --- |
| "The network never holds a pooled key" | An N-of-N `Q_graph` controls key-path spends of every vault and is never deleted | C-4 |
| "One honest watcher can stop a bad payout" | A watcher who fronts 1.45 BTC plus fee per lane and may not be repaid, plus five other assumptions | H-4 |
| Proofs "end at Bitcoin's proof-of-work" | Validity ends at a 21-of-30 BLS committee; Bitcoin only timestamps | H-7 |
| "Security is funded by the network's own staking token" | True, so BTC safety depends on ZNN's price and liquidity | C-1 |
| "Millions of transactions per second"; per-second streams | About 9 tx/s by default and 4,400 at the ceiling; mobile PoW takes 2–10 s per transfer | M-9 |
| Spam multiplier "0.5–5×" | In neither the spec nor the code; prices have no ceiling | M-9 |
| "Community-driven" operators and treasury | Unassigned guardian and governance roles; spork and Plasma authority sit with two single keys | H-3 |
| "Peg-free", "zero vault trust" swaps | The swaps are atomic, but the zBTC received is still a claim on the vaults | M-4 |
| "0 satoshi fees" | No BTC fee for zBTC transfers only; peg-in and peg-out pay BTC fees plus `pegOutFeeSats`, and transfers need locked QSR or CPU work | M-9 |
| "Oracle verified" | Internally consistent, not measured | M-14 |

The bigidea page also never names Zenon, ZNN, QSR or Pillars. A reader who finds out later will take the omission as concealment. Name the network.

## Where the reviews disagreed, and how this review resolves it

The three input reviews contradict each other in eight places, and each also has gaps the others fill. This review takes the position in the right-hand column.

| Topic | What the reviews said | Resolution here |
| --- | --- | --- |
| Can a 21-of-30 cartel censor Zenon? | R1 first said yes, then retracted after reading `election_algorithm.go`. R2 (L5) and R3 (C-2) still assume it can. | Mostly no. Each 5-minute tick has 30 producer slots: 15 drawn from the top 30 by delegation, 15 from everyone else. A 21-of-30 cartel produces roughly 35–40% of Momentums, a minority, so honest producers can include slashing proofs and challenges. Censorship stays a path to analyse, not the main one. |
| PTLC free option | R1 said Bob holds it; R2 and R3 said Alice. | Both do. Alice chooses when to release her adaptor signature; Bob then chooses whether to claim (M-4). |
| Zenon capacity | R2 and R3 used the spec's "100 blocks per 10 s Momentum, about 5 tx/s". | R1's code reading is right: that constant is retired under Dynamic Plasma. Capacity is about 9 tx/s by default, at 11.4 s per Momentum (M-9). |
| Break-even of 289.0 kvB | R1 called it an erratum (1.45 BTC ÷ 500 sat/vB = 290 kvB). R3 recomputed it and found 289.0 correct. | Not an erratum; the spec nets out a fee. Dropped from L-4. |
| Slot-expiry split | R2: about 25% at T + 4 h. R3: about 35%. | Both stand; they condition on different moments (a fixed time vs the earliest allowed re-claim). Both are shown in M-1. |
| Operator loss in a certificate stall | R3: 1 BTC fronted + 3.70 BTC bond. | It leaves out the 1.45 BTC the operator receives from `ChallengeTx`. Net is about −3.25 BTC plus the ZNN bond (H-2). |
| BitVM2 disprove size | R2: 3.5–4 MB, so non-standard. R1 and R3 accepted the spec's 95 kvB as given. | The assert gap is real. The disprove comparison is with an unchunked design, so the true finding is "no published build shows leaves this small" (C-3, M-6). |
| ZNN price | R1: about 537,600 ZNN/BTC. R3: 400–540k. R2: about 727,000, all within two days. | Reported as one dated range, 400,000–727,000, with the thinness of the market as a finding in itself (C-1). |

**Severity also varied.** Q\_graph was Critical in R1 and High in R2 and R3; it is Critical here, because it fails on safety (sweep) and liveness (brick) at once. Exit liveness was High in R1 and R2 but Medium in R3; it is High here. R1's watcher finding was Critical; it is High here, because the spec discloses the bad case itself, and the real gap is not saying which case holds.

**What each review contributed.** R3 supplied the trust-model framing (C-2, H-1, H-2), the R6 disposition and the gate list. R2 supplied the BitVM2 cost finding (C-3) and the node-baseline work (M-3). R1 supplied most Zenon-specific facts: spork keys, Momentum timing, Dynamic Plasma capacity, anchoring and the pre-mint.

## What the spec gets right

The failures above come from the spec's premises, not its mechanics. Taken as arithmetic, the design is correct.

- **Disclosure is unusually honest.** It says "Tier 1A is NOT trustless," admits watchers are altruistic, labels unmeasured inputs `ASSUMED` and includes an 11-item wind-down plan.
- **Code citations are exact at their pins.** Every citation the reviews spot-checked (18 anchors in 14 files, including `token.go`, `pillars.go` and `ptlc.go`) matches `770e893`. They drift only because rc2 moved underneath them.
- **The Bitcoin-side accounting balances.** Value balances are exact in integer satoshis. The timelock order 46 d < 56 d < 58 d holds at the nominal block rate, and the 288-block kill-to-burn gap exceeds the 72-block trap.
- **The certificate DA design is clever.** A fixed 408-byte certificate published on Bitcoin, plus slashing checked against historical committee roots, closes the handoff-forgery problem R6 found without an in-circuit oracle. Its layout (7 SHA-256 blocks, 1,239 W-OTS digits, inputs \[393, 444, 402\]) re-derives exactly.
- **SPV depth is sized to the pilot.** Forging 14 Bitcoin blocks forgoes 43.75 BTC of subsidy, against a 10 BTC cap on unfinalized mints. The confirmation depth K rises at each halving (12, 13, 26), with a migration rule before 2032.
- **Most of R6 is fixed.** 9 of R6's 16 findings are fully closed in v2.5, including the forged-handoff case (R6-H1), the certificate length (R6-M1) and reachability with reservations (R6-M2).
- **Staging is conservative.** Fixed 1 BTC deposits, a paused shadow stage with at least 30 days of mainnet tracking, then a capped pilot.
- **Governance limits point the right way.** Governance can't fabricate `RELEASED` or `REFUNDED` records or add custodial sweep keys.

## Required before Stage 0C

Every gate below is open today. The first six are design decisions, not measurements: passing every existing mechanism gate would still leave them open. G-24 to G-29 extend the spec's own gate numbering (they were proposed in R3).

| Order | Gate | What must be true | Closes |
| --- | --- | --- | --- |
| 1 | G-24 Economic security | Caps set from measured slashable value with a haircut, or bonds priced in BTC. Today's numbers allow about 0.2–0.4 BTC | C-1, H-1, M-2 |
| 2 | G-25 Zenon state honesty | Validity proofs (Phase 3 ZK), or proven censorship resistance and challenger liveness, before BTC is at risk; the circuit checks the fronting payment on Bitcoin | C-2, M-8 |
| 3 | G-2 Measured weights (re-scoped) | BitVM2 re-costed from published data, Leaf 3B measured on Signet, every disprove leaf proven standard or a non-standard path specified | C-3, M-6 |
| 4 | G-27 Custody model | Either true BitVM2 (deleted keys, non-expiring graphs) or a t-of-N key with a recovery leaf; the number of vaults that can exit after one key loss quantified | C-4, M-7 |
| 5 | G-28 Upgrade isolation | Per-vault frozen settlement semantics (`settlementCodeHash`), a privileged-powers table, and a legitimate spork authority | H-3, H-8 |
| 6 | G-26 Committee liveness | A certificate stall can't burn honest operators; committee and exit liveness are both in §4 | H-2, H-5 |
| 7 | G-7 Fronting and fees | The domain is the only slot authority; exclusivity drops after repeated lapses | M-1, M-2 |
| 8 | G-13 Timeouts | Bounds re-derived from the 2021 and 2024 worst cases, the 1.287× trigger, one time unit per deadline | H-6, M-10 |
| 9 | Anchoring | Paid, mandatory handoff anchoring, a specified Bitcoin header source and `minimumPostAnchorWork` | H-7 |
| 10 | U0 baseline | Pinned to a tag containing `0aa299e`, citations by symbol and hash in CI, #239 closed before U3–U4 | M-3 |
| 11 | Parameters | Every TBD fixed or marked blocking; the oracle fed measured inputs | M-14, M-5, M-4 |
| 12 | G-29 Independent review | Reviewers with BitVM implementation experience, outside the R1–R7 loop | M-15 |

If gates 1, 2 and 4 can't be met, the honest alternative is to relabel the design as a federated pilot of well under 1 BTC, and drop the trust-minimized claims.

## Questions the authors must answer

Each should get a written answer in the spec, not in a thread.

- [ ] **C-1.** At what ZNN/BTC price does forging become profitable against the current cap, and what happens on-chain when the market crosses it?
- [ ] **C-2.** What stops a fake `FOREIGN_RELEASE` in an unchallenged batch from reimbursing an operator who never paid?
- [ ] **C-3.** What are the measured assert and disprove sizes, and is every disprove leaf standard?
- [ ] **C-4.** Why must `Q_graph` keep key-path control instead of signing only graph and rollover transactions with keys that are then deleted? What happens to each vault if one signer is lost for good?
- [ ] **H-1.** Why is committee weight delegated rather than slashable stake, and why a single snapshot?
- [ ] **H-3.** List every address or contract with pause, drain, reset, release, upgrade or bond-setting authority, and who holds each key. Can the top 30 Pillars reach the upgrade threshold on their own?
- [ ] **H-4.** Who runs and funds the pilot's watchers (14.6 BTC)? Can anyone other than the challenger broadcast the burn or disprove transactions and collect the watcher share?
- [ ] **H-5.** What is the minimum time to honour peg-outs for 100% of supply, and who supplies the fronting liquidity meanwhile?
- [ ] **H-6.** What happens to each lane, and to user funds, under April 2024 fees and June 2021 block intervals? Show the timeline.
- [ ] **H-7.** Who anchors each epoch handoff, who pays, and what happens if nobody does? Where does a phone get Bitcoin headers?
- [ ] **H-8.** Can any single `SettlementContract` code path move treasury zBTC beyond `MaxRepresentationSupply`? Show the test.
- [ ] **M-9.** How much of Zenon's capacity does zBTC get, and is "millions of tx/s" a design target or a pitch?
- [ ] **M-15.** Who will do the independent review of v2.5.0, and will its findings block the RFC label?

## Scope, method and limits

**What this is.** A consolidation of three hostile reviews of the zBTC v2.5.0-rfc spec (`btc-moonshot/spec` at `7b47b8c`, Nov 24, 2026). Between them they covered `SPEC.md`, Parts 1–5, the oracle script, reviews R1–R6, the bigidea page, and go-zenon `f19955f` (rc1), `770e893` (the spec's `dev` pin), `b85ee94` (rc2), `b19d3e2` (current `dev`) and `e8986a6` (v0.0.10).

**What I did.** Merged and de-duplicated the findings, re-graded severity, re-ran the arithmetic each finding depends on (the ZNN conversions, the BitVM2 re-pricing, the Poisson tails, the slow-block and stall windows), and resolved the contradictions shown above. I spot-checked three outside claims against primary sources: the `0aa299e` fix commit, Alpen's BitVM2 figures, and the Liquid incident. All three held up.

**Limits.**

- **I did not read the spec or the go-zenon code myself.** Spec and code facts come from the input reviews, apart from the three spot-checks above.
- **The input reviews aren't independent.** All three are by one reviewer within 48 hours and share phrasing, so their agreement is weaker evidence than three separate reviews would be. This consolidation doesn't replace the independent BitVM review in gate 12.
- **No code was run.** None of the reviews executed `verify_spec_bounds.py`. R3's own check script (`r7_check.py`) wasn't among the files provided, so its 45 passing checks couldn't be reproduced here.
- **Prices are thin and moving.** ZNN quotes come from aggregators with near-zero volume and disagree with each other. Any single figure is indicative only.
- **Network facts are unverified.** Live Pillar count, delegation distribution and which sporks are active on mainnet were not queried from a node.
- **BitVM data may be dated.** Alpen's 611-commitment figure is from October 2024, and newer work may have lowered it.

## Sources

**The spec**

- [zBTC spec v2.5.0-rfc](https://btc-moonshot.github.io/spec/) and [repo](https://github.com/btc-moonshot/spec)
- [Review index (R1–R6)](https://btc-moonshot.github.io/spec/reviews/) and [Hostile Review R6](https://btc-moonshot.github.io/spec/raw/reviews/HOSTILE_REVIEW_R6.md)
- [A Feeless Settlement Lattice for Bitcoin (bigidea page)](https://btc-moonshot.github.io/bigidea/)

**go-zenon**

- [go-zenon repository](https://github.com/zenon-network/go-zenon), with [`release/0.0.11-rc2`](https://github.com/zenon-network/go-zenon/tree/release/0.0.11-rc2) and [`dev`](https://github.com/zenon-network/go-zenon/tree/dev)
- [Commit `0aa299e`: re-verify externally supplied blocks mutated by VM execution](https://github.com/zenon-network/go-zenon/commit/0aa299e0484ee69130f14b34bf1348dbd622aa35) (checked)
- [PR #47: governance v1 (open)](https://github.com/zenon-network/go-zenon/pull/47), [issue #227](https://github.com/zenon-network/go-zenon/issues/227), [PR #174](https://github.com/zenon-network/go-zenon/pull/174), [PR #310](https://github.com/zenon-network/go-zenon/pull/310)
- [HyperCore: Draft Governance ZIP v1](https://forum.hypercore.one/t/draft-governance-zip-v1-for-comment/935)

**BitVM**

- [Alpen: State of SNARK verification with BitVM2](https://www.alpen.org/blog/state-of-snark-verification-with-bitvm2) (checked)
- [Citrea: Clementine v2 with garbled circuits](https://www.blog.citrea.xyz/clementine-v2-with-garbled-circuits-and-toop/)
- [Bridging Bitcoin to Second Layers via BitVM2 (USENIX '26)](https://www.usenix.org/system/files/usenixsecurity26-woll.pdf)
- [BitVM2-bridge (ePrint 2025/1158)](https://eprint.iacr.org/2025/1158), [Clementine (ePrint 2025/776)](https://eprint.iacr.org/2025/776), [BitVM3](https://bitvm.org/bitvm3.pdf)
- [Bitlayer mainnet (Blockworks)](https://blockworks.co/news/bitvm-implementation-stage)

**Bitcoin history and incidents**

- [Forklog: block 840,000 fees](https://forklog.com/en/bitcoin-block-840000-sees-users-pay-2-4-million-in-fees/), [Spark: fee rate history](https://www.spark.money/tools/bitcoin-fee-rate-history), [Cointelegraph: fees after the halving](https://cointelegraph.com/news/bitcoin-fees-crash-after-daily-average-record-halving-day)
- [K33: 23-minute blocks, June 2021](https://k33.com/research/archive/articles/23-minute-blocks), [The Daily Dive: slow blocks](https://bmpro.substack.com/p/the-daily-dive-012-historically-slow)
- [CertiK: Liquid Network incident analysis](https://www.certik.com/blog/liquid-network-incident-analysis) and [The Block: attacker returns 3,400 BTC](https://theblock.co/news/defi/2026-09-07-liquid-network-attacker-says-they-will-return-most-of-4000-btc-after-bug-fix-413673) (checked)

**Prices**

- [ZNN on CoinMarketCap](https://coinmarketcap.com/currencies/zenon/), [ZNN on CoinGecko](https://www.coingecko.com/en/coins/zenon/usd), [CoinStats snapshot](https://coinstats.app/en/coins/zenon-2/)
- [BTC price, Nov 19, 2026 (Fortune)](https://fortune.com/article/price-of-bitcoin-11-19-2026/)
