# Changelog — `v0` (`v2.5.0-rfc`) → `v1` (`v3.0.0-rfc`)

**Date:** 2026-11-27  
**Baseline (`v0`):** [`v2.5.0-rfc`](./versions/v0/SPEC.md) (archived byte-for-byte from commit `7b47b8c`, SHA-256 verified in [`versions/v0/SHA256SUMS.txt`](./versions/v0/SHA256SUMS.txt))  
**Trigger:** Consolidated Hostile Review [`R7`](./reviews/HOSTILE_REVIEW_R7_CONSOLIDATED.md) (4 Critical, 8 High, 15 Medium, 4 Low) + 2-round adversarial convergence peer review with Claude Opus 5.5 (`xhigh`) uncovering 6 additional issues (`N-1..N-6`) and 5 blocking implementation constraints (`B1..B5`).

---

## Executive Summary of `v0` → `v1` Architecture Shift

`v1` (`v3.0.0-rfc`) abandons `v0`'s unviable BitVM2 + rotating-PoS-committee hybrid and replaces it with **`Tier F` (`BTC-CUSTODY-F1`)**:

1. **Honest Capped Federated Custody (`BTC-CUSTODY-F1`):** Taproot NUMS + `k`-of-`n` `OP_CHECKSIGADD` HSM federation (`7-of-10` pilot / `11-of-15` scaled) + `<52,560> OP_CSV` (~365-day) backup recovery leaf with mandatory `26,280`-block refresh safety duty. Zero BitVM2, zero `N`-of-`N` standing keys, zero ZNN in the BTC safety path, and a policy-set Stage 1B cap of **`5.0 BTC`** (arbitrary amounts `>= 100,000` sats).
2. **Direct-on-L1 Trimmed Bitcoin SPV + Federation Co-Signature:** Removes `v0`'s optimistic `BatchCommitmentV3`, executors, Multi-Tx Witness Sessions, 48h challenge delay, and `0x04` streaming (replaced with `<= 6 KiB` stripped federation tx cap + coinbase SHA-256 midstate proof).
3. **Dual-Implementation Signer Policy (`B3a/B3b` + `H-3` Firewall):** At least two independent signer builds enforce VM-balance supply conservation (`Circ == R`), the exact in-flight backing inequality, and a pinned `settlementCodeHash` upgrade firewall on every signature.
4. **Tranche-Isolated `zBTC` Treasury (`H-8, B3c`):** `21M` pre-mint sits in `TreasuryTrancheEscrow`, releasing only `<= ActiveCap` tranches to `SettlementContract` behind a `>= 14d` governance timelock.
5. **Conflict-Only Refunds (`B4`):** Signed Bitcoin payouts never expire; timeout-only refunds are deleted and replaced by Zenon-final `BatchIntent` + `K`-deep `SubmitConflictRefundProof`.
6. **Non-Normative `v2` Research Annex:** Trust-minimized deleted-key BitVM / garbled circuits + ZK execution validity + Bitcoin-anchored fork choice are preserved honestly in [`spec/01 Appendix A`](./spec/01-bitcoin-taproot-vault-enforcement.md#appendix-a-non-normative-v2-research-annex-path-a-trust-minimized-bitvm) behind explicit Research Gates **R-1..R-8**.

---

## Complete Finding-by-Finding Disposition (`R7` + `N-1..N-6` + `B1..B5`)

### Critical Findings (`C-1` – `C-4`)

| ID | Finding Summary | Disposition in `v1` | Spec Reference |
|---|---|---|---|
| **C-1** | Security priced in ZNN at `10,500 ZNN/BTC` (40–70× above market `400k–727k`) | **Resolved by removal.** ZNN removed from BTC safety; `10,500 ZNN/BTC` deleted; Stage 1B cap (`5.0 BTC`) is policy-set. Long-term ZK/anchored path in Annex A (`R-1, R-2`). | [SPEC §1, §4, §9](./SPEC.md), [Part 1](./spec/01-bitcoin-taproot-vault-enforcement.md) |
| **C-2** | Honest BLS certs over dishonest canonical Zenon state (unchallenged batch / censorship / upgrade) | **Closed in `v1`.** Optimistic batches deleted (direct L1 SPV + `>= k` federation attestation); signers enforce `B3a/B3b` VM balances and pinned `settlementCodeHash` firewall. Full ZK validity in Annex A (`R-1, R-3`). | [SPEC §3, §4](./SPEC.md), [Part 1 §3](./spec/01-bitcoin-taproot-vault-enforcement.md), [Part 2 §1](./spec/02-btc-authorization-domain-and-spv.md) |
| **C-3** | BitVM2 assert (`220 kvB`) & disprove (`<= 95 kvB`) sizes 4–10× below published measurements | **Resolved by removal (moved to `v2` Gate R-4).** BitVM2 removed from `v1`; Annex A Gate `R-4` mandates measured Signet sizes across BitVM2 and garbled circuits before `v2`. | [Part 1 Annex A](./spec/01-bitcoin-taproot-vault-enforcement.md#appendix-a-non-normative-v2-research-annex-path-a-trust-minimized-bitvm) |
| **C-4** | Never-deleted `N`-of-`N` `Q_graph` can sweep everything or brick everything; contradicts C-07 & Wind-Down #8 | **Closed.** Replaced with explicit `k`-of-`n` `OP_CHECKSIGADD` HSM federation (`7-of-10` / `11-of-15`, tolerating `n - k` key losses) + `<52,560> OP_CSV` recovery leaf; C-07 replaced with honest custodial disclosure; Wind-Down rewritten with explicit loss model. Deleted-key non-expiring graphs moved to `R-6`. | [Part 1 §1, §2, §5](./spec/01-bitcoin-taproot-vault-enforcement.md) |

### High Findings (`H-1` – `H-8`)

| ID | Finding Summary | Disposition in `v1` | Spec Reference |
|---|---|---|---|
| **H-1** | Committee seats rented via free instant delegation at one snapshot | **Fixed (and decoupled from `v1` custody).** `spec/04 §3.1` switches U2 selection to epoch-averaged variable slashable self-bond or unbiased randomness-beacon sampling (no free delegation, no uniform-bond address grinding). | [Part 4 §3.1](./spec/04-bitcoin-anchoring-and-light-client.md) |
| **H-2** | `>= 10` committee seats withholding certs profitably burn honest operators | **Resolved by removal in `v1`; fixed in `v2` Annex.** No operator bonds or BitVM kickoffs in `v1`. Annex A (`R-6`) records the cert-before-kickoff precondition. | [Part 1 Annex A](./spec/01-bitcoin-taproot-vault-enforcement.md#appendix-a-non-normative-v2-research-annex-path-a-trust-minimized-bitvm) |
| **H-3** | Upgrade & Plasma authority = custody authority; single spork keys unlisted in §4 | **Closed.** Added complete **Privileged Powers Table** (`SPEC §4.1`, incl. both spork keys + community renewal windows), pinned `settlementCodeHash` signer firewall, `>= 30d` custody upgrade timelock, `GovernanceContract` Stage 1B hard gate, and pinned `2.1M` Plasma floor (`B2`). | [SPEC §4.1](./SPEC.md#41-complete-privileged-powers-table-h-3-closed), [Part 1 §3.1](./spec/01-bitcoin-taproot-vault-enforcement.md), [Part 5 §3–4](./spec/05-go-zenon-upgrade-plan.md) |
| **H-4** | Altruistic watcher fronts `1.45 BTC`/lane (`14.6 BTC` total) and loses against self-slasher/MEV | **Resolved by removal (moved to `v2` Gate R-5).** *(Note: `v0` did disclose `-1.46 BTC` EV and sighash flags, but the economic fragility was real.)* | [Part 1 Annex A](./spec/01-bitcoin-taproot-vault-enforcement.md#appendix-a-non-normative-v2-research-annex-path-a-trust-minimized-bitvm) |
| **H-5** | Exit liveness missing from §4; exits throttled to `1.82 vaults/day` | **Closed.** Federation liveness (`n - k + 1` offline) explicitly added to `SPEC §4`; serial 5.5d lanes deleted — federation batch-pays directly from vaults. Parallel kickoffs gated for `v2` (`R-7`). | [SPEC §4, §9](./SPEC.md), [Part 1 §3](./spec/01-bitcoin-taproot-vault-enforcement.md) |
| **H-6** | April 2024 fees & June 2021 slow blocks broke envelope; real slow-block tolerance was `1.287×` | **Closed.** `46d/56d/58d` CLTV cliff deleted; recovery CSV is `52,560` blks with `13,140`-blk alert margin; Operations Reserve sized for `2,000 sat/vB` across all `64` vault UTXOs (`>= 0.50 BTC`); PTLC sized for `2.0×` slow blocks. | [Part 1 §2.1, §2.4](./spec/01-bitcoin-taproot-vault-enforcement.md), [Part 3 §5.1](./spec/03-settlement-minted-zbtc-and-feeless-rails.md) |
| **H-7** | Unpaid epoch handoff anchoring, missing mobile BTC header source & `minimumPostAnchorWork`, overclaimed "end at Bitcoin PoW" | **Closed.** Decoupled from `v1` custody; `spec/04` mandates committee handoff anchoring + Reserve fallback bounty, specifies mobile header sources + `minimumPostAnchorWork`, and corrects public wording (`SPEC §8`). | [SPEC §8](./SPEC.md), [Part 4 §1, §4](./spec/04-bitcoin-anchoring-and-light-client.md) |
| **H-8** | 21M pre-mint inside `SettlementContract` makes full supply the blast radius | **Closed (`B3c`).** Pre-mint owned by separate `TreasuryTrancheEscrow`, releasing only `<= ActiveCap` (`5.0 BTC`) tranches to `SettlementContract` behind `>= 14d` governance timelock + `>= k` federation co-sig. | [Part 3 §1](./spec/03-settlement-minted-zbtc-and-feeless-rails.md), [Part 5 §3.2](./spec/05-go-zenon-upgrade-plan.md) |

### Medium Findings (`M-1` – `M-15`)

| ID | Finding Summary | Disposition in `v1` | Spec Reference |
|---|---|---|---|
| **M-1** | Fronting slots expire on two different clocks (Settlement vs domain) | **Resolved by removal.** No fronting slots in `v1`. | [Part 3 §2](./spec/03-settlement-minted-zbtc-and-feeless-rails.md) |
| **M-2** | Two colluding operators alternate slot lapses cheaply | **Resolved by removal.** No fronting slots in `v1`. | [Part 3 §2](./spec/03-settlement-minted-zbtc-and-feeless-rails.md) |
| **M-3** | U0 pinned to superseded `rc1`; `rc2` ships `ad3b729` regression fixed in `0aa299e`; `#239` open | **Closed (`B1`).** U0 updated to first release tag containing `0aa299e`; `#239` closed is a hard gate before U3; CI symbol+hash citation checks added. *(Note: `v0` already marked `v0.0.10` legacy only.)* | [SPEC §5](./SPEC.md), [Part 5 §1–2](./spec/05-go-zenon-upgrade-plan.md) |
| **M-4** | PTLC 12-block refund race, "broadcast" vs "confirmed", free options, undefined `T_btc_worst` & `Δ_safety` | **Closed.** CSV raised to `72` blks; Bob MUST confirm by `h_conf + 66` with CPFP; Alice `+6`-blk release deadline; `T_btc_worst = 86,400s` (24h @ `2.0×`); `T_znn >= 108,000s`; LN `Δ_safety = 36` blks + per-peer Hold Invoice rate limit & 5-min cancel TTL. | [Part 3 §5](./spec/03-settlement-minted-zbtc-and-feeless-rails.md) |
| **M-5** | Valid `BTC_TX_STREAM_CHUNK` spam is free & unconsumed streams never pruned | **Closed by removal.** Streaming `0x04` and `SubmitInput` deposits deleted; federation txs capped at `<= 6,144 B` stripped + coinbase SHA-256 midstate proof (`<= 616 B`). | [Part 2 §2, §3.2](./spec/02-btc-authorization-domain-and-spv.md) |
| **M-6** | Leaf 3B SHA-256 without `OP_CAT` in `<= 95 kvB` & `470` free stack slots unproven | **Resolved by removal.** Leaf 3B disappears in `v1` and in validity-proof `v2` (`R-1, R-4`). | [Part 1 Annex A](./spec/01-bitcoin-taproot-vault-enforcement.md) |
| **M-7** | Admission control ran after irreversible `RolloverTx` custody | **Closed.** Added `ReserveMintCapacity` before sweep + `<288> OP_CSV` depositor refund leaf (`h_dep + 200` sweep cutoff). | [SPEC §3.1](./SPEC.md), [Part 1 §2.2](./spec/01-bitcoin-taproot-vault-enforcement.md), [Part 3 §2.2](./spec/03-settlement-minted-zbtc-and-feeless-rails.md) |
| **M-8** | Zenon censorship of release proof causes double-pay | **Closed by construction (`B4`).** Timeout-only refunds deleted; refunds require `K`-deep Bitcoin proof of conflict (`SubmitConflictRefundProof`) against `BatchIntent`. | [Part 1 §3.1](./spec/01-bitcoin-taproot-vault-enforcement.md), [Part 2 §3.3](./spec/02-btc-authorization-domain-and-spv.md) |
| **M-9** | Feeless capacity is `~9` tx/s default / `~4,400` ceiling under Dynamic Plasma, throttled by spork key | **Closed (`B2`).** Updated capacity math to Dynamic Plasma at `11.4s`/Momentum; pinned `MaxBasePlasmaInMomentum >= 2,100,000` floor and `MaxPriceChangePercent <= 25%` in `MintedZbtcSpork`; retired "millions of tx/s" & "0.5–5×" claims (`SPEC §8`). | [SPEC §3.2, §8](./SPEC.md), [Part 3 §3](./spec/03-settlement-minted-zbtc-and-feeless-rails.md), [Part 5 §3.1](./spec/05-go-zenon-upgrade-plan.md) |
| **M-10** | Observed Momentum time is `~11.4s`, not `10s`; finality today is 30-Momentum local rollback bound | **Closed.** All conversions updated to `11.4s`/Momentum; signers use explicit `D_znn = 60` Momentums (`2×` 30-Momentum bound, zero U2 dependency); every deadline uses one canonical unit. | [SPEC §3.2, §3.3](./SPEC.md), [Part 1 §3.1](./spec/01-bitcoin-taproot-vault-enforcement.md), [Part 3 §3](./spec/03-settlement-minted-zbtc-and-feeless-rails.md) |
| **M-11** | Certs in `(frontier, frontier + 60]` unslashable during stall (re-graded Low) | **Fixed.** Light clients and future consumers must wait for a subsequent certified Momentum (`frontier >= h`). | [Part 4 §3.3](./spec/04-bitcoin-anchoring-and-light-client.md) |
| **M-12** | Setup Committee could divert deposits & inflate G-21 phantom rounds | **Closed by removal.** Setup Committee & G-21 deleted; replaced with `k`-of-`n` federation (`>= k` independent keys) + pre-sweep reservation (`M-7`). | [Part 1 §2.2](./spec/01-bitcoin-taproot-vault-enforcement.md) |
| **M-13** | Precedence ranked Bitcoin custody (Part 1) below Zenon contracts | **Fixed.** Part 1 (`BTC-CUSTODY-F1`) is now #1 non-overridable layer in `SPEC §2.1`. | [SPEC §2.1](./SPEC.md#21-authority--conflict-precedence-m-13-fixed) |
| **M-14** | Missing/TBD parameters & circular "oracle verified" framing | **Closed.** Filled all applicable `v1` parameters (`minimumPostAnchorWork`, `Δ_safety = 36`, `T_btc_worst = 24h`, `SlashEquivocation = 100%`, `minDeposit = 100k` sats, `peginFee` floors, `ActiveCap = 5.0 BTC`); relabeled `verify_spec_bounds.py` a **Consistency & Bounds Checker** with sourced inputs + 2,000-step randomized simulation. *(Note: `v0` did enumerate all 11 wind-down items and derive `f_chal`.)* | [scripts/verify_spec_bounds.py](./scripts/verify_spec_bounds.py), [SPEC §8](./SPEC.md) |
| **M-15** | No independent review; self-declared closures | **Addressed explicitly.** Stage 1B hard-gated on independent third-party custody/HSM & bridge review; `v1` explicitly labeled pre-implementation RFC (`v3.0.0-rfc`). | [SPEC §7, §9](./SPEC.md) |

### Low Findings (`L-1` – `L-4`)

| ID | Finding Summary | Disposition in `v1` | Spec Reference |
|---|---|---|---|
| **L-1** | Undefined `<21` BLS Pillars & U2 competing certified branches | **Fixed.** Defined `FINALITY_DEGRADED` fallback (`<21` Pillars) and earliest-anchored / `FINALITY_HALTED` fork choice for competing certified branches. | [Part 4 §3.2](./spec/04-bitcoin-anchoring-and-light-client.md) |
| **L-2** | G-21 mint-stall window was `5.5d`, not `5.0d` | **Resolved by removal (and confirmed `N-6`).** G-21 & 30-day BitVM rotations deleted. | [Part 3 §2](./spec/03-settlement-minted-zbtc-and-feeless-rails.md) |
| **L-3** | Stale-acknowledgement fix (`#227`) active only after `DynamicPlasmaSpork` | **Fixed.** `DynamicPlasmaSpork` is now a hard runtime precondition for `MintedZbtcSpork` with MUST-fail vectors. | [Part 5 §2, §3.1, §6](./spec/05-go-zenon-upgrade-plan.md) |
| **L-4** | Errata (`BTC_SPV_VERIFIER_V2.4`, tie-break, assumption count, `bigidea` claims) | **Fixed.** Updated to `BTC_SPV_VERIFIER_V3.0`, documented `LOWEST_BLOCK_HASH_BE` tie-break vs `K = 14`, complete numbered §4 assumptions, and full `bigidea` claims alignment table (`SPEC §8`). *(Note: `v0`'s `0x0C` ABI table, `Take1` CPFP note, and `48h+12h` definition were misreads of two distinct calls / already stated.)* | [SPEC §4, §8](./SPEC.md), [Part 2 §1](./spec/02-btc-authorization-domain-and-spv.md) |

### Additional Issues Discovered & Closed During Peer Convergence (`N-1..N-6`, `B1..B5`)

| ID | Discovery | Disposition in `v1` |
|---|---|---|
| **N-1** | Sub-quorum single-Pillar equivocation triggered M0 mint freeze for 15k ZNN (~0.02–0.04 BTC) | **Fixed in `Part 4 §3.3` & resolved by removal in `v1` custody:** Only quorum-level (`>= 21`) equivocation triggers finality impairment. |
| **N-2** | `CommitteeIdentityKey` was an `N`-of-`N` twin of `Q_graph` (`14+` single points of failure) | **Resolved by removal:** Replaced with `k`-of-`n` independent federation keys (never aggregated `N`-of-`N`). |
| **N-3** | `FinalizeBatch` had no enforced 60h ceiling (chained commits/sessions extended indefinitely) | **Resolved by removal:** Optimistic batches and challenge sessions deleted in `v1`. |
| **N-4** | Fixed `10%` `ChallengeDepositZnn` contradicted descending priority ordering over retired 100-slot cap | **Resolved by removal:** Challenge priority lane deleted in `v1`. |
| **N-5** | Operator fraud was profitable whenever `P(challenge) < 68%` (self-slash `-0.40` vs `+0.999` gain) | **Resolved by removal:** BitVM2 operator model removed from `v1`. |
| **N-6** | `v0` oracle confirmed `5.0d` via half-day sampling despite its own `5.5d` comment | **Resolved by removal:** `v1` checker replaces discrete sampling with exact integer arithmetic + 2,000-step conservation simulation. |
| **B1** | One panicking embedded receive permanently stalls `SettlementContract` FIFO queue (`ErrABSequencerNotNext`) | **Closed:** Mandatory `recover()` in every Settlement/SPV method, `#239` deterministic failed-receive gate before U3, and zero-internal-error fuzz gate. |
| **B2** | Unmetered receives + `210,000` Plasma floor blocks calls `> 2,011 B` in `content_selector.go` | **Closed:** `DynamicPlasmaSpork` hard precondition, `EMBEDDED_HEAVY_SPV_TIER = 73,500`, storage-op caps, and spork-pinned `MaxBasePlasmaInMomentum >= 2,100,000` floor. |
| **B3a/b/c** | Exact in-flight backing inequality, VM-balance `Circ` check, and `TreasuryTrancheEscrow` cap isolation | **Closed:** Normative `B3a/B3b` signer policy in `Part 1 §3.1`, `TreasuryTrancheEscrow` in `Part 3 §1`, and 2,000-step simulation in `scripts/verify_spec_bounds.py`. |
| **B4** | Timeout-only refunds double-pay because signed Bitcoin transactions never expire | **Closed:** Zenon-final `BatchIntent` before signing + `K`-deep `SubmitConflictRefundProof` ONLY. |
| **B5** | `v0` must be archived byte-for-byte from published commit `7b47b8c` (zero local filesystem paths) | **Closed:** Archived verbatim in `versions/v0/` with `SHA256SUMS.txt` verified in build & CI. |
