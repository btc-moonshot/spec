# Part 1: Bitcoin Federated Custody Enforcement (`BTC-CUSTODY-F1`) & `v2` Research Annex

**Document Class:** Normative Bitcoin Custody Specification (`v1` / `v3.0.0-rfc`; supersedes `v0` `BTC-ENFORCEMENT-V1`)  
**Spec Identifier:** `BTC-CUSTODY-F1`  
**Precedence:** **Highest normative layer** ([`SPEC.md §2.1`](../SPEC.md#21-authority--conflict-precedence-m-13-fixed)) — honest federation signers MUST enforce Part 1 invariants even if Zenon contract state conflicts.  
**Target Chain:** Bitcoin Mainnet (`bip-0340` Schnorr, `bip-0341` Taproot, `bip-0342` Tapscript, `bip-0068`/`bip-0112` relative timelocks, SegWit v1 P2TR)  
**Consistency Checker:** [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py)

---

## 1. Custody Model & Explicit Scope

`v1` replaces `v0`'s never-deleted `N`-of-`N` `Q_graph` + BitVM2 hybrid with an **honest, auditable, capped `k`-of-`n` Tapscript HSM federation (`Tier F`)**. There is **no BitVM2**, **no fronting operators**, **no `N`-of-`N` standing key (`C-4, N-2`)**, and **no ZNN collateral in the Bitcoin safety path (`C-1`)**.

| Profile | Mechanism | Custody Trust Root | Status in `v1` |
|---|---|---|---|
| **Tier F (`BTC-CUSTODY-F1`, Normative `v1`)** | Taproot NUMS + `k`-of-`n` `OP_CHECKSIGADD` active HSM leaf (`7-of-10` pilot / `11-of-15` scaled) + `<52,560> OP_CSV` backup recovery leaf + dual-implementation signer policy (`B3a/B3b` + `settlementCodeHash` firewall) | `k`-of-`n` active federation safety; `n - k + 1` liveness; `k'`-of-`n'` recovery set after `52,560` blocks | **Normative `v1` target** |
| **Tier 1B (Optional Sovereign)** | Per-deposit self-custodial Taproot escrow (depositor co-signs key path + CLTV refund) | Depositor + counterparty per deposit | Optional separate non-fungible binding |
| **Tier 2 / Path A (`v2` Research Track)** | Deleted-key non-expiring BitVM / garbled circuits + ZK execution validity + Bitcoin-anchored fork choice | Gated on Research Gates **R-1..R-8** (Appendix A) | **Non-normative research annex** |

> **Explicit Custodial Disclosure (replacing `v0` C-07):** `Tier F` IS a federated custodial peg. Signer identities, jurisdictions, organizational separation, HSM hardware attestations, and independent signer-software builds MUST be published before Stage 1B activation.

---

## 2. Bitcoin Vault & Deposit Taproot Scripts

### 2.1 Canonical Vault Output (`VaultScript_F1`)

Every active federation vault UTXO is a SegWit v1 P2TR output (`OP_1 <32B x-only tweaked pubkey>`) with a provably unspendable **NUMS internal key**:
`H_NUMS_X = 0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0` (`lift_x(SHA256(uncompressed G))`)

The Taproot Merkle tree has **exact depth 1 (two Tapscript leaves)**:

1. **Leaf 1 — Active Federation (`k`-of-`n` `OP_CHECKSIGADD`):**
   ```text
   <pk_1> OP_CHECKSIG
   <pk_2> OP_CHECKSIGADD
   ...
   <pk_n> OP_CHECKSIGADD
   <OP_k> OP_NUMEQUAL
   ```
   - **Pilot (`Stage 1B`):** `7-of-10` (`342 B` script, `1,034 WU` = **`258.50 vB`/input**, `4.50×` key-path `57.5 vB`).
   - **Scaled:** `11-of-15` (`512 B` script, `1,465 WU` = **`366.25 vB`/input**, `6.37×` key-path `57.5 vB`).
   - *Why `OP_CHECKSIGADD` over FROST in `v1`:* Zero interactive DKG or MuSig2/FROST nonce-state footguns, natively supported on standard HSMs, every individual signer is auditable on-chain, and signer rotation is an explicit on-chain migration (since FROST resharing cannot cryptographically revoke old key shares anyway). The `4.5×–6.4×` input weight overhead is explicitly priced into peg-in fees and the Operations Reserve (§2.4).

2. **Leaf 2 — Custodial Backup Recovery (`<52,560> OP_CSV` + `k'`-of-`n'`):**
   ```text
   <0x50cd00> OP_CHECKSEQUENCEVERIFY OP_DROP
   <rpk_1> OP_CHECKSIG
   <rpk_2> OP_CHECKSIGADD
   ...
   <rpk_n'> OP_CHECKSIGADD
   <OP_k'> OP_NUMEQUAL
   ```
   - `T_RECOVERY_CSV = 52,560` Bitcoin blocks (~365 days nominal; strictly `<= 65,535` BIP-68 block-type limit; minimal little-endian script push `03 50cd00`).
   - Held by a distinct backup recovery set (`k'`-of-`n'`, e.g. `5-of-7`, separate HSMs and jurisdictions from the active quorum).
   - **Refresh is a safety duty, not hygiene:** Once a vault UTXO reaches `52,560` confirmations without being refreshed, Leaf 2 unlocks and the recovery set can race the active set. Every vault UTXO (including un-swept tweaked deposit outputs) MUST be refreshed on-chain before `T_REFRESH_TRIGGER = 26,280` blocks (~182.5 days, 50% of CSV). Any UTXO reaching `T_REFRESH_IMPAIRMENT = 39,420` blocks (~273.75 days, leaving `13,140` blocks ≈ 91.3 days margin) triggers an automatic **Impairment Alert & Mint Pause**.

### 2.2 Per-Recipient Deposit Output (`DepositScript_F1`, Closing `M-7`)

Each user peg-in targets a unique P2TR output using the tweaked internal key `P_dep = lift_x(H_NUMS_X) + H("zBTC/DepositTweak/v2", zenonRecipient(20B) || refundPk(32B)) * G` (unspendable NUMS tweak) with depth-1 Taproot tree:
- **Leaf 1:** Identical `k`-of-`n` `OP_CHECKSIGADD` active federation script (§2.1).
- **Leaf 2 (Unconditional User Refund):** `<288> OP_CHECKSEQUENCEVERIFY OP_DROP <refundPk> OP_CHECKSIG` (`~48h`, `>> K_pilot = 14`).

**Sweep Cutoff:** Signers MUST ONLY sweep deposits that have an active Zenon `ReserveMintCapacity` record AND whose confirmation height satisfies `h_tip < h_dep + 200` (leaving `>= 88` blocks safety margin before Leaf 2 matures). If a deposit cannot be swept (cap full, paused, or invalid), the user unilaterally reclaims via Leaf 2 after `288` blocks. Any swept deposit output not immediately consolidated MUST be tracked in the refresh calendar.

### 2.3 Federation Transaction Size Cap & Coinbase Verification

All federation-built transactions (`SweepTx`, `PayoutTx`, `RefreshTx`, `CancelTx`) MUST have **stripped (non-witness) serialized size `<= 6,144` bytes** (`MAX_FED_STRIPPED_TX_BYTES`), guaranteeing direct on-L1 SPV verification without streaming (`0x04` deleted from normative path).

### 2.4 Fee Floors, Fragmentation Defense & Operations Surplus Reserve

- **Minimum Deposit & Peg-Out Floor:** `100,000` sats (`0.001 BTC`). Arbitrary amounts above floor are supported (fixed `1.0 BTC` buckets deleted).
- **Consolidation Fee Floor (`PegInFee`):** Because `100,000`-sat script-path UTXOs become uneconomic dust above `386.8 sat/vB` (`7-of-10`) or `273.0 sat/vB` (`11-of-15`), every peg-in deducts `pegInFee >= ceil(input_vb * r_ref)` (`25,850` sats for `7-of-10`, `36,625` sats for `11-of-15` at `r_ref = 100 sat/vB`) into the vault surplus `S = V - Circ - P` to fund future refreshes and consolidations.
- **Peg-Out Fee:** Deducted directly from the user's gross burn (`netPayout = burnGross - userFeeShare`), with `sum(userFeeShare) >= maxFee(t)` across all outputs of a `BatchIntent` (RBF bumps above `sum(userFeeShare)` may draw only from surplus `S` subject to `B3a`).
- **Vault UTXO Cap & Seeded Surplus Reserve (`H-6`):** `MaxVaultUtxos = 64`. The Operations/Surplus Reserve `S` MUST be seeded prior to Stage 1B with at least `MaxVaultUtxos * ceil(input_vb) * 2,000 sat/vB` (covering April 2024's `>1,805 sat/vB` fee spike across all 64 vault UTXOs): `>= 0.33152 BTC` (`7-of-10`) or `>= 0.46976 BTC` (`11-of-15`) — **normative seed `>= 0.50 BTC`**.

---

## 3. Normative Dual-Implementation Signer Policy (`B3a`, `B3b`, `B4`, `H-3`)

Every federation signer MUST run its own full `bitcoind` node and its own pinned `go-zenon` full node. The federation MUST operate **at least two independently engineered signer implementations** (different teams/codebases, e.g. Rust + Go) so a single accounting bug cannot compromise quorum.

### 3.1 Mandatory Pre-Sign Verification Checklist (Evaluated on EVERY Spend)

Before producing a Schnorr signature on ANY payout, fee bump, sweep, refresh, or cancel transaction `new`, a signer MUST verify ALL of the following at a **single `K = 14`-deep Bitcoin snapshot** and a **single `D_znn = 60`-Momentum-deep Zenon snapshot** (`>= 2×` `protocol/chain_bridge.go:293`'s 30-Momentum rollback limit; zero U2 dependency):

1. **Cross-Signer Zenon Snapshot Agreement:** At least `k` independent signer nodes agree on the exact Zenon Momentum hash at the evaluation height `H_eval <= frontier - 60`.
2. **Pinned `settlementCodeHash` Upgrade Firewall (`H-3`):** The signer's local `go-zenon` node MUST match the signer operator's explicitly pinned `(activeSporkSetHash, goZenonReleaseDigest)` for `SettlementContract`. If an unapproved spork activates or mutates `SettlementContract` semantics, honest signers IMMEDIATELY halt signing until `>= k` signer operators independently audit and re-pin after the `>= 30-day` upgrade window.
3. **VM-Balance Supply Conservation (`B3b`):** Compute circulating supply strictly from **VM account balances** (never trusting `SettlementContract`'s internal counter alone):
   $$\text{Circ} = \text{TotalSupply} - \bigl(\text{Balance}(\text{SettlementContract}) + \text{Balance}(\text{TreasuryTrancheEscrow})\bigr)$$
   Assert **`Circ == SettlementContract.RepresentationOutstanding`**. On ANY mismatch, **HALT SIGNING IMMEDIATELY**, emit an emergency alert, and require manual forensic reconciliation. *(Honest disclosure: this stops unbacked `zBTC` from draining Bitcoin vaults via peg-outs, but cannot prevent an attacker from selling unbacked `zBTC` for BTC over PTLC/LN before the halt becomes public.)*
4. **Exact Conservation & Backing Inequality (`B3a`):** Let `V_conf` be the sum of all `K`-deep confirmed UTXOs controlled by the federation across ALL active vault scripts (including tweaked deposit addresses and legacy scripts during migration), and let `InFlight` be the set of all previously signed, unconfirmed federation transactions. Assert:
   $$V_{\text{conf}} - \sum_{t \in \text{InFlight} \cup \{\text{new}\}} \bigl(\text{nonVaultOut}(t) + \text{maxFee}(t)\bigr) \;\ge\; \text{Circ} + P - \sum_{t \in \text{InFlight} \cup \{\text{new}\}} \text{burnGross}(t)$$
   subject to:
   - `maxFee(t)` is the maximum fee across all signed RBF variants of `t`;
   - every `nonVaultOut` matches a `D_znn`-final `PegOutRecord` listed in a `D_znn`-final `BatchIntent`;
   - distinct in-flight transactions have **strictly disjoint inputs** (except RBF/cancel variants of the exact same `BatchIntent`);
   - **zero unconfirmed change chaining:** signers NEVER spend unconfirmed vault change (except a single federation CPFP child paying back to a valid vault script, also counted in `InFlight`).
5. **Zenon-Final `BatchIntent` First (`B4`):** For every payout transaction, a matching `BatchIntent(intentId, inputs[], outputs[], feeCapSats)` MUST be `D_znn`-final on Zenon BEFORE any signer signs. All RBF fee bumps MUST reuse the identical `inputs[]` set.
6. **24-Hour Velocity Limit:** Cumulative `nonVaultOut` signed over the trailing 24 hours MUST NOT exceed the policy velocity cap (pilot default: `2.5 BTC / 24h`, adjustable via Governance + `>= k` signers).

### 3.2 Signer-Set Rotation & On-Chain Migration

Rotating signer keys (`Set A → Set B`) is ALWAYS an **explicit on-chain migration**:
1. Governance + `>= k` signers register `Set B`'s `ChainBinding` (`>= 14d` timelock).
2. New deposits target `Set B`; existing `Set A` vaults are swept into `Set B` vault outputs by `Set A` signers (preserving `B3a` across the union `V_conf(Set A) + V_conf(Set B)`).
3. Once `V_conf(Set A) == 0` for `>= K = 14` blocks, `Set A` is retired.

---

## 4. Machine-Readable Proof-of-Reserves

Signers publish a signed, reproducible Proof-of-Reserves bundle every `6` hours (and within `2` hours of any pause/impairment):
- Exact list of `K`-deep vault UTXOs (outpoint, script descriptor, value, confirmation height, age vs `T_REFRESH_TRIGGER`);
- All signed `InFlight` `BatchIntent`s and `maxFee(t)` bounds;
- Zenon snapshot `(H_eval, momentumHash)`, VM `Circ`, `RepresentationOutstanding`, `PendingForeignRelease`, `Balance(SettlementContract)`, `Balance(TreasuryTrancheEscrow)`, and surplus `S = V_conf - Circ - P`.

---

## 5. Impairment, Permanent Failure & Wind-Down Plan (With Explicit Loss Model)

1. **Impairment Triggers:** `B3b` mismatch (`Circ != RepresentationOutstanding`), `B3a` violation, unexpected vault spend not matching a signed `BatchIntent`, any vault UTXO age `>= 39,420` blocks unrefreshed, Bitcoin reorg `> K = 14` orphaning an admitted lock/release, Operations Reserve `S` falling below `50%` of the stress refresh floor, or `>= n - k + 1` active signers offline for `> 72` hours.
2. **Pause Scope (`H-3`):** Pause freezes new mints (`ReserveMintCapacity`, `SubmitSweepLockProof`) and new deposit sweeps ONLY. **`RequestPegOut`, `SubmitHeaderBatch`, `SubmitReleaseProof`, `SubmitConflictRefundProof`, and honest signer payouts STAY OPEN.**
3. **Incident Snapshot:** Publish `(H_eval, momentumHash, V_conf, Circ, P, InFlight[], ActiveReservations[], Surplus S)` within `2` hours.
4. **Orderly Wind-Down (Active Quorum Alive):** Federation ceases sweeps, lets pending deposits refund via Leaf 2 (`288` blks), fulfills all `RequestPegOut` requests FIFO up to `100%` of `Circ + P`, and cancels stuck `BatchIntent`s via conflict-proof re-spends (`B4`).
5. **Recovery-Leaf Wind-Down (`>= n - k + 1` Active Signers Permanently Lost):**
   - Wait until vault UTXOs reach `52,560` blocks (`<= 365` days worst-case wait from last refresh).
   - Backup recovery set (`k'`-of-`n'`) sweeps all remaining vault BTC into an audited pro-rata Wind-Down distribution contract/payout list covering all verified `zBTC` holders (`Circ`) plus unpaid `PendingForeignRelease` claims (`P`) at their **gross** burn amount.
6. **Explicit Loss Model:**
   - *Active-quorum loss / liveness failure:* **0% principal loss** (minus Bitcoin sweep/payout fees); time-value lockup of up to `52,560` blocks (~365 days).
   - *Partial theft / unbacked Zenon mint exploit sold externally:* Any shortfall `Δ = (Circ + P) - V_remaining` is disclosed transparently in the PoR snapshot and distributed strictly **pro-rata** (`payout_i = claim_i * V_remaining / (Circ + P)`); zero silent socialization.
   - *Total `k`-of-`n` active collusion or `k'`-of-`n'` recovery collusion after maturity:* **Up to 100% loss of vault BTC.** This risk is irreducible in `Tier F` and is bounded solely by signer independence, HSM controls, velocity limits, and the `5.0 BTC` pilot cap.

---

## Appendix A: Non-Normative `v2` Research Annex (Path A: Trust-Minimized BitVM)

> **Status: NON-NORMATIVE RESEARCH TRACK.** Nothing in `v1` (`Tier F`) relies on this annex, and no public material may claim trust minimization until ALL eight Research Gates (**R-1..R-8**) below are empirically closed and audited.

### A.1 Why `v0`'s BitVM2 Hybrid Could Not Be Patched Into `v1`

Without Bitcoin covenants, a bridge can have at most two of: (i) deleted setup keys, (ii) a rotating PoS committee root pinned inside pre-signed graphs, and (iii) no standing custodial key. Pinning Zenon's 30-day committee root forced `58d` graph expiry → `30d` re-graphing → never-deleted `N`-of-`N` `Q_graph` (`C-4`) and `N`-of-`N` `CommitteeIdentityKey` (`N-2`). Independently, trusting committee-signed state tied safety to ZNN's thin market cap (`C-1, C-2, H-1..H-3`), and unchunked/Groth16 BitVM2 script sizes blew up `F_assert` and watcher economics (`C-3, H-4, M-6`).

### A.2 Mandatory Research Gates for `v2` (`R-1` through `R-8`)

| Gate | Requirement to Enter `v2` Spec |
|---|---|
| **R-1 (ZK State Validity)** | Either a full **ZK light client of Zenon execution** covering every block touching `zBTC` balances + all mint/burn/refund handlers, OR moving `zBTC` into a **ZK-proven execution domain** (explicitly accepting the trade-off of losing native feeless block-lattice transfers). Pin `vk` per vault (providing `H-3` upgrade isolation) and define a migration path for bug fixes. |
| **R-2 (Bitcoin-Anchored Full-Node Fork Choice)** | Adopt "earliest Bitcoin-anchored certified branch wins" in **Zenon full-node consensus** (not light clients alone), and make timely Bitcoin anchoring of every epoch handoff a mandatory committee duty backed by a Reserve bounty (`H-7` becomes Critical once graphs stop expiring). |
| **R-3 (In-Circuit Bitcoin Header Chain + Watchtower Challenge)** | Prove `FrontingTx` Bitcoin SPV + header chain inside the BitVM circuit paired with a watchtower chain-work challenge (preventing private-fork proofs). |
| **R-4 (Measured Signet Script Weights)** | Empirical Signet comparison of modern **BitVM2** vs **garbled circuits (BitVM3 / DV-SNARK)**. Measure real assert and disprove sizes; prove every disprove leaf is `< 400 kWU` standard OR specify a non-standard miner submission path and its censorship model (`C-3, M-6`). *(Note: Leaf-3B cert-DA SHA-256 disappears once validity proofs replace ZNN slashing.)* |
| **R-5 (Non-Front-Runnable Watcher Incentives)** | Solve `H-4` via a front-run-resistant watcher reward (or protocol-paid bonded watchtower set) and re-derive `F_assert`, operator bonds, and `D_bucket` from **R-4** measurements. |
| **R-6 (Deleted-Key Non-Expiring Graphs & Operator-Loss Policy)** | Per-deposit deleted setup keys (NUMS key path, zero 30d re-graphing) with an explicit policy decision on total operator-set loss: either accept permanent unrecoverability (pure `C-07`) OR include a long-timelock recovery leaf and disclose it honestly (`C-4`). Require certificate availability *before* kickoff (`H-2` fix) if any committee cert remains. |
| **R-7 (Parallel Exit Throughput)** | Support multiple concurrent kickoffs per operator round and publish worst-case time-to-exit math for 100% of supply (`H-5`). |
| **R-8 (`v1` → `v2` Migration Path)** | Define opt-in migration where `Tier F` federation signers sweep `v1` vault BTC directly into `v2` vaults (or launch `v2` under a distinct `AssetID`). |
