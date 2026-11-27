# zBTC: Bitcoin–Zenon Interoperability Protocol Specification

**Version:** `v1` (`v3.0.0-rfc` — Tier F Honest Capped Federated Custody + Direct-on-L1 Trimmed SPV; supersedes archived `v0` / `v2.5.0-rfc`, see [CHANGELOG.md](./CHANGELOG.md))  
**Status:** Public Request for Comment (`v1` / `v3.0.0-rfc`) — NOT mainnet-active; gated on independent custody/HSM & bridge review (**M-15**), upstream `go-zenon` release & issue `#239` closure (**B1**), Signet drills, and governance decentralization (§7).  
**Target Networks:** Bitcoin Mainnet (`bip-0340`/`bip-0341`/`bip-0342` Taproot `OP_CHECKSIGADD` HSM federation) ↔ Zenon Network (`go-zenon` first tagged release containing `0aa299e` with `DynamicPlasmaSpork` enforced; legacy `v0.0.10` `e8986a6` reference only)  
**Consistency & Bounds Checker:** All modeled Tapscript input weights, BIP-68 CSV refresh margins, direct-on-L1 SPV ABI & Dynamic Plasma floor bounds, PTLC/HTLC timelocks, halving-indexed `K`, and a 2,000-step randomized simulation of the signer backing/conservation invariant are asserted by [`scripts/verify_spec_bounds.py`](./scripts/verify_spec_bounds.py) (`python3 -I scripts/verify_spec_bounds.py`). *This script verifies internal mathematical consistency against explicitly labeled `SOURCED_` and `POLICY_` inputs; it is not an empirical Signet benchmark or audit.*

**Upstream Provenance & Review Trail:**
- Vision Proposal: [`https://btc-moonshot.github.io/bigidea/`](https://btc-moonshot.github.io/bigidea/) *(see §8 for required claims alignment)*
- Reference Node Codebase: [`go-zenon`](https://github.com/zenon-network/go-zenon) (`origin/dev` pinned at `770e893` for verified code anchors, `release/0.0.11-rc2` `b85ee94` + fix `0aa299e`)
- Archived Baseline (`v0` / `v2.5.0-rfc`): Frozen byte-for-byte in [`versions/v0/`](./versions/v0/) (SHA-256 verified in CI).
- Consolidated Hostile Review (`R7`): [`reviews/HOSTILE_REVIEW_R7_CONSOLIDATED.md`](./reviews/HOSTILE_REVIEW_R7_CONSOLIDATED.md) — every finding `C-1..C-4`, `H-1..H-8`, `M-1..M-15`, `L-1..L-4`, plus audit discoveries `N-1..N-6` and convergence blockers `B1..B5`, is dispositioned in [`CHANGELOG.md`](./CHANGELOG.md).

---

## 1. Executive Summary & Architectural Pivot (`v0` → `v1`)

This specification defines **`Tier F` (`BTC-CUSTODY-F1`)**: an **honest, capped federated Bitcoin peg** issuing 1:1 `zBTC` (`1 base unit = 1 satoshi`, 8 decimals, `21,000,000 BTC` max token cap, Stage 1B policy cap **`5.0 BTC`**) on Zenon's feeless block-lattice, verified by **direct-on-L1 trimmed Bitcoin SPV + `k`-of-`n` federation co-signatures**, paired with **peg-free PTLC adaptor swaps and Lightning Network submarine-swap gateways**.

**Why `v1` replaces `v0`'s BitVM2 hybrid:** The consolidated hostile review of `v0` (`v2.5.0-rfc`) and independent peer review established four fundamental blockers in the `v0` hybrid: (1) ZNN's thin market liquidity (`400k–727k ZNN/BTC` vs assumed `10,500 ZNN/BTC`) cannot economically secure a 15 BTC pilot via Pillar slashing (**C-1**); (2) trusting committee-signed canonical Zenon state makes unchallenged optimistic batches, spork upgrades, and free-delegation committees fatal (**C-2, H-1, H-2, H-3**); (3) published Groth16 BitVM2 assert sizes (~1–4.8 MB) are 4–10× larger than `v0`'s assumed `220 kvB`, breaking bond/watcher economics (**C-3, H-4, M-6**); and (4) rotating 30-day committee roots forced an un-deleted `N`-of-`N` `Q_graph` key (plus an `N`-of-`N` `CommitteeIdentityKey`), creating both custodial sweep risk and 1-of-`N` permanent bricking (**C-4, N-2**).

**What `v1` is, stated plainly:**
- **Custody:** A `k`-of-`n` Tapscript `OP_CHECKSIGADD` HSM federation (`7-of-10` pilot / `11-of-15` scaled) under a NUMS internal key, with an explicit custodial `<52,560> OP_CSV` (~365-day) backup recovery leaf and mandatory on-chain vault refresh every `26,280` blocks (~182.5 days). **No BitVM2, no operators/fronting slots, and ZERO ZNN in the Bitcoin safety path.**
- **Mint & Burn Settlement:** Direct-on-L1 trimmed Bitcoin SPV inside `SettlementContract` (no optimistic batches, no 48h challenge lag, no executors) co-signed by `≥ k` federation signers, with `SettlementContract`'s exposure isolated behind a timelocked `TreasuryTrancheEscrow` (**H-8, B3c**).
- **Signer Firewall & Conservation:** At least two independent signer implementations independently check a strict VM-balance conservation invariant (**B3a/B3b**) and a pinned `settlementCodeHash` firewall (**H-3**) before signing any Bitcoin spend.
- **No Timeout-Only Refunds:** Signed Bitcoin payouts never expire; peg-out refunds require a K-deep Bitcoin SPV **proof of conflict** (`SubmitConflictRefundProof`) against a Zenon-final `BatchIntent` (**B4**).
- **Trust-Minimized Future (`v2`):** Deleted-key non-expiring BitVM / garbled circuits + ZK execution validity proofs + Bitcoin-anchored full-node fork choice are preserved honestly as a **non-normative `v2` Research Annex** in [`spec/01 Appendix A`](./spec/01-bitcoin-taproot-vault-enforcement.md#appendix-a-non-normative-v2-research-annex-path-a-trust-minimized-bitvm) gated on Research Gates **R-1..R-8**.

---

## 2. Normative Module Map & Authority Precedence

| Module | File | Normative Scope in `v1` (`v3.0.0-rfc`) |
|---|---|---|
| **Master** | [`SPEC.md`](./SPEC.md) | Tier F architecture, end-to-end flows (§3), complete Threat Model & Privileged Powers Table (§4), Upstream Amendments (§6), Stage 0/1A/1B Gates (§7), Public Claims Alignment (§8), and Written Q&A Disposition (§9). |
| **Part 1** | [`spec/01-bitcoin-taproot-vault-enforcement.md`](./spec/01-bitcoin-taproot-vault-enforcement.md) | **`BTC-CUSTODY-F1` (Highest Custody Precedence):** Taproot NUMS + `OP_CHECKSIGADD` active leaf (`7-of-10` / `11-of-15`), `<52,560> OP_CSV` recovery leaf, mandatory refresh safety duty, dual-implementation signer policy (`B3a/B3b` conservation + `settlementCodeHash` firewall), `BatchIntent` + conflict-only refunds (`B4`), Proof-of-Reserves, Wind-Down with loss model, and **Appendix A: Non-Normative `v2` BitVM Research Annex (R-1..R-8)**. |
| **Part 2** | [`spec/02-btc-authorization-domain-and-spv.md`](./spec/02-btc-authorization-domain-and-spv.md) | **Direct-on-L1 Trimmed Bitcoin SPV Verifier (`vm/embedded/btcspv/`):** Pure-Go, panic-recovered (`B1`) ABI methods (`SubmitHeaderBatch`, `StepReorg`, `PruneStaleHeaders`, `SubmitSweepLockProof`, `PostBatchIntent`, `SubmitReleaseProof`, `SubmitConflictRefundProof`), coinbase midstate proof (no streaming `0x04`), `<= 6,144 B` stripped federation tx cap, halving-indexed `K_pilot = 14`, explicit `minimumPostAnchorWork`, `LOWEST_BLOCK_HASH_BE` tie-break, and conformance vectors. |
| **Part 3** | [`spec/03-settlement-minted-zbtc-and-feeless-rails.md`](./spec/03-settlement-minted-zbtc-and-feeless-rails.md) | **Lightweight `SettlementContract`, Tranche-Isolated `zBTC`, Dynamic Plasma & Peg-Free Rails:** `TokenContract.IssueMinted` → `TreasuryTrancheEscrow` + capped `SettlementContract` tranches (`H-8, B3c`), `ReserveMintCapacity` (`M-7`), `RequestPegOut`, `BatchIntent` & conflict refunds (`B4`), Dynamic Plasma capacity at `11.4s`/Momentum with pinned `2.1M` floor (`B2, M-9, M-10`), hardened PTLC (`>= 72`-blk CSV, confirmed-before-refund, `T_btc_worst = 24h`) & LN gateway (`Δ_safety = 36` blks, hold-invoice rate limits, `M-4`). |
| **Part 4** | [`spec/04-bitcoin-anchoring-and-light-client.md`](./spec/04-bitcoin-anchoring-and-light-client.md) | **Zenon History Anchoring & Light Client Infrastructure *(Non-Custodial — NOT a `v1` activation gate and NOT in the `v1` BTC custody path)***: Genesis BTC anchor `710,968`, `proof-format.md` V1 SMT proofs, epoch-averaged slashable/beacon committee selection (`H-1`), `<21` Pillar fallback & competing certified branches (`L-1`), quorum-only impairment (`N-1`), mandatory bountied epoch handoff anchoring & light-client BTC header source (`H-7`). |
| **Part 5** | [`spec/05-go-zenon-upgrade-plan.md`](./spec/05-go-zenon-upgrade-plan.md) | **Detailed `go-zenon` Node Upgrade Plan:** U0 on first release tag containing `0aa299e`, CI symbol+hash citations, `#239` + `recover()` FIFO-stall gate (`B1`), `DynamicPlasmaSpork` hard precondition + pinned `2.1M` Plasma floor (`B2, L-3`), lightweight U3 (`SettlementContract` + direct L1 `btcspv`, U4 retired), U5 `GovernanceContract` + `MultisigContract` hard gate before Stage 1B. |
| **Checker** | [`scripts/verify_spec_bounds.py`](./scripts/verify_spec_bounds.py) | Deterministic Python 3 consistency & bounds checker asserting Tapscript weights (`258.50` / `366.25 vB`), BIP-68 CSV push (`03 50cd00`), ABI & B2 Plasma floor (`2,100,000`), `11.4s` Dynamic Plasma TPS, PTLC/LN timelocks, `K_pilot = 14`, and a 2,000-step randomized simulation of B3a/B3b/B3c/B4. |
| **Changelog** | [`CHANGELOG.md`](./CHANGELOG.md) | Complete finding-by-finding (`C-1..C-4`, `H-1..H-8`, `M-1..M-15`, `L-1..L-4`, `N-1..N-6`, `B1..B5`) disposition from `v0` (`v2.5.0-rfc`) to `v1` (`v3.0.0-rfc`). |

### 2.1 Authority & Conflict Precedence (`M-13` Fixed)

1. **Bitcoin Custody Invariants in [`spec/01`](./spec/01-bitcoin-taproot-vault-enforcement.md) (`BTC-CUSTODY-F1`)** — non-overridable layer: Taproot script policy, signer `B3a/B3b` VM-balance conservation check, pinned `settlementCodeHash` firewall, refresh safety duty, and conflict-only refunds. Any Zenon contract behavior that conflicts with Part 1 is a spec bug, and honest signers MUST refuse to sign.
2. Deployed Zenon L1 consensus rules (post-U0 tag containing `0aa299e` with `DynamicPlasmaSpork` enforced).
3. [`spec/03`](./spec/03-settlement-minted-zbtc-and-feeless-rails.md) & [`spec/05`](./spec/05-go-zenon-upgrade-plan.md) (`SettlementContract`, `TreasuryTrancheEscrow`, Plasma & upgrade gates).
4. [`spec/02`](./spec/02-btc-authorization-domain-and-spv.md) (direct-on-L1 trimmed `btcspv` verifier).
5. [`spec/04`](./spec/04-bitcoin-anchoring-and-light-client.md) (non-custodial Zenon anchoring & light-client infrastructure).

---

## 3. End-to-End Protocol Flows (`Tier F`)

### 3.1 Peg-In: BTC → Tweaked Vault Deposit → Sweep → Direct-L1 SPV Mint

1. **Capacity Reservation (`M-7`):** Before sending BTC, user (or relayer) calls `SettlementContract.ReserveMintCapacity(depositOutpoint_or_commitment, expectedAmountSats, zenonRecipient)` to verify `Circ + PendingForeignRelease + ActiveReservations + expectedAmountSats <= ActiveCap` and `Status == ACTIVE` (`Halted == 0`). Reservations expire automatically after `288` Bitcoin blocks if unused.
2. **Provisional Tweaked Deposit Address:** User derives a per-recipient Taproot deposit address using the active federation vault policy under a deterministic NUMS tweak `H_NUMS + H("zBTC/DepositTweak/v2", zenonRecipient || refundPk) * G`:
   - **Leaf 1 (Active Federation):** `k`-of-`n` `OP_CHECKSIGADD` (`7-of-10` pilot / `11-of-15` scaled).
   - **Leaf 2 (Depositor Refund, `M-7`):** `<288> OP_CSV OP_DROP <refundPk> OP_CHECKSIG` (~48h, `>> K_pilot = 14`).
   User sends any amount `>= 100,000` sats (`0.001 BTC`) plus peg-in consolidation fee `>= ceil(input_vb * r_ref)` (`25,850` sats for `7-of-10` / `36,625` sats for `11-of-15` at `r_ref = 100 sat/vB`).
3. **Federation Sweep:** After deposit confirms (and strictly before `h_dep + 200`, leaving an `>= 88`-block safety buffer before Leaf 2 unlocks), `>= k` signers independently verify the Zenon capacity reservation and sign a batched `SweepTx` (`stripped size <= 6,144 B`) consolidating deposits into standard `BTC-CUSTODY-F1` vault UTXOs (respecting `MaxVaultUtxos = 64`). If capacity was exhausted or the federation is paused, the federation does NOT sweep and the user recovers unconditionally via Leaf 2 after `288` blocks.
4. **Direct-on-L1 SPV Mint (`SubmitSweepLockProof`):** Once `SweepTx` reaches `K_pilot = 14` confirmations, anyone submits `SubmitHeaderBatch` + `SubmitSweepLockProof(strippedSweepTx, blockHash, txIdx, txBranch, cbMidstateProof, mintAllocations[], fedSigs[>=k])` directly to `SettlementContract` (no 48h batch delay). On-chain `btcspv` verifies `K`-deep Bitcoin inclusion, CVE-2017-12842 coinbase midstate (`len != 64`), `sum(mintAllocations) <= sum(vaultOutputs) - minPegInFees`, deposit-outpoint replay uniqueness, and `>= k` independent federation signatures attesting recipient attribution (auditable off-chain via Taproot sighash input amounts). `SettlementContract` atomically transfers `netAmount` `zBTC` from its cap-bounded tranche to each `zenonRecipient`.

### 3.2 Feeless `zBTC` Transfers on Zenon Block-Lattice (`M-9`, `M-10`)

Standard `zBTC` transfers cost **0 satoshis BTC fee** and `21,000` base Plasma per account block (`42,000` Plasma total for send + receive), funded via refundable QSR fusion (`10 QSR` per block at floor price `1,000`) or SHA3-256 PoW (`31.5M` expected hashes per block at floor price; ~0.1–0.3s desktop, ~2–10s mobile/WASM). Under Dynamic Plasma at observed mainnet Momentum intervals of **`~11.4s`** (`origin/dev:vm/embedded/definition/spork.go`):
- Pinned `v1` spork floor (`2,100,000` Plasma/Momentum): `100` base blocks/Momentum (`~4.4` full send+receive transfers/s).
- Default (`4,200,000` Plasma/Momentum): `200` base blocks/Momentum (`~8.8` full transfers/s).
- Hard protocol ceiling (`2,100,000,000` Plasma/Momentum): `100,000` base blocks/Momentum (`~4,386` full transfers/s).

### 3.3 Peg-Out: Burn → `BatchIntent` → Dual-Implementation Signer Firewall → Payout or Conflict Refund (`B3a`, `B4`)

1. **`RequestPegOut(recipientScriptPubKey, grossAmountSats, maxUserFeeSats)`** *(ALWAYS open, even while `Halted == 1`)*: User sends `grossAmountSats >= 100,000` sats of `zBTC` to `SettlementContract` (which returns `zBTC` to `SettlementContract`'s tranche, decrements `RepresentationOutstanding`, and increments `PendingForeignRelease`). User's `maxUserFeeSats` covers their share of the Bitcoin payout fee.
2. **Zenon-Final `BatchIntent` (`B4`):** After peg-out burns reach `D_znn >= 60` Momentums depth (`~11.4` min at `11.4s`/Momentum; `2x` `protocol/chain_bridge.go:293`'s 30-Momentum rollback limit), federation coordinators post `PostBatchIntent(intentId, inputs[], outputs[(outboxId, spk, netSats)], feeCapSats, fedSigs[>=k])` on Zenon. `BatchIntent` MUST itself reach `D_znn >= 60` Momentums before ANY signer signs the Bitcoin payout transaction. All RBF fee-bump variants MUST spend the **identical `inputs[]` set**.
3. **Independent Signer Verification (`B3a/B3b` + `H-3` Firewall):** Each signer independently queries its own `bitcoind` (at a single `K`-deep snapshot) and its own pinned `go-zenon` node (at a single `D_znn`-final snapshot, with `>= k` independent signer nodes agreeing on the Momentum hash), verifies the pinned `settlementCodeHash` firewall, checks `Circ == RepresentationOutstanding` from VM balances (`B3b`), verifies the **B3a** conservation inequality across all signed in-flight batches + the new batch, checks the 24h payout rate limit, and only then signs its `OP_CHECKSIGADD` share.
4. **Completion (`SubmitReleaseProof`) or Conflict Refund (`SubmitConflictRefundProof`, `B4`):**
   - Once the Bitcoin payout confirms to `K = 14`, anyone calls `SubmitReleaseProof` (no upper deadline!) to mark each `outboxId` `RELEASED` and decrement `PendingForeignRelease`.
   - **No timeout-only refunds:** Because signed Bitcoin transactions never expire, a peg-out can ONLY be refunded via `SubmitConflictRefundProof`, which proves a `K`-deep Bitcoin transaction spent one of the `BatchIntent`'s inputs *without* paying `outboxId` (e.g., a federation cancel/refresh tx). If the federation dies permanently, unpaid peg-outs become Wind-Down claims at their gross amount (`spec/01 §5`).

### 3.4 Peg-Free Atomic Swaps & Lightning Gateway (`M-4`)

Specified in [`spec/03 §5`](./spec/03-settlement-minted-zbtc-and-feeless-rails.md#5-peg-free-atomic-swaps--lightning-submarine-swap-gateway):
- **PTLC Taproot MuSig2 Adaptor Swaps (BIP-327):** Bitcoin refund leaf `<72> OP_CSV`, Bob's claim MUST confirm by `h_conf + 66` (with CPFP anchor), Alice must release adaptor partial sig within `6` blocks of Zenon PTLC confirmation or Bob aborts, `T_btc_worst = 86,400s` (24h at `2.0x` slow blocks), `T_znn >= 108,000s` (30h / `~9,474` Momentums).
- **HTLC / Lightning Submarine-Swap Gateway:** `hashType = 1` (`HashTypeSHA256`), numeric `Δ_safety = 36` Bitcoin blocks (`CLTV >= now + 72` blocks on inbound Hold Invoices), per-peer rate limits (`<= 5` pending / `<= 0.1 BTC`, 5-minute cancel TTL). *Note: swaps are atomic, but the `zBTC` received remains a claim on the Tier F federation vaults.*

---

## 4. Honest Threat Model & Privileged Powers Table (`H-3`, `H-5`, `H-7`, `C-4`)

**`v1` (`Tier F`) is an honest, capped federated peg — NOT trustless BitVM.** Security is bounded by the following explicit trust assumptions:

1. **Federation Custody Safety (`k`-of-`n`, e.g., `7-of-10` pilot / `11-of-15` scaled):** Any `k` colluding active signers (or compromise of `k` HSMs) can steal all BTC in active vaults.
2. **Federation Liveness (`n - k + 1` offline):** If `>= n - k + 1` active signers go offline permanently, peg-in sweeps and normal peg-out exits freeze until the backup recovery leaf matures (`52,560` blocks / ~365 days).
3. **Recovery Set Trust (`k'`-of-`n'` after `52,560` blocks):** Once a vault UTXO ages past `52,560` blocks without refresh, the custodial backup recovery set can spend it and race the active set. **Timely on-chain vault refresh (`26,280` blocks / alert at `39,420`) is a safety duty, not hygiene.**
4. **Zenon Finality Depth, Liveness & Censorship:** Signers rely on `D_znn = 60` Momentum depth (`2x` `go-zenon`'s 30-Momentum rollback limit) and `>= k` independent signer nodes agreeing on the Momentum hash. Sustained Zenon halts or censorship delay minting, `BatchIntent` posting, and peg-outs, but cannot forge BTC spends past signer `B3a/B3b` checks. **ZNN's market price is NOT in `v1` BTC safety; it affects only Zenon economic liveness.**
5. **Upgrade Authority & Code-Hash Firewall:** Anyone controlling Zenon spork keys can alter `SettlementContract` code and mint unbacked `zBTC` on Zenon. Signers' pinned `settlementCodeHash` firewall and `B3b` VM-balance check stop unbacked `zBTC` from draining Bitcoin vaults through peg-outs, **but cannot stop an attacker from selling unbacked `zBTC` over PTLC/LN swaps before the halt is public.**
6. **SPV Header Relayer Liveness:** At least one relayer (including the federation itself) submits `SubmitHeaderBatch` so direct-on-L1 SPV tracks the canonical Bitcoin tip.
7. **Swap Timing & Bitcoin Fee/Block Envelope:** PTLC/LN users assume Bitcoin block confirmation within the `72`-block / `36`-block safety windows using CPFP fee bumping.

### 4.1 Complete Privileged Powers Table (`H-3` Closed)

| Power / Action | Holder (Today vs Stage 1B) | Threshold | Timelock | Maximum Effect / Blast Radius |
|---|---|---|---|---|
| **Create / Activate Protocol Sporks** (`CreateSpork`, `ActivateSpork`) | **Today:** `types.SporkAddress` (`z1qpxsw...`, unlimited) OR `types.CommunitySporkAddress` (`z1qqvwz...`, Mariposa01 Pillar, renewal window heights `14,567,887–19,791,986` ≈ Nov 2026–Sep 2028, `dev:vm/embedded/definition/spork.go:46-73`). **Stage 1B Hard Gate:** Replaced by `GovernanceContract` (`U5`). | Today: `1-of-1` single key (blocks Stage 1B). Stage 1B: Pillar governance vote + `>= k` federation co-sign for custody changes. | Custody-relevant sporks: **`>= 30 days`** (min `SporkMinHeightDelay = 6` Momentums at node layer). | Can change `SettlementContract` consensus code and mint unbacked `zBTC` on Zenon; **blocked from draining BTC vaults** by signers' pinned `settlementCodeHash` firewall & `B3b` check (until `>= k` signer operators explicitly re-pin). |
| **Modify Dynamic Plasma Variables** (`SetPlasmaVariables`) | Same two spork keys today; `GovernanceContract` in Stage 1B. | Same as above. | Governance timelock (`>= 48h`); **cannot breach `v1` spork-pinned floor `MaxBasePlasmaInMomentum >= 2,100,000`** (`B2`). | Can raise Plasma fees / lower throughput down to pinned `2.1M` floor (`~4.4` transfers/s, `3` max-SPV calls/Momentum); cannot lock out SPV proofs. |
| **Active Vault Spend & Peg-In Attestation** | Independent Federation Signers (published identities, jurisdictions, HSM attestations). | `k`-of-`n` (`7-of-10` pilot / `11-of-15` scaled). | None (rate-limited per 24h in signer policy). | Full custody of active vault BTC; mint attribution on sweeps (bounded on-chain by sweep vault outputs). |
| **Backup Recovery Vault Spend** | Independent Recovery Signer Set (distinct keys/jurisdictions from active quorum). | `k'`-of-`n'` (e.g., `5-of-7`). | **`52,560` Bitcoin blocks** (~365 days `OP_CSV`) per unrefreshed UTXO. | Can spend any unrefreshed vault UTXO once CSV matures; races active set if refresh fails. |
| **Re-pin `settlementCodeHash` Firewall** | Federation Signer Operators (out-of-band configuration update). | `>= k` signer operators independently upgrading & re-pinning. | After `>= 30-day` upgrade notice & audit. | Authorizes signers to accept peg-outs from upgraded `SettlementContract` release/spork set. |
| **Release Cap Tranche (`TreasuryTrancheEscrow` → `SettlementContract`)** | `GovernanceContract` (`U5`) + `>= k` Federation Co-Sign. | Governance supermajority + `>= k` federation. | **`>= 14 days`** timelock. | Raises `SettlementContract`'s available `zBTC` tranche up to new `MaxRepresentationSupply` cap (Stage 1B starts at `5.0 BTC`). |
| **Add / Migrate Chain Binding (`AddBinding`)** | `GovernanceContract` (`U5`) + `>= k` Federation Co-Sign. | Governance supermajority + `>= k` federation. | **`>= 14 days`** timelock. | Registers new vault script / federation signer set for on-chain migration. |
| **Emergency Pause / Lower Cap (`GuardianPause`)** | `MultisigContract` (`U5`, e.g. `5-of-9` Ed25519 Guardians). | `M`-of-`N` (`5-of-9`). | Immediate (**narrowing only**). | Freezes new mints (`Halted = 1` / cap lower); **NEVER blocks `RequestPegOut` or honest signer payouts.** |
| **Un-Halt / Resume Minting (`ResumeMinting`)** | `GovernanceContract` (`U5`) + `>= k` Federation Signers. | Governance supermajority + `>= k` federation. | **`>= 48 hours`** timelock after incident snapshot & Proof-of-Reserves reconciliation. | Re-enables `ReserveMintCapacity` and `SubmitSweepLockProof`. |

---

## 5. Reference `go-zenon` Ground-Truth Baseline (`M-3`, `B1`, `B2`, `L-3`)

- **Normative U0 Target:** The **first tagged `go-zenon` release containing commit `0aa299e`** (which fixes `release/0.0.11-rc2` `b85ee94`'s regression `ad3b729` skipping post-VM hash verification on mutated embedded send blocks; parent of `0aa299e` is `b85ee94`). Neither `rc1` (`f19955f`) nor `rc2` (`b85ee94`) is a valid U0 baseline. Legacy `v0.0.10` (`e8986a6`) is reference only.
- **Hard U3 Preconditions:** (1) `DynamicPlasmaSpork` MUST be enforced prior to activating `MintedZbtcSpork` (**L-3, B2**); (2) upstream `go-zenon` issue `#239` (embedded receive failure provenance) MUST be closed with deterministic failed-receive guarantees (**B1**); (3) all code citations in [`spec/05`](./spec/05-go-zenon-upgrade-plan.md) are verified by symbol and content hash in CI.

---

## 6. Upstream Amendment Register (`v1` Trimmed Scope)

| ID | Upstream Target | Status in `v1` | Normative Requirement |
|---|---|---|---|
| **A-SPEC-1, A-SPEC-2, A-SPEC-6** | `Project Zeno` optimistic bridge framework | **Not required in `v1`** | Direct-on-L1 SPV removes `L1_RELAYED`, `OPTIMISTIC`, `CHALLENGE_WINDOW`, and `BatchCommitmentV3` from `v1`. |
| **A-SPEC-4** | L1 Peg-Out ID | **Required (`v1`)** | Standardize deterministic L1 `outboxId = SHA3-256("ZNN_L1_PEGOUT_V2" \|\| domainId \|\| pegOutSeq \|\| sendBlockHash)`. |
| **A-BTC-1** | Bitcoin Authorization / Refund Rules | **Required (`v1`, simplified)** | Drop BitVM reimbursement gating; gate refunds strictly on `K`-deep Bitcoin **proof of conflict** (`SubmitConflictRefundProof`) against a Zenon-final `BatchIntent` (**B4**). |
| **A-MINT-1** | `MINTED` Treasury Issuance | **Required (`v1`, hardened)** | `TokenContract.IssueMinted` mints `21M * 10^8 zBTC` into `TreasuryTrancheEscrow` (NOT `SettlementContract`), releasing only `<= MaxRepresentationSupply` tranches to `SettlementContract` behind a `>= 14d` governance timelock (**H-8, B3c**). |
| **A-PILLAR-1** | `go-zenon` `pillars.go` BLS12-381 & 72d lock | **Non-blocking for `v1`** | Zenon finality infrastructure (`spec/04`, Phase U2); decoupled from `v1` BTC custody safety (required only for `v2` Research Track). |

---

## 7. Phased Delivery & Blocking Stage Gates (`M-15`)

| Stage | Scope | Mandatory Blocking Exit Criteria |
|---|---|---|
| **Stage 0 (Engineering & Signet Conformance)** | Ship U0 (`go-zenon` tag containing `0aa299e`, `DynamicPlasmaSpork` enforced); close `#239` (**B1**); build lightweight `SettlementContract` + `TreasuryTrancheEscrow` + panic-recovered direct L1 `btcspv` + `MaxBasePlasmaInMomentum >= 2.1M` floor (**B2**); build **two independent federation signer implementations**; run HSM key ceremony with published attestations. | Fuzz gate proving zero internal errors / FIFO receive stalls across all Settlement methods (**B1**); unit tests for `IssueMinted -> TreasuryTrancheEscrow -> SettlementContract` tranche isolation (**H-8, G-11**); end-to-end Signet drill *(labeled SPV conformance-only)* covering deposit, sweep, mint, `BatchIntent`, payout, RBF fee-bump, conflict cancel + refund (**B4**), vault refresh, recovery-leaf drill, signer-set migration, and a test proving signers **refuse** when `B3a/B3b` or `settlementCodeHash` fails; Signet↔Zenon PTLC/LN adversarial suite (**M-4, G-18**). |
| **Stage 1A (Mainnet Shadow)** | Deploy `SettlementContract` in `PAUSED` mode (`SubmitHeaderBatch` live; mints/peg-outs disabled); run federation nodes and live Proof-of-Reserves feed on Bitcoin mainnet. | `>= 30` consecutive days uninterrupted mainnet header/retarget tracking and PoR reconciliation with zero signer divergence. |
| **Stage 1B (Capped Federated Pilot — `<= 5.0 BTC`)** | Deploy `GovernanceContract` + `MultisigContract` (`U5`, zero single-key `SporkAddress`); publish seeded `>= 0.50 BTC` Operations/Surplus Reserve; obtain **independent third-party custody/HSM and bridge security review** with all blocking findings closed (**M-15**). | Unpause with policy cap `<= 5.0 BTC`, `7-of-10` HSM active set, `52,560`-block recovery leaf, `MaxVaultUtxos = 64`, `K_pilot = 14`, `D_znn = 60` Momentums; live peg-in, feeless transfer, batched peg-out, and PoR verified with zero `B3a/B3b` drift. |
| **Stage 2 (`v2` Research Track — Non-Normative)** | Trust-minimized deleted-key BitVM / garbled circuits + ZK execution validity + Bitcoin-anchored fork choice. | Strictly gated on completing Research Gates **R-1 through R-8** in [`spec/01 Appendix A`](./spec/01-bitcoin-taproot-vault-enforcement.md#appendix-a-non-normative-v2-research-annex-path-a-trust-minimized-bitvm). |

---

## 8. Public Claims Alignment (`bigidea` Synchronization)

All public materials (including [`btc-moonshot.github.io/bigidea`](https://btc-moonshot.github.io/bigidea/)) MUST be updated to match `v1` verbatim:

| Outdated Public Claim (`v0` / `bigidea`) | Accurate `v1` (`v3.0.0-rfc`) Statement |
|---|---|
| "The network never holds a pooled key" | **`v1` uses an explicit `k`-of-`n` Tapscript `OP_CHECKSIGADD` HSM federation (`7-of-10` / `11-of-15`) plus a `52,560`-block custodial recovery leaf.** Trust-minimized deleted-key BitVM is a `v2` research target (Annex A). |
| "One honest watcher can stop a bad payout" | **Not applicable in `v1`** (no BitVM2 challenge game). Safety rests on `k`-of-`n` independent HSM signers running dual implementations with `B3a/B3b` conservation and `settlementCodeHash` checks. |
| Proofs "end at Bitcoin's proof-of-work" | In `v1`, peg-in/peg-out inclusion is verified by Bitcoin PoW SPV (`K = 14`), while custody and sweep attribution are authorized by the `k`-of-`n` federation. In Zenon light clients (`spec/04`), validity comes from a 21-of-30 BLS committee and Bitcoin provides timestamp ordering. |
| "Security is funded by the network's own staking token" | **False for `v1` BTC custody.** ZNN's price is NOT in `v1` BTC safety; it affects only Zenon economic liveness. |
| "Millions of transactions per second"; per-second streams | Zenon Dynamic Plasma provides `~8.8` full send+receive transfers/s at default (`4.2M`), `~4.4` tx/s at the `v1` pinned floor (`2.1M`), and `~4,386` tx/s at the hard protocol ceiling (`2.1B`) at `11.4s`/Momentum; mobile PoW takes `~2–10s`/block. |
| Spam multiplier "0.5–5×" | **Removed** — does not exist in `go-zenon` code; Dynamic Plasma resource prices adjust up to `MaxPriceChangePercent` per Momentum with a `1,000` floor and no ceiling. |
| "0 satoshi fees" | **0 BTC fees for `zBTC` transfers on Zenon only** (requiring refundable fused QSR or SHA3-256 PoW). Peg-ins and peg-outs pay Bitcoin network & consolidation fees. |
| "Peg-free, zero vault trust swaps" | PTLC/LN swaps are atomic with zero intermediary theft risk during the swap, **but the `zBTC` received remains a claim on the Tier F federation vaults.** |
| "Oracle verified" | **Consistency-checked** via `scripts/verify_spec_bounds.py` against sourced/policy inputs; not empirically audited until Stage 0/1B gates pass. |
| Omission of Zenon / ZNN / QSR / Pillars | Public pages MUST explicitly name **Zenon Network, ZNN, QSR, and Pillars**. |

---

## 9. Written Answers to Hostile Review Questions

Every question posed by the consolidated hostile review (`R7`) is answered normatively here:

- **C-1 (ZNN/BTC forging price):** *Not applicable in `v1`.* ZNN is removed from BTC custody safety; the `10,500 ZNN/BTC` assumption is deleted. Stage 1B cap (`5.0 BTC`) is policy-set. See Annex A Gate **R-1/R-2** for `v2`.
- **C-2 (Fake `FOREIGN_RELEASE` in unchallenged batch):** *Closed by removal in `v1`.* Optimistic batches are deleted; payouts require `>= k` independent HSM signers checking `D_znn = 60`-final Zenon burns, `B3a/B3b` VM balances, and `settlementCodeHash`. See Annex A Gates **R-1/R-3** for `v2`.
- **C-3 (Measured BitVM2 assert/disprove sizes & standardness):** *Not applicable in `v1`.* BitVM2 is moved to Annex A Gate **R-4** (requiring measured Signet sizes across BitVM2 and garbled circuits before `v2`).
- **C-4 (Why `Q_graph` was never deleted & key-loss impact):** *Resolved in `v1`.* `v0`'s never-deleted `N`-of-`N` `Q_graph` (and `N`-of-`N` `CommitteeIdentityKey`) is replaced by a `k`-of-`n` `OP_CHECKSIGADD` HSM federation tolerant of `n - k` key losses + a `52,560`-block recovery leaf. Deleted-key non-expiring graphs are Annex A Gate **R-6**.
- **H-1 (Why delegated stake at one snapshot):** *Fixed in `spec/04 §3.1`.* Decoupled from `v1` BTC custody; Zenon U2 committee selection now uses epoch-averaged variable slashable stake or beacon-randomized selection (never free instant delegation or fixed self-bond tie-break).
- **H-3 (Complete privileged-powers list & Pillar upgrade threshold):** Answered in **§4.1** above. Single-key spork authority blocks Stage 1B; custody upgrades require `>= 30-day` timelock + `>= k` federation signer firewall re-pinning.
- **H-4 (Watcher capital & front-running):** *Not applicable in `v1`.* Moved to Annex A Gate **R-5**.
- **H-5 (100% exit time & liquidity):** *Resolved in `v1`.* No serial fronting lanes or 5.5-day cooldowns; the federation batch-pays directly from confirmed vaults (`<= 64` UTXOs), limited only by signer 24h velocity limits and Bitcoin block space (`<= 1–3` days for 100% of a `5.0 BTC` pilot cap under normal conditions).
- **H-6 (April 2024 fees & June 2021 slow blocks):** *Resolved in `v1`.* No 46d/56d/58d CLTV cliff; recovery CSV is `52,560` blocks (~365d) with `13,140`-block (~91d) alert margin, Operations Reserve is sized for `2,000 sat/vB` across all `64` vault UTXOs, and PTLC timelocks use `2.0x` slow-block margins.
- **H-7 (Who anchors handoffs, who pays, mobile BTC headers):** Decoupled from `v1` custody; for Zenon light clients (`spec/04`), epoch handoff anchoring is a mandatory committee duty with Reserve fallback bounty, header sources (Neutrino/BIP-157, multi-source checkpoints, PoW header sync) and `minimumPostAnchorWork` are specified, and public wording is corrected (§8).
- **H-8 (Can a `SettlementContract` bug exceed `MaxRepresentationSupply`):** *Prevented structurally (`B3c`).* `SettlementContract` never holds more than the active cap tranche; excess pre-mint sits in timelocked `TreasuryTrancheEscrow`. Unit test required in Stage 0 (`G-11`).
- **M-9 (zBTC share of Zenon capacity & "millions of tx/s"):** Answered in **§3.2** and **§8**: `~8.8` transfers/s default (`~4.4` at pinned `2.1M` floor, `~4,386` at hard ceiling). "Millions of tx/s" is retired.
- **M-15 (Independent review of RFC):** Stage 1B explicitly blocks on an **independent third-party custody/HSM and bridge security review** outside the internal review loop; until completed, `v1` remains a pre-implementation RFC (`v3.0.0-rfc`), not a production approval.
