# zBTC: Bitcoin–Zenon Interoperability Protocol Specification

**Version:** `v1` (`v3.0.0-rfc` — **Zero-Federation Phased Architecture**: Stage 0 Verify Bitcoin SPV + Non-Custodial PTLC/LN → Stage 1A Right-Sized `BitVMX` `n=8` Sovereign ZK Validity Rollup | Stage 1B `clArk` Alternative Gate → Stage 2 Zero-TTP Scale & Upgrade; supersedes archived `v0` / `v2.5.0-rfc`, see [CHANGELOG.md](./CHANGELOG.md))  
**Status:** Public Request for Comment (`v1` / `v3.0.0-rfc`) — NOT mainnet-active; Stage 0 gated on upstream `go-zenon` release (`0aa299e` + `#239` closure + full `SetPlasmaVariables` pinning); Stage 1A gated on `BitVMX-CPU` Signet verification, independent third-party cryptography/Bitcoin-Script audit (**M-15**), and hard-BTC operator/verifier capital commitment.  
**Target Networks:** Bitcoin Mainnet TODAY (`bip-0141`/`bip-0340`/`bip-0341`/`bip-0342`/`bip-0431` Taproot + TRUC v3 + `P2A` — **zero Bitcoin soft forks**, **zero federated signers**) ↔ Zenon Network (`go-zenon` first tagged release containing `0aa299e`, `#239` closed, `DynamicPlasmaSpork` & `PtlcSpork` enforced; local reference clone `master` `e8986a6` / `origin/dev` `770e893`)  
**Consistency & Bounds Checker:** All modeled `n = 8` `BitVMX` W-OTS/TRUC v3 weights, 256-bit Lamport `TakeTx` stack/size bounds, timelock ordering (`[0, 144] → 1,104 < 1,152 < 1,296 < 1,440`), colluding-verifier positive-EV matrices (`k_collude = 0..6`), `{0.50, 0.25, 0.25}` BTC bank-run exit bounds, halving-indexed TVL-scaled `K`, 1-/2-block coinbase midstate SHA-256 padding, honest `8 MiB` `go-zenon` Plasma bounds, PTLC `2.3×` slow-block margins, `clArk` exit weights, and a **non-no-op 2,000-step randomized state-machine simulation (including real Bitcoin reorgs, `ExitSlotUTXO` grief slashes, and Lamport equivocation slashes)** are asserted by [`scripts/verify_spec_bounds.py`](./scripts/verify_spec_bounds.py) (`python3 -I scripts/verify_spec_bounds.py`). *This script checks internal mathematical consistency against explicitly labeled `SOURCED_`, `POLICY_`, and `PRE_MAINNET_TARGET_` inputs; it is not an empirical Signet benchmark or audit.*

**Upstream Provenance & Review Trail:**
- Vision Proposal: [`https://btc-moonshot.github.io/bigidea/`](https://btc-moonshot.github.io/bigidea/) *(see §9 for mandatory claims alignment)*
- Zenon Non-Bridging Thesis: `zenon-developer-commons/essays/Verify Bitcoin, Don't Bridge It.md` & `docs/specs/spv-event-oracle-spec.md`
- Reference Node Codebase: [`go-zenon`](https://github.com/zenon-network/go-zenon) (`master` `e8986a6`, `origin/dev` `770e893`, target release tag containing `0aa299e` + `#239`)
- Archived Baseline (`v0` / `v2.5.0-rfc`): Frozen byte-for-byte in [`versions/v0/`](./versions/v0/) (SHA-256 verified in CI).
- Consolidated Hostile Review (`R7` of `v0`): [`reviews/HOSTILE_REVIEW_R7_CONSOLIDATED.md`](./reviews/HOSTILE_REVIEW_R7_CONSOLIDATED.md) — every finding `C-1..C-4`, `H-1..H-8`, `M-1..M-15`, `L-1..L-4`, plus convergence findings `N-1..N-6` and `B1..B5`, is dispositioned in [`CHANGELOG.md`](./CHANGELOG.md).

---

## 1. Executive Summary & Architectural Pivot (`v0` → `v1`)

### 1.1 Why `v0` Failed — and Why Custodial Federated Multisigs Are Explicitly Rejected

The consolidated hostile review of `v0` (`v2.5.0-rfc`, [`R7`](./reviews/HOSTILE_REVIEW_R7_CONSOLIDATED.md)) and subsequent consensus/cryptographic audits established that **`v0` cannot be patched**:
1. **ZNN cannot secure BTC (`C-1`):** Real market liquidity (`400k–727k ZNN/BTC`, total ZNN market cap `~25–33 BTC`) makes `v0`'s `10,500 ZNN/BTC` slashing deterrents worth only `1.4–2.6%` of stated value (`~0.43–0.79 BTC` for 21 Pillars against a `15 BTC` cap).
2. **Zenon consensus fails at `≤ 49%` compromise (`C-2, H-1, H-2, H-3`):** Current `go-zenon` is longest-chain DPoS with zero slashing, deterministic height-only grindable `findSeed`, unweighted top-30 `groupA` sybil amplification, and a 30-Momentum hard rollback cliff (`protocol/chain_bridge.go`) allowing permanent chain splits at `49%`; adding classical BFT (`CommitteeRootSpork`) breaks BOTH safety and liveness at `> 33.3%`. Single-key `SporkAddress` / `CommunitySporkAddress` can mutate consensus code, and refundable QSR fusion allows whale Dynamic Plasma DoS.
3. **BitVM2 script costs break low-cap economics (`C-3, H-4, M-6`):** Real chunked Groth16 BitVM2 asserts (`~1.0–1.3M vB` / `4.0–4.8 MB` W-OTS) are `4.4–10×` larger than `v0`'s `220 kvB`, forcing `~13.30–18.175 BTC`/lane (`~40–91 BTC` in bonds even at bare-minimum `M = 3–5, L = 1`, exceeding ZNN's entire market cap!).
4. **Never-deleted `N`-of-`N` `Q_graph` & `CommitteeIdentityKey` (`C-4, N-2`) + fixed `1.0 BTC` buckets:** Rotating 30-day PoS committee roots forced never-deleted standing keys (sweep-all OR 1-key bricking at day 56), while fixed `1.0 BTC` buckets rejected `0.50` and `0.25 BTC` exits.

**Why `v1` explicitly REJECTS custodial `k`-of-`n` federated multisigs:**
Falling back to a custodial `k`-of-`n` federated multisig is **normatively forbidden in `v1`**. Federated custody:
- Violates Bitcoin's non-custodial ethos and Zenon's own thesis (*"Bridges Are Custody Wearing a Mask"* — `Verify Bitcoin, Don't Bridge It.md`);
- Fails **Bob's partial-recovery test** under `49%` Zenon compromise (a 49% `go-zenon` DPoS split breaks cross-signer Zenon state agreement and freezes payouts, while safety depends entirely on trusting external custodians);
- Fails **Mike's zero-signer-cooperation test** completely (if federated signers refuse to sign Mike's `0.25 BTC` payout, `0` satoshis leave custody; a backup recovery timelock belongs to another custodial multisig and never unlocks while active signers refresh UTXOs).

### 1.2 Governing Cryptographic Boundaries (Theorem 1 & Theorem 2)

Every design decision in `v1` is constrained by two formal theorems (proved in [`spec/01 §1`](./spec/01-bitcoin-taproot-vault-enforcement.md#1-cryptographic-boundaries-theorem-1--theorem-2) and [`spec/04 §1`](./spec/04-bitcoin-anchoring-and-light-client.md)):

> **Theorem 1 (Bitcoin Mainnet No-Covenant Impossibility — BIP-340/341/342, Zero Soft Forks):** Given pooled deposit UTXOs `U_A`, `U_B` created at `t_0` on Bitcoin Mainnet today, if ZERO pre-committed parties produce a new signature at `t_1`, it is **cryptographically impossible** for an unknown future recipient Mike (`P_Mike`, `0.25 BTC` unknown at `t_0`) to spend `U_A` or `U_B` paying `0.25 BTC → P_Mike` while binding `0.75 BTC` back into custody. Tapscript lacks output introspection (`nValue`/`scriptPubKey`), so any unsigned spend is trivially miner-front-run, while pre-signed transactions at `t_0` cannot bind future unknown `(P_Mike, 0.25 BTC)`. **Corollary 1B:** On Bitcoin Mainnet today, optimistic reimbursement bridges (`BitVM2`/`BitVMX`/`BitVM3`) are strictly bounded by **`1-of-N` ephemeral setup deletion + challenger/verifier safety + `1-of-M` pre-committed operator exit liveness**.

> **Theorem 2 (Young Low-Cap Capital / Trust / UX Trilemma — 0 Federation, 0 Soft Forks, `2–20 BTC` Bootstrap Capital):** With zero federated signers, zero Bitcoin soft forks, `~25–33 BTC` ZNN market cap (`0%` ZNN slashing usable), and realistic bootstrap capital `C ∈ [2, 20] BTC`, NO protocol can simultaneously achieve all three of:
> - **(A)** Instant, non-expiring, fungible cross-depositor `zBTC` (`Alice + Bob → Mike` with zero sender-collusion risk),
> - **(B)** `1-of-∞` permissionless challenging surviving `200–500 sat/vB` fee spikes (blocked by BitVM2's irreducible `~40–91 BTC` bond floor even at `M = 3–5, L = 1`), AND
> - **(C)** `0-of-N` unilateral arbitrary-amount Bitcoin L1 exit (blocked by Theorem 1; `clArk` achieves post-round `0-of-N` only by sacrificing **(A)** via discrete expiring VTXOs and pre-round `arkoor` sender+ASP collusion).

### 1.3 What `v1` (`v3.0.0-rfc`) Is, Stated Plainly

`v1` specifies a **zero-federation, zero-soft-fork, zero-ZNN-custody-coupling** phased architecture starting from zero custody risk:

1. **Stage 0 (`0–6 months`, `0 BTC` bridge custody risk, `0–5 BTC` voluntary LP — Mandatory Start):**
   - Ship the **Direct-on-L1 Bitcoin SPV Event Oracle** (`spec/02 §2`, strictly Event Validity, zero custody authority, aligned with `Verify Bitcoin, Don't Bridge It.md`) and **non-custodial PTLC / Lightning HTLC atomic swaps** (`spec/03 §1`, hardened for `2.3×` June 2021 slow blocks) while building and auditing the Stage 1A Rollup Core + `BitVMX-CPU` RISC-V verifier on Signet.
2. **Stage 1 Decision Gate (Explicitly Governed by Hard-BTC Commitment & Timeline):**
   - **Stage 1A — Primary Path for Pooled Fungible `zBTC` (`12–18+ months` incl. audit for 4–6 engineers; requires `~12.8–18.8 BTC` of non-yielding hard BTC ≈ `40–75%` of ZNN's `~25–33 BTC` market cap):**
     - **Shared Core (0% Zenon Trust — Survives 49%–100% Zenon Compromise):** A **Bitcoin-Anchored Sovereign ZK Validity Rollup** where Zenon is demoted to an untrusted feeless sequencing & soft-preconfirmation layer (`AccountBlock.Data`, `~28,480` Plasma, `0` sat BTC fee, NOT native ZTS). Canonical ordering, complete mutated-leaf DA (`0x02 BATCH_DA` + embedded `π_batch`), and uncensorable forced inclusion (`0x01 FORCED_EXIT`, `0x03 FORCED_TRANSFER`) live strictly on Bitcoin L1 via full stripped-block (`≤ 1,000,000 B`) scanning.
     - **Custody Engine (Right-Sized `BitVMX`, `n = 8`, `M = 3–5`, `L = 1`, `N = 7`):** Open-source `BitVMX-CPU` (`RV32IM`) interactive bisection (`~7.44 kvB`/prover tx, **100% BIP-431 TRUC v3** with `P2A` ephemeral anchors; `~75 kvB` Prover / `~15 kvB` Verifier; `F_chal = 0.40 BTC` covering `500 sat/vB` sustained across all `20` steps, `533 sat/vB` break-even), deleted-key `{0.50, 0.25, 0.25}` BTC multi-tier vaults, 256-bit Lamport `TakeTx` equivocation slashing (`~3.1 kvB` TRUC v3), dual-input `Stake_r` + `VaultConnector_r` bisection slashing (`0` BTC stolen from vault, positive EV `≥ +0.0167 BTC` for every honest verifier even if `6 of 7` verifiers collude with the operator!), and `(2M + 1)`-leaf registered-operator spend-or-refund `ExitSlotUTXO`. **Pre-mainnet maturity explicitly disclosed.**
   - **Stage 1B — Explicit Alternative Gate (If Hard-BTC Budget `< 5–10 BTC`, `3–6 mo` Launch Target, or `0-of-N` Post-Round Exit Outweighs Pooled Fungibility):**
     - Do **NOT** under-bond `BitVMX`/`BitVM2`. Deploy **`clArk` (`Second bark` / `Ark Labs arkd`) + Zenon SPV/PTLC** (`2–5 BTC` active ASP liquidity, `0` bonds), explicitly relinquishing global pooled `zBTC` in favor of discrete expiring VTXOs (disclosing `arkoor` sender+ASP collusion and `log2(N)` L1 exit fees).
3. **Stage 2 (`12+ months`, Zero-TTP Scale & Upgrade — Zero Dead-End User Trap):**
   - Deleted-key Stage 1A vaults NEVER expire and drain organically 1:1 to native BTC via `0x01` exits (no deleted-key L1 rollover). Identical-STF `BitVMX` expansion (`M = 5 → 20`, `L = 1 → 4`, `K = 36 → 144`) uses strictly `N`-of-`N` Cohort 1 voluntary handover; changing custody backends (`BitVM3-GC` / `BitVM2` / **Appendix A Track B Pure Tier-0 `OP_CCV + OP_TXHASH + OP_VERIFY_STARK` or `OP_CAT` Covenant**) ALWAYS launches a clean, non-commingled `zBTC_v2` instance with zero governance backdoor.

---

## 2. Normative Module Map & Authority Precedence

| Module | File | Normative Scope in `v1` (`v3.0.0-rfc`) |
|---|---|---|
| **Master** | [`SPEC.md`](./SPEC.md) | Zero-federation phased architecture, Theorems 1–2, end-to-end Bob & Mike traces (§3), honest Threat Model & Privileged Powers Table (§4), `go-zenon` baseline (§5), Upstream Amendments (§6), Stage 0/1A/1B/2 Decision Gates (§7), Non-Bridging Alignment & Public Claims (§8–§9), and Written R7 Disposition (§10). |
| **Part 1** | [`spec/01-bitcoin-taproot-vault-enforcement.md`](./spec/01-bitcoin-taproot-vault-enforcement.md) | **Highest Custody Precedence (`BTC-BITVMX-V1`):** Theorems 1–2; acyclic `OP_DROP` `DepositTx` (`{0.50, 0.25, 0.25}` deleted-key vaults, `certBlob = 104 B`, `opBitmask`, zero-TTP cohort rule); `BitVMX-CPU` `n = 8` bisection (`301` W-OTS digits ≈ `7.44 kvB`, `20` steps, `75/15 kvB`, `F_chal = 0.40 BTC`, 100% TRUC v3); simultaneous `[0, 144]` challenge window, `T_take = 1,152`, `T_cooldown = 1,296`, `RetireStakeTx = 1,440`; 256-bit Lamport `TakeTx` (`5,922 B` script, `~3.1 kvB`); dual-input slash (`0.15/1.85/0.55` positive-EV matrix); `(2M+1)`-leaf `ExitSlotUTXO`; exact `12.8/18.8 BTC` capital & `65–72d` bank-run math; Stage 1B `clArk` spec; **Appendix A (Track B Pure Tier-0 Bitcoin Soft-Fork Covenant + BitVM2/BitVM3 Reference)**. |
| **Part 2** | [`spec/02-btc-authorization-domain-and-spv.md`](./spec/02-btc-authorization-domain-and-spv.md) | **Stage 0 Direct-on-L1 Bitcoin SPV Event Oracle** (Event Validity only, 1-/2-block coinbase midstate SHA-256 final padding covering all `len % 64`, exact ABI/storage-op/`dp.MaxContractBlocks = 40` budget) + **Stage 1A Bitcoin-L1-Canonical Authorization Domain** (`0x00`..`0x07` `OP_RETURN "ZBTX"` tags, full `≤ 1 MB` stripped-block scan + single `wtxid_i` branch, launch-time `(h_lane_init, H, D)` PoW anchor with `D ≥ 0.50 × D(h_lane_init)` and TVL-scaled `K`). |
| **Part 3** | [`spec/03-settlement-minted-zbtc-and-feeless-rails.md`](./spec/03-settlement-minted-zbtc-and-feeless-rails.md) | **Stage 0 Hardened Non-Custodial PTLC & LN HTLC Swaps** (absolute Unix timestamps, `2.3×` slow-block margin) + **Stage 1A Sovereign Rollup STF `F` & Feeless Zenon Sequencer Rails** (`AccountBlock.Data` `~28,480` Plasma, honest `8 MiB` `~1,050–1,200 tx/s` ceiling, `RollupHTLC`/`RollupPTLC`, `B_zbtc = 0.60 BTC`/lane accounting, `ExitSlotUTXO` spend-or-refund, permissionless DA batchers) + **Stage 1B `clArk` VTXO Coordination**. |
| **Part 4** | [`spec/04-bitcoin-anchoring-and-light-client.md`](./spec/04-bitcoin-anchoring-and-light-client.md) | **Zenon `49%` Consensus Reality (`go-zenon` Code Proof) & Inverted Trust Hierarchy:** Proof of DPoS failure at `49%` (height-only `findSeed`, unweighted top-30 `groupA`, zero slashing, 30-Momentum cliff) and BFT failure at `> 33.3%`, why Bitcoin L1 ordering + DA + forced inbox achieves `0-of-N` Zenon trust (eliminating BLS finality from BTC custody), and non-custodial light-client UX notes. |
| **Part 5** | [`spec/05-go-zenon-upgrade-plan.md`](./spec/05-go-zenon-upgrade-plan.md) | **Minimal `go-zenon` Upgrade Plan:** Stage 0 prerequisites (`0aa299e` tag, `#239` FIFO panic-stall closure, `DynamicPlasmaSpork` + full `SetPlasmaVariables` pinning of `MaxBasePlasmaInMomentum`, `MaxPriceChangePercent`, `FusedPlasmaTarget`, `PowPlasmaTarget`, `PriceChangeDenominator`, `PtlcSpork`, Stage 0 SPV Event Oracle) + **zero-hard-fork custody boundary for Stage 1A/1B** (`SporkAddress` cannot steal BTC or censor L1 exits). |
| **Checker** | [`scripts/verify_spec_bounds.py`](./scripts/verify_spec_bounds.py) | Stdlib-only Python 3 Consistency & Bounds Checker asserting all Stage 0, Stage 1A (`BitVMX n=8`), Stage 1B (`clArk`), and Theorem 2 bounds + non-no-op 2,000-step randomized simulation with real Bitcoin reorgs, `ExitSlotUTXO` grief slashes, and Lamport equivocation slashes. |
| **Changelog** | [`CHANGELOG.md`](./CHANGELOG.md) | Complete `v0` (`v2.5.0-rfc`) → `v1` (`v3.0.0-rfc`) finding-by-finding disposition (`C-1..C-4`, `H-1..H-8`, `M-1..M-15`, `L-1..L-4`, `N-1..N-6`, `B1..B5`) and rejection rationale for custodial federated multisigs. |

### 2.1 Authority & Conflict Precedence (`M-13` Fixed)

1. **Bitcoin L1 Consensus & Part 1 Vault Scripts ([`spec/01`](./spec/01-bitcoin-taproot-vault-enforcement.md), `BTC-BITVMX-V1`)** — non-overridable custody layer. Hard-pinned `vk_STF`, deleted-key Taproot graphs, `StakeChain`, and `ExitSlotUTXO` rules cannot be overridden by any Zenon contract, Pillar, or spork.
2. **Bitcoin-L1-Canonical Authorization & Rollup STF ([`spec/02`](./spec/02-btc-authorization-domain-and-spv.md) & [`spec/03`](./spec/03-settlement-minted-zbtc-and-feeless-rails.md))** — deterministic state transition over Bitcoin L1 blocks (`0x00`..`0x07`).
3. **Stage 0 `go-zenon` Runtime & SPV Event Oracle ([`spec/05`](./spec/05-go-zenon-upgrade-plan.md))** — governs feeless Zenon sequencing UX and Stage 0 non-custodial SPV/PTLC rails; holds ZERO authority over Stage 1A BTC custody.
4. **Non-Custodial Anchoring & Light-Client Infrastructure ([`spec/04`](./spec/04-bitcoin-anchoring-and-light-client.md))** — informational/UX layer only.

---

## 3. End-to-End Protocol Flows & Hostile Scenario Traces

### 3.1 Stage 0: Verify Bitcoin (SPV Event Oracle + Non-Custodial PTLC/LN)

Zero pooled BTC custody (`0 BTC` bridge exposure):
1. Relayers submit Bitcoin headers and Merkle inclusion proofs (with 1- or 2-block SHA-256 coinbase midstate padding) to the Stage 0 SPV Event Oracle (`spec/02 §2`), proving Event Validity on the best PoW chain.
2. Users swap native BTC / Lightning against Zenon assets atomically via BIP-327 Taproot MuSig2 PTLCs (`<72> OP_CSV` refund leaf, `h_conf + 66` confirmed-before-refund with CPFP, `T_znn = now + 108,000s` = `30h` leaving `4.7h` margin under `2.3×` June 2021 slow blocks) or SHA-256 HTLCs (`hashType = 1`, `Δ_safety = 36` blks, Hold Invoice rate limits, `spec/03 §1`).

### 3.2 Stage 1A: Sovereign ZK Validity Rollup + Right-Sized `BitVMX` (`n = 8`, `M = 3–5`, `N = 7`)

#### Flow A — Acyclic Deposit (`Alice 1 BTC`, `Bob 1 BTC`, Closes `v0 C-4, N-2, M-7`)
1. Alice locks `1.0 BTC + fee` in her own self-custodial staging UTXO `U_Alice_wallet` with Tapscript `OP_DROP <pk_Alice> OP_CHECKSIG`.
2. Alice prepares `DepositTx` spending `U_Alice_wallet` → `vout[0..2]` = multi-tier deleted-key vaults **`{0.50, 0.25, 0.25}` BTC** (`3` vaults/BTC, avg `0.333 BTC`, `maxVaultDenom = 0.50 BTC`) + `vout[3]` = `69 B` `OP_RETURN "ZBTX" || 0x00 || recipientAcctHash(32B) || vaultParamsHash(32B)`. Because `vout[3]` does not hash `certBlob`, **`txid_dep` is fixed before signing**.
3. Alice + `N = 7` presigners + all online operators (`≥ M_min`, recorded in `opBitmask`) presign the `TakeTx_{d,j,l,r}` graphs (`M × L × R = 5 × 1 × 64 = 320` pre-signed `TakeTx`s per vault ≈ `40 KB`, `< 100ms` MuSig2 ONCE at deposit) using fresh per-deposit ephemeral keys `Q_setup_d = MuSig2(P_{1..N,d}, P_{A,d})`.
4. Each presigner **permanently deletes `x_{i,d}`** and signs non-spending identity attestation `σ_cert` over `txid_dep`, forming `certBlob = σ_cert(64B) || Q_setup_d(32B) || opBitmask(8B)` (`104 B ≤ 520 B` BIP-342 stack limit).
5. Only after verifying all pre-signed `TakeTx`s and `σ_cert` does Alice delete `x_{A,d}`, push `[sig_Alice, certBlob, script, controlBlock]` into `DepositTx.vin[0].witness`, and broadcast (zero hash cycle, zero stranding!). At `K = 14` confirmations, the STARK scans `DepositTx` via stripped block + `wtxid_dep` and credits `1.0 zBTC` to Alice (identical for Bob).

#### Flow B — Feeless `zBTC` Transfers on Zenon (`AccountBlock.Data`)
- Signed rollup transfers (`~110 B`) are submitted in Zenon `AccountBlock.Data`, paying **`0` satoshis BTC fee**, **`0` burned ZNN/QSR**, and **`21,000 + 68 × 110 = 28,480` Plasma** (`~14` refundable fused QSR or `~42.7M` SHA3-256 PoW hashes at floor price `1,000`; `~11.4s` soft confirmations; honest throughput `~4.4` tx/s at `2.1M` floor, `~8.8` tx/s default, **`~1,050–1,200` tx/s real hard ceiling** under `MaxMomentumContentBytes = 8 MiB`).
- Permissionless market-funded batch proposers aggregate feeless transfers every `~6` Bitcoin blocks into `0x02 BATCH_DA` carrying **complete mutated SMT leaves** (`16 B` existing / `48 B` new account) + succinct embedded proof `π_batch` (transparent STARK/IPA or Groth16). First valid `0x02` matching `R_{h-1}` in Bitcoin L1 block/tx order wins; invalid batches are deterministically skipped in-circuit.

#### Flow C — Hostile Trace 1: Bob (`1 BTC → 1 zBTC → spends 0.5 → recovers 0.5 BTC` Under `49%`–`100%` Zenon Compromise)
1. Bob deposits `1.0 BTC` (`{0.50, 0.25, 0.25}` vaults) → `1.0 zBTC` canonical on Bitcoin L1.
2. Bob spends `0.5 zBTC` feelessly on Zenon (retaining `0.5 zBTC`). Even if **`49%`–`100%` of Zenon Pillars are Byzantine**, `go-zenon` permanently splits across its 30-Momentum cliff, Dynamic Plasma spikes `100,000×`, or `SporkAddress` upgrades `go-zenon` maliciously: **no attacker can forge Bob's signature on his remaining `0.5 zBTC` or mutate `vk_STF`**.
3. Bob bypasses Zenon completely by broadcasting a `~150 vB` Bitcoin L1 **`0x01 FORCED_EXIT`** (`0.50 BTC → P_Bob`) creating a `546`-sat `(2M + 1)`-leaf **`ExitSlotUTXO`**.
4. Any `1-of-M` (`M = 3–5`) operator spends `ExitSlotUTXO` as `vin[0]` and pays **`0.50 BTC - f_op`** directly to `P_Bob` in `vout[0]` (**confirmed in ~1 Bitcoin block / ~10 minutes**).
5. At `K = 14`, the STARK credits `ReimbursementCredit[O_j] += 0.50 BTC`, FIFO-assigns one `0.50 BTC` vault `U_d` to `O_j`, and `O_j` claims `U_d` via `RoundTx_r → TakeTx` (`T_take = 1,152` blks, verified by `N = 7` pre-committed verifiers under `n = 8` `BitVMX` bisection).

#### Flow D — Hostile Trace 2: Mike (`Alice 1 + Bob 1 → Mike 2 → recovers 0.25 BTC` When Zenon Signers Refuse to Sign)
1. Alice (`1.0 BTC`) and Bob (`1.0 BTC`) deposit into `{0.50, 0.25, 0.25}` vaults and send `2.0 zBTC` feelessly to Mike on Zenon.
   - Once anchored in `0x02 BATCH_DA`, Mike's `2.0 zBTC` has **100% Bitcoin PoW finality** (immune to 100% Zenon + 100% Alice/Bob collusion).
   - If Zenon Pillars stall or refuse to batch BEFORE `0x02` posts, Mike self-includes Alice's and Bob's raw signed transfers directly on Bitcoin L1 via **`0x03 FORCED_TRANSFER`**! *(Pre-L1-batch `~11.4s` Zenon confirmation is honestly disclosed as a soft confirmation; large receipts like `2 BTC` wait for L1 batch confirmation.)*
2. **Zenon signers refuse to sign everything.** Mike ignores Zenon completely and broadcasts L1 **`0x01 FORCED_EXIT`** (`0.25 BTC → P_Mike`, creating `ExitSlotUTXO`; Mike retains `1.75 zBTC`).
3. Any `1-of-M` (`M = 3–5`) operator spends `ExitSlotUTXO` and pays **`0.25 BTC - f_op`** directly to `P_Mike` in `vout[0]` (~10 minutes). **Alice and Bob cannot front-run or steal it; Bitcoin L1 UTXO exclusion prevents double-fronting.**
4. At `K = 14`, the STARK FIFO-assigns one `0.25 BTC` vault to `O_j` (the remaining `0.75 BTC` of Alice's split — `0.50 + 0.25` — stays untouched in deleted-key BitVMX vaults!). For arbitrary non-bucket exits (e.g., `0.2371 BTC` or `0.001 BTC`), `O_j` still pays the exact amount in `FrontingTx` and accumulates `ReimbursementCredit[O_j]` until hitting an available `0.25`/`0.50 BTC` vault — zero new presigning needed!
5. **Fee-spike & grief recovery:** If Bitcoin fees spike above `f_op`, Mike bumps `f_op` via `0x06 EXIT_FEE_BUMP` or cancels after `<288> OP_CSV` via Leaf `2M` (`EXIT_CANCEL`). If a rogue operator sweeps `ExitSlotUTXO` without paying `vout[0]`, the STARK atomically refunds `0.25 zBTC` to Mike, slashes `0.01 BTC` from the operator's `0.05 BTC` grief buffer to Mike, and auto-suspends the operator.

---

## 4. Honest Threat Model, Residual Boundaries & Privileged Powers Table (`H-3` Closed)

**`v1` Stage 1A (`BitVMX` Rollup) is trust-minimized (`Tier 1`), NOT pure `Tier 0` (which Theorem 1 proves requires a Bitcoin soft fork — see `spec/01 Appendix A`).** Delivered security is bounded by the following explicit, un-sugarcoated assumptions:

1. **Zero Zenon Consensus or ZNN Market-Cap Trust (`0-of-N` Zenon — Survives 49%–100% Zenon Compromise):** Neither Zenon Pillars, `go-zenon` DPoS/BFT, ZNN's `~25–33 BTC` market cap, nor Zenon `SporkAddress` sit in the Bitcoin custody safety or L1 forced-exit path. Zenon Plasma DoS temporarily degrades *feeless* UX to L1 BTC fees (`0x03`/`0x01`), never custody.
2. **`1-of-N` Ephemeral Setup Deletion & Open-Cohort Attestation (`N = 7` Pilot):** At least 1 of `N` presigners honestly deletes its per-deposit ephemeral share `x_{i,d}` (depositor also participates and deletes `x_{A,d}`!) AND at least 1 of `N` long-term attestation keys `id_i` remains uncompromised while a cohort is open to new deposits. Compromising all `N` `id_i` keys cannot sweep existing deleted-key vaults; losing 1 of `N` `id_i` never bricks existing vaults (only halts *new* deposits on `v1`, requiring a clean non-commingled `zBTC_v2`).
3. **`1-of-N` Pre-Committed Online Verifier Safety (`N = 7` Pilot, NOT `1-of-∞`):** At least 1 of `N = 7` independent pre-committed verifiers monitors Bitcoin within `[0, 144]` blks (~24h) and runs `n = 8` `BitVMX` bisection (`20` steps, `T_step = 48` blks, `~15 kvB` total verifier weight) with CPFP. Anyone on Earth can detect fraud and alert all 7 verifiers off-chain, and every honest verifier has **positive EV (`≥ +0.0167 BTC` @ `500 sat/vB`) even if `6 of 7` verifiers collude with the operator**. If ALL `7` verifiers go offline or collude simultaneously during `[0, 144]`, a cheating operator can steal `≤ 0.50 BTC`/round.
4. **`1-of-M` Pre-Committed Operator Exit Liveness (`M = 3–5` Pilot — Irreducible Corollary 1B Bound):** At least 1 of `M = 3–5` independent bonded operators remains online with liquid BTC to front exits. If ALL `M = 3–5` operators vanish permanently, Mike cannot self-claim on Bitcoin L1 today (`0` theft; after `288` blks Mike cancels via Leaf `2M` and retains `0.25 zBTC`, exits stalled until an operator returns).
5. **Sustained Dispute Fee-Rate Envelope (`≤ 500 sat/vB` for `6.7` Consecutive Days):** `F_chal = 0.40 BTC` covers `~75 kvB` Prover bisection up to `533 sat/vB` sustained across all `20` steps (`6.7` days); Verifier `~15 kvB` is covered up to `610 sat/vB` (worst-case 6-way split) / `1,000 sat/vB` (winner L1 payout). Historical peaks (`1,805 sat/vB` April 2024 lasted `~33h` ≈ 2–4 steps) fit comfortably; a hypothetical week-long `> 533 sat/vB` spike erodes honest dispute coverage.
6. **TVL-Scaled Private-Fork Bound (`0.50 × K × Subsidy(era) > Cap_TVL`):** Without `OP_BLOCKHASH`, each lane pins launch-time `(h_lane_init, H, D)` with `D(h) ≥ 0.50 × D(h_lane_init)` and caps TVL strictly below private-fork PoW cost (`K = 14` ⇒ `Cap_TVL ≤ 15 BTC`; `K = 36` ⇒ `≤ 50 BTC`; `K = 144` ⇒ `≤ 200 BTC`).
7. **Bank-Run Recycling Queue (`~65–72` Days for 100% Run at `M = 3–5, L = 1`):** While individual exits front in ~10m up to available operator float (`2.20–3.00 BTC`), a 100% bank run recycles at `0.111 BTC/day` (`M = 3`, `~72d` for `10 BTC`) or `0.185 BTC/day` (`M = 5`, `~65d` for `15 BTC`) under `{0.50, 0.25, 0.25}` vaults (or `~47d`/`~43d` under `{0.50, 0.50}` vaults).
8. **Stage 1B (`clArk`) Alternative Assumptions (If Chosen Instead):** Zero operator bonds and pure `0-of-N` post-round unilateral exit until VTXO expiry, BUT sacrifices pooled fungible `zBTC`, carries hard VTXO expiry (`log2(N)` L1 branch exit fees), requires `100%` ASP liquidity per cycle, and exposes pre-round `arkoor` transfers to `sender + ASP` collusion.

### 4.1 Complete Privileged Powers Table (`H-3` Closed — ZERO Custodial Authority)

| Power / Action | Holder | Threshold | Timelock | Maximum Effect / Blast Radius on Stage 1A BTC Custody |
|---|---|---|---|---|
| **Spend Existing Stage 1A BTC Vaults (`U_d`)** | **NOBODY (ephemeral `Q_setup_d` deleted)** | N/A | N/A | **0 sats custodial sweep power.** Spendable ONLY via pre-signed `TakeTx` after `T_take = 1,152` blks subject to `N = 7` `BitVMX` verifiers + Lamport equivocation slash. |
| **Mutate Rollup STF Rules (`vk_STF`) on Existing Vaults** | **NOBODY (`vk_STF` hard-pinned at `t = 0`)** | N/A | N/A | **0 effect.** No Zenon spork, governance vote, or operator can alter STF rules on existing vaults. |
| **Voluntary Cohort Handover (Same `vk_STF` Only)** | Cohort 1 Presigners (`id_1..id_N`) | **`N`-of-`N` (`7-of-7`)** | None (new deposits only) | Strictly `1-of-N` safe; cannot touch existing vaults. Involuntary `1-of-N` loss halts new `v1` deposits cleanly (`zBTC_v2` required). |
| **Zenon Protocol Sporks (`CreateSpork`, `ActivateSpork`, `SetPlasmaVariables`)** | `SporkAddress` (`z1qpxsw...`) / `CommunitySporkAddress` (`z1qqvwz...`, window heights `14,567,887–19,791,986`, `origin/dev:vm/embedded/definition/spork.go`) → future `GovernanceContract` | `1-of-1` today | `SporkMinHeightDelay = 6` Momentums (node layer) | **0 BTC custody blast radius in Stage 1A.** Can disrupt feeless Zenon sequencing or Stage 0 embedded SPV contract, but **cannot steal 1 satoshi from BitVMX vaults or censor L1 `0x01`/`0x03` exits**. *(Stage 0 pins full `SetPlasmaVariables` floor in `spec/05`.)* |
| **Operator Fronting & Reimbursement Claim (`O_1..O_M`)** | Independent Bonded Operators (`M = 3–5` pilot) | `1-of-M` for exit liveness | `T_take = 1,152` blks; `T_cooldown = 1,296` blks | **Zero theft power** under `1-of-N` verifier honesty (`-1.94` to `-2.55 BTC` net loss on fraud: `-2.55 BTC` solo, `-2.40` to `-1.9417 BTC` with `1..6` colluders); all `M` vanishing stalls exits (`0` principal loss). |
| **BitVMX Fraud Challenge (`V_1..V_7`)** | Independent Pre-Committed Verifiers (`N = 7`) | **`1-of-7`** | `[0, 144]` blks open; `T_step = 48` blks | Any 1 honest verifier stops fraud, collects `≥ +0.0167` to `+0.075 BTC` net profit, and burns `1.85 BTC` of rogue operator's bond. |

---

## 5. Reference `go-zenon` Ground-Truth Baseline (`M-3`, `B1`, `B2`, `L-3`)

- **Verified Local Clone:** `master` (`e8986a6`, `v0.0.10-alphanet`) and `origin/dev` (`770e893`, carrying `DynamicPlasmaSpork`, `PtlcSpork`, `Libp2pSpork`). *(Note: upstream fix `0aa299e` is not present in the local git clone and remains an explicit Stage 0 upstream release gate.)*
- **Stage 0 Hard Preconditions (`spec/05`):** (1) First tagged `go-zenon` release containing `0aa299e`; (2) upstream issue `#239` deterministic failed-receive closure (`B1`); (3) `DynamicPlasmaSpork` enforced with **complete `SetPlasmaVariables` pinning** (`MaxBasePlasmaInMomentum >= 2,100,000`, `MaxPriceChangePercent <= 25%`, PLUS lower bounds on `FusedPlasmaTarget >= 525,000`, `PowPlasmaTarget >= 525,000`, and `PriceChangeDenominator >= 8`, preventing exponential Dynamic Plasma lockout); (4) `PtlcSpork` active.
- **Stage 1A / 1B Zero-Hard-Fork Property:** Stage 1A Rollup nodes read standard Zenon `AccountBlock.Data` and Bitcoin L1 — requiring **zero `go-zenon` consensus hard fork** beyond Stage 0.

---

## 6. Upstream Amendment Register (`v1` Zero-Federation Scope)

| ID | Upstream Target | Status in `v1` | Normative Requirement |
|---|---|---|---|
| **A-SPEC-1, A-SPEC-2, A-SPEC-6** | `Project Zeno` optimistic bridge framework | **Not required in `v1`** | Stage 0 uses direct Event-Validity SPV; Stage 1A uses Bitcoin-L1-canonical ZK validity (`0x00`..`0x07`). |
| **A-SPEC-4** | Deterministic Exit ID | **Required (`Stage 1A`)** | `exitId = SHA256("ZBTX_EXIT_V1" \|\| bitcoinTxid \|\| voutOrIdx \|\| nonce)` derived deterministically on Bitcoin L1. |
| **A-BTC-1** | Bitcoin Refund / Exclusion Rules | **Required (`Stage 1A`)** | Refunds enforced strictly by Bitcoin L1 UTXO exclusion (`ExitSlotUTXO` spend-or-refund rule) — zero timeout-vs-fronting double-pay races (`M-8`). |
| **A-MINT-1** | `TokenContract.IssueMinted` | **Retired in `v1`** | Stage 1A `zBTC` balances live in the Bitcoin-canonical Rollup SMT (NOT pre-minted inside a Zenon embedded contract, eliminating `H-8` entirely!). |
| **A-PILLAR-1** | `go-zenon` `pillars.go` BLS12-381 & 72d lock | **Not required in `v1`** | Zenon consensus & Pillar committees are removed from BTC custody completely (`spec/04`). |

---

## 7. Phased Delivery, Capital Decision Gates & Zero-Dead-End Growth (`M-15`)

| Stage | Timeline & Hard-BTC Capital | Normative Scope & Blocking Exit Criteria | Zero-Dead-End Migration Guarantee |
|---|---|---|---|
| **Stage 0 (Mandatory Foundation — Verify Bitcoin)** | **`0–6 months`**, **`0 BTC` bridge custody risk** (`0–5 BTC` voluntary LP) | Ship `go-zenon` prerequisites (`0aa299e`, `#239`, full `SetPlasmaVariables` pinning, `PtlcSpork`), **Direct-on-L1 Bitcoin SPV Event Oracle** (1-/2-block coinbase midstate, `≤ 24` storage ops, `dp.MaxContractBlocks = 40`), and **non-custodial PTLC/LN atomic swaps** (`2.3×` slow-block safe). Build & test the Rollup stripped-block STARK + `BitVMX-CPU` (`RV32IM` `n=8`) stack on Signet. | Zero custodial BTC at risk while proving every Rollup + `BitVMX` primitive on Signet. |
| **Stage 1A (Primary Path — Right-Sized `BitVMX` Rollup)** | **`12–18+ months` (incl. audit, 4–6 engineers)**; **`12.8 BTC`** (`M=3, N=7, ≤ 10 BTC` TVL) or **`18.8 BTC`** (`M=5, N=7, ≤ 15 BTC` TVL) *(≈ `40–75%` of ZNN's `~25–33 BTC` mcap)* | **Hard Entry Gates:** (1) Full Signet drill of `DepositTx`, `0x01–0x07`, `ExitSlotUTXO` (fronting, grief slash, cancel), `RoundTx → TakeTx` (Lamport equivocation slash), and `n=8` `BitVMX` 20-step TRUC v3 bisection (verifying measured weights `≤ 7.44 kvB`/tx); (2) independent third-party cryptography & Bitcoin-Script audit (**M-15**); (3) committed independent operator + verifier hard BTC (`2.60 BTC`/lane + `0.40 BTC`/verifier). *Pre-mainnet maturity of `BitVMX-CPU` explicitly disclosed.* | Deleted-key vaults NEVER expire and stay 100% redeemable 1:1 via `0x01 FORCED_EXIT` to native BTC L1. |
| **Stage 1B (Explicit Alternative Gate — `clArk`)** | **`3–6 months`**, **`2–5 BTC`** active ASP liquidity (`0` bonds) | **Trigger:** Choose Stage 1B ONLY if the ecosystem cannot commit `~12.8–18.8 BTC` of non-yielding hard BTC OR prioritizes `3–6 mo` launch / `0-of-N` post-round exit over pooled fungibility. Deploy `Second bark` / `Ark Labs arkd` + Zenon SPV/PTLC (`spec/01 §7`, `spec/03 §3`). Do **NOT** under-bond `BitVMX`/`BitVM2`. | Users hold self-custodial expiring VTXOs with unilateral L1 exit; explicitly non-commingled with any future Rollup `zBTC`. |
| **Stage 2 (Zero-TTP Scale & Upgrade)** | **`12+ months` post-Stage 1** (`15–200+ BTC` TVL, or unlimited w/ soft fork) | **(a) Same-STF `BitVMX` scaling (`M=5→20, L=1→4, K=36→144`):** strictly via pre-planned **`N`-of-`N` Cohort 1 voluntary handover** (zero governance key). **(b) Custody backend upgrades (`BitVM3-GC` / `BitVM2` / Appendix A Track B Pure Tier-0 `OP_CCV` or `OP_CAT` Covenant):** ALWAYS launch a clean, non-commingled `zBTC_v2` reusing the open-source Rollup STF codebase. | Zero deleted-key L1 rollover needed; Stage 1A vaults drain organically 1:1 to native BTC via `0x01` exits. |

---

## 8. Alignment with Zenon's Non-Bridging Philosophy (`Verify Bitcoin, Don't Bridge It.md`)

- **Stage 0** implements `Verify Bitcoin, Don't Bridge It.md` verbatim: Bitcoin stays strictly in user custody while Zenon imports verified PoW Event Validity and coordinates atomic PTLC/LN swaps.
- **Stage 1A** respects the essay's core warning (*"Zenon can't prevent spending. That's Bitcoin's job"*) by refusing custodial federations and refusing to place Zenon consensus in Bitcoin's enforcement path — pushing 100% of custody enforcement, canonical ordering, DA, and forced exits onto Bitcoin L1 (`BitVMX` + ZK validity).

---

## 9. Public Claims Alignment (`bigidea` Synchronization)

All public materials (including [`btc-moonshot.github.io/bigidea`](https://btc-moonshot.github.io/bigidea/)) MUST match `v1` verbatim:

| Outdated Public Claim (`v0` / `bigidea`) | Accurate `v1` (`v3.0.0-rfc`) Statement |
|---|---|
| "The network never holds a pooled key" | **True in `v1` for existing vaults:** per-deposit ephemeral keys `Q_setup_d` are permanently deleted at deposit (with zero custodial federation). **Honest disclosure:** Stage 1A still relies on `1-of-N` (`N=7`) open-cohort deposit attestation + `1-of-N` pre-committed online `BitVMX` verifiers + `1-of-M` (`M=3–5`) bonded fronting operators. Pure `0-of-N` unilateral exit requires a Bitcoin soft fork (`spec/01 Appendix A`). |
| "One honest watcher can stop a bad payout" | **Clarified for Stage 1A:** Any **`1-of-7` pre-committed online `BitVMX` verifier** can stop a bad payout with positive EV (`≥ +0.0167 BTC` @ `500 sat/vB`), and anyone on Earth can detect fraud and relay it to all 7 verifiers. (`1-of-∞` permissionless BitVM2 requires `~45–100+ BTC` even at `M=3–5` and is unaffordable for a young project.) |
| Proofs "end at Bitcoin's proof-of-work" | **True in Stage 1A:** Canonical `zBTC` state ordering, DA (`0x02`), and forced exits (`0x01`/`0x03`) are anchored directly on Bitcoin PoW with `0%` Zenon consensus trust (bounded by TVL-scaled `K` against private PoW forks). |
| "Security is funded by the network's own staking token" | **False — explicitly rejected.** ZNN (`~25–33 BTC` total market cap) is **0% in the BTC custody safety path**; all operator/verifier collateral is hard BTC. |
| "Millions of transactions per second"; per-second streams | Zenon Dynamic Plasma at `~11.4s`/Momentum provides `~4.4` base transfers/s at the `2.1M` floor, `~8.8` tx/s at default `4.2M`, and a **real hard ceiling of `~1,050–1,200` tx/s** under `go-zenon`'s `8 MiB` `MaxMomentumContentBytes` cap (NOT `4,386` tx/s). Stage 1A rollup txs use `AccountBlock.Data` (`~28,480` Plasma, `~11.4s` soft confirmation, Bitcoin L1 finality on `0x02` batch anchor). |
| "0 satoshi fees" | **0 satoshi BTC fee for Stage 1A feeless rollup transfers on Zenon** (costing `~28,480` refundable QSR/PoW Plasma; NOT native ZTS). Deposits, L1 forced exits (`0x01`), and fronting spreads pay Bitcoin L1 fees; under Zenon Plasma DoS, users bypass Zenon via Bitcoin L1 fees. |
| "Oracle verified" | **Consistency-checked** via `scripts/verify_spec_bounds.py` against `SOURCED_`, `POLICY_`, and `PRE_MAINNET_TARGET_` inputs; not empirically audited until Stage 0/1A Signet & third-party audit gates pass. |
| Omission of Zenon / ZNN / QSR / Pillars | Public pages MUST explicitly name **Zenon Network, ZNN, QSR, and Pillars**, and disclose `BitVMX-CPU`'s pre-mainnet status (`12–18+ mo` timeline) and `~65–72d` 100% bank-run exit queue. |

---

## 10. Written Answers to Consolidated Hostile Review (`R7`)

Every `R7` question against `v0` is answered normatively in `v1` without resorting to federated multisigs (full table in [`CHANGELOG.md`](./CHANGELOG.md)):

- **C-1 (ZNN/BTC forging price):** *Closed by removal.* `0%` ZNN in BTC safety; all `BitVMX` bonds (`2.60 BTC`/lane) and verifier escrows (`0.40 BTC`) are hard BTC.
- **C-2 (Honest BLS certs over dishonest Zenon state):** *Closed by removal.* BLS Pillar committees and optimistic Zenon batches are deleted; Stage 1A verifies an immutable Bitcoin-anchored ZK validity rollup (`vk_STF`, `0-of-N` Zenon trust).
- **C-3 (BitVM2 4.4–10× under-costed assert/disprove):** *Resolved by architecture switch.* Groth16 BitVM2 (`~1.0–1.3M vB`, `~45–100+ BTC` min bonds) is replaced with `n = 8` `BitVMX-CPU` (`RV32IM`) bisection (`~7.44 kvB`/tx TRUC v3, `~75 kvB` Prover / `~15 kvB` Verifier, `12.8–18.8 BTC` total pilot capital).
- **C-4 (Never-deleted `N`-of-`N` `Q_graph`):** *Closed.* Because `vk_STF` never rotates with PoS epochs, vault graphs never expire; ephemeral `Q_setup_d` and `Q_lane` keys are **permanently deleted** after setup. Zero custodial multisigs.
- **H-1 & H-2 (Free-delegation capture & 10-seat cert withholding):** *Closed by removal.* No Pillar finality committee exists in BTC custody.
- **H-3 (Upgrade & Plasma authority = custody authority):** *Closed.* `vk_STF` is hard-pinned on Bitcoin L1 (`SporkAddress` has `0` BTC custody blast radius); Stage 0 pins all `SetPlasmaVariables` fields (`spec/05`); full Privileged Powers Table in §4.1.
- **H-4 (Altruistic watcher `-1.46 BTC` EV & self-slash):** *Closed.* Pre-committed `BitVMX` verifiers receive `0.15 BTC` L1 directly from `Stake_r` (`1.85 BTC` burned), reclaim `100%` of `F_chal` from `ChalEscrow_{r,i}`, and remaining honest challengers split `0.55 BTC` from `B_zbtc` (`≥ +0.0167 BTC` positive EV even against `6-of-7` verifier collusion!).
- **H-5 (Missing exit liveness & throughput math):** *Closed.* `1-of-M` (`M = 3–5`) operator liveness is Assumption #4 (§4); exact throughput (`0.111–0.185 BTC/day`) and 100% bank-run duration (`~65–72` days under `{0.50, 0.25, 0.25}` vaults; `~43–47d` under `{0.50, 0.50}`) are published alongside `Cap_TVL`.
- **H-6 (April 2024 fees & June 2021 slow blocks):** *Closed.* Zero absolute CLTV cliffs (relative CSVs only); 100% TRUC v3 + `0`-sat `P2A` ephemeral anchors eliminate pre-signed fee cliffs; PTLC sized for `2.3×` slow blocks; sustained `500 sat/vB` 6.7-day bisection envelope disclosed explicitly.
- **H-7 (Unpaid anchoring & mobile BTC proofs):** *Closed.* Bitcoin L1 IS the canonical rollup ordering & DA layer (`0x02`/`0x01`/`0x03`); no Zenon epoch-handoff anchoring is needed for BTC custody.
- **H-8 (21M pre-mint blast radius inside `SettlementContract`):** *Closed by removal.* Stage 1A `zBTC` is accounted strictly in the Bitcoin-canonical Rollup SMT, never pre-minted into an upgradeable Zenon embedded contract.
- **M-9 & M-10 (`11.4s` Momentum, Dynamic Plasma & honest `8 MiB` ceiling):** *Closed.* Honest `~4.4 / ~8.8 / ~1,050–1,200 tx/s` ceiling (`MaxMomentumContentBytes = 8 MiB`), `28,480` Plasma per `AccountBlock.Data` rollup tx, and full `SetPlasmaVariables` pinning.
- **M-15 (Independent review):** *Enforced.* Stage 1A mainnet activation blocks strictly on Signet measurements and an independent third-party cryptography/Bitcoin-Script audit.
