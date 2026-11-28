# Part 5: `go-zenon` Upgrade Plan, Zero-Hard-Fork Custody Boundary & 3-Stage Delivery Roadmap

**Document Class:** Engineering Upgrade & Delivery Blueprint (`v1` / `v3.0.0-rfc` — Zero-Federation Phased Architecture; supersedes archived `v0` `v2.5.0-rfc`)  
**Reference Codebase Verified:** Local `go-zenon` clone is at `master` (`e8986a6`, `v0.0.10-alphanet`) and `origin/dev` (`770e893`).  
**Consistency Checker:** [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py)

---

## 1. Architectural Upgrade Principle: Zero `go-zenon` Custody Authority & Zero Hard Fork for Stage 1A/1B

Unlike archived `v0` (which demanded deep `go-zenon` consensus hard forks — `StateRootSpork`, `CommitteeRootSpork`, `OptimisticRefereeSpork`, ZNN slashing, and single-key governance custody controls), **`v1` decouples Bitcoin custody completely from `go-zenon` upgrades and Zenon governance**:

| Stage | `go-zenon` Changes Required | Zenon Spork / Governance Authority Over BTC Custody |
|---|---|---|
| **Stage 0 (`Verify Bitcoin`: SPV Event Oracle + Non-Custodial PTLC/LN)** | Upstream `go-zenon` U0 release (`0aa299e` + `#239` closed) + `DynamicPlasmaSpork` (w/ 5-parameter variable bounds) + `PtlcSpork` + lightweight `BtcSpvOracleSpork` (`vm/embedded/btcspv`). | **NONE (`0 BTC` custody in Stage 0).** Oracle provides read-only Event Validity only. |
| **Stage 1A (Right-Sized `BitVMX` `n = 8` + Sovereign ZK Rollup)** | **ZERO `go-zenon` consensus hard fork required!** Rollup sequencer/indexer reads standard `AccountBlock.Data` (`UserSend`) + Bitcoin L1 (`0x00`–`0x07`). | **ZERO!** `vk_STF` is immutably pinned on Bitcoin L1 at launch. Even total compromise of `SporkAddress` / `CommunitySporkAddress` or `100%` of Pillars cannot steal 1 satoshi or censor Bitcoin L1 `0x01` exits! |
| **Stage 1B (`clArk` Alternative Gate)** | **ZERO `go-zenon` consensus hard fork required!** Uses open-source `Second bark/barkd` or `Ark Labs arkd` coordinated alongside Zenon indexing / Stage 0 SPV. | **ZERO!** Custody lives strictly in Bitcoin L1 `clArk` VTXO trees. |
| **Stage 2 (Scale / BitVM3-GC / Track B Covenants)** | **ZERO `go-zenon` consensus hard fork required** for BTC custody. Optional `GovernanceContract` / `StateRoot` remain purely Zenon network UX infrastructure. | **ZERO!** Stage 1 vaults drain 1:1 via `0x01`; identical-STF scaling uses `N`-of-`N` voluntary Cohort 1 handover; backend swaps launch clean non-commingled `zBTC_v2`. |

---

## 2. Stage 0 `go-zenon` Prerequisites (`U0` Gate, `B1`, `B2`, Full Dynamic Plasma Pinning)

### 2.1 Upstream `go-zenon` Release Gate (`0aa299e` & Issue `#239`)

- **Local Clone Honesty Disclosure:** As verified directly against the local `go-zenon` reference clone, `HEAD` (`master`) is `e8986a6` (`v0.0.10-alphanet`) and `origin/dev` is `770e893`. Upstream commit **`0aa299e`** (*post-VM hash re-verification fix for externally supplied blocks mutated by `ValidateSendBlock`*) is **not yet present in this local clone** and remains a hard upstream release prerequisite before activating Stage 0 sporks on mainnet.
- **Close Upstream Issue `#239` (`B1` Blocking Gate for Stage 0 SPV Oracle):**
  - Embedded receives execute strictly FIFO per contract (`verifier/account_block.go:397-417`, `chain/account/sequencer.go:19-33`). On `master`, a VM panic returns `ErrVmRunPanic` (`vm/supervisor.go:228`) and aborts `pillar/worker_contract_generator.go:38-40` without advancing the sequencer, permanently stalling the contract.
  - **Normative Gate:** Every embedded method in `BtcSpvOracleContract` and `vm/embedded/btcspv/` MUST wrap execution in `defer func() { if r := recover(); r != nil { err = constants.ErrInvalidMethodParam } }()`, contain **zero** calls to `common.DealWithErr`, and rely on `#239`'s deterministic failure provenance so bounded receive retries ALWAYS terminate in a canonical failed receive (never a FIFO stall).

### 2.2 `DynamicPlasmaSpork` & Full 5-Parameter `SetPlasmaVariables` Pinning (`B2`)

`DynamicPlasmaSpork` (`origin/dev:dp/dp.go`, `origin/dev:vm/plasma.go:172-200`) is a hard precondition for Stage 0 `BtcSpvOracleSpork` because it enables `EmbeddedSendBasePlasma` (`tier + 68/byte` past the 4-byte selector) and stale-acknowledgement rejection (`origin/dev:chain/acknowledgement_recency.go`).

**Complete `SetPlasmaVariables` Lower/Upper Parameter Pinning:**
In unmodified `origin/dev:vm/embedded/definition/plasma.go:66-84`, `SetPlasmaVariables` (controlled by single-key `SporkAddress` / `CommunitySporkAddress` at `origin/dev:vm/embedded/implementation/plasma.go:199`) permits:
- `MaxBasePlasmaInMomentumLowerLimit = 210,000` (`L66`, blocking every SPV call `> 2,011 B` in `pillar/content_selector.go:328`), AND
- `FusedPlasmaTargetLowerLimit = 1` (`L69`), `PowPlasmaTargetLowerLimit = 1` (`L72`), `PriceChangeDenominatorLowerLimit = 1` (`L84`). Setting `target = 1` and `denom = 1` allows a single transaction to trigger the maximum per-Momentum price jump (`1.25^52 > 100,000×` in ~10 minutes!).

Therefore, `BtcSpvOracleSpork` MUST enforce **ALL FIVE** `SetPlasmaVariables` guardrails simultaneously:

| Parameter (`vm/embedded/definition/plasma.go`) | Unmodified `origin/dev` Bound | Normative Stage 0 Spork Floor / Ceiling | Why Required |
|---|---|---|---|
| `MaxBasePlasmaInMomentum` | `>= 210,000` (`L66`) | **`>= 2,100,000`** | Guarantees `>= 3` max `ProveTxInclusion` calls (`591,388` Plasma) and `dp.MaxContractBlocks >= 40` (`dp/dp.go:259-264`). |
| `MaxPriceChangePercent` | `<= 100` (`L75`) | **`<= 25`** (default `10`) | Caps per-Momentum adaptive step size. |
| `FusedPlasmaTarget` | `>= 1` (`L69`) | **`>= 525,000`** (`>= 25%` of `2.1M` floor) | Closes `target = 1` exponential fused-Plasma price-spike DoS. |
| `PowPlasmaTarget` | `>= 1` (`L72`) | **`>= 525,000`** (`>= 25%` of `2.1M` floor) | Closes `target = 1` exponential PoW-Plasma price-spike DoS. |
| `PriceChangeDenominator` | `>= 1` (`L84`) | **`>= 8`** | Damps step amplification even under sustained `100%` utilization. |

> **Honest Residual Dynamic Plasma Disclosure:** `origin/dev:dp/dp.go:102-151` intentionally has **no absolute upper clamp** on `NextFusionPrice`/`NextWorkPrice`, and fused QSR is refundable (zero burn). Even with all five bounds pinned, a well-funded QSR whale + `49%` malicious Pillars can still drive Zenon Plasma prices up exponentially over tens of minutes (`1.10^72 ≈ 955×` at default `+10%`/Momentum). This is **explicitly safe for Stage 1A custody** because Bob and Mike can always submit `0x01 FORCED_EXIT` / `0x03 FORCED_TRANSFER` directly on Bitcoin L1, completely bypassing Zenon Plasma!

### 2.3 Stage 0 SPV Event Oracle & Non-Custodial Swaps (`BtcSpvOracleSpork` + `PtlcSpork`)

1. Activate **`PtlcSpork`**, **`EmbeddedRefundSpork`**, **`Libp2pSpork`**, and **`EpochRewardTermsSpork`** (all implemented on `origin/dev:common/types/spork.go`).
2. Deploy lightweight **`BtcSpvOracleContract`** (`vm/embedded/btcspv/`: `header.go`, `tx.go` with 1-/2-block coinbase midstate verification, `oracle.go` — **zero** custody, minting, or federation code!).
3. Add local RPC/indexer helpers (`DeleteMomentum` WebSocket `momentumsReverted` push + HTLC/PTLC `getByDestination`/`getByPointLock`/`getByHashLock`) for wallets and Stage 0 swap LPs.
4. *(Recommended Non-Custodial Zenon Hygiene, Non-Blocking for BTC Custody):* Replace single-key `SporkAddress` / `CommunitySporkAddress` (`vm/embedded/implementation/spork.go:46-49, 117-119`, which can currently terminate all nodes via `os.Exit(2)` after `SporkMinHeightDelay = 6` Momentums at `chain/momentum_pool.go:53-68`) with a timelocked `GovernanceContract`. Even if un-upgraded, **`SporkAddress` compromise has `0` custody power over Stage 1A/1B BTC!**

---

## 3. Stage 1A / 1B Off-Chain Software Stack (Piggybacking on Open-Source Ecosystems)

A small young engineering team (4–6 engineers) MUST NOT write custom Bitcoin Script Groth16 compilers or custom BitVM3 garbled-circuit frameworks from scratch. Both Stage 1 paths piggyback directly on audited/open-source Bitcoin stacks:

- **Stage 1A (`BitVMX` `n = 8` Sovereign Rollup Stack — Primary Path for Pooled Fungible `zBTC`):**
  1. **Reuse `BitVMX FORCE` / Fairgate Open-Source Core:** `BitVMX-CPU` (`RV32IM` RISC-V verifier & single-opcode Bitcoin Script evaluator) + `BitVMX-protocol` (pre-signed `n = 8` bisection graph builder & W-OTS commitment engine).
  2. **Zenon Team's Focused Scope (Pure Rust → `RV32IM`):**
     - Deterministic Rollup STF $\mathcal{F}$ (stripped-block parser, BIP-141 witness verifier, SMT transitions, `ExitSlotUTXO` spend-or-refund, `B_zbtc` slashing) compiled cleanly to `RV32IM` (zero custom Bitcoin Script Groth16 circuits!).
     - `zbtc-sequencer` / `zbtc-batcher` daemon (reads Zenon `AccountBlock.Data`, builds `π_batch`, posts `0x02 BATCH_DA`).
     - Operator fronting & `StakeChain` daemon (`M = 3–5`) + `N = 7` Verifier watchtower daemon (monitors `KickoffTx_r` and opens simultaneous `ChallengeTx_{r,i}` in `[0, 144]`).
- **Stage 1B (`clArk` Alternative Gate Stack):**
  - Fork/integrate mainnet-live **`Second bark/barkd`** or **`Ark Labs arkd`** (`2–5 BTC` active ASP liquidity) + lightweight Zenon coordination/SPV client (`~3–6` months).

---

## 4. Concrete 3-Stage Delivery Roadmap & Capital Gates

| Stage | Timeline (4–6 Engineers) | Hard BTC Capital Required | Deliverables & Security Milestone | Exit / Migration Guarantee |
|---|---|---:|---|---|
| **Stage 0: `Verify Bitcoin` Foundation** *(Mandatory Start)* | **`0–6 months`** | **`0 BTC` bonds** (`0–5 BTC` voluntary LP) | Upstream `U0` (`0aa299e` + `#239`) + `DynamicPlasmaSpork` (5-param pin) + `PtlcSpork` + Stage 0 `BtcSpvOracleContract` (1-/2-block midstate) + non-custodial PTLC/LN swaps. Parallel Signet prototype of Rollup STF $\mathcal{F}$ on `BitVMX-CPU`. | Zero custody risk; users hold native BTC on L1/LN at all times. |
| **Stage 1 Decision Gate** | **Month 6 Gate** | *Gate Check* | **Choose Stage 1A ONLY if** pooled fungible non-expiring `zBTC` is non-negotiable **AND** `>= 12.8–18.8 BTC` of independent bonded BTC is committed for `12–18+` months (incl. audit). **Otherwise choose Stage 1B (`clArk`)** (`2–5 BTC` active liquidity, `3–6 mo` launch) — NEVER under-bond BitVMX/BitVM2 below `500 sat/vB`! | Explicit upfront commitment; zero hidden federation fallback. |
| **Stage 1A: Right-Sized `BitVMX` (`n = 8`, `M = 3–5`, `N = 7`) Sovereign Rollup** | **`12–18+ months`** *(incl. external Bitcoin Script + STF audit)* | **`12.8 BTC`** (`M = 3`, `Cap <= 10 BTC`) / **`18.8 BTC`** (`M = 5`, `Cap <= 15 BTC`) | Mainnet `BitVMX` `n = 8` TRUC v3 vaults (`{0.50, 0.25, 0.25}`), `0-of-N` Zenon trust (`49%–100%` proof), Bob `0.50` & Mike `0.25` L1 forced exits, `100%` positive-EV `N = 7` verifiers even under `6-of-7` collusion. | Deleted-key vaults remain 100% live forever; zero governance capture surface. |
| **Stage 1B *(Alt)*: `clArk` + Zenon SPV/PTLC** | **`3–6 months`** | **`2–5 BTC`** active ASP liquidity (`0` bonds) | Mainnet `bark`/`arkd` VTXO rounds + Zenon coordination. Pure `0-of-N` post-round unilateral exit; honest disclosure of `arkoor` sender+ASP collusion, VTXO expiry, and discrete non-pooled VTXOs. | Users hold self-custodial pre-signed L1 exit branches at all times. |
| **Stage 2: Zero-TTP Scale & Upgrade** | **`12+ months` post-Stage 1** | Scales with TVL (`K = 36` → `50 BTC`; `K = 144` → `200 BTC`) | (a) Identical-STF scaling (`M = 5 → 20`, `L = 1 → 4`) via voluntary `N`-of-`N` Cohort 1 handover; (b) Backend upgrade to mature reusable BitVM3-GC, BitVM2, or **Track B Pure Tier-0 Covenants (`OP_CCV + OP_TXHASH + OP_VERIFY_STARK` / `OP_CAT`)** via clean non-commingled `zBTC_v2`. | Zero dead-end migration: Stage 1 vaults drain organically 1:1 via `0x01` exits (zero deleted-key L1 rollover magic!). |

---

## 5. Mandatory CI & Conformance Verification Gates

1. **Symbol & Line-Hash Citation CI:** Automated check pinning every `go-zenon` symbol cited in Parts 2–5 against the tagged U0 release containing `0aa299e` and `#239`.
2. **Panic & FIFO-Stall Fuzz Gate (`B1`):** Continuous fuzzer across all 4 Stage 0 `BtcSpvOracleContract` methods asserting zero panics, zero `common.DealWithErr` calls, and zero sequencer stalls.
3. **Dynamic Plasma 5-Parameter Bounds & 1-/2-Block Midstate Vectors (`B2`):** MUST-fail tests verifying `SetPlasmaVariables` rejects ANY violation of the 5 pinned bounds (`MaxBasePlasmaInMomentum < 2.1M`, `MaxPriceChangePercent > 25`, `FusedPlasmaTarget < 525k`, `PowPlasmaTarget < 525k`, `PriceChangeDenominator < 8`), plus 1-block and 2-block SHA-256 coinbase midstate vectors.
4. **Stage 0 PTLC/LN Adversarial Suite (`M-4`):** Signet↔Zenon tests asserting absolute Unix timestamp `now + 108,000`, `2.3×` slow-block `25.3h < 30h` margin, `>= 72`-block CSV, CPFP confirm `<= h_conf + 66`, BIP-327 odd-$y(R')$ parity, `hashType = 0` rejection, and LN Hold Invoice `ACCEPTED`-first + 5-minute cancel TTL.
5. **Stage 1A `BitVMX` `n = 8` & Rollup STF Conformance Suite:** Deterministic verification of `scripts/verify_spec_bounds.py` (`7.44 kvB <= 10 kvB` TRUC v3, `0.40 BTC` `F_chal` @ `500 sat/vB`, `1,104 < 1,152 < 1,296 < 1,440` timelocks, `k_collude = 0..6` positive verifier EV, `0.01 BTC` `ExitSlotUTXO` grief slash, `256`-bit Lamport `TakeTx` `<= 3.2 kvB`, real Bitcoin reorgs, and 2,000-step strict 1:1 solvency conservation).
