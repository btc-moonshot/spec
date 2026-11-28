# Part 4: Zenon Consensus Reality (`go-zenon`), Inverted Trust Hierarchy & Optional Light-Client Anchoring

**Document Class:** Normative Consensus Security Proof & Non-Custodial Anchoring Specification (`v1` / `v3.0.0-rfc` — Zero-Federation Phased Architecture; supersedes archived `v0` `v2.5.0-rfc`)  
**Codebase Verified:** `go-zenon` `master` (`e8986a6`, `v0.0.10-alphanet`) and `origin/dev` (`770e893`)  
**Consistency Checker:** [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py)

---

## 1. Why Zenon Consensus Cannot Sit in the Bitcoin Custody Path (Grounded in `go-zenon`)

A bridge or L2 inherits the weakest safety and liveness threshold of the consensus engine it trusts. Direct inspection of `go-zenon` (`master` `e8986a6` and `origin/dev` `770e893`) proves that **neither current `go-zenon` DPoS nor a future classical BFT upgrade (`CommitteeRootSpork`) can survive a `49%` Zenon compromise**:

### 1.1 Current `go-zenon` Is Longest-Chain DPoS With Zero Slashing, Grindable Seeds & a 30-Momentum Split Cliff

Across `consensus/`, `protocol/`, `verifier/`, and `vm/embedded/implementation/pillars.go` on **both** `master` and `origin/dev`, there is **zero** BFT voting, **zero** quorum certificates, **zero** finality gadget, **zero** equivocation detection, and **zero** slashing:

1. **Unweighted Top-30 Cutoff (`groupA`) Amplifies Stake Into >50% Slots:**
   - `vm/constants/consensus.go:15-20` sets `BlockTime = 10s`, `NodeCount = 30`, `RandCount = 15`, `CountingZTS = ZNN` (`300s` election tick, `consensus/context.go:23`).
   - `consensus/election_algorithm.go:65-75` (`master`; `89-99` on `origin/dev`) puts the top 30 active Pillars by live delegated ZNN (`chain/momentum/embedded.go:59-104`) into `groupA`, selects `15` uniformly from `groupA`, moves the unselected `15` into `groupB`, and selects `15` from `groupB` (`election_algorithm.go:78-118`). Because `groupA` is unweighted inside the top 30, an attacker with `49%` of delegated ZNN can Sybil-split stake just above the #30 Pillar cutoff to capture **>50% of `groupA` slots**.
2. **Deterministic Height-Only PRNG Seed Is Trivially Grindable:**
   - `consensus/election_algorithm.go:38-40` (`master`; `58-60` on `origin/dev`): `findSeed` returns **`int64(context.hashH.Height)`** — **purely the Momentum height, with ZERO block-hash entropy**.
   - Because `proofBlock = GetMomentumBeforeTime(EndTime(tick - 2))` (`consensus/election.go:90-145`), a `49%` adversary controlling `~14–15` slots in tick `T - 2` can precompute `SelectProducers` offline for `H_base + {0..15}` and skip just enough of their own slots in tick `T - 2` to land `proofBlock.Height` on the exact integer $H^*$ maximizing their slots in tick `T` (expected max over 15 draws shifts mean `14.7 → ~19.4` slots = **`~65%` of slots in tick `T`**!).
3. **Zero Equivocation Checks + Hardcoded 30-Momentum Rollback Cliff = Permanent Chain Split:**
   - `verifier/momentum.go:217-275` checks only signature + slot producer — a Pillar can sign arbitrarily many conflicting Momentums for the same slot at zero cost.
   - `protocol/chain_bridge.go:241, 246` (`master`; `293, 304` on `origin/dev`) enforces pure **longest-chain-by-height** (`tail.Height <= ourFrontier.Height` → reject) AND hard-refuses any rollback deeper than `30` Momentums (`ourFrontier.Height - target.Height > 30` → reject).
   - **49% Permanent Split Attack:** By equivocating on both sides of a network delay/partition splitting the `51%` honest Pillars into `26%` and `25%`, the `49%` adversary powers Branch A (`26% + 49% = 75%`) and Branch B (`25% + 49% = 74%`) simultaneously past depth `30` (`~6.5` minutes), **permanently locking the two halves on incompatible histories**.
   - **Censorship & Sync Gating:** Empty Momentums (`len(Content) == 0`) are valid (`verifier/momentum.go:158-210`, `pillar/worker_momentum.go:13`), allowing `49%` Pillars to omit user exits, orphan honest inclusion blocks via seed-ground `>50%` ticks, and exploit `ReadyToProduce` (`protocol/readiness.go:16, 94-122`, `producerStallWindow = 60s`).
4. **No Succinct External State Proof & Low Market Cap:**
   - `Momentum.ChangesHash` is `SHA3-256(leveldb.Batch.Dump())` (`common/db/patch.go:124-126`) — an opaque diff dump, NOT a state root (`Minimum Verifier Spec.md:735-756`). `Content.Hash()` is a flat hash over headers (`Minimum Verifier Spec.md:168`).
   - With total ZNN market cap at **`~25–33 BTC`**, ZNN-denominated slashing can never economically secure multi-BTC vaults.

### 1.2 Why Classical BFT (`CommitteeRootSpork`) Also Fails at `49%`

Even if Zenon upgraded to a classical partially synchronous BFT finality committee (`n >= 3f + 1`), **`49% > 33.3%` breaks BOTH liveness and safety**:
- **Liveness Halt (`>= 33.4%`):** `49%` withholding votes blocks `67%` quorum indefinitely.
- **Safety Equivocation (`>= 33.4%`):** `49%` splits `51%` honest validators into `25.5% + 25.5%` and signs **two conflicting `74.5% > 66.7%` finality certificates**, allowing a malicious prover to drain any bridge whose verifier trusts Zenon BFT certificates. *(Synchronous BFT cannot be verified by Bitcoin L1/SNARK circuits because Bitcoin cannot observe Zenon's network delay $\Delta$.)*

---

## 2. The Inverted Trust Hierarchy (`0-of-N` Zenon Trust — Surviving `49%–100%` Zenon Compromise)

Because Zenon consensus breaks at `49%` (DPoS) and `>33.3%` (BFT) and ZNN market cap is `~25–33 BTC`, **`v1` completely removes Zenon consensus and ZNN slashing from Bitcoin custody**:

```text
Bitcoin Mainnet L1 (PoW Canonical Ordering + Complete 0x02 DA + 0x01/0x03 Forced Inclusion + BitVMX Custody)
        ▲
        │  Canonical zBTC state root R_h derived 100% from Bitcoin L1 blocks (0% Zenon trust!)
        │  Unilateral L1 forced exit (0x01) & transfer (0x03) bypass Zenon completely
        │
Zenon Network L1 (Untrusted Feeless Soft-Preconfirmation Sequencer via AccountBlock.Data + Stage 0 SPV Event Oracle)
```

| Property | Traditional Bridge / Archived `v0` | `v1` Inverted Trust Hierarchy (Stage 1A) |
|---|---|---|
| **Canonical `zBTC` Fork Choice** | Zenon DPoS or BLS BFT Committee (breaks at `33.4%–49%`) | **Bitcoin Mainnet PoW** (first valid `0x02` matching `R_{h-1}` wins; `0%` Zenon trust) |
| **Data Availability (DA)** | Zenon full nodes / committee | **Bitcoin L1 `0x02` Taproot witness** (complete mutated SMT leaves `16 B`/`48 B` + `π_batch`) |
| **Exit Censorship Resistance** | Censored by Zenon Pillars / Plasma spikes / signers | **Bitcoin L1 `0x01 FORCED_EXIT`** (uncensorable even under **100%** Zenon compromise!) |
| **Custody Security Coupling to ZNN** | ZNN staking/slashing (`~25–33 BTC` mcap ceiling) | **`0%` ZNN coupling** (100% BTC-denominated `BitVMX` bonds `2.60 BTC`/lane + `1-of-N` verification) |
| **Zenon's Actual Value-Add** | Custody bottleneck | **Feeless `~11.4s` soft preconfirmations (`0` sat BTC fee) + Stage 0 Bitcoin Event Oracle** |

---

## 3. Optional Non-Blocking Zenon Anchoring & Light-Client Track (Consumer UX Only)

> **Hard Custody Boundary:** Nothing in §3 is required for Stage 0, Stage 1A (`BitVMX`), Stage 1B (`clArk`), or Stage 2 `zBTC` custody. All items below are optional, non-blocking Zenon network infrastructure for consumer mobile/browser light clients verifying *non-BTC Zenon-native state* (ZNN, QSR, Accelerator-Z).

### 3.1 Genesis Bitcoin Anchor (Live on Mainnet)

Zenon Genesis Momentum (`Height = 1`, hash `9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0`, `ts = 1637755200`) embeds Bitcoin mainnet block `710,968` (`000000000000000000004dd040595540d43ce8ff5946eeaa403fb13d0e582d8f`) in `Momentum.Data` (`chain/genesis/embedded_genesis_string.go:6`), grounding Genesis-Anchored Lineage Verification (`zenon-developer-commons`: `docs/specs/GALV_spec_draft.md`).

### 3.2 Optional Periodic Zenon Checkpoint Anchoring & `StateRoot` (`common/trie`)

If Zenon independently ships optional `StateRoot` (`common/trie` 256-bit `SHA3-256` SMT) and periodic Bitcoin checkpoint anchoring (`OP_RETURN "ZNNA" || u64BE(height) || SHA256("ZNN_BTC_ANCHOR_V2" || digest)` every `360` Momentums ≈ `68m` at `11.4s`/Momentum) for native Zenon light clients:
- **Honest Light-Client Trust Statement:** Bitcoin checkpoint anchoring provides **immutable timestamp ordering and long-range tie-breaking ONLY — NOT execution validity** of Zenon L1 state. Native Zenon light clients still trust Zenon's Pillar set for non-rollup state transitions.
- **Optional U2 Committee Quorum & Selection Hardening (`H-1`, `L-1`):** If Zenon ever deploys an optional non-custodial BLS12-381 finality committee (`K_fin = 30`), any degraded-membership rule for `21 <= eligible < 30` MUST define quorum strictly as **`popcount >= ceil(2 * eligible / 3)`** (e.g., `14-of-21` at `eligible = 21`, up to `20-of-30` / `21-of-30` at `eligible = 30`) — **NEVER** requiring both `ceil(2 * eligible / 3)` AND `popcount >= 21`, which forces `21-of-21` (`100%`) unanimity at `eligible = 21`! Furthermore, any future committee selection MUST NOT rely on non-existent `prevEpochRandao`; it requires either time-weighted variable slashable self-bond or a dedicated VRF/commit-reveal randomness beacon.
- **Zero Impact on `zBTC`:** Because Stage 1A `zBTC` derives 100% of its state root $R_h$ from Bitcoin L1, consumer `zBTC` wallets verify their balances directly against Bitcoin headers (via BIP-157/158 Neutrino) + `0x02` SMT Merkle proofs — requiring **zero** Zenon BLS committee or Zenon `StateRoot`!
