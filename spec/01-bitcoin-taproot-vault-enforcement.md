# Part 1: Zero-Federation Bitcoin Taproot Vault Enforcement (`BTC-BITVMX-V1`), Stage 1B `clArk` Gate & Track B Soft-Fork Annex

**Document Class:** Normative Bitcoin Custody Specification (`v1` / `v3.0.0-rfc`; supersedes `v0` `BTC-ENFORCEMENT-V1`)  
**Spec Identifier:** `BTC-BITVMX-V1`  
**Precedence:** **Highest normative layer** ([`SPEC.md §2.1`](../SPEC.md#21-authority--conflict-precedence-m-13-fixed)) — Bitcoin L1 scripts, deleted-key Taproot graphs, `StakeChain` timelocks, and `ExitSlotUTXO` consensus rules cannot be overridden by any Zenon contract, Pillar, or spork.  
**Target Chain:** Bitcoin Mainnet TODAY (`bip-0141` SegWit, `bip-0340` Schnorr, `bip-0341` Taproot, `bip-0342` Tapscript, `bip-0068`/`bip-0112` relative CSV timelocks, `bip-0431` TRUC v3 + `P2A` ephemeral anchors — **zero Bitcoin soft forks**, **zero custodial federated multisigs**)  
**Consistency Checker:** [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py)

---

## 1. Cryptographic Boundaries (Theorem 1 & Theorem 2) & Prohibition of Federated Custody

### 1.1 Explicit Prohibition of Custodial Federated Multisigs

Pooled custodial `k`-of-`n` multisig federations (whether `OP_CHECKSIGADD`, FROST, or HSM-backed, with or without custodial backup recovery leaves) are **STRICTLY FORBIDDEN** in `v1`. Federated custody introduces up to `100%` collusion loss, breaks liveness whenever `n - k + 1` signers refuse to sign Mike's `0.25 BTC` exit, and stalls under `49%` Zenon DPoS consensus splits.

### 1.2 Formal Boundary Proofs

**Theorem 1 (Impossibility of Pure `0-of-N` Arbitrary Unilateral Exit on Bitcoin Mainnet Today):**
Given pooled deposit UTXOs `U_A` (`1 BTC`), `U_B` (`1 BTC`) created at `t_0` under current Bitcoin consensus (BIP-340/341/342, zero soft forks), if ZERO pre-committed parties sign a new transaction at `t_1`, no valid Bitcoin L1 transaction exists that allows an unknown future recipient Mike (`P_Mike`, `0.25 BTC` unknown at `t_0`) to spend `U_A` or `U_B` paying `0.25 BTC → P_Mike` while locking `0.75 BTC` back into custody:
1. BIP-342 Tapscript lacks output introspection (`nValue`/`scriptPubKey`); any spend succeeding without a signature committing to outputs is trivially RBF-replaced by miners substituting `(1.0 BTC → P_miner)`.
2. Pre-signed transactions at `t_0` using `SIGHASH_ALL`/`SINGLE` fix outputs before `(P_Mike, 0.25 BTC)` exist; `SIGHASH_NONE` permits total theft.
3. **Corollary 1A (Bob's `0.5 BTC`):** Depositor CSV refund leaves on `U_B` are impossible after fungible minting (Bob would spend `0.5 zBTC` then reclaim `1.0 BTC` via CSV).
4. **Corollary 1B (Optimistic Reimbursement Bound):** On Bitcoin Mainnet today, every BitVM-family bridge (`BitVM2`/`BitVMX`/`BitVM3`) requires **`1-of-N` ephemeral setup deletion + challenger/verifier safety + `1-of-M` pre-committed operator exit liveness**.

**Theorem 2 (Young Low-Cap Capital / Trust / UX Trilemma — 0 Federation, 0 Soft Forks, `2–20 BTC` Bootstrap Capital):**
With `0` federated signers, `0` soft forks, `~25–33 BTC` ZNN market cap (`0%` ZNN slashing usable), and realistic bootstrap capital `C ∈ [2, 20] BTC`, no protocol simultaneously achieves **(A)** instant non-expiring fungible cross-depositor `zBTC`, **(B)** `1-of-∞` permissionless challenging surviving `200–500 sat/vB`, and **(C)** `0-of-N` unilateral arbitrary L1 exit:
- **Minimal `BitVM2` (`M = 3–5, L = 1`) fails `C ≤ 20 BTC`:** Groth16 `AssertTx` (`~1.0–1.3M vB` / `4.0–4.8 MB` W-OTS) is a fixed Bitcoin-Script constant imposing `13.30–18.175 BTC`/lane (`39.9–90.9 BTC` in bonds alone before fronting liquidity; under-bonding to `≤ 20 BTC` breaks above `50 sat/vB`).
- **Stage 1A Right-Sized `BitVMX` (`n = 8`, `M = 3–5`, `L = 1`, `N = 7`)** achieves **(A)** inside **`12.8–18.8 BTC`** by accepting `1-of-N` (`N = 7`) pre-committed online verifiers and `1-of-M` (`M = 3–5`) operator liveness.
- **Stage 1B `clArk`** achieves post-round **(C)** inside **`2–5 BTC`** by sacrificing **(A)** (discrete expiring VTXOs, pre-round `arkoor` sender+ASP collusion, no global pooled `zBTC`).

| Custody Track | Soft Fork? | Bootstrap BTC | Zenon Trust (`49%–100%`) | Custody Safety | Mike `0.25 BTC` Liveness (0 Zenon Signers) | Status in `v1` |
|---|---|---|---|---|---|---|
| **Stage 0 (SPV + PTLC/LN)** | No | `0 BTC` bonds (`0–5` LP) | `0-of-N` | Pure self-custody | N/A (no pooled `zBTC`) | **Mandatory Stage 0** |
| **Stage 1A (`BitVMX n=8` Rollup)** | **No (Today)** | **`12.8–18.8 BTC`** | **`0-of-N`** | `1-of-N` setup/cohort + **`1-of-7`** online verifier | **`1-of-M` (`M=3–5`)** op (`~10m` front; `65–72d` 100% run) | **Primary Stage 1A** *(pre-mainnet R&D)* |
| **Stage 1B (`clArk` VTXOs)** | **No (Today)** | **`2–5 BTC` liq** | **`0-of-N`** | Post-round `0-of-N` (pre-round `arkoor` trusts ASP) | Post-round `0-of-N` until expiry (whole VTXO) | **Explicit Stage 1B Alt** |
| **Appendix A: Track B Covenant+ZK** | **Yes (`OP_CCV`+ZK or `OP_CAT`)** | **`0 BTC` bonds** | **`0-of-N`** | **Pure `0-of-N`** | **Pure `0-of-N`** (1 L1 tx direct from pooled UTXO) | **Non-Normative Annex** |

---

## 2. Stage 1A Deleted-Key Vaults, Acyclic Deposit Ceremony & Zero-TTP Cohort Rule

### 2.1 Multi-Tier Vault Split (`{0.50, 0.25, 0.25}` BTC)

Every `1.0 BTC` deposit splits at deposit time into three standardized deleted-key vault UTXOs:
- **Canonical Stage 1A Split:** **`{0.50, 0.25, 0.25}` BTC** (`3` vaults/BTC, average vault **`0.333 BTC`**, **`maxVaultDenom = 0.50 BTC`**).
  - Bob's `0.50 BTC` recovery maps 1:1 to a `0.50 BTC` vault immediately; Mike's `0.25 BTC` recovery maps 1:1 to a `0.25 BTC` vault immediately; arbitrary non-bucket amounts (e.g. `0.2371 BTC` or `0.001 BTC`) are paid in exact satoshis by `FrontingTx` and batched via `ReimbursementCredit[O_j]` until hitting an available `0.25`/`0.50 BTC` vault (**zero new presigning needed**).
  - *Throughput Option:* Operators/deployments prioritizing faster bank-run recycling over direct `0.25 BTC` vault mapping may configure `{0.50, 0.50}` BTC (`2` vaults/BTC, avg `0.50 BTC`, reducing 100% bank-run duration by `~33%` with identical `maxVaultDenom = 0.50 BTC` and zero bond increase).

### 2.2 Acyclic `DepositTx` Ceremony (`OP_DROP` Witness-Stack Push — Closes `v0 C-4, N-2, M-7`)

Because `vk_STF` is immutably hard-pinned and never rotates with PoS epochs, **Stage 1A vault graphs NEVER expire and NEVER require re-graphing**. There is NO `ProvisionalDepositScript`, NO `RolloverTx`, and NO standing `CommitteeIdentityKey`:

1. **Self-Custodial Staging UTXO (`U_dep_wallet`):** Depositor locks `1.0 BTC + fee` into a pre-committed Tapscript **`OP_DROP <pk_depositor> OP_CHECKSIG`** (independent of `DepositTx`, eliminating any SHA-256 hash cycle!).
2. **Deterministic Unsigned `DepositTx`:** Spends `vin[0] = U_dep_wallet` → `vout[0..2]` = vault UTXOs `U_0 (0.50 BTC)`, `U_1 (0.25 BTC)`, `U_2 (0.25 BTC)` + `vout[3]` = **`69 B` standard `OP_RETURN`**:
   ```text
   OP_RETURN <"ZBTX"(4B) || 0x00(1B) || recipientAcctHash(32B) || vaultParamsHash(32B)>
   ```
   Because `vout[3]` does **NOT** hash `certBlob`, **`txid_dep` is 100% fixed before presigning or attestation**.
3. **Ephemeral Deleted-Key Presigning:** Depositor + `N = 7` presigners + all online operators (`≥ M_min`, encoded in `opBitmask` `u64`) generate fresh per-deposit ephemeral keys `(x_{i,d}, P_{i,d})` (including the depositor's own ephemeral key `P_{dep,d}`!) forming `Q_setup_d = MuSig2_KeyAgg(P_{1,d}, ..., P_{N,d}, P_{dep,d})`. They presign ONE `TakeTx_{d,j,l,r}` per eligible operator lane `(j, l)` and unused round `r ∈ {r_cur..R}` (Stage 1A `M = 5, L = 1, R = 64` ⇒ **`320` pre-signed `TakeTx`s per vault**, `~40 KB` off-chain, `< 100ms` batch MuSig2 ONCE at deposit).
4. **Immediate Ephemeral Key Deletion & Non-Spending Attestation:** Each presigner `i` **permanently deletes `x_{i,d}`** and signs a non-spending identity attestation `σ_cert` (`64 B` MuSig2 over `id_1..id_N`, co-verified by eligible operators) covering `(txid_dep, Q_setup_d, opBitmask, vaultParamsHash)`:
   ```text
   certBlob = σ_cert(64B) || Q_setup_d(32B) || opBitmask(8B)   [exact 104 B <= 520 B BIP-342 limit]
   ```
5. **Zero-Stranding Broadcast:** Only after verifying every pre-signed `TakeTx` and `σ_cert` does the depositor delete `x_{dep,d}`, push witness stack **`[sig_depositor, certBlob, script, controlBlock]`** into `DepositTx.vin[0].witness`, and broadcast. Because witness stacks are excluded from `txid_dep` and authenticated by `wtxid_dep` in the coinbase BIP-141 witness commitment, there is **zero hash cycle**. At `K` confirmations, the Rollup STARK (`spec/02 §3`) verifies real satoshi outputs, Taproot script derivation, and `σ_cert`, and credits `1.0 zBTC`.

### 2.3 Zero-TTP Cohort Lifecycle Rule

Inside a single fungible `zBTC` pool, **NO governance key, Pillar vote, or threshold committee can EVER add a new presigner cohort**:
1. **Voluntary Handover (Same `vk_STF` Only):** Only **`N`-of-`N`** (`7-of-7`) of Cohort 1 (preserving strict `1-of-N` safety!) may sign a handover certificate registering Cohort 2.
2. **Involuntary `1-of-N` `id_i` Key Loss:** All existing Cohort 1 vaults and `zBTC` balances remain **100% safe and 100% live forever** (zero bricking), while *new* deposits on `v1` halt cleanly. Future deposits launch a **clean, non-commingled sovereign deployment (`zBTC_v2`)** with fresh Cohort 2. *(Long-term `id_i` uses redundant HSM backup; ephemeral `x_{i,d}` is NEVER backed up.)*
3. **Explicit Residual Open-Cohort Bound:** While a cohort accepts new deposits, at least `1-of-N` `{id_1..id_N}` must remain uncompromised (otherwise all `N` compromised `id_i` keys could attest a fake new deposit into the shared pool; existing deleted-key vaults still cannot be swept directly).

---

## 3. Right-Sized `BitVMX` (`n = 8`, `RV32IM`) `StakeChain`, 256-Bit Lamport `TakeTx` & TRUC v3 Wiring

### 3.1 Launch-Time `StakeChain` & PoW Anchor (`t = 0`, `M = 3–5`, `L = 1`, `N = 7`, `R = 64`)

Before accepting deposits, each operator `O_j` (`j ∈ {1..M}`) launches `L = 1` serial `StakeChain` lane `(j, l)` (`R = 64` finite rounds):
- **Launch-Time Bitcoin PoW Anchor (Zero Pre-Broadcast Cycle):** Each lane pins an **already-confirmed** Bitcoin block `(h_lane_init, H(h_lane_init), D(h_lane_init))` inside its `BitVMX-CPU` `RV32IM` verifier program at `t = 0` (before `Q_lane_{j,l}` deletion). In-circuit header verification enforces full Bitcoin PoW + 2,016-block retargeting from `h_lane_init` with minimum difficulty floor **`D(h) ≥ 0.50 × D(h_lane_init)`** across the lane's finite `R = 64`-round horizon.
- **TVL-Scaled Private-Fork Confirmation Depth `K`:** Sized against **100% multi-operator collusion on a single private fork**:
  ```text
  0.50 * K(era, Cap_TVL) * Subsidy(era) > Cap_TVL
  ```
  At `Subsidy = 3.125 BTC` (2024–2028) and `α_diff = 0.50` (`1.5625 BTC/blk` floor, `3.125 BTC/blk` nominal):
  - **`Cap_TVL ≤ 15 BTC` (Stage 1A Pilot):** **`K = 14` blocks** (~2.3h) ⇒ PoW cost `21.88–43.75 BTC > 15 BTC`.
  - **`Cap_TVL ≤ 50 BTC` (Stage 2):** `K = 36` blocks (~6h) ⇒ PoW cost `56.25–112.50 BTC > 50 BTC`.
  - **`Cap_TVL ≤ 200 BTC` (Stage 2):** `K = 144` blocks (~24h) ⇒ PoW cost `225.0–450.0 BTC > 200 BTC`.
  *(If mainnet difficulty grows `> 2×` within a lane's active lifetime, `α_diff` tightens proportionally — e.g. `0.33` at `3×` growth ⇒ `K = 20 / 54 / 216` — or fresh lanes re-anchor `(h_lane_init, D)`.)*
- **Pre-Signed Linear `StakeChain` (`Stake_0 → RoundTx_1 → Stake_1 → ... → RoundTx_R`):**
  - `O_j` locks **`Bond_BTC = 2.00 BTC`** in `Stake_0` under ephemeral `Q_lane_{j,l}` (all `N = 7` presigner ephemeral shares **permanently deleted** after presigning the `R = 64` rounds!).
  - Each round `r ∈ {1..R}` binds a one-time **256-bit Lamport keypair `L_{j,l,r}`** (`256` `OP_HASH160` pairs `(H_{k,0}, H_{k,1})`) signing `vaultHash_d = SHA256(outpoint_d)`.
  - **`RoundTx_r`** (spends `Stake_{r-1}` after `<1,296> OP_CSV`, revealing `256` Lamport preimages = `5,376 B` witness ≈ `1,344 vB`, total `RoundTx_r ≈ 1.8 kvB ≤ 10,000 vB` **TRUC v3**) creates:
    - **`Out 0 = Stake_r` (`Bond_BTC = 2.00 BTC`):**
      - **Leaf 1 (Next Round):** `<1,296> OP_CSV` (`9.0d` — enforces `W_max = 1` active kickoff per lane on L1!) → `RoundTx_{r+1}`.
      - **Leaf 2 (Clean Retirement):** `<1,440> OP_CSV` (`10.0d`) → **`RetireStakeTx_r`** (returns `2.00 BTC` to `O_j`; spending `Stake_r` **permanently double-spends and kills `RoundTx_{r+1..R}` forever**! The STF forbids unlocking `O_j`'s `B_zbtc` until `RetireStakeTx_r` confirms `K`-deep!).
      - **Leaf 3 (Bisection Slash):** Immediate → `DisproveTx_{r,i}` / `TimeoutSlashTx_{r,i}` (**MUST spend BOTH `vin[0] = Stake_r` AND `vin[1] = VaultConnector_r`!**) paying **`0.15 BTC`** directly on L1 to winning verifier `P_{V_i}` and burning **`1.85 BTC` to `OP_RETURN`**.
      - **Leaf 4 (256-Leaf Lamport Equivocation Slash, Depth 8, Pre-Signed at `t = 0`):** Leaf `k ∈ [0..255]` verifies `OP_HASH160 <H_{k,0}> OP_EQUALVERIFY OP_HASH160 <H_{k,1}> OP_EQUALVERIFY <Q_lane_{j,l}> OP_CHECKSIG` → `BurnBondTx_{r,k}` (`~200 vB` TRUC v3, spends `Stake_r` alone) burning **`100%` of `2.00 BTC` `Bond_BTC` to `OP_RETURN`**.
    - **`Out 1 = VaultConnector_r` (`546` sats):** `<1,152> OP_CSV` (`8.0d` > `max_dispute_end = 1,104` blks!) → **ONE single `TakeTx_{d,j,l,r}`** (OR spent immediately as `vin[1]` of `DisproveTx_{r,i}`/`TimeoutSlashTx_{r,i}`, guaranteeing **`0` satoshis stolen from `U_d`** on any bisection slash!).
    - **`Out 2..8 = VerifierSlot_1..7` (`546` sats each):** **Simultaneous non-staggered `[0, 144]` block challenge window** — ALL `N = 7` slots open at block `0` (`<P_{V_i}> OP_CHECKSIG`) and expire at `<144> OP_CSV` (`24h`). Colluding `V_1` can NEVER delay honest `V_2..V_7` past `T_take` or `T_cooldown`!
    - **`Out 9 = 0`-sat `P2A` Ephemeral Anchor** (`0x51024e73`).

### 3.2 `n = 8` `BitVMX-CPU` (`RV32IM`) Interactive Bisection & 100% BIP-431 TRUC v3 Compliance

The disputed computation is a compact Rollup proof verifier compiled from standard **Rust → `RV32IM`** (`≤ 2^27 = 134,217,728` RISC-V instructions) using open-source `BitVMX-CPU` / `BitVMX-protocol`:

- **`n = 8` Search Branching (`3` bits/round, `7 × 20 B` `OP_HASH160` Intermediate Trace Hashes):**
  - W-OTS cost per prover search tx: `7` hashes × `43` digits (`40` data nibbles + `3` checksum nibbles per 20-byte hash) = **`301` W-OTS digits** × `95.5 WU/digit` = **`28,746 WU`** (`7,186.5 vB`) + `~250 vB` tx overhead **`≈ 7,437 vB (7.44 kvB) ≤ 10,000 vB` (100% BIP-431 TRUC v3!)**.
  - Search depth: `ceil(27 / 3) = 9` search rounds (`9` prover txs + `9` verifier 3-bit interval choice txs) + `1` Start/Read (`~3.0 kvB` prover) + `1` Final Trace (`~5.0 kvB` prover) / Execute-1-RISC-V-Opcode (`~8.0 kvB` verifier) = **`20` sequential steps**.
  - **Total worst-case dispute weights:**
    - **Prover (`O_j`):** `9 × 7.44 + 3.0 + 5.0 = 74.96 ≈ 75 kvB`.
    - **Verifier (`V_i`):** `Challenge (0.35) + 9 × 0.35 (3.15) + Execute/Disprove (8.0) = 11.5 kvB` (conservatively budgeted at **`15 kvB`**).
- **Exact Timelock Ordering (`T_step = 48` blocks = `8h`/step):**
  ```text
  Challenge Window [0, 144] (24h)
    → Max Dispute End: 144 + (20 * 48) = 1,104 blocks (7.67 days)
    → VaultConnector_r (T_take):         1,152 blocks (8.00 days)  [+48 blk margin]
    → Stake_r -> RoundTx_{r+1} (T_cool): 1,296 blocks (9.00 days)  [+144 blk post-TakeTx equivocation margin]
    → RetireStakeTx_r:                   1,440 blocks (10.00 days) [+144 blk retirement margin]
  ```
- **BIP-431 TRUC v3 (`nVersion = 3`) & `P2A` Audit:**
  - Every pre-signed tx is `≤ 10,000 vB` (`RoundTx_r` ~`1.8 kvB`, `TakeTx` ~`3.1 kvB`, Prover search tx `7.44 kvB`, Execute-1-Opcode `≤ 8.0 kvB`, Verifier choice/Slash/Burn `~0.2–0.5 kvB`).
  - Every sequential step spends **confirmed** parent outputs (`ancestor_count = 1`); `ChallengeTx` is fee-funded directly via verifier's `vin[1]` (`descendant_count = 1`); all other pre-signed txs use ONE `~160 vB ≤ 1,000 vB` CPFP child via `0`-sat `P2A` (`descendant_count = 2`). **100% BIP-431 TRUC v3 compliant — zero pre-signed fee cliffs!**
- **Honest Fee-Rate Design Envelope (`500 sat/vB` Sustained Across ALL `20` Steps):**
  - Prover worst-case fee @ `500 sat/vB`: `75,000 × 500 = 37,500,000` sats (`0.375 BTC`) ≤ **`F_chal = 0.40 BTC`** (exact break-even **`533 sat/vB`** sustained across all `10` prover txs!).
  - Verifier worst-case fee @ `500 sat/vB`: `15,000 × 500 = 7,500,000` sats (`0.075 BTC`; `0.15 BTC` @ `1,000 sat/vB`).

### 3.3 256-Bit Lamport `TakeTx` Leaf (Zero `ReimburseEscrow`, Zero `RecoveryVault`)

At deposit `d`, `U_d`'s Tapscript leaf for `(j, l, r)` verifies `L_{j,l,r}(SHA256(outpoint_d))` directly inside `TakeTx_{d,j,l,r}` (`vin[0] = U_d`, `vin[1] = VaultConnector_r`, `vout[0] = D_d → P_{O_j}`, `vout[1] = 0`-sat `P2A`):
```text
# 256 iterations (k = 0..255, b_k = bit k of SHA256(outpoint_d)):
OP_HASH160 <H_{k, b_k}> OP_EQUALVERIFY
...
<Q_setup_d> OP_CHECKSIG
```
- **Exact BIP-342 & TRUC v3 Weights:**
  - Tapscript size: `256 × 23 + 34 = 5,922 B`.
  - Preimages in witness: `256 × 21 = 5,376 B`.
  - Control block: **`321 B`** (depth 9 for `320` leaves at Stage 1A `M = 5, R = 64`) or **`417 B`** (depth 12 for `2,560` leaves at Stage 2 `40` lanes × `64`).
  - Peak stack elements: **`258 << 1,000`** BIP-342 limit.
  - Total `TakeTx` weight: `~3,071–3,095 vB` (+ `VaultConnector_r` `~100 vB` ≈ **`~3,170–3,200 vB ≤ 10,000 vB` TRUC v3**).
- **Equivocation Solvency:** If `O_j` committed `U_1` in `RoundTx_r`, passed `T_take = 1,152`, and broadcast `TakeTx` on `U_2 ≠ U_1`, `O_j` MUST reveal both preimages for `~128` differing bits `k`, letting any `1-of-∞` challenger execute `BurnBondTx_{r,k}` on `Stake_r` Leaf 4 during `[1,152, 1,296]` (`144`-blk window). `100%` of `2.00 BTC` `Bond_BTC` burns to `OP_RETURN`, and the STARK burns `D_d` (`≤ 0.50 BTC`) from `O_j`'s `B_zbtc` (`0.60 BTC`) + pays `0.05 BTC` equivocation bounty — keeping remaining `zBTC` **100% 1:1 solvent (`0` user loss)**.

---

## 4. Front-Run-Proof, Collusion-Resistant Verifier Economics (`H-4` Closed)

Every `ChallengeTx_{r,i}` opened by Verifier `V_i` during `[0, 144]` locks **`F_chal = 0.40 BTC`** in **`ChalEscrow_{r,i}`** (NOT sent to `O_j` upfront!) and appends `41 B` `OP_RETURN "ZBTX" || 0x04 || kickoffTxid || verifierAcctId_i`:
- `ChalEscrow_{r,i}` pays `0.40 BTC` to `O_j` **ONLY IF** `O_j` wins `Dispute_i` (covering full `75 kvB` honest prover fees up to `533 sat/vB`); otherwise `V_i` reclaims `100%` of `0.40 BTC` cleanly.
- Each operator lane locks **`B_zbtc = 0.60 BTC`** inside canonical Rollup state (`0.50 BTC` vault restitution / challenger-split slice + `0.05 BTC` equivocation bounty = **`0.55 BTC` hard custody floor**, PLUS **`0.05 BTC` dedicated `ExitSlotUTXO` grief buffer**).

**Bisection Slash Matrix (`k_collude ∈ {0..6}` of `N = 7` Verifiers Colluding with Cheating `O_j` @ `500 sat/vB`):**
Because `DisproveTx_{r,*}` / `TimeoutSlashTx_{r,*}` spends **BOTH `Stake_r` AND `VaultConnector_r`**, **`0` BTC is stolen from `U_d`** — freeing `O_j`'s entire `0.55 BTC` custody slice of `B_zbtc` to split equally across all other `k ≤ 6` challengers (`0x04` opened in `[0, 144]`):

| Colluding Verifiers (`k_collude`) | Vault Stolen | Winning Verifier L1 Payout (`Stake_r`) | `Bond_BTC` Burned | Each Other Honest Challenger (`B_zbtc` Split) | Honest Verifier Net EV (@ `500 sat/vB`, `0.075` fee) | Combined `(O_j + k_collude)` Net P&L |
|---|---|---|---|---|---|---|
| `0` (all honest) | `0.00 BTC` | `0.15 BTC` (to honest winner) | `1.85 BTC` | `≥ 0.0917 BTC` (`0.55 / 6`) | **`+0.075 BTC`** (winner) / **`≥ +0.0167 BTC`** (others) | **`-2.55 BTC`** (`-2.00 - 0.55`) |
| `1` (`V_1` throws & steals L1 payout) | `0.00 BTC` | `0.15 BTC` (to `V_1`) | `1.85 BTC` | **`0.0917 BTC`** (`0.55 / 6` each to `V_2..V_7`) | **`+0.0167 BTC`** (EVERY honest `V_2..V_7`!) | **`-2.40 BTC`** |
| `6` (worst case: ONLY `V_7` honest; `V_1` wins L1, `V_2..V_6` also claim `0x04`) | `0.00 BTC` | `0.15 BTC` (to `V_1`) | `1.85 BTC` | **`0.0917 BTC`** (`0.55 / 6` to `V_7`) | **`+0.0167 BTC`** (`V_7` still strictly profitable!) | **`-1.9417 BTC`** (`-1.85 - 0.0917`) |

*Notice: Even if `6 of 7` verifiers collude with `O_j`, the lone honest verifier `V_7` recovers `100%` of `F_chal`, nets `≥ +0.0167 BTC` at `500 sat/vB`, and the attacker/colluding cartel suffers `-1.94` to `-2.55 BTC` net loss (`-2.55 BTC` solo; `-2.40` to `-1.9417 BTC` with `1..6` colluders) with `0` sats stolen from users!*

---

## 5. Atomic `(2M + 1)`-Leaf `ExitSlotUTXO` (Zero Double-Fronting, Zero Grief Freeze)

Every Stage 1A exit — both hostile L1 `0x01 FORCED_EXIT` (created by Mike/Bob) and cooperative `0x02 BATCH_DA` exits (created by batcher) — outputs a **`546`-sat `ExitSlotUTXO`** (P2TR, unspendable `H_NUMS` internal key) with **`2M + 1` Tapscript leaves** (zero anonymous `OP_TRUE` leaves!):
- **Leaves `0 .. M-1` (Deterministic Priority Windows):** `<6*r> OP_CSV OP_DROP <P_{O_{k_r}}> OP_CHECKSIG` where `k_r = H(exitId || r) mod M`.
- **Leaves `M .. 2M-1` (Registered Open Race After `6*M` Blocks):** `<6*M> OP_CSV OP_DROP <P_{O_j}> OP_CHECKSIG` for each registered operator `O_j` (depth 4 for `M = 5`, `11` leaves; depth 6 for `M = 20`, `41` leaves).
- **Leaf `2M` (`EXIT_CANCEL`):** `<288> OP_CSV OP_DROP <cancelPubKey> OP_CHECKSIG` (`288 > 6*M` blks).

**Universal STARK Spend-or-Refund Rule (`K`-deep spend of `ExitSlotUTXO`):**
1. **Valid Fronting (Leaf `0..2M-1` AND `vout[0] == (destScriptPubKey, ≥ grossSats - f_op)`):** Exit marked `COMPLETED`; `ReimbursementCredit[O_j] += grossSats`. Bitcoin L1 UTXO exclusion makes double-fronting and refund-vs-front races (`M-8`) cryptographically impossible.
2. **Non-Paying Operator Grief Spend (Leaf `0..2M-1` AND `vout[0]` fails payout check):** STARK **atomically cancels exit, refunds full `grossSats` `zBTC` to user, slashes `0.01 BTC` grief penalty from `O_j`'s `0.05 BTC` grief buffer to user, and auto-suspends `O_j`** until `B_zbtc` is topped back up to `≥ 0.60 BTC` (protecting the `0.55 BTC` custody floor).
3. **User Cancel (Leaf `2M`) or Fee Bump (`0x06 EXIT_FEE_BUMP`):** `0x06` raises `f_op` in-place during fee spikes; Leaf `2M` cleanly refunds `grossSats` `zBTC` after `288` blks unfronted.

---

## 6. Stage 1A Bootstrap Capital, Throughput, Finite-Round Cap & Bank-Run Bounds

Every parameter below is verified in [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py):

| Configuration (`L = 1`, `N = 7`, `R = 64`, `K = 14`, `T_cooldown = 9.0d`) | Per-Lane Bond (`Bond_BTC + B_zbtc`) | Total Op Bonds | Op Fronting Float | Verifier Standby (`7 × 0.40`) | **Total Hard BTC Capital** (`%` of `25–33 BTC` ZNN MCap) | Recycling Rate (`{0.50, 0.25, 0.25}` avg `0.333 BTC`) | **100% Bank-Run Exit Duration** (`{0.50, 0.25, 0.25}` / `{0.50, 0.50}`) |
|---|---|---|---|---|---|---|---|
| **Bare-Minimum Pilot (`M = 3`, `Cap_TVL ≤ 10 BTC`)** | `2.60 BTC` (`2.00 + 0.60`) | `7.80 BTC` | `2.20 BTC` | `2.80 BTC` | **`12.80 BTC`** (`~39–51%`) | `0.333` vaults/d (**`0.111 BTC/d`**) | `2.20 BTC` in ~10m + `7.80 BTC` in **`~72 days`** (`~47d` w/ `{0.50, 0.50}`) |
| **Recommended Stage 1A Pilot (`M = 5`, `Cap_TVL ≤ 15 BTC`)** | `2.60 BTC` (`2.00 + 0.60`) | `13.00 BTC` | `3.00 BTC` | `2.80 BTC` | **`18.80 BTC`** (`~57–75%`) | `0.556` vaults/d (**`0.185 BTC/d`**) | `3.00 BTC` in ~10m + `12.00 BTC` in **`~65 days`** (`~43d` w/ `{0.50, 0.50}`) |
| **Stage 2 Scaled (`M = 20, L = 2`, `Cap_TVL ≤ 50–200 BTC`, `K = 36–144`)** | `2.60 BTC` | `104.0 BTC` | `16.0 BTC` | `2.80 BTC` | `122.8 BTC` | `4.444` vaults/d (**`1.481 BTC/d`**) | `16 BTC` in ~10m + `34 BTC` in `~23d` (for `50 BTC` TVL) |

- **Finite-Round Admission Cap & FIFO Drainage:** New deposits are admitted only while `N_live_vaults ≤ 0.50 × RemainingTotalRounds` (`≤ 160` live vaults for `M = 5, R = 64` = `320` total slots; `160 × 0.333 = 53.3 BTC > 15 BTC` cap). Strict **FIFO oldest-vault-first** assignment (filtered by `opBitmask`) drains oldest vaults first and naturally prevents multi-year difficulty staleness.
- **Zero Passive-Timeout Slash:** Once `U_d` is assigned to `O_j` (after `O_j` ALREADY fronted BTC to Mike!), remaining unassigned vaults equal remaining `zBTC` 1:1 even if `O_j` vanishes forever. Assigned vaults NEVER passively expire into a slashable state (eliminating withholding-miner slash attacks); only explicit `O_j`-signed `0x07 RELEASE_ASSIGNMENT` releases an assignment.
- **Maturity & Engineering Reality:** `BitVMX-CPU` / `BitVMX-protocol` is **pre-mainnet** today. Production delivery (stripped-block STARK + `RV32IM` verifier + `StakeChain` ceremony + `ExitSlotUTXO` + third-party audit) is realistically **`12–18+ months`** for 4–6 strong engineers.

---

## 7. Stage 1B Explicit Alternative Gate: `clArk` (Covenant-Free Ark VTXOs)

If a young project **cannot commit `~12.8–18.8 BTC` of non-yielding hard BTC** (e.g. `< 5–10 BTC` budget) OR requires mainnet launch in **`3–6 months`** OR prioritizes `0-of-N` post-round unilateral exit over pooled fungibility, **do NOT under-bond `BitVMX`/`BitVM2`** — adopt Stage 1B **`clArk`** (`Second bark` / `Ark Labs arkd` + Zenon SPV/PTLC coordination):
- **Bootstrap Capital:** **`2–5 BTC`** active ASP liquidity (`0` slashing bonds; round turnover capped by ASP liquidity per 14–30 day VTXO expiry cycle).
- **Bob & Mike Security Model:**
  - **Post-L1-round (after `P_Bob`/`P_Mike` confirms in an Ark VTXO tree):** **Pure `0-of-N` unilateral exit** (zero ASP, zero Zenon signers!) by broadcasting `log2(N)` pre-signed tree-branch transactions (`N = 64 → 6` txs; `N = 1,024 → 10` txs) prior to VTXO expiry.
  - **Explicit Compromises Relinquished:** (1) **No pooled fungible `zBTC` token** (discrete VTXOs; exiting `0.25 BTC` unilaterally from a `2.0 BTC` VTXO requires exiting the entire `2.0 BTC` VTXO on-chain unless pre-split in-round); (2) **Pre-round `arkoor` transfers trust the ASP not to collude with sender `Alice`/`Bob`**; (3) **Hard VTXO expiry** forces Mike online to refresh or pay `log2(N)` L1 branch fees (small VTXOs become uneconomical during fee spikes).

---

## Appendix A: Non-Normative Future Tracks — Track B Pure Tier-0 Bitcoin Soft-Fork Covenant & Track A1/A2 Reference

> **Status: NON-NORMATIVE.** Nothing in `v1` depends on Bitcoin soft forks or BitVM2/BitVM3.

### A.1 Track B: Pure Tier-0 (`0-of-N` Safety AND `0-of-N` Liveness) With Minimal Bitcoin Soft Fork

If Bitcoin activates a stateful covenant soft fork, a **clean non-commingled `zBTC_v2`** eliminates ALL presigning committees, ALL operators, ALL verifiers, ALL bonds, and ALL bank-run delays:

- **Direct L1 Pooled Covenant Custody (`U_vault(R_t, V_t)` — Zero Header Scanning!):**
  - Internal key = provably unspendable `H_NUMS`. **Every custody transition spends `vin[0] = U_vault(R_t, V_t)` directly on Bitcoin L1**, so Bitcoin consensus natively enforces exact BTC inputs/outputs and canonical UTXO ordering (zero private-fork/orphaned-block drain; no `OP_BLOCKHASH` needed for custody!):
    1. **Deposits:** Depositor's `DepositInboxUTXO(acctHash, <144> OP_CSV refund)` is spent directly as `vin[1..d]` of `T`; covenant verifies `V_out0 = V_in0 + sum(V_in_dep) - sum(V_out_exit)` (miner fee paid strictly by external fee input!).
    2. **Feeless Zenon Batches:** Complete mutated-leaf state diffs + transparent STARK `π_STF` live directly in `T`'s witness (zero CRS).
    3. **Mike's Direct Unilateral `0.25 BTC` Exit (`0` Signers, `0` Operators, `0` LPs):** Mike spends `vin[0] = U_vault(R_t, 2.0 BTC)` + `vin[1] = Mike_fee_UTXO` → `vout[0] = U_vault(R_{t+1}, 1.75 BTC)` + `vout[1] = 0.25 BTC → P_Mike` + fee change in **1 Bitcoin block (~10m)**.
- **Two Concrete Minimal Soft-Fork Primitives:**
  - **Path B1 (`OP_CCV` BIP-443 + `OP_TXHASH` + `OP_VERIFY_STARK`):** Single `~1–3 kvB` L1 tx, instant 1-block finality, zero challengers.
  - **Path B2 (`OP_CAT` BIP-347 Alone):** Poelstra Schnorr-trick sighash introspection enforcing recursive state-carry + value conservation, paired with either chained in-Script Circle-STARK (`~40–100 kvB` witness, 0 challengers) OR `OP_CAT`-MATT optimistic bisection (`~500 vB` happy path, `~5–20 kvB` on dispute, `0` committees/operators, `1-of-∞` safety).
- **UTXO Contention Handling:** Track B-Base enforces `<1> OP_CSV` (`nSequence ≥ 1`, max 1 spend/block) + native Bitcoin RBF fee-market priority (zero `OP_BLOCKHASH`). Optional **Track B+** additionally adds `OP_BLOCKHASH` if an external `OP_RETURN` mandatory forced-exit queue (`D_force = 6` blks) without RBF bidding against batchers is desired.

### A.2 High-Capital / Research Reference (`BitVM2` & `BitVM3-GC`)

- **Scaled `BitVM2` (`1-of-∞` Permissionless Challenger, Zero Soft Fork):** Viable only once `≥ 50–100+ BTC` (minimal `M=3–5`) or `532–1,454 BTC` (`40–80` lanes) of operator capital is available (`13.30–18.175 BTC`/lane at `~1.0–1.3M vB` Groth16 asserts, `nVersion = 2` non-TRUC large txs, `≤ 500 sat/vB` fee ceiling).
- **Future `BitVM3-GC` (Garbled-Circuit SNARK, `1-of-N` Online Verifier):** Shrinks on-chain assert to `~2.4–10 kvB` and disprove to `~0.1–1.0 kvB` (`F_assert ≈ 0.20 BTC` even at `2,000 sat/vB`, `2.10 BTC`/lane), but one-time-use multi-GB (`1–5 GB`) garbled circuits currently require tens–hundreds of TB across `M × L × R × N` rounds until **reusable DV-SNARK garbled circuits** mature past early research.
