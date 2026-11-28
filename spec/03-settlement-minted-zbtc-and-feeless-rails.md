# Part 3: Stage 0 Non-Custodial PTLC/HTLC Swaps, Stage 1A Sovereign Rollup STF & Feeless Zenon Rails, and Stage 1B `clArk` Coordination

**Document Class:** Normative Settlement, Rollup State Transition & Feeless Payment Specification (`v1` / `v3.0.0-rfc` — Zero-Federation Phased Architecture; supersedes archived `v0` `v2.5.0-rfc`)  
**Custody Posture:** **ZERO federated signers, ZERO ZNN governance/slashing custody coupling, ZERO federated multisig or embedded-contract pre-minting.**  
**Consistency Checker:** [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py)

---

## 1. Stage 0: Non-Custodial PTLC & HTLC Atomic Swaps (`PtlcSpork`, `M-4` Hardened)

Stage 0 launches with **`0 BTC` protocol custody** (`0–5 BTC` voluntary LP capital), strictly honoring `zenon-developer-commons` (`essays/Verify Bitcoin, Don't Bridge It.md`). Native BTC stays in user self-custody on Bitcoin L1 or Lightning; Zenon swaps native ZNN/QSR/ZTS assets atomically via `PtlcContract` and `HtlcContract`.

> **Stage 0 Scope Honesty:** Stage 0 atomic swaps do **not** create pooled, fungible `zBTC` on Zenon. A counterparty LP is required for every swap, and under a severe Zenon attack rational LPs pull liquidity. Stage 0 delivers immediate zero-custody Bitcoin interoperability while Stage 1A (`BitVMX` Sovereign Rollup) or Stage 1B (`clArk`) is built and audited.

### 1.1 Hardened BIP-327 Tweaked Taproot PTLC Swap (`M-4`)

**Protocol (Alice sells BTC on Bitcoin L1; Bob sells Zenon asset on Zenon; Bob holds secret scalar $t \in \mathbb{Z}_n^*$):**
1. **Setup:** Bob sends compressed 33-byte point $T = \text{compress}(t \cdot G)$ to Alice.
2. **Bitcoin Taproot Funding (`>= 72`-Block CSV):** Compute $P_{\text{swap}} = \text{MuSig2\_KeyAgg}(pk_A, pk_B)$, Tapscript refund leaf $L_{\text{ref}} = \text{<72> OP\_CSV OP\_DROP <pk\_A> OP\_CHECKSIG}$, tweak $t_{\text{tap}} = H_{\text{"TapTweak"}}(x(P_{\text{swap}}) \parallel \text{TapLeaf}(L_{\text{ref}}))$, and $Q_{\text{swap}} = P_{\text{swap}} + t_{\text{tap}} \cdot G$ with BIP-327 accumulated tweak `t_acc` and parity `g_key`. Alice funds `0x51 0x20 || x(Q_swap)`. Let $h_{\text{conf}}$ be Bitcoin confirmation height and `now_unix` be current UTC Unix seconds.
3. **Absolute Unix Timestamp Lock & `2.3×` Slow-Block Margin:**
   - `go-zenon`'s `PtlcContract.Create` compares `momentum.Timestamp.Unix() >= param.ExpirationTime` (`origin/dev:vm/embedded/implementation/ptlc.go:326`), requiring an **absolute Unix timestamp** (NEVER a relative duration!).
   - Define `T_znn_sec = 108,000` seconds (`30.0h`, `~9,474` Momentums at observed `11.4s`/Momentum) and **`expirationTime = now_unix + T_znn_sec`**.
   - **Verified `2.3×` June-2021 Slow-Block Margin:** Bob MUST confirm his Bitcoin claim by `h_conf + 66` (`6` blocks before Alice's `h_conf + 72` refund). Even under June 2021's worst daily average block slowdown (`2.3×` nominal = `1,380s`/block), `66 × 600s × 2.3 = 91,080s = 25.3h < 30.0h`, leaving Alice **`>= 4.7h`** of honest wall-clock safety margin to extract $t$ and call `PtlcContract.Unlock`.
   - Bob calls `PtlcContract.Create(expirationTime = now_unix + 108000, pointType = 2, pointLock = compress(T), destination = Alice_Addr)` (`origin/dev:vm/embedded/definition/ptlc.go:118-129`).
4. **Adaptor Exchange & Explicit Grief/Free-Option Disclosure:**
   - Alice sends BIP-327 adaptor partial signature $\tilde{s}_A$ within `<= 6` Bitcoin blocks of Zenon PTLC confirmation ($R' = R_A + R_B + T$ with parity $g_R$, $\tilde{s} = \tilde{s}_A + \tilde{s}_B + e \cdot g_{\text{key}} \cdot t_{\text{acc}} \pmod n$).
   - **Explicit Disclosure:** Because `PtlcContract` has **no early reclaim** prior to `ExpirationTime`, if Alice withholds $\tilde{s}_A$, Bob's Zenon funds remain grief-locked for the full `30h` duration (zero theft, pure time-lock grief). Once Alice releases $\tilde{s}_A$, Bob holds an `~8h` (`~48`-block) free option until his `h_conf + 54` (`18`-block remaining) broadcast cutoff. Production LPs bound this via small per-peer swap limits or reputation/Lightning Hold Invoices.
5. **Confirmed-Before-Refund Atomic Claim:** Bob completes $s = \tilde{s} + g_R \cdot t \pmod n$ with a `<pk_B>` CPFP anchor and **MUST confirm by `h_conf + 66`**. Alice extracts $t_{\text{ext}} = g_R \cdot (s - \tilde{s}) \bmod n$, checks `compress(t_ext * G) == PointLock`, and calls `PtlcContract.Unlock(ptlcId, t_ext)` (`origin/dev:vm/embedded/implementation/ptlc.go:82-97`).

### 1.2 HTLC & Lightning Submarine-Swap Gateway

- **Hash Type:** ALL Bitcoin/Lightning HTLCs MUST use **`hashType = 1` (`HashTypeSHA256`, `origin/dev:vm/embedded/definition/htlc.go:92`)**.
- **Consistent Unix-Second Arithmetic:** Let `Δ_safety_blocks = 36` (`6h` nominal, `13.8h` at `2.3×` slow blocks) and `Δ_safety_sec = 36 × 600 = 21,600s` (or `49,680s` at `2.3×`).
  - **Inbound (`LN → Zenon`):** User pays Gateway's LN Hold Invoice FIRST; ONLY AFTER Hold Invoice reaches `ACCEPTED` with `remaining_cltv_blocks >= 72` (`2 × Δ_safety_blocks`) does Gateway lock Zenon funds in `HtlcContract` with **`expirationTime_unix <= now_unix + (remaining_cltv_blocks - 36) * 600`**. Gateways MUST enforce `<= 5` concurrent pending hold invoices, `<= 0.10 BTC` exposure per peer, and a **5-minute cancel TTL**.
  - **Outbound (`Zenon → LN`):** User locks Zenon funds (`hashType = 1`, `expirationTime_unix >= now_unix + 2 * 21,600`); Gateway pays BOLT-11 invoice whose CLTV expiry satisfies `now_unix + cltv_blocks * 600 <= expirationTime_unix - 21,600`, learns preimage $r$, and unlocks Zenon `HtlcContract`.

---

## 2. Stage 1A: Sovereign Rollup STF $\mathcal{F}$ & Feeless Zenon Sequencer Rails

In Stage 1A, `zBTC` is a **Bitcoin-Anchored Sovereign ZK Validity Rollup** backed by **right-sized `BitVMX` (`n = 8`, `M = 3–5`, `N = 7`) deleted-key vaults** (`spec/01`). **Zero federated signers and zero ZNN governance keys touch BTC custody or `zBTC` supply.**

### 2.1 Immutable Rollup SMT State Schema

The canonical `zBTC` ledger state $R_h$ is a 256-bit Sparse Merkle Tree (`SHA-256` / Poseidon2) maintained deterministically by $\mathcal{F}$ over Bitcoin L1 blocks (`spec/02 §3`):

| SMT Namespace | Key | Value Fields | Invariants |
|---|---|---|---|
| `Accounts` | `acctId (u32)` | `{ pubkey: bytes32 (BIP-340), balanceSats: u64, nonce: u32 }` | `balanceSats >= 0`; `nonce` strictly monotonic (`+1`/tx). |
| `Vaults` | `vaultId (bytes32)` | `{ denomSats: u64 ∈ {50_000_000, 25_000_000}, status: UNASSIGNED \| ASSIGNED(opId, lane, round) \| REIMBURSED \| SLASHED_EQUIV }` | Total active vaults always back `Circ + PendingExits + ReimbursementCredit` 1:1. |
| `PendingExits` | `exitId (bytes32)` | `{ acctId, grossSats, maxOpFeeSats, destScriptPubKey, cancelPubKey, exitSlotOutpoint(36B), status: OPEN \| COMPLETED \| CANCELLED }` | Created ONLY by burning `grossSats` from `Accounts[acctId]` via `0x02` or L1 `0x01`. |
| `RollupLocks` | `lockId (bytes32)` | `{ senderAcctId, destAcctId, amountSats, expiryBtcHeight, lockType: HTLC \| PTLC, lockDigest(33B) }` | First-class rollup opcodes (`RollupHTLC`, `RollupPTLC`) for atomic swaps inside the SMT. |
| `OperatorState` | `opId (u32)` | `{ active: bool, lanes: [L], suspended: bool }` | Auto-suspended if `B_zbtc < 0.60 BTC`/lane. |
| `ReimbursementCredit` | `opId (u32)` | `creditSats: u64` | Incremented ONLY on `K`-deep verified `ExitSlotUTXO` payout (`vout[0]`); deterministically consumed FIFO inside $\mathcal{F}$ to assign the oldest eligible `UNASSIGNED` vault (re-credited only on explicit `O_j`-signed `0x07 RELEASE_ASSIGNMENT`). |
| `LockedOperatorCollateral` (`B_zbtc`) | `(opId, lane)` | `collateralSats: u64` (**`60,000,000` sats = `0.60 BTC`/lane floor**) | Partitioned: `0.50 BTC` max-vault restitution + `0.05 BTC` equivocation bounty + `0.05 BTC` `ExitSlotUTXO` grief buffer. |

**Global Solvency Conservation Invariant (Checked on Every State Transition $R_{h-1} \to R_h$):**
$$\sum_{v \in \text{Unassigned} \cup \text{Assigned}} D_v \;=\; \sum_{a \in \text{Accounts}} \text{balance}_a \;+\; \sum_{\ell \in \text{RollupLocks}} \text{amt}_\ell \;+\; \sum_{e \in \text{PendingExits}_{\text{OPEN}}} \text{gross}_e \;+\; \sum_{o} \text{ReimbursementCredit}_o \;+\; \sum_{o,l} B_{\text{zbtc}}(o,l)$$

### 2.2 Honest Feeless Zenon Sequencer Rails (`M-9`, `M-10`)

- **Exact Zenon Transport Format (NOT Native `TokenContract` ZTS):**
  - Because `TokenContract` ZTS transfers depend on Zenon L1 consensus (which fails at 49% — `spec/04 §1`), Stage 1A `zBTC` balances live strictly in the Rollup SMT above, **NOT** in `go-zenon`'s `TokenContract`.
  - Users transmit signed `110 B` rollup transactions (`op(1) || domain(1) || fromAcctId(4) || toAcctId(4) || amountSats(8) || nonce(4) || batchTipSats(4) || expiryBtcHeight(4) || memoTag(16) || bip340Sig(64)` = **`110 B`**; `+32 B = 142 B` when creating a new recipient pubkey) inside standard Zenon `AccountBlock.Data` (`UserSend` to a canonical burn/sequencer sink address with `Amount = 0`).
  - **Exact Zenon Plasma Cost (At Floor Price `1,000`):**
    $$\text{BasePlasma}(\text{110 B rollup tx}) = 21{,}000 + 68 \times 110 = \mathbf{28{,}480\text{ Plasma}}$$
    - Funded by **`14 QSR` refundable fused Plasma** (`ceil(28,480 / 2,100) = 14 QSR`, zero burn, replenished immediately upon confirmation) OR **`42.72M` SHA3-256 PoW hashes** (`28,480 × 1,500`, `~0.15–0.4s` desktop / `~3–12s` mobile WASM).
    - **Bitcoin L1 Fee Paid by User on Zenon Transfer:** **`0` satoshis** (`0` burned ZNN/QSR; optional `batchTipSats` for fast L1 `0x02` batch inclusion).
- **Honest `go-zenon` Throughput Ceilings (Bounded by `8 MiB` Wire Cap):**
  - Observed mainnet Momentum time is **`~11.4s`** (`origin/dev:vm/embedded/definition/spork.go:43-46`).
  - Standard 2-block Zenon transfers (`21,000` send + `21,000` receive = `42,000` Plasma): **`~4.4` tx/s** at the pinned `2,100,000` floor, **`~8.8` tx/s** at the `4,200,000` default.
  - 1-block `110 B` `AccountBlock.Data` rollup sends (`28,480` Plasma, zero receive block needed): **`~6.5` tx/s** at `2.1M` floor, **`~12.9` tx/s** at `4.2M` default.
  - **Real Hard Protocol Ceiling (`MaxMomentumContentBytes = 8 MiB`):** `origin/dev:verifier/momentum.go:93` hard-caps cumulative protobuf-serialized Momentum content at **`8,388,608 B` (`8 MiB`)** and `origin/dev:protocol/protocol.go:70` caps `MaxDetailedMomentumWireSize = 10 MiB - 2 MiB - 4 KiB` (`~8.38 MB`). At `~300–350 B` serialized per account block, a Momentum holds `~24,000–27,000` blocks **maximum** — yielding **`~1,050–1,200` full 2-block transfers/s** (or `~2,100–2,400` 1-block rollup sends/s), **NOT** the naive `4,386` tx/s implied by `2.1B / 42,000 / 11.4`!
- **Graceful Degradation Under Dynamic Plasma DoS:** Because `origin/dev:dp/dp.go:102-151` has no absolute upper price clamp, a whale QSR attack can temporarily spike Zenon Plasma prices (`spec/05 §2.2`). Under such an attack, feeless Zenon soft preconfirmations degrade cleanly to **Bitcoin L1 `0x03 FORCED_TRANSFER` and `0x01 FORCED_EXIT`** (paying standard Bitcoin L1 miner fees, completely bypassing Zenon!).

### 2.3 Permissionless DA Batcher Economics

- **Zero Trusted Sequencer or Protocol Treasury:** Anyone (an operator, a wallet provider, or a user) can read `AccountBlock.Data` rollup txs from Zenon, generate `π_batch`, and post `0x02 BATCH_DA` onto Bitcoin L1 with complete mutated SMT leaves (`16 B` existing / `48 B` new).
- **Sustainable Incentives:** Batchers earn optional `batchTipSats` from rollup transfers, operator fronting fee spreads (since fronting operators need timely `0x02` batching to settle `PendingExits`), or self-sponsored batching by users/merchants. A batch of `500` transfers updating `~600` existing accounts requires `~9.6 KB` witness (`~2.4 kvB` vbytes) + `~0.1–10 kvB` proof = `~2.5–12.4 kvB` (`~0.0005–0.0025 BTC` at `20 sat/vB`, or `~100–500` sats amortized per transfer!).

### 2.4 `B_zbtc` Accounting, `ExitSlotUTXO` Spend-or-Refund & Dual-Input Slash Split

1. **Per-Lane `B_zbtc` Collateral (`0.60 BTC` = `60,000,000` sats):**
   - `0.50 BTC` (`maxVaultDenom`) reserved for 1:1 vault restitution if $O_j$ executes a Lamport equivocation on `TakeTx` after `T_take = 1,152`.
   - `0.05 BTC` equivocation bounty paid to the challenger who broadcasts `BurnBondTx_{r,k}` before `T_cooldown = 1,296` (on top of burning `100%` of $O_j$'s `2.00 BTC` L1 `Bond_BTC` to `OP_RETURN`).
   - `0.05 BTC` `ExitSlotUTXO` grief buffer (handles up to `5` consecutive non-paying grief attempts before hitting the `0.55 BTC` custody floor, with immediate auto-suspension on the first grief!).
2. **`ExitSlotUTXO` Universal Spend-or-Refund Rule (Zero Frozen Exits):**
   - Created by `0x01 FORCED_EXIT` with **`2M + 1` Tapscript leaves** (zero anonymous `OP_TRUE` leaves!):
     - Leaves `0..M-1`: Priority slot per registered operator $O_j$ (staggered `<6*j> OP_CSV OP_DROP <P_{O_j}> OP_CHECKSIG`).
     - Leaves `M..2M-1`: Open-race leaves for all registered operators (`<6*M> OP_CSV OP_DROP <P_{O_j}> OP_CHECKSIG`).
     - Leaf `2M` (`EXIT_CANCEL`): `<288> OP_CSV OP_DROP <cancelPubKey_user> OP_CHECKSIG`.
   - On **ANY `K`-deep spend** of `ExitSlotUTXO`:
     - **Valid Fronting (Leaf `0..2M-1` AND `vout[0]` pays `destScriptPubKey` `>= grossSats - maxOpFeeSats`):** Transition `PendingExits[exitId] -> COMPLETED`, credit `ReimbursementCredit[O_j] += grossSats`.
     - **Non-Paying Grief Spend (Leaf `0..2M-1` AND `vout[0]` FAILS payment check):** Atomically transition `PendingExits[exitId] -> CANCELLED`, refund full `grossSats` `zBTC` to `Accounts[acctId]`, **slash `0.01 BTC` (`1,000,000` sats) from $O_j$'s `B_zbtc` grief buffer (credited to the victim's `zBTC` balance to cover L1 retry fees)**, and **auto-suspend $O_j$** from fronting until $O_j$ tops `B_zbtc` back up to `>= 0.60 BTC`/lane!
     - **User Cancel (Leaf `2M` after `288` blocks):** Atomically transition `PendingExits[exitId] -> CANCELLED` and refund full `grossSats` `zBTC` to `Accounts[acctId]`.
3. **Dual-Input `Stake_r` Slash (Positive EV Even Against `6-of-7` Verifier Collusion):**
   - When `DisproveTx_{r,i}` or `TimeoutSlashTx_{r,i}` spends **BOTH `Stake_r` (`vin[0]`) AND `VaultConnector_r` (`vin[1]`)** before `T_take = 1,152`:
     - **`0` sats** are stolen from `U_d`; `Vaults[vaultId]` immediately returns to `UNASSIGNED`.
     - L1 `Stake_r` (`2.00 BTC`) splits **`0.15 BTC` → winning verifier $V_i$** and **`1.85 BTC` → `OP_RETURN` burn**.
     - Inside $\mathcal{F}$, $O_j$'s entire **`0.55 BTC` custody slice of `B_zbtc`** (`0.50 + 0.05`, untouched because `0` sats were stolen!) is **atomically split equally across all remaining `k <= 6` verifiers** who posted `0x04 CHALLENGE_CLAIM` in `[0, 144]`: each receives **`>= 0.55 / 6 = 0.09166666 BTC > 0.075 BTC`** (`15 kvB` verifier fee @ `500 sat/vB`) + `100%` of their `F_chal = 0.40 BTC` returned from `ChalEscrow_{r,j}`, guaranteeing **`>= +0.0167 BTC` positive EV** for every honest verifier even if `6 of 7` verifiers collude with $O_j$ (while attacker P&L is **`-2.55 BTC`** solo and **`-2.40` to `-1.9417 BTC`** with `1..6` colluding verifiers — strictly `-1.94` to `-2.55 BTC`!).

### 2.5 End-to-End State Traces: Bob (`0.50 BTC`) & Mike (`0.25 BTC`)

- **Bob's Partial Recovery (`1 BTC → spend 0.50 zBTC → recover 0.50 BTC` under `49%–100%` Zenon Compromise):**
  1. Bob deposits `1.00 BTC` via `0x00 DEPOSIT` → creates deleted-key vaults `{0.50, 0.25, 0.25}` BTC; after `K = 14` blocks, `Accounts[Bob] = 1.00 zBTC`.
  2. Bob sends `0.50 zBTC` to Carol via `110 B` `AccountBlock.Data` on Zenon (`28,480` Plasma, `0` sat BTC fee) → batcher anchors `0x02 BATCH_DA` → `Accounts[Bob] = 0.50 zBTC`, `Accounts[Carol] = 0.50 zBTC`.
  3. **Attack:** `49%` (or `100%`) of Zenon Pillars turn hostile, split Zenon across its 30-Momentum cliff, censor Bob on Zenon, and spike Dynamic Plasma.
  4. **Bob Exits Directly on Bitcoin L1:** Bob broadcasts `0x01 FORCED_EXIT(0.50 BTC, P_Bob, maxOpFee)` + `ExitSlotUTXO` on Bitcoin L1 (completely bypassing Zenon!). After `K = 14` blocks, $\mathcal{F}$ burns Bob's `0.50 zBTC` and opens `PendingExits[exit_Bob]`.
  5. Any `1-of-M` honest operator $O_j$ (`M = 3–5`) spends `ExitSlotUTXO` paying `0.50 BTC - fee` directly to `P_Bob` in `vout[0]` (~10 min on L1!), earns `ReimbursementCredit[O_j] += 0.50 BTC`, and later reclaims one `0.50 BTC` vault via `BitVMX` `RoundTx_r` → `TakeTx` (monitored by `N = 7` verifiers). **Zero Zenon signers, zero federated signers, zero ZNN trust.**
- **Mike's Cross-Depositor Exit (`Alice 1 + Bob 1 → Mike 2 → Mike recovers 0.25 BTC` with `0` Zenon Signer Cooperation):**
  1. Alice deposits `1.00 BTC` (`{0.50, 0.25, 0.25}`) and Bob deposits `1.00 BTC` (`{0.50, 0.25, 0.25}`); both send `1.00 zBTC` feelessly to Mike on Zenon → `0x02 BATCH_DA` sets `Accounts[Mike] = 2.00 zBTC`.
  2. **Attack:** Zero Zenon signers cooperate; Alice and Bob are offline or hostile.
  3. **Mike Exits `0.25 BTC` Directly on Bitcoin L1:** Mike posts `0x01 FORCED_EXIT(0.25 BTC, P_Mike, maxOpFee)` + `ExitSlotUTXO`. Any `1-of-M` honest operator $O_j$ fronts `0.25 BTC - fee` directly to `P_Mike` in `vout[0]` (leaving Mike `1.75 zBTC` intact in `Accounts[Mike]`), earns `ReimbursementCredit[O_j] += 0.25 BTC`, and reclaims one `0.25 BTC` vault from the unassigned pool (`0.50 + 0.25 + 0.25` maps `0.25 BTC` 1:1 with zero change bottleneck!).
  4. *Irreducible Residual Boundary ([`spec/01 §1.2`](./01-bitcoin-taproot-vault-enforcement.md) Corollary 1B):* If **100% of all `M = 3–5` pre-registered operators** vanish simultaneously, Mike's exit stalls until an operator returns (zero theft; Mike can reclaim his `0.25 zBTC` via Leaf `2M` `EXIT_CANCEL` after `288` blocks). Under a `100%` bank run of `15 BTC` (`3.0` float + `12.0` vaults), full queue drain takes **`~65 days`** (`M = 5`, `0.556` vaults/d ≈ `0.185 BTC/d`) or **`~72 days`** (`M = 3` on `10 BTC`, `~43–47d` with `{0.50, 0.50}` vaults).

---

## 3. Stage 1B (Alternative Gate): `clArk` VTXO Coordination Rails

If the project cannot commit `~12.8–18.8 BTC` of hard operator/verifier capital or requires a `3–6` month mainnet ship window using existing audited open-source stacks (`Second bark/barkd` or `Ark Labs arkd`), Stage 1B offers an explicit **non-federated, zero-soft-fork alternative** with **`2–5 BTC` active ASP liquidity** (`0` dead slashing bonds):

- **Zenon's Role:** Feeless off-chain coordination, round scheduling, VTXO intent indexing, and Stage 0 SPV verification — **0% Zenon consensus custody dependency**.
- **Exact Trade-Offs (Mandatory Disclosure):**
  1. **Post-Round `0-of-N` Unilateral Exit (Until Expiry):** Once Mike's `0.25 BTC` VTXO is confirmed in an L1 `clArk` round tree, Mike exits unilaterally on Bitcoin L1 with **zero ASP/signer cooperation** by broadcasting his pre-signed `log2(N)` branch (`6..10` txs for `N = 64..1,024` VTXOs, using TRUC v3 + ephemeral anchors).
  2. **Pre-Round (`arkoor`) Sender+ASP Collusion Risk:** Instant feeless out-of-round transfers (`Alice -> Mike`) are vulnerable to `Alice + ASP` double-spend collusion until the next L1 round refreshes Mike into a new VTXO tree.
  3. **Hard VTXO Expiry & Liquidity Lockup:** VTXOs expire (e.g., `14–30` days) back to the ASP sweep key, forcing Mike online to refresh or pay `log2(N)` L1 exit fees; ASP liquidity (`2–5 BTC`) is locked `100%` for each full expiry cycle, capping round turnover to `2–5 BTC`/cycle.
  4. **No Global Pooled `zBTC` Token:** `clArk` VTXOs are discrete UTXO trees, not a single global fungible `zBTC` balance sheet composable with Zenon DeFi — and `clArk` VTXOs do **not** migrate automatically into Stage 1A Rollup `zBTC` without on-chain L1 settlement.
