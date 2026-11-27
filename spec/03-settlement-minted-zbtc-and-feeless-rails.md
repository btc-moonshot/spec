# Part 3: Lightweight Settlement Contract, Tranche-Isolated `zBTC`, Dynamic Plasma & Peg-Free Rails

**Document Class:** Normative L1 Settlement, Tokenomics & Peg-Free Application Specification (`v1` / `v3.0.0-rfc`)  
**Target Baseline:** `go-zenon` first release tag containing `0aa299e` (`DynamicPlasmaSpork` enforced; `#239` closed)  
**Contracts:** `SettlementContract` & `TreasuryTrancheEscrow` ([`spec/05 §4`](./05-go-zenon-upgrade-plan.md))  
**Consistency Checker:** [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py)

---

## 1. Tranche-Isolated Treasury Pre-Mint Issuance (`H-8`, `B3c`, `A-MINT-1`)

In `go-zenon`, `TokenContract` does not intercept standard transfers and `MaxSupply` cannot be raised after issuance (`dev:vm/embedded/implementation/token.go:330`). Putting all `21,000,000 zBTC` inside `SettlementContract` (as `v0` did) meant a single `SettlementContract` dispatch bug could mint up to `21M` unbacked `zBTC` (**H-8**).

**`v1` isolates blast radius with a separate `TreasuryTrancheEscrow` embedded contract (`B3c`):**

1. **Step 1 — `TreasuryTrancheEscrow.InitiateMintedToken("ZenonBitcoin", "zBTC", domain, 8, 21_000_000*10^8)`** (Governance, attaches `1 ZNN`):
   - Emits descendant `ContractSend` calling `TokenContract.IssueMinted(...)` (`sendBlock.Address == types.TreasuryTrancheEscrow`, exempts `checkToken` regexes `dev:vm/embedded/implementation/token.go:40,43`, sets `TotalSupply = MaxSupply = 21M*10^8`, `IsMintable = false`, `IsBurnable = false`, `Owner = types.TreasuryTrancheEscrow`).
   - `TokenContract` sends all `21,000,000 * 10^8 zBTC` via `Data = ABITrancheEscrow.PackMethod("ReceiveInitialTreasury")` (`dev:vm/vm.go:204-226`). `ReceiveInitialTreasury()` is single-use (`TreasuryInitialized == 0`).
   - **Sealing `TokenContract`:** `TokenContract.UpdateToken` and `TokenContract.Burn` reject whenever `tokenInfo.Owner == types.TreasuryTrancheEscrow`.
2. **Step 2 — Timelocked Cap Tranche Release (`ReleaseCapTranche`):**
   - `TreasuryTrancheEscrow` releases ONLY `<= ActiveCap` (Stage 1B: **`5.0 BTC` = `500,000,000` base units**) to `SettlementContract.ReceiveTranche()`.
   - Any subsequent cap increase requires a **`GovernanceContract` vote + `>= k` federation co-signature + `>= 14-day` timelock** before releasing the incremental tranche delta.
   - `SettlementContract` can return excess treasury to `TreasuryTrancheEscrow` on cap reductions (`GuardianLowerSupplyCap`).
3. **Exact VM Conservation Invariant (`B3b`):**
   $$\text{Circ} = 21{,}000{,}000 \times 10^8 - \bigl(\text{Balance}(\text{SettlementContract}) + \text{Balance}(\text{TreasuryTrancheEscrow})\bigr)$$
   - `SettlementContract.Balance(zBTC)` NEVER exceeds `ActiveCap` (`5.0 BTC` at Stage 1B). Even a catastrophic bug inside `SettlementContract` is structurally bounded by its held tranche — never `21M BTC`!
   - Federation signers independently check `Circ == RepresentationOutstanding` from VM balances on every spend (`spec/01 §3.1`).

---

## 2. Minimal `SettlementContract` Storage & State Transitions

All `v0` BitVM2 / optimistic-rollup state (`BatchCommitmentV3`, `StepTraceLeaf`, `DomainInputBySeq`, `ChallengeSession`, `ExecutorRegistration`, `OperatorRegistry`, `OperatorLaneState`, `VaultUtxoSet` quarantine/`ORPHANED`, `DeferredLockQueue`, fronting slots, `SlotBondZnn`) is **removed**.

### 2.1 Storage Prefixes (`SettlementContract`)

| Prefix | Entity | Key | Contents |
|---|---|---|---|
| `0x01` | `BridgeConfig` | singleton | `activeCapSats(u64)`, `activeBindingHash(32B)`, `status(0=ACTIVE\|1=PAUSED)`, `minDepositSats(u64=100_000)`, `minPegInFeeSats(u64)`, `governanceContract`, `guardianMultisig` |
| `0x02` | `CustodyAccounting` | singleton | `representationOutstanding(u64)`, `pendingForeignRelease(u64)`, `activeReservedMint(u64)`, `cumulativeMinted(u64)`, `cumulativeBurned(u64)`, `cumulativeReleased(u64)`, `cumulativeRefunded(u64)` |
| `0x03` | `MintReservation` | `reservationId(32B)` | `zenonRecipient(20B)`, `expectedAmountSats(u64)`, `expiryBtcHeight(u64)` (`BestTip + 288`), `consumed(u8)` (`M-7`) |
| `0x04` | `PegOutNonce` | singleton | `u64` monotonic counter |
| `0x05` | `PegOutRecord` | `outboxId(32B)` | `outboxId = SHA3-256("ZNN_L1_PEGOUT_V2" \|\| chainBindingHash \|\| pegOutSeq \|\| sendBlockHash)`, `recipientScriptPubKey`, `refundRecipient(20B)`, `grossAmountSats(u64)`, `maxUserFeeSats(u64)`, `intentId(32B, 0 if unassigned)`, one-way `state(0=PENDING\|1=INTENT\|2=RELEASED\|3=REFUNDED)` |
| `0x06` | `BatchIntent` | `intentId(32B)` | `inputs[](36B each)`, `outputs[](outboxId, spk, netSats)`, `feeCapSats(u64)`, `postedHeight(u64)`, `status(0=OPEN\|1=CONFIRMED\|2=CONFLICTED)` (`B4`) |
| `0x20`–`0x26` | `btcspv` Sub-Store | *(see Part 2 §4)* | `ChainMeta`, `HeaderNode`, `ActiveChainByHeight`, `AdmittedEventBlocks`, `DepositOutpointUsed`, `SweepProcessed`, `RecognizedBindings` |

### 2.2 Core Settlement Methods (All Wrapped in `recover()` — `B1`)

- **`ReserveMintCapacity(reservationId, expectedAmountSats, zenonRecipient)` (`M-7`):** Requires `status == ACTIVE && ChainMeta.Halted == 0` and `representationOutstanding + pendingForeignRelease + activeReservedMint + expectedAmountSats <= activeCapSats`. Stores `MintReservation` expiring at `BestTipHeight + 288`. Expired reservations are permissionlessly pruned by `ExpireMintReservation`.
- **`SubmitSweepLockProof(...)`:** Verifies `K`-deep sweep SPV + `>= k` federation attestation (`spec/02 §3.3 #1`), consumes matching `MintReservation` (or checks cap directly), increments `representationOutstanding` and `cumulativeMinted`, and sends `netMintSats` `zBTC` from `SettlementContract`'s tranche to each `zenonRecipient`.
- **`RequestPegOut(recipientScriptPubKey, maxUserFeeSats)`** *(ALWAYS open, even when `PAUSED` or `Halted == 1`)*: User attaches `grossAmountSats >= 100,000` `zBTC` (returned to `SettlementContract`'s tranche). Decrements `representationOutstanding`, increments `pendingForeignRelease` and `cumulativeBurned`, writes `PegOutRecord{state = PENDING}`.
- **`PostBatchIntent(intentId, inputs[], outputs[], feeCapSats, fedSigs[>=k])` (`B4`):** Verifies `>= k` federation signatures, checks each `outboxId` is `PENDING` with `netSats >= grossAmountSats - maxUserFeeSats` and `sum(gross - net) >= feeCapSats` (or surplus-funded flag), checks `inputs[]` disjoint from other `OPEN` intents, transitions each `PegOutRecord` `PENDING -> INTENT`.
- **`SubmitReleaseProof(...)`:** Verifies `K`-deep payout tx matching `BatchIntent` (`spec/02 §3.3 #2`), transitions `BatchIntent -> CONFIRMED`, marks all `outputs[]` `PegOutRecord -> RELEASED`, decrements `pendingForeignRelease`, increments `cumulativeReleased`. *(No upper height deadline.)*
- **`SubmitConflictRefundProof(intentId, outboxId, ...)` (`B4`):** Verifies `K`-deep conflict tx spending any `BatchIntent.inputs[]` without paying `outboxId` (`spec/02 §3.3 #3`), transitions `PegOutRecord -> REFUNDED`, decrements `pendingForeignRelease`, increments `representationOutstanding` and `cumulativeRefunded`, and atomically sends `grossAmountSats` `zBTC` back to `refundRecipient`. *(Resolves `M-8` by construction; no refund escrow needed.)*

---

## 3. Dynamic Plasma Capacity Budget & Momentum Timing (`B2`, `M-9`, `M-10`)

- **Observed Momentum Interval (`M-10`):** Mainnet Momentums average **`~11.4s`** (`11.35–11.46s`, documented in `origin/dev:vm/embedded/definition/spork.go`), NOT `10s`. All deadlines in this spec are expressed in a single canonical unit (Bitcoin blocks for Bitcoin scripts, Zenon Momentums for signer depth `D_znn = 60`, or explicit seconds at `11.4s`/Momentum).
- **Dynamic Plasma Bounds (`B2`, `M-9`):**
  - `MaxAccountBlocksInMomentum = 100` is retired under `DynamicPlasmaSpork`. Capacity is governed by `MaxBasePlasmaInMomentum` (`dev:vm/embedded/definition/plasma.go:57-97`).
  - **Pinned Spork Floor (`B2`):** `MintedZbtcSpork` enforces **`MaxBasePlasmaInMomentum >= 2,100,000`** (`SetPlasmaVariables` MUST reject any lower value) and bounds `MaxPriceChangePercent <= 25%` per Momentum. This guarantees the largest `v1` SPV call (`SubmitSweepLockProof`, `8,644 B` ABI, `661,020` Plasma) ALWAYS fits (`>= 3` max-SPV calls/Momentum at floor, `6` at default `4,200,000`).
  - **Contract-Block Budget:** Embedded receives cost `0` Plasma (`dev:vm/plasma.go:147`) and share the per-Momentum contract-block cap `MaxBasePlasmaInMomentum / 52,500` (`40` at pinned floor, `80` at default `4.2M`, `dev:dp/dp.go:260`). Heavy SPV methods therefore pay `EMBEDDED_HEAVY_SPV_TIER = 73,500` + `68/byte` on send and enforce hard storage-op caps (`<= 24` ops, `spec/02 §2`).
  - **Honest User Transfer Throughput (`11.4s`/Momentum):** `~4.4` full send+receive `zBTC` transfers/s at the `2.1M` floor, `~8.8` transfers/s at the `4.2M` default, and `~4,386` transfers/s at the `2.1B` hard protocol ceiling.

---

## 4. Governance & Guardian Narrowing Controls (`H-3`)

- **`MultisigContract` (Guardian `5-of-9` Ed25519):** Narrowing actions ONLY — `GuardianPause` (sets `status = PAUSED`, halting mints/sweeps only; NEVER blocks `RequestPegOut` or payouts) and `GuardianLowerSupplyCap`.
- **`GovernanceContract` (`U5`, Stage 1B Hard Gate):** Controls `ReleaseCapTranche` (`>= 14d` timelock + `>= k` federation), `AddBinding` (`>= 14d` + `>= k` federation), `ResumeMinting` (`>= 48h` + `>= k` federation), and protocol sporks (`>= 30d` timelock for custody-relevant code).

---

## 5. Peg-Free Atomic Swaps & Lightning Submarine-Swap Gateway (`M-4` Hardened)

> **Scope Honesty:** Swaps execute atomically with zero intermediary custody risk during the swap, **but the `zBTC` asset received remains backed by the `Tier F` federation vaults.**

### 5.1 PTLC Taproot MuSig2 Adaptor Atomic Swap (BIP-327 Tweaked)

**Protocol (Alice sells BTC, Bob sells `zBTC`; Bob holds secret $t$):**
1. **Setup:** Bob samples $t \in \mathbb{Z}_n^*$, sends compressed 33-byte point $T = \text{compress}(t \cdot G)$ to Alice.
2. **Bitcoin Funding (BIP-327 Tweaked Taproot, `>= 72`-Block CSV):** Compute $P_{\text{swap}} = \text{MuSig2\_KeyAgg}(pk_A, pk_B)$, Tapscript refund leaf $L_{\text{ref}} = \text{<72> OP\_CSV OP\_DROP <pk\_A> OP\_CHECKSIG}$ (upgraded from `v0`'s unsafe `12` blocks!), tweak $t_{\text{tap}} = H_{\text{"TapTweak"}}(x(P_{\text{swap}}) \parallel \text{TapLeaf}(L_{\text{ref}}))$, and $Q_{\text{swap}} = P_{\text{swap}} + t_{\text{tap}} \cdot G$ with BIP-327 accumulated tweak `t_acc` and parity `g_key`. Alice funds `0x51 0x20 || x(Q_swap)`. Let $h_{\text{conf}}$ be confirmation height.
   - **Normative `T_btc_worst`:** Defined explicitly at the `2.0×` June-2021 slow-block multiple: `T_btc_worst = 72 * 600s * 2.0 = 86,400s` (24 hours).
3. **Bob Locks `zBTC` FIRST:** Before Alice releases any partial signature, Bob calls `PtlcContract.Create(expirationTime = T_znn, pointType = 2, pointLock = compress(T), destination = Alice_Addr)` (`dev:vm/embedded/definition/ptlc.go:114-120`) with **`T_znn >= T_btc_worst + 21,600s = 108,000s` (30 hours, `~9,474` Momentums at `11.4s`)**.
4. **Bounded Adaptor Exchange (Anti-Free-Option, `M-4`):** Alice MUST release her BIP-327 adaptor partial signature $\tilde{s}_A$ within **`<= 6` Bitcoin blocks** of Zenon PTLC confirmation (forming $R' = R_A + R_B + T$ with parity $g_R$, $\tilde{s} = \tilde{s}_A + \tilde{s}_B + e \cdot g_{\text{key}} \cdot t_{\text{acc}} \pmod n$); otherwise Bob aborts cleanly before revealing $t$.
5. **Confirmed-Before-Refund Atomic Claim (`M-4` Fixed):** Bob checks that remaining blocks before refund maturity are `>= 18` blocks, completes $s = \tilde{s} + g_R \cdot t \pmod n$, includes a `<pk_B>` CPFP anchor output, and **MUST have his claim tx CONFIRMED at or before `h_conf + 66`** (`6` blocks before Alice's `h_conf + 72` refund leaf matures — NEVER "broadcast before `h_conf + 72`", which enables RBF double-theft!). Alice extracts $t_{\text{ext}} = g_R \cdot (s - \tilde{s}) \bmod n$, verifies $\text{compress}(t_{\text{ext}} \cdot G) == \text{PointLock}$, and calls `PtlcContract.Unlock(ptlcId, t_ext)` (`dev:vm/embedded/implementation/ptlc.go:82-95`).

### 5.2 HTLC Atomic Swaps & Lightning Submarine-Swap Gateway

- **Hash Type:** ALL Bitcoin/Lightning HTLCs MUST pass **`hashType = 1` (`HashTypeSHA256`, `dev:vm/embedded/definition/htlc.go:92`)**.
- **Normative `Δ_safety`:** **`Δ_safety = 36` Bitcoin blocks** (~6h nominal, ~12h at `2.0×` slow blocks).
- **Inbound (`LN → zBTC`) & Channel-Jamming Defense (`M-4`):** User pays Gateway's LN Hold Invoice FIRST; ONLY AFTER Hold Invoice reaches `ACCEPTED` with `CLTV >= now + 2 * Δ_safety` (`72` blocks) does Gateway lock `zBTC` in `HtlcContract` (`T_znn <= T_ln - Δ_safety`). Gateways MUST enforce per-peer Hold Invoice rate limits (`<= 5` concurrent pending hold invoices and `<= 0.10 BTC` concurrent exposure per peer, with a **5-minute cancel TTL** if the user does not progress).
- **Outbound (`zBTC → LN`):** User locks `zBTC` (`hashType = 1`); Gateway pays BOLT-11 invoice (`T_ln <= T_znn - Δ_safety`), learns preimage $r$, unlocks `zBTC`.
- **Stage 0 Conformance Suite (`G-18`):** Signet↔Zenon tests for `>= 72`-block CSV, CPFP claim confirmation by `h_conf + 66`, Alice timeout abort at `+6` blocks, odd-$y(R')$ parity, BIP-327 `PartialSigAgg`, `hashType = 0` rejection, and LN Hold Invoice `ACCEPTED`-first + 5-min cancel TTL.
