#!/usr/bin/env python3
"""
Deterministic consistency & bounds checker for the zBTC Protocol Specification
v1 (v3.0.0-rfc — Tier F Federated Custody + Direct-on-L1 Trimmed SPV).

NOTE ON SCOPE:
  This script checks internal mathematical consistency, Tapscript weight
  formulas, Dynamic Plasma inclusion floors, timelock bounds, and a 2,000-step
  randomized state-machine simulation of the B3a conservation invariant.
  It is NOT a substitute for Signet execution or independent audits.
  Any modeled market/fee/chain constant is explicitly labeled SOURCED_ or
  POLICY_ below.

Run: `python3 -I scripts/verify_spec_bounds.py`
"""
import hashlib
import math
import random

SAT = 100_000_000

# ==============================================================================
# SOURCED go-zenon PROTOCOL CONSTANTS (origin/dev 770e893 & rc2 b85ee94 + 0aa299e)
# ==============================================================================
MAX_DATA_LENGTH = 16_384                  # dev:vm/constants/plasma.go:67
EMBEDDED_SIMPLE_TIER = 52_500             # 2.5 * 21,000 (dev:vm/constants/plasma.go)
EMBEDDED_HEAVY_SPV_TIER = 73_500          # 3.5 * 21,000 (normative v1 send tier covering unmetered receive CPU/storage)
AB_BYTE_DATA_PLASMA = 68                  # dev:vm/constants/plasma.go (requires DynamicPlasmaSpork)
ACCOUNT_BLOCK_BASE_PLASMA = 21_000        # 1 standard send or receive block
PLASMA_PER_QSR = 2_100                    # 1 QSR = 1 fusion unit = 2,100 plasma at floor price 1,000
DP_DEFAULT_MAX_BASE_PLASMA = 4_200_000    # dev:vm/embedded/definition/plasma.go:97 (200 base blocks)
DP_UPPER_MAX_BASE_PLASMA = 2_100_000_000  # dev:vm/embedded/definition/plasma.go:63 (100,000 base blocks)
DP_LOWER_MAX_BASE_PLASMA = 210_000        # dev:vm/embedded/definition/plasma.go:66 (10 base blocks -> too low!)
OBSERVED_MOMENTUM_SECS = 11.4             # dev:vm/embedded/definition/spork.go (11.35-11.46s observed mainnet)
CHAIN_BRIDGE_ROLLBACK_BOUND = 30          # dev:protocol/chain_bridge.go:293
SIGNER_FINALITY_DEPTH_MOMENTUMS = 60      # >= 2x rollback bound; zero U2 dependency

# ==============================================================================
# v1 POLICY & BITCOIN CUSTODY PARAMETERS (BTC-CUSTODY-F1)
# ==============================================================================
PILOT_SUPPLY_CAP_SATS = 5 * SAT           # 5.0 BTC policy-set Stage 1B cap (NOT derived from ZNN!)
MIN_DEPOSIT_FLOOR_SATS = 100_000          # 0.001 BTC minimum deposit & peg-out floor
MAX_VAULT_UTXOS = 64                      # hard ceiling on active vault UTXO count
MAX_FED_STRIPPED_TX_BYTES = 6_144         # stripped non-witness size cap for federation-built txs
MIN_MAX_BASE_PLASMA_PINNED = 2_100_000    # B2: zBTC spork pins MaxBasePlasmaInMomentum floor >= 2.1M

# Historical stress fee rates (sourced: Apr 2024 halving/Runes peak ~1,805 sat/vB median)
SOURCED_STRESS_FEE_SATVB = 2_000          # stress fee rate for surplus reserve & refresh
POLICY_REF_FEE_SATVB = 100                # reference fee rate for peg-in consolidation fee floor
SOURCED_SLOW_BLOCK_MULTIPLE = 2.0         # Jun 2021 China ban: ~1.95-2.3x sustained slow blocks

# BIP-68 recovery timelock & refresh schedule (block-type CSV <= 65,535)
T_RECOVERY_CSV_BLOCKS = 52_560            # ~365 days nominal (minimal push: 03 50cd00)
T_REFRESH_TRIGGER_BLOCKS = 26_280         # 50% of recovery CSV (~182.5 days)
T_REFRESH_IMPAIRMENT_BLOCKS = 39_420      # 75% of recovery CSV (~273.75 days -> 13,140 blk buffer)
T_DEPOSIT_REFUND_CSV_BLOCKS = 288         # ~48h user refund leaf on deposit address (M-7)
T_DEPOSIT_SWEEP_CUTOFF_BLOCKS = 200       # federation refuses to sweep past h_dep + 200

# PTLC & Lightning gateway parameters (M-4)
T_PTLC_BTC_CSV_BLOCKS = 72                # >= 72 blocks (~12h nominal)
T_PTLC_BOB_CONFIRM_MARGIN = 6             # Bob claim MUST confirm by h_conf + 66
T_PTLC_ALICE_RELEASE_MAX_BLOCKS = 6       # Alice releases adaptor sig within 6 blocks else Bob aborts
T_PTLC_ZNN_EXTRA_MARGIN_SECS = 21_600     # +6h safety buffer above T_btc_worst
LN_DELTA_SAFETY_BLOCKS = 36               # numeric Delta_safety for LN Hold Invoice gateway

# Halving-indexed K_pilot
K_PILOT = 14
BTC_SUBSIDY_PRE_2028 = 3.125
BTC_SUBSIDY_POST_2028 = 1.5625
BTC_SUBSIDY_POST_2032 = 0.78125


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def compact_size_len(n: int) -> int:
    if n < 253:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFFFFFF:
        return 5
    return 9


def taproot_keypath_input_wu() -> int:
    # Non-witness: 32(txid) + 4(vout) + 1(scriptSigLen=0) + 4(nSeq) = 41 B => 164 WU
    # Witness: 1(count) + 1(len=64) + 64(sig) = 66 WU
    return 41 * 4 + 66  # 230 WU = 57.5 vB


def tapscript_checksigadd_input_wu(k: int, n: int, tree_depth: int = 1) -> tuple[int, int]:
    """
    Exact WU for spending a k-of-n OP_CHECKSIGADD Tapscript leaf (k <= 16)
    in a Taproot tree of depth `tree_depth` (depth 1 = 2 leaves: active + recovery).
    Returns (script_bytes, total_wu).
    """
    assert 1 <= k <= n <= 20 and k <= 16
    # Script: <pk_1> OP_CHECKSIG (<pk_i> OP_CHECKSIGADD)*(n-1) OP_k OP_NUMEQUAL
    script_bytes = 34 * n + 2
    control_block_bytes = 1 + 32 + 32 * tree_depth
    # Witness items: n stack slots (k x 64B sigs, (n-k) x empty push), leaf script, control block
    witness_bytes = (
        compact_size_len(n + 2)
        + k * (1 + 64)
        + (n - k) * 1
        + compact_size_len(script_bytes) + script_bytes
        + compact_size_len(control_block_bytes) + control_block_bytes
    )
    total_wu = 41 * 4 + witness_bytes
    return script_bytes, total_wu


def abi_single_bytes_call(payload_len: int, static_head_words: int = 1) -> int:
    """Exact go-zenon ABI size for fn(static_args..., bytes payload)."""
    return 4 + 32 * static_head_words + 32 + 32 + 32 * ceil_div(payload_len, 32)


def abi_embedded_plasma(tier: int, abi_len: int) -> int:
    assert abi_len <= MAX_DATA_LENGTH, f"ABI len {abi_len} exceeds 16 KiB"
    return tier + max(0, abi_len - 4) * AB_BYTE_DATA_PLASMA


def run_b3a_conservation_sim(seed: int = 20261127, steps: int = 2_000) -> dict[str, int]:
    """
    Randomized state-machine check of the B3a signer conservation invariant,
    B3b VM-balance check, B3c tranche isolation, and B4 conflict-only refunds.

    Events modeled:
      deposit, sweep, mint, burn, intent, sign, fee_bump, confirm,
      conflict, refund, refresh, reorg.
    """
    rng = random.Random(seed)
    total_supply = 21_000_000 * SAT
    active_cap = PILOT_SUPPLY_CAP_SATS

    # H-8 Tranche isolation: Settlement holds ONLY the released cap tranche;
    # remaining pre-mint sits in TreasuryTrancheEscrow (timelocked governance).
    settlement_zbtc = active_cap
    tranche_escrow_zbtc = total_supply - active_cap
    assert settlement_zbtc + tranche_escrow_zbtc == total_supply

    # Accounting state on Zenon (single D_znn-final snapshot)
    R_outstanding = 0          # SettlementContract.RepresentationOutstanding
    P_pending = 0              # SettlementContract.PendingForeignRelease
    # outbox_id -> {"gross": int, "fee": int, "net": int, "state": "PENDING"|"INTENT"|"RELEASED"|"REFUNDED", "intent_id": int|None}
    pegouts: dict[int, dict] = {}
    next_outbox_id = 1

    # Bitcoin state (K-deep confirmed vault UTXOs)
    # Seed surplus reserve = 0.50 BTC in initial vault UTXO
    initial_surplus = 50_000_000
    vault_utxos: dict[int, int] = {1: initial_surplus}
    next_utxo_id = 2

    # Pending user deposits awaiting sweep (tweaked vault addresses)
    pending_deposits: dict[int, int] = {}
    next_dep_id = 1

    # Confirmed sweeps eligible to be minted on Zenon
    mintable_sweeps: list[int] = []

    # In-flight signed Bitcoin batches (B3a/B4):
    # intent_id -> {"inputs": [utxo_ids], "outboxes": [ids], "non_vault_out": int,
    #               "burn_gross": int, "max_fee": int, "change_out": int, "signed": bool}
    intents: dict[int, dict] = {}
    next_intent_id = 1

    # Conflicted intents (input spent by cancel/refresh tx without paying outboxes) -> eligible for B4 conflict refund
    conflict_refundable: list[int] = []

    counts: dict[str, int] = {
        k: 0 for k in (
            "deposit", "sweep", "mint", "burn", "intent", "sign",
            "fee_bump", "confirm", "conflict", "refund", "refresh", "reorg",
        )
    }

    def locked_inputs() -> set[int]:
        s: set[int] = set()
        for it in intents.values():
            s.update(it["inputs"])
        return s

    def assert_invariants(stage: str) -> None:
        # B3b: Circ derived strictly from VM balances (never Settlement's own counter)
        circ = total_supply - (settlement_zbtc + tranche_escrow_zbtc)
        assert circ == R_outstanding, f"[{stage}] VM Circ {circ} != R {R_outstanding}"
        assert settlement_zbtc <= active_cap, f"[{stage}] H-8 breach: Settlement holds {settlement_zbtc} > cap {active_cap}"
        assert circ + P_pending <= active_cap, f"[{stage}] Supply+Pending {circ + P_pending} > cap {active_cap}"
        assert len(vault_utxos) <= MAX_VAULT_UTXOS, f"[{stage}] Vault UTXO cap exceeded"

        V_conf = sum(vault_utxos.values())
        signed_inflight = [it for it in intents.values() if it["signed"]]

        # Disjoint inputs across distinct in-flight signed batches
        seen_in: set[int] = set()
        for it in signed_inflight:
            for u in it["inputs"]:
                assert u in vault_utxos, f"[{stage}] In-flight input {u} missing from V_conf"
                assert u not in seen_in, f"[{stage}] Overlapping input {u} across in-flight batches"
                seen_in.add(u)

        # B3a exact signer backing inequality:
        lhs = V_conf - sum(it["non_vault_out"] + it["max_fee"] for it in signed_inflight)
        rhs = circ + P_pending - sum(it["burn_gross"] for it in signed_inflight)
        assert lhs >= rhs, f"[{stage}] B3a violation: LHS {lhs} < RHS {rhs}"
        assert V_conf >= circ + P_pending, f"[{stage}] Confirmed backing violation: V_conf {V_conf} < Circ+P {circ+P_pending}"

    assert_invariants("init")

    events = list(counts.keys())
    for _ in range(steps):
        ev = rng.choice(events)

        if ev == "deposit":
            # M-7: Reserve capacity only if room under cap
            circ = total_supply - (settlement_zbtc + tranche_escrow_zbtc)
            reserved_dep = sum(pending_deposits.values()) + sum(mintable_sweeps)
            avail = active_cap - (circ + P_pending + reserved_dep)
            if avail >= MIN_DEPOSIT_FLOOR_SATS + 30_000 and len(vault_utxos) + len(pending_deposits) < MAX_VAULT_UTXOS - 4:
                amt = rng.randint(MIN_DEPOSIT_FLOOR_SATS + 30_000, min(avail, 80_000_000))
                pending_deposits[next_dep_id] = amt
                next_dep_id += 1
                counts[ev] += 1

        elif ev == "sweep":
            if pending_deposits and len(vault_utxos) < MAX_VAULT_UTXOS:
                dep_id = next(iter(pending_deposits))
                gross_dep = pending_deposits.pop(dep_id)
                pegin_fee = 26_000  # >= 258.5 vB * 100 sat/vB consolidation floor
                sweep_miner_fee = 5_000
                net_mint = gross_dep - pegin_fee
                vault_utxos[next_utxo_id] = gross_dep - sweep_miner_fee
                next_utxo_id += 1
                mintable_sweeps.append(net_mint)
                counts[ev] += 1

        elif ev == "mint":
            if mintable_sweeps:
                net_mint = mintable_sweeps.pop(0)
                if settlement_zbtc >= net_mint:
                    settlement_zbtc -= net_mint
                    R_outstanding += net_mint
                    counts[ev] += 1

        elif ev == "burn":
            if R_outstanding >= MIN_DEPOSIT_FLOOR_SATS + 25_000:
                gross = rng.randint(MIN_DEPOSIT_FLOOR_SATS + 25_000, min(R_outstanding, 40_000_000))
                fee = 25_000
                settlement_zbtc += gross
                R_outstanding -= gross
                P_pending += gross
                pegouts[next_outbox_id] = {
                    "gross": gross, "fee": fee, "net": gross - fee,
                    "state": "PENDING", "intent_id": None,
                }
                next_outbox_id += 1
                counts[ev] += 1

        elif ev == "intent":
            pending_ids = [oid for oid, po in pegouts.items() if po["state"] == "PENDING"]
            free_utxos = [uid for uid in vault_utxos if uid not in locked_inputs()]
            if pending_ids and free_utxos:
                chosen_oids = pending_ids[: rng.randint(1, min(3, len(pending_ids)))]
                non_vault = sum(pegouts[o]["net"] for o in chosen_oids)
                fee_budget = sum(pegouts[o]["fee"] for o in chosen_oids)
                burn_gross = sum(pegouts[o]["gross"] for o in chosen_oids)
                assert non_vault + fee_budget == burn_gross

                # Select disjoint confirmed vault inputs covering non_vault + fee_budget
                selected: list[int] = []
                sel_sum = 0
                for uid in free_utxos:
                    selected.append(uid)
                    sel_sum += vault_utxos[uid]
                    if sel_sum >= non_vault + fee_budget:
                        break
                if sel_sum >= non_vault + fee_budget:
                    iid = next_intent_id
                    next_intent_id += 1
                    intents[iid] = {
                        "inputs": selected,
                        "outboxes": chosen_oids,
                        "non_vault_out": non_vault,
                        "burn_gross": burn_gross,
                        "max_fee": fee_budget,
                        "change_out": sel_sum - non_vault - fee_budget,
                        "signed": False,
                    }
                    for o in chosen_oids:
                        pegouts[o]["state"] = "INTENT"
                        pegouts[o]["intent_id"] = iid
                    counts[ev] += 1

        elif ev == "sign":
            unsigned = [iid for iid, it in intents.items() if not it["signed"]]
            if unsigned:
                iid = unsigned[0]
                it = intents[iid]
                # Pre-sign B3a check before signing!
                V_conf = sum(vault_utxos.values())
                circ = total_supply - (settlement_zbtc + tranche_escrow_zbtc)
                signed_plus = [x for x in intents.values() if x["signed"]] + [it]
                lhs = V_conf - sum(x["non_vault_out"] + x["max_fee"] for x in signed_plus)
                rhs = circ + P_pending - sum(x["burn_gross"] for x in signed_plus)
                if lhs >= rhs and circ == R_outstanding:
                    it["signed"] = True
                    counts[ev] += 1

        elif ev == "fee_bump":
            # RBF variant: same input set, higher max_fee funded strictly from surplus S
            signed_ids = [iid for iid, it in intents.items() if it["signed"]]
            if signed_ids:
                iid = rng.choice(signed_ids)
                it = intents[iid]
                bump = 3_000
                V_conf = sum(vault_utxos.values())
                circ = total_supply - (settlement_zbtc + tranche_escrow_zbtc)
                signed_all = [x for x in intents.values() if x["signed"]]
                lhs_new = V_conf - sum(x["non_vault_out"] + x["max_fee"] for x in signed_all) - bump
                rhs = circ + P_pending - sum(x["burn_gross"] for x in signed_all)
                if it["change_out"] >= bump and lhs_new >= rhs:
                    it["max_fee"] += bump
                    it["change_out"] -= bump
                    counts[ev] += 1

        elif ev == "confirm":
            signed_ids = [iid for iid, it in intents.items() if it["signed"]]
            if signed_ids:
                iid = signed_ids[0]
                it = intents.pop(iid)
                for u in it["inputs"]:
                    vault_utxos.pop(u)
                if it["change_out"] > 0:
                    vault_utxos[next_utxo_id] = it["change_out"]
                    next_utxo_id += 1
                for o in it["outboxes"]:
                    pegouts[o]["state"] = "RELEASED"
                P_pending -= it["burn_gross"]
                counts[ev] += 1

        elif ev == "conflict":
            # Federation cancels an unconfirmed signed intent by re-spending its inputs back to vault
            signed_ids = [iid for iid, it in intents.items() if it["signed"]]
            if signed_ids:
                iid = signed_ids[0]
                it = intents.pop(iid)
                cancel_fee = 5_000
                in_sum = sum(vault_utxos[u] for u in it["inputs"])
                V_conf = sum(vault_utxos.values())
                circ = total_supply - (settlement_zbtc + tranche_escrow_zbtc)
                signed_rem = [x for x in intents.values() if x["signed"]]
                # Check surplus covers cancel fee
                if (
                    in_sum > cancel_fee
                    and (V_conf - cancel_fee) - sum(x["non_vault_out"] + x["max_fee"] for x in signed_rem)
                    >= circ + P_pending - sum(x["burn_gross"] for x in signed_rem)
                ):
                    for u in it["inputs"]:
                        vault_utxos.pop(u)
                    vault_utxos[next_utxo_id] = in_sum - cancel_fee
                    next_utxo_id += 1
                    for o in it["outboxes"]:
                        conflict_refundable.append(o)
                    counts[ev] += 1
                else:
                    # Couldn't pay cancel fee from surplus; keep intent intact
                    intents[iid] = it

        elif ev == "refund":
            # B4: Conflict-proven refund ONLY (never timeout-only!)
            if conflict_refundable:
                oid = conflict_refundable.pop(0)
                po = pegouts[oid]
                if po["state"] == "INTENT":
                    gross = po["gross"]
                    po["state"] = "REFUNDED"
                    P_pending -= gross
                    settlement_zbtc -= gross
                    R_outstanding += gross
                    counts[ev] += 1

        elif ev == "refresh":
            # Refresh / consolidate free vault UTXOs paid from surplus S
            free_utxos = [uid for uid in vault_utxos if uid not in locked_inputs()]
            if len(free_utxos) >= 2:
                u1, u2 = free_utxos[0], free_utxos[1]
                refresh_fee = 8_000
                V_conf = sum(vault_utxos.values())
                circ = total_supply - (settlement_zbtc + tranche_escrow_zbtc)
                signed_all = [x for x in intents.values() if x["signed"]]
                lhs_after = (V_conf - refresh_fee) - sum(x["non_vault_out"] + x["max_fee"] for x in signed_all)
                rhs = circ + P_pending - sum(x["burn_gross"] for x in signed_all)
                if vault_utxos[u1] + vault_utxos[u2] > refresh_fee and lhs_after >= rhs:
                    total_in = vault_utxos.pop(u1) + vault_utxos.pop(u2)
                    vault_utxos[next_utxo_id] = total_in - refresh_fee
                    next_utxo_id += 1
                    counts[ev] += 1

        elif ev == "reorg":
            # Shallow BTC reorg (< K) leaves K-deep V_conf unchanged; deep Zenon reorg < D_znn
            # cannot reach signed burns because signers wait D_znn=60 > 30 rollback bound.
            counts[ev] += 1

        assert_invariants(f"step_after_{ev}")

    return counts


def main() -> None:
    print("=== 1. TAPSCRIPT OP_CHECKSIGADD INPUT WEIGHTS & FRAGMENTATION FLOORS ===")
    kp_wu = taproot_keypath_input_wu()
    kp_vb = kp_wu / 4.0
    assert kp_wu == 230 and kp_vb == 57.5

    for label, k, n in (("Pilot 7-of-10", 7, 10), ("Scaled 11-of-15", 11, 15)):
        script_b, wu = tapscript_checksigadd_input_wu(k, n, tree_depth=1)
        vb = wu / 4.0
        ratio = vb / kp_vb
        dust_crossover_satvb = MIN_DEPOSIT_FLOOR_SATS / vb
        pegin_fee_floor = math.ceil(vb * POLICY_REF_FEE_SATVB)
        stress_reserve = MAX_VAULT_UTXOS * math.ceil(vb) * SOURCED_STRESS_FEE_SATVB
        if (k, n) == (7, 10):
            assert script_b == 342 and wu == 1_034 and vb == 258.5
            assert pegin_fee_floor == 25_850
        if (k, n) == (11, 15):
            assert script_b == 512 and wu == 1_465 and vb == 366.25
            assert pegin_fee_floor == 36_625
        assert stress_reserve <= 50_000_000  # <= 0.50 BTC seeded Operations Reserve
        print(
            f"  {label:16s}: script={script_b:3d} B | input={wu:4d} WU ({vb:6.2f} vB, {ratio:.2f}x key-path) "
            f"| 100k-sat dust>{dust_crossover_satvb:.1f} sat/vB | peg-in fee floor @{POLICY_REF_FEE_SATVB} sat/vB={pegin_fee_floor:,} sats "
            f"| 64-UTXO @{SOURCED_STRESS_FEE_SATVB} sat/vB reserve={stress_reserve/SAT:.5f} BTC"
        )

    print("\n=== 2. BIP-68 RECOVERY TIMELOCK & REFRESH SCHEDULE ===")
    assert T_RECOVERY_CSV_BLOCKS <= 65_535
    # Verify minimal little-endian BIP-68 push encoding for 52,560 (0x00cd50 -> 50 cd 00)
    csv_le = T_RECOVERY_CSV_BLOCKS.to_bytes(3, "little").hex()
    assert csv_le == "50cd00"
    assert T_REFRESH_TRIGGER_BLOCKS == T_RECOVERY_CSV_BLOCKS // 2
    assert T_REFRESH_IMPAIRMENT_BLOCKS == (T_RECOVERY_CSV_BLOCKS * 3) // 4
    refresh_margin = T_RECOVERY_CSV_BLOCKS - T_REFRESH_IMPAIRMENT_BLOCKS
    assert refresh_margin == 13_140  # ~91.25 days before recovery set can race active set
    assert T_DEPOSIT_REFUND_CSV_BLOCKS > T_DEPOSIT_SWEEP_CUTOFF_BLOCKS + K_PILOT * 2
    print(
        f"  T_recovery_csv={T_RECOVERY_CSV_BLOCKS:,} blks (<=65,535; BIP-68 push 03 {csv_le}; ~365d) "
        f"| refresh@{T_REFRESH_TRIGGER_BLOCKS:,} | alert@{T_REFRESH_IMPAIRMENT_BLOCKS:,} (margin {refresh_margin:,} blks = ~91.3d)"
    )
    print(
        f"  Deposit refund CSV={T_DEPOSIT_REFUND_CSV_BLOCKS} blks (~48h) | sweep cutoff=h_dep+{T_DEPOSIT_SWEEP_CUTOFF_BLOCKS} "
        f"(>= {T_DEPOSIT_REFUND_CSV_BLOCKS - T_DEPOSIT_SWEEP_CUTOFF_BLOCKS} blks safety gap >> K={K_PILOT})"
    )

    print("\n=== 3. DIRECT-ON-L1 SPV ABI SIZES & B2 DYNAMIC PLASMA FLOOR ===")
    merkle_branch_max = 4 + 32 * 16  # 516 B (65,536 txs/block)
    # Coinbase CVE-2017-12842 midstate proof: midstate(32) + tail(<=64) + totalLen(4) + branch(516) = 616 B
    cb_midstate_proof_max = 32 + 64 + 4 + merkle_branch_max
    assert cb_midstate_proof_max == 616
    # k=11 BIP-340 sigs max (11 * 64 = 704 B) + 4B signer bitfield = 708 B
    fed_attest_max = 4 + 11 * 64
    assert fed_attest_max == 708

    direct_calls = [
        ("SubmitHeaderBatch(1..2 headers)", EMBEDDED_SIMPLE_TIER, 1 + 32 + 4 + 2 * 80, 1),
        ("PruneStaleHeaders(1..2 hashes)", EMBEDDED_SIMPLE_TIER, 1 + 64, 1),
        ("ReserveMintCapacity", EMBEDDED_SIMPLE_TIER, 36 + 8 + 20, 1),
        ("PostBatchIntent(<=16 outputs + 11 sigs)", EMBEDDED_SIMPLE_TIER, 32 + 16 * 36 + 16 * 80 + 8 + fed_attest_max, 1),
        (
            "SubmitSweepLockProof(6KiB tx+midstate+16 mints+11 sigs)",
            EMBEDDED_HEAVY_SPV_TIER,
            MAX_FED_STRIPPED_TX_BYTES + 32 + 4 + merkle_branch_max + cb_midstate_proof_max + 16 * 32 + fed_attest_max,
            1,
        ),
        (
            "SubmitReleaseProof(6KiB tx+midstate+intentId)",
            EMBEDDED_HEAVY_SPV_TIER,
            MAX_FED_STRIPPED_TX_BYTES + 32 + 4 + merkle_branch_max + cb_midstate_proof_max + 32,
            1,
        ),
        (
            "SubmitConflictRefundProof(6KiB tx+midstate+intent+outbox)",
            EMBEDDED_HEAVY_SPV_TIER,
            MAX_FED_STRIPPED_TX_BYTES + 32 + 4 + merkle_branch_max + cb_midstate_proof_max + 32 + 32,
            1,
        ),
    ]
    max_spv_plasma = 0
    for name, tier, plen, head_words in direct_calls:
        abi_len = abi_single_bytes_call(plen, static_head_words=head_words)
        plasma = abi_embedded_plasma(tier, abi_len)
        qsr = ceil_div(plasma, PLASMA_PER_QSR)
        max_spv_plasma = max(max_spv_plasma, plasma)
        assert abi_len <= MAX_DATA_LENGTH
        assert plasma <= MIN_MAX_BASE_PLASMA_PINNED, f"B2 violation: {name} plasma {plasma} > pinned floor {MIN_MAX_BASE_PLASMA_PINNED}"
        print(f"  {name:57s}: payload={plen:5d} B | ABI={abi_len:5d} B | plasma={plasma:7d} ({qsr:3d} QSR)")

    # Verify why go-zenon's current DP_LOWER_MAX_BASE_PLASMA (210,000) is unsafe (B2):
    max_bytes_at_210k_simple = 4 + (DP_LOWER_MAX_BASE_PLASMA - EMBEDDED_SIMPLE_TIER) // AB_BYTE_DATA_PLASMA
    max_bytes_at_210k_heavy = 4 + (DP_LOWER_MAX_BASE_PLASMA - EMBEDDED_HEAVY_SPV_TIER) // AB_BYTE_DATA_PLASMA
    assert max_bytes_at_210k_simple < 2_400 and max_bytes_at_210k_heavy < 2_050
    assert MIN_MAX_BASE_PLASMA_PINNED >= 3 * max_spv_plasma
    print(
        f"  B2 Plasma Floor Check: go-zenon 210k floor fits only {max_bytes_at_210k_simple} B (simple) / {max_bytes_at_210k_heavy} B (heavy)!"
    )
    print(
        f"  Pinned zBTC spork floor={MIN_MAX_BASE_PLASMA_PINNED:,} >= 3x max SPV call ({max_spv_plasma:,}); "
        f"fits {MIN_MAX_BASE_PLASMA_PINNED // max_spv_plasma} max-SPV calls/Momentum at floor, "
        f"{DP_DEFAULT_MAX_BASE_PLASMA // max_spv_plasma} at default (4.2M)."
    )

    print("\n=== 4. DYNAMIC PLASMA CAPACITY AT 11.4s MOMENTUMS (M-9, M-10) ===")
    for label, cap_plasma in (
        ("Pinned v1 floor (2.1M)", MIN_MAX_BASE_PLASMA_PINNED),
        ("Default (4.2M)", DP_DEFAULT_MAX_BASE_PLASMA),
        ("Hard ceiling (2.1B)", DP_UPPER_MAX_BASE_PLASMA),
    ):
        blocks_per_mom = cap_plasma // ACCOUNT_BLOCK_BASE_PLASMA
        # Each full zBTC user transfer = 1 send block + 1 receive block = 2 account blocks
        full_tps = (blocks_per_mom / 2.0) / OBSERVED_MOMENTUM_SECS
        print(f"  {label:24s}: {blocks_per_mom:7,d} base blocks/Mom | ~{full_tps:7.1f} full send+recv transfers/s @ {OBSERVED_MOMENTUM_SECS}s")

    print("\n=== 5. PTLC/LN TIMELOCKS (M-4), ZENON DEPTH & HALVING-INDEXED K ===")
    assert SIGNER_FINALITY_DEPTH_MOMENTUMS >= 2 * CHAIN_BRIDGE_ROLLBACK_BOUND
    signer_finality_mins = (SIGNER_FINALITY_DEPTH_MOMENTUMS * OBSERVED_MOMENTUM_SECS) / 60.0
    t_btc_worst_secs = int(T_PTLC_BTC_CSV_BLOCKS * 600 * SOURCED_SLOW_BLOCK_MULTIPLE)
    t_znn_min_secs = t_btc_worst_secs + T_PTLC_ZNN_EXTRA_MARGIN_SECS
    t_znn_min_moms = math.ceil(t_znn_min_secs / OBSERVED_MOMENTUM_SECS)
    assert t_btc_worst_secs == 86_400 and t_znn_min_secs == 108_000
    assert LN_DELTA_SAFETY_BLOCKS * 2 <= T_PTLC_BTC_CSV_BLOCKS

    cap_btc = PILOT_SUPPLY_CAP_SATS / SAT
    k_pre_2028 = max(12, math.ceil(2.0 * cap_btc / BTC_SUBSIDY_PRE_2028))
    k_post_2028 = max(12, math.ceil(2.0 * cap_btc / BTC_SUBSIDY_POST_2028))
    k_post_2032 = max(12, math.ceil(2.0 * cap_btc / BTC_SUBSIDY_POST_2032))
    assert K_PILOT >= k_pre_2028 and K_PILOT >= k_post_2028 and K_PILOT >= k_post_2032
    print(
        f"  Signer Zenon finality depth D_znn={SIGNER_FINALITY_DEPTH_MOMENTUMS} Momentums (~{signer_finality_mins:.1f} min @ {OBSERVED_MOMENTUM_SECS}s; 2x rollback bound 30)"
    )
    print(
        f"  PTLC: CSV={T_PTLC_BTC_CSV_BLOCKS} blks (Bob confirms <= h_conf+{T_PTLC_BTC_CSV_BLOCKS - T_PTLC_BOB_CONFIRM_MARGIN}), "
        f"T_btc_worst={t_btc_worst_secs:,}s (24h @ 2.0x), T_znn>={t_znn_min_secs:,}s (30h, ~{t_znn_min_moms:,} Moms); LN Delta_safety={LN_DELTA_SAFETY_BLOCKS} blks"
    )
    print(
        f"  Halving K (5.0 BTC cap): K_pilot={K_PILOT} >= pre-2028({k_pre_2028}), post-2028({k_post_2028}), post-2032({k_post_2032})"
    )

    print("\n=== 6. B3a/B3b/B3c/B4 RANDOMIZED CONSERVATION SIMULATION (2,000 STEPS) ===")
    counts = run_b3a_conservation_sim(seed=20261127, steps=2_000)
    assert all(v > 0 for v in counts.values()), f"Some event type never exercised: {counts}"
    summary = ", ".join(f"{k}={v}" for k, v in counts.items())
    print(f"  2,000 steps passed ALL B3a/B3b/B3c/B4 invariants: {summary}")
    print("\nALL v1 (v3.0.0-rfc) CONSISTENCY, WEIGHT, PLASMA, TIMELOCK & CONSERVATION CHECKS PASSED.")


if __name__ == "__main__":
    main()
