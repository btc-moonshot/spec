#!/usr/bin/env python3
"""
Deterministic Consistency & Bounds Checker for the zBTC Protocol Specification
v1 (v3.0.0-rfc — Zero-Federation Phased Architecture:
    Stage 0 Verify Bitcoin SPV Oracle + Non-Custodial PTLC/LN
 -> Stage 1A Right-Sized BitVMX (n=8, M=3..5, N=7) + Bitcoin-Anchored Sovereign ZK Rollup
  | Stage 1B clArk Alternative Gate
 -> Stage 2 Zero-TTP Scale & Upgrade).

SCOPE & HONESTY DISCLOSURE:
  This script checks internal mathematical consistency, SHA-256 coinbase midstate
  final-block padding across all 64 remainders, go-zenon Dynamic Plasma & wire-size
  bounds, PTLC/HTLC slow-block margins, Theorem 2 capital ratios, BIP-431 TRUC v3
  and BIP-342 Tapscript/Lamport weights, simultaneous-window BitVMX timelocks,
  colluding-verifier P&L matrices, multi-tier vault bank-run exit bounds,
  halving-indexed private-fork K inequalities, clArk tree exit weights, and a
  REAL 2,000-step randomized state-machine simulation with genuine Bitcoin reorgs.

  Every modeled constant is explicitly prefixed by provenance:
    - SOURCED_             : Bitcoin BIPs, historical chain telemetry, or go-zenon origin/dev
    - POLICY_              : Explicit protocol design parameters
    - PRE_MAINNET_TARGET_  : BitVMX-CPU / rollup sizing targets to be empirically measured on Signet

  This script is a consistency & bounds checker — NOT an empirical Signet benchmark
  and NOT a substitute for independent cryptographic/implementation audits.

Run: `python3 -I scripts/verify_spec_bounds.py`
"""
import hashlib
import math
import random
import struct

SAT = 100_000_000

# ==============================================================================
# SOURCED CONSTANTS (Bitcoin BIPs, Historical Telemetry, go-zenon origin/dev)
# ==============================================================================
SOURCED_BIP431_TRUC_MAX_VB = 10_000                 # BIP-431 TRUC v3 single-tx vByte limit
SOURCED_BIP342_MAX_STACK_ITEMS = 1_000              # BIP-342 Tapscript max stack elements
SOURCED_BIP342_MAX_PUSH_BYTES = 520                 # BIP-342 Tapscript max push element size
SOURCED_BIP141_MAX_STRIPPED_BLOCK_BYTES = 1_000_000 # Bitcoin consensus max non-witness block bytes
SOURCED_BTC_TARGET_BLOCK_SECS = 600                 # 10 min nominal Bitcoin block interval
SOURCED_BTC_BLOCKS_PER_DAY = 144                    # Nominal blocks/day
SOURCED_JUNE2021_SLOW_WEEKLY_MULT = 2.0             # June 2021 China ban: ~1.95-2.0x 7d avg
SOURCED_JUNE2021_SLOW_DAILY_MULT = 2.3              # June 2021 China ban: ~23 min/blk daily peak
SOURCED_APR2024_MEDIAN_FEE_SATVB = 1_805            # April 2024 halving/Runes median peak

# Bitcoin block subsidy schedule (BTC/block) across halvings
SOURCED_BTC_SUBSIDY_BY_ERA = {
    "2024-2028": 3.125,
    "2028-2032": 1.5625,
    "2032-2036": 0.78125,
    "2036-2040": 0.390625,
}

# ZNN market-cap context (Nov 2026 observed range; 0% ZNN in BTC custody safety!)
SOURCED_ZNN_MCAP_BTC_LOW = 25.0
SOURCED_ZNN_MCAP_BTC_HIGH = 33.0

# go-zenon origin/dev protocol constants
SOURCED_ZNN_MAX_DATA_LENGTH = 16_384                # dev:vm/constants/plasma.go:67
SOURCED_ZNN_ACCOUNT_BLOCK_BASE_PLASMA = 21_000      # dev:vm/constants/plasma.go
SOURCED_ZNN_AB_BYTE_DATA_PLASMA = 68                # dev:vm/constants/plasma.go (DynamicPlasmaSpork)
SOURCED_ZNN_EMBEDDED_SIMPLE_TIER = 52_500           # 2.5 * 21,000
SOURCED_ZNN_EMBEDDED_HEAVY_SPV_TIER = 73_500        # 3.5 * 21,000
SOURCED_ZNN_PLASMA_PER_QSR = 2_100                  # 1 QSR = 1 fusion unit = 2,100 Plasma @ price 1,000
SOURCED_ZNN_POW_DIFF_PER_PLASMA = 1_500             # dev:vm/constants/plasma.go
SOURCED_ZNN_MIN_RESOURCE_PRICE = 1_000              # dev:dp/dp.go
SOURCED_ZNN_DP_DEFAULT_MAX_BASE_PLASMA = 4_200_000  # dev:vm/embedded/definition/plasma.go:97
SOURCED_ZNN_DP_UPPER_MAX_BASE_PLASMA = 2_100_000_000  # dev:vm/embedded/definition/plasma.go:63
SOURCED_ZNN_DP_LOWER_MAX_BASE_PLASMA = 210_000      # dev:vm/embedded/definition/plasma.go:66
SOURCED_ZNN_OBSERVED_MOMENTUM_SECS = 11.4           # dev:vm/embedded/definition/spork.go (11.35-11.46s)
SOURCED_ZNN_CHAIN_BRIDGE_ROLLBACK = 30              # dev:protocol/chain_bridge.go:293
SOURCED_ZNN_MAX_MOMENTUM_CONTENT_BYTES = 8 * 1024 * 1024  # dev:verifier/momentum.go:93 (8 MiB)
SOURCED_ZNN_PROTOCOL_MAX_MSG_SIZE = 10 * 1024 * 1024      # dev:protocol/protocol.go (10 MiB)
SOURCED_ZNN_SOFT_RESPONSE_LIMIT = 2 * 1024 * 1024         # dev:protocol/protocol.go (2 MiB)
SOURCED_ZNN_MAX_DETAILED_MOMENTUM_WIRE = (
    SOURCED_ZNN_PROTOCOL_MAX_MSG_SIZE - SOURCED_ZNN_SOFT_RESPONSE_LIMIT - 4096
)  # 8,384,512 B (dev:protocol/protocol.go:70)
SOURCED_ZNN_MIN_ACCOUNT_BLOCK_WIRE_LOW = 300        # Conservative minimal serialized AccountBlock + content header
SOURCED_ZNN_MIN_ACCOUNT_BLOCK_WIRE_HIGH = 350       # Typical minimal signed AccountBlock + 52B header

# ==============================================================================
# POLICY PARAMETERS (Stage 0, Stage 1A BitVMX, Stage 1B clArk)
# ==============================================================================
POLICY_PINNED_MAX_BASE_PLASMA_FLOOR = 2_100_000     # Pinned >= 2.1M Plasma/Momentum
POLICY_PINNED_MAX_PRICE_CHANGE_PCT = 25             # MaxPriceChangePercent <= 25%
POLICY_PINNED_MIN_TARGET_SHARE_PCT = 25             # Fused/Pow targets >= 25% of 2.1M floor (525,000)
POLICY_PINNED_MIN_PRICE_DENOM = 8                   # PriceChangeDenominator >= 8 (spec/05 §2.2)
POLICY_STAGE0_MAX_STRIPPED_TX_BYTES = 6_144         # Stage 0 SPV Event Oracle tx cap
POLICY_STAGE0_MAX_STORAGE_OPS = 24                  # Per-call L1 storage op ceiling

# Stage 0 PTLC / LN non-custodial swap parameters
POLICY_PTLC_BTC_CSV_BLOCKS = 72
POLICY_PTLC_BOB_CONFIRM_MARGIN_BLOCKS = 6           # Bob confirms <= h_conf + 66 w/ CPFP
POLICY_PTLC_ALICE_RELEASE_MAX_BLOCKS = 6
POLICY_PTLC_ZNN_DURATION_SECS = 108_000             # 30.0 hours (passed as now + 108_000 Unix ts!)
POLICY_LN_DELTA_SAFETY_BLOCKS = 36

# Stage 1A Right-Sized BitVMX (n=8) + Sovereign ZK Rollup parameters
POLICY_BITVMX_N_BRANCH = 8                          # n=8 (3 bits/round -> 7 intermediate hashes)
POLICY_BITVMX_SEARCH_ROUNDS = 9                     # 8^9 = 2^27 = 134,217,728 RV32IM instructions
POLICY_BITVMX_M_MIN = 3                             # Minimal competitive operator count
POLICY_BITVMX_M_MAX = 5                             # Pilot operator count
POLICY_BITVMX_L_LANES = 1                           # Lanes per operator
POLICY_BITVMX_N_VERIFIERS = 7                       # Pre-committed online verifiers
POLICY_BITVMX_R_ROUNDS = 64                         # Pre-signed rounds per lane
POLICY_STAGE2_TOTAL_LANES = 40                      # Stage 2 scaled lane count (40 * 64 = 2,560 leaves)

POLICY_VAULT_TIERS_SATS = (50_000_000, 25_000_000, 25_000_000)  # {0.50, 0.25, 0.25} BTC per 1.0 BTC deposit
POLICY_VAULT_ALT_SPLIT_SATS = (50_000_000, 50_000_000)          # Optional {0.50, 0.50} split comparison
POLICY_MAX_VAULT_DENOM_SATS = 50_000_000                        # 0.50 BTC ceiling per vault UTXO
POLICY_MIN_EXIT_SATS = 100_000                                  # 0.001 BTC minimum exit

# Stage 1A Per-Lane Bond & Verifier Economics
POLICY_BOND_BTC_SATS = 200_000_000                  # 2.00 BTC L1 Stake_r bond
POLICY_B_ZBTC_CUSTODY_SATS = 50_000_000             # 0.50 BTC maxVaultDenom restitution floor
POLICY_B_ZBTC_EQUIV_BOUNTY_SATS = 5_000_000         # 0.05 BTC Lamport equivocation bounty
POLICY_B_ZBTC_GRIEF_BUFFER_SATS = 5_000_000         # 0.05 BTC ExitSlotUTXO grief buffer
POLICY_B_ZBTC_TOTAL_SATS = (
    POLICY_B_ZBTC_CUSTODY_SATS + POLICY_B_ZBTC_EQUIV_BOUNTY_SATS + POLICY_B_ZBTC_GRIEF_BUFFER_SATS
)                                                   # 0.60 BTC total locked zBTC/lane
POLICY_B_ZBTC_CUSTODY_SLICE_SATS = (
    POLICY_B_ZBTC_CUSTODY_SATS + POLICY_B_ZBTC_EQUIV_BOUNTY_SATS
)                                                   # 0.55 BTC custody slice split across remaining challengers on Disprove
POLICY_LANE_TOTAL_BOND_SATS = POLICY_BOND_BTC_SATS + POLICY_B_ZBTC_TOTAL_SATS  # 2.60 BTC/lane
POLICY_F_CHAL_SATS = 40_000_000                     # 0.40 BTC verifier challenge escrow
POLICY_WINNING_VERIFIER_L1_SATS = 15_000_000        # 0.15 BTC L1 payout to winning verifier
POLICY_BURNED_BOND_SATS = 185_000_000               # 1.85 BTC burned to OP_RETURN on Disprove/TimeoutSlash
POLICY_EXIT_GRIEF_SLASH_SATS = 1_000_000            # 0.01 BTC non-paying ExitSlotUTXO slash
POLICY_DESIGN_SUSTAINED_FEE_SATVB = 500             # 500 sat/vB sustained across full dispute

# Stage 1A Simultaneous-Challenge BitVMX Timelocks (blocks)
POLICY_T_CHAL_WINDOW = 144                          # Simultaneous [0, 144] challenge window (24h)
POLICY_T_STEP = 48                                  # 8h per bisection step
POLICY_T_TAKE = 1_152                               # 8.0d (> max_dispute_end = 1,104)
POLICY_T_COOLDOWN = 1_296                           # 9.0d (1,152 + 144-blk Lamport equivocation slash window)
POLICY_T_RETIRE = 1_440                             # 10.0d Stake retirement CSV
POLICY_T_EXIT_CANCEL = 288                          # 48h user unilateral EXIT_CANCEL leaf

# Stage 1A Capital & TVL Profiles
POLICY_STAGE1A_PROFILES = {
    "M=3 (<=10 BTC cap)": {"M": 3, "cap_btc": 10.0, "float_btc": 2.20, "K_2024": 14},
    "M=5 (<=15 BTC cap)": {"M": 5, "cap_btc": 15.0, "float_btc": 3.00, "K_2024": 14},
}
POLICY_TVL_TIERS_BTC = (10, 15, 50, 200)
POLICY_CONFIGURED_K_2024 = {10: 14, 15: 14, 50: 36, 200: 144}
POLICY_CONFIGURED_K_BY_ERA = {
    "2024-2028": {10: 14, 15: 14, 50: 36, 200: 144},
    "2028-2032": {10: 14, 15: 20, 50: 66, 200: 260},
    "2032-2036": {10: 28, 15: 40, 50: 130, 200: 516},
}

# ==============================================================================
# PRE-MAINNET TARGETS (BitVMX-CPU / Rollup / BitVM2 / clArk — Signet-Gated)
# ==============================================================================
PRE_MAINNET_TARGET_ROLLUP_TX_DATA_BYTES = 110       # Signed rollup transfer in AccountBlock.Data
PRE_MAINNET_TARGET_DEPOSIT_CERTBLOB_BYTES = 104     # Acyclic OP_DROP certBlob <= 520 B
PRE_MAINNET_TARGET_WOTS_DIGIT_WU = 95.5             # Per base-16 W-OTS digit weight (WU)
PRE_MAINNET_TARGET_BISECTION_OVERHEAD_VB = 250.0    # Per prover bisection tx non-WOTS overhead (vB)
PRE_MAINNET_TARGET_START_TX_VB = 3_000.0            # Prover StartTx vBytes
PRE_MAINNET_TARGET_FINAL_TRACE_TX_VB = 5_000.0      # Prover FinalTraceTx vBytes
PRE_MAINNET_TARGET_CHALLENGE_TX_VB = 350.0          # Verifier ChallengeTx vBytes
PRE_MAINNET_TARGET_VERIFIER_CHOICE_VB = 350.0       # Verifier 3-bit interval choice tx vBytes
PRE_MAINNET_TARGET_EXECUTE_OPCODE_VB = 8_000.0      # Verifier final 1-opcode disprove tx vBytes
PRE_MAINNET_TARGET_VERIFIER_CONSERVATIVE_VB = 15_000  # Conservative verifier total dispute budget (vB)
PRE_MAINNET_TARGET_PROVER_CONSERVATIVE_VB = 75_000    # Conservative prover total dispute budget (vB)
PRE_MAINNET_TARGET_BITVM2_LANE_BOND_BTC_LOW = 13.30   # Minimal BitVM2 lane bond @ 200 sat/vB
PRE_MAINNET_TARGET_BITVM2_LANE_BOND_BTC_HIGH = 18.175 # Minimal BitVM2 lane bond @ 500 sat/vB
PRE_MAINNET_TARGET_CLARK_ACTIVE_LIQ_BTC = (2.0, 5.0)  # Stage 1B clArk active ASP liquidity range
PRE_MAINNET_TARGET_CLARK_VTXO_COUNTS = (64, 128, 256, 512, 1024)


# ==============================================================================
# HELPER FUNCTIONS (Pure Python Stdlib)
# ==============================================================================
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


def abi_single_bytes_call(payload_len: int, static_head_words: int = 1) -> int:
    """Exact go-zenon ABI size for fn(static_args..., bytes payload)."""
    return 4 + 32 * static_head_words + 32 + 32 + 32 * ceil_div(payload_len, 32)


def abi_embedded_plasma(tier: int, abi_len: int) -> int:
    assert abi_len <= SOURCED_ZNN_MAX_DATA_LENGTH, f"ABI len {abi_len} exceeds 16 KiB"
    return tier + max(0, abi_len - 4) * SOURCED_ZNN_AB_BYTE_DATA_PLASMA


# FIPS 180-4 SHA-256 single-block compression (for real coinbase midstate verification)
_SHA256_IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)) & 0xFFFFFFFF


def sha256_compress(state: tuple[int, ...], block64: bytes) -> tuple[int, ...]:
    assert len(block64) == 64
    w = list(struct.unpack(">16I", block64))
    for i in range(16, 64):
        s0 = _rotr32(w[i - 15], 7) ^ _rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr32(w[i - 2], 17) ^ _rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
        ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
        t1 = (h + S1 + ch + _SHA256_K[i] + w[i]) & 0xFFFFFFFF
        S0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF
    return tuple((s + x) & 0xFFFFFFFF for s, x in zip(state, (a, b, c, d, e, f, g, h)))


def complete_midstate_double_sha256(midstate_bytes: bytes, tail: bytes, total_len: int) -> tuple[bytes, int]:
    """
    Normative 1-/2-block coinbase midstate completion (spec/02 §2.3):
      - Enforces total_len >= 65 (rejects total_len == 64 CVE-2017-12842 leaf forgery & short txs)
      - Enforces len(tail) == total_len % 64 < 64
      - Handles BOTH 1-block (rem < 56) and 2-block (rem in 56..63) final SHA-256 padding.
    Returns (double_sha256_digest, final_compression_blocks_used).
    """
    assert len(midstate_bytes) == 32
    assert total_len >= 65, "CVE-2017-12842: totalCoinbaseBytes must be >= 65 (64-byte leaf forbidden)"
    rem = total_len % 64
    assert len(tail) == rem and len(tail) < 64
    padded = bytearray(tail)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0x00)
    padded.extend(struct.pack(">Q", total_len * 8))
    blocks = len(padded) // 64
    assert blocks in (1, 2)
    state = struct.unpack(">8I", midstate_bytes)
    for idx in range(blocks):
        state = sha256_compress(state, bytes(padded[idx * 64 : (idx + 1) * 64]))
    first_round = struct.pack(">8I", *state)
    return hashlib.sha256(first_round).digest(), blocks


def dp_next_price(
    current_price: int,
    used_plasma: int,
    target_plasma: int,
    max_change_pct: int,
    denom: int,
) -> int:
    """Exact mirror of go-zenon origin/dev:dp/dp.go dynamic price step."""
    delta = used_plasma - target_plasma
    # Go big.Int truncation toward zero on division
    num = delta * current_price
    if num >= 0:
        change = (num // target_plasma) // denom
    else:
        change = -((-num // target_plasma) // denom)
    nxt = current_price + change
    max_nxt = (current_price * (100 + max_change_pct)) // 100
    min_nxt = (current_price * (100 - max_change_pct)) // 100
    if nxt > max_nxt:
        nxt = max_nxt
    if nxt < min_nxt:
        nxt = min_nxt
    if nxt < SOURCED_ZNN_MIN_RESOURCE_PRICE:
        nxt = SOURCED_ZNN_MIN_RESOURCE_PRICE
    return nxt


# ==============================================================================
# REAL, NON-NO-OP 2,000-STEP RANDOMIZED STAGE 1A SOLVENCY SIMULATION
# ==============================================================================
def run_stage1a_solvency_sim(seed: int = 20261128, steps: int = 2_000) -> dict[str, int]:
    """
    Adversarial state-machine simulation of the Stage 1A BitVMX (n=8, M=5, N=7)
    + Bitcoin-Anchored Sovereign ZK Rollup with:
      - Explicit Bob (1 -> 0.5 -> exit 0.5) & Mike (Alice 1 + Bob 1 -> 2 -> exit 0.25) flows
      - Real Bitcoin block tip + confirmation depth K=14
      - GENUINE Bitcoin reorgs (popping 1..K-1 unconfirmed blocks & discarding orphaned events!)
      - Multi-tier {0.50, 0.25, 0.25} BTC deposits
      - Feeless rollup transfers
      - ExitSlotUTXO honest fronting + non-paying grief slashes (0.01 BTC + refund + auto-suspend)
      - Leaf 2M EXIT_CANCEL user refunds after 288 blocks
      - Dual-input Disprove slashes (Stake_r + VaultConnector_r -> 0 vault stolen + 0.55 BTC split)
      - Lamport L_{j,l,r} equivocation slashes (D_d burned from B_zbtc -> exact 1:1 solvency!)
    Asserts EXACT 1:1 backing conservation at EVERY single step.
    """
    rng = random.Random(seed)
    K = POLICY_CONFIGURED_K_2024[15]  # 14 blocks
    cap_sats = int(15.0 * SAT)

    # Canonical K-deep rollup state
    users: dict[str, int] = {
        "alice": 0, "bob": 0, "mike": 0, "carol": 0, "dave": 0,
        "challenger_pool": 0,
    }
    # Operators O_0 .. O_4 (M = 5)
    # Each operator starts with 1.00 BTC deposited (two 0.50 BTC vaults) backing 0.60 B_zbtc + 0.40 liquid zBTC
    # so every satoshi of B_zbtc in the rollup is backed 1:1 by real confirmed L1 vault BTC!
    confirmed_vaults: dict[int, int] = {}  # vault_id -> sats (unassigned & unspent K-deep)
    next_vault_id = 1
    operators: dict[int, dict] = {}
    for op_id in range(POLICY_BITVMX_M_MAX):
        for _ in range(2):
            confirmed_vaults[next_vault_id] = 50_000_000  # 0.50 BTC
            next_vault_id += 1
        operators[op_id] = {
            "b_zbtc": POLICY_B_ZBTC_TOTAL_SATS,        # 0.60 BTC locked collateral
            "free_zbtc": 40_000_000,                   # 0.40 BTC operator liquid zBTC (for top-ups)
            "credit": 0,                               # ReimbursementCredit[op]
            "suspended": False,
        }

    # Pending exits (canonical K-deep): exit_id -> {"user", "gross", "created_h", "state": "OPEN"}
    pending_exits: dict[int, dict] = {}
    next_exit_id = 1

    # Unconfirmed Bitcoin tip buffer (heights > finalized_height; reorgable!)
    # Each block = {"height": int, "events": list[dict]}
    finalized_height = 100
    tip_blocks: list[dict] = []

    # Track unconfirmed reservations so we don't double-spend same exit/vault inside one fork
    unconf_spent_exits: set[int] = set()
    unconf_claimed_vaults: set[int] = set()
    unconf_pending_credit_used: dict[int, int] = {i: 0 for i in range(POLICY_BITVMX_M_MAX)}

    counts: dict[str, int] = {
        k: 0 for k in (
            "deposit", "transfer", "forced_exit", "front_paid", "front_grief",
            "exit_cancel", "take_honest", "disprove_dual_slash",
            "lamport_equivocation_slash", "topup_op", "mine_block", "reorg",
            "reorg_blocks_reverted", "reorg_events_reverted",
        )
    }

    def rebuild_unconf_locks() -> None:
        unconf_spent_exits.clear()
        unconf_claimed_vaults.clear()
        for i in unconf_pending_credit_used:
            unconf_pending_credit_used[i] = 0
        for blk in tip_blocks:
            for ev in blk["events"]:
                kind = ev["kind"]
                if kind in ("front_paid", "front_grief", "exit_cancel"):
                    unconf_spent_exits.add(ev["exit_id"])
                elif kind == "take_honest":
                    unconf_claimed_vaults.add(ev["vault_id"])
                    unconf_pending_credit_used[ev["op_id"]] += ev["amount"]
                elif kind == "lamport_equivocation_slash":
                    unconf_claimed_vaults.add(ev["vault_id"])

    def apply_finalized_event(ev: dict, blk_height: int) -> None:
        nonlocal next_vault_id, next_exit_id
        kind = ev["kind"]
        if kind == "deposit":
            # Multi-tier vaults enter confirmed L1 pool AND mint exact 1:1 zBTC
            for vid, vamt in ev["vaults"]:
                confirmed_vaults[vid] = vamt
            users[ev["user"]] += sum(vamt for _, vamt in ev["vaults"])
            counts["deposit"] += 1

        elif kind == "forced_exit":
            u = ev["user"]
            amt = ev["gross"]
            if users[u] >= amt:
                users[u] -= amt
                pending_exits[ev["exit_id"]] = {
                    "user": u, "gross": amt, "created_h": blk_height,
                }
                counts["forced_exit"] += 1

        elif kind == "front_paid":
            eid = ev["exit_id"]
            if eid in pending_exits:
                ex = pending_exits.pop(eid)
                operators[ev["op_id"]]["credit"] += ex["gross"]
                counts["front_paid"] += 1

        elif kind == "front_grief":
            # Non-paying ExitSlotUTXO spend -> cancel + refund + 0.01 BTC slash + auto-suspend!
            eid = ev["exit_id"]
            op = operators[ev["op_id"]]
            if eid in pending_exits and op["b_zbtc"] >= POLICY_B_ZBTC_CUSTODY_SLICE_SATS + POLICY_EXIT_GRIEF_SLASH_SATS:
                ex = pending_exits.pop(eid)
                users[ex["user"]] += ex["gross"]
                op["b_zbtc"] -= POLICY_EXIT_GRIEF_SLASH_SATS
                users[ex["user"]] += POLICY_EXIT_GRIEF_SLASH_SATS
                op["suspended"] = True
                assert op["b_zbtc"] >= POLICY_B_ZBTC_CUSTODY_SLICE_SATS, "Grief slash breached 0.55 BTC custody floor!"
                counts["front_grief"] += 1

        elif kind == "exit_cancel":
            eid = ev["exit_id"]
            if eid in pending_exits and blk_height >= pending_exits[eid]["created_h"] + POLICY_T_EXIT_CANCEL:
                ex = pending_exits.pop(eid)
                users[ex["user"]] += ex["gross"]
                counts["exit_cancel"] += 1

        elif kind == "take_honest":
            vid = ev["vault_id"]
            op = operators[ev["op_id"]]
            if vid in confirmed_vaults and op["credit"] >= confirmed_vaults[vid]:
                vamt = confirmed_vaults.pop(vid)
                op["credit"] -= vamt
                counts["take_honest"] += 1

        elif kind == "disprove_dual_slash":
            # Dual-input Disprove spends Stake_r + VaultConnector_r -> 0 vault stolen!
            # 0.55 BTC custody slice of B_zbtc splits across remaining challengers; operator paused.
            op = operators[ev["op_id"]]
            if op["b_zbtc"] >= POLICY_B_ZBTC_CUSTODY_SLICE_SATS:
                op["b_zbtc"] -= POLICY_B_ZBTC_CUSTODY_SLICE_SATS
                users["challenger_pool"] += POLICY_B_ZBTC_CUSTODY_SLICE_SATS
                op["suspended"] = True
                counts["disprove_dual_slash"] += 1

        elif kind == "lamport_equivocation_slash":
            # Operator stole vault U_2 != U_1 (D_d <= 0.50 BTC); BurnBondTx burns 2.00 BTC L1,
            # STARK atomically burns D_d from op.b_zbtc (1:1 solvency!) + pays 0.05 BTC bounty.
            vid = ev["vault_id"]
            op = operators[ev["op_id"]]
            if vid in confirmed_vaults:
                vamt = confirmed_vaults[vid]
                if op["b_zbtc"] >= vamt + POLICY_B_ZBTC_EQUIV_BOUNTY_SATS:
                    confirmed_vaults.pop(vid)
                    op["b_zbtc"] -= (vamt + POLICY_B_ZBTC_EQUIV_BOUNTY_SATS)
                    users["challenger_pool"] += POLICY_B_ZBTC_EQUIV_BOUNTY_SATS
                    op["suspended"] = True
                    counts["lamport_equivocation_slash"] += 1

    def assert_solvency(label: str) -> None:
        vault_backing = sum(confirmed_vaults.values())
        circ_users = sum(users.values())
        pending_total = sum(ex["gross"] for ex in pending_exits.values())
        credits_total = sum(op["credit"] for op in operators.values())
        op_b_zbtc = sum(op["b_zbtc"] for op in operators.values())
        op_free_zbtc = sum(op["free_zbtc"] for op in operators.values())
        total_liabilities = circ_users + pending_total + credits_total + op_b_zbtc + op_free_zbtc
        assert vault_backing == total_liabilities, (
            f"[{label}] Solvency mismatch! vault_backing={vault_backing} != liabilities={total_liabilities}"
        )
        # Active non-suspended operators must always maintain full 0.60 BTC B_zbtc floor
        for oid, op in operators.items():
            if not op["suspended"]:
                assert op["b_zbtc"] >= POLICY_B_ZBTC_TOTAL_SATS, (
                    f"[{label}] Active operator {oid} b_zbtc={op['b_zbtc']} < 0.60 BTC floor"
                )

    def mine_one_block(events: list[dict]) -> None:
        nonlocal finalized_height
        next_h = finalized_height + len(tip_blocks) + 1
        tip_blocks.append({"height": next_h, "events": events})
        counts["mine_block"] += 1
        # Finalize any block now >= K deep (tip_height - blk_height + 1 >= K)
        while len(tip_blocks) >= K:
            fin_blk = tip_blocks.pop(0)
            finalized_height = fin_blk["height"]
            for ev in fin_blk["events"]:
                apply_finalized_event(ev, finalized_height)
            rebuild_unconf_locks()

    def current_tip_height() -> int:
        return finalized_height + len(tip_blocks)

    assert_solvency("init")

    # ------------------------------------------------------------------
    # DETERMINISTIC VERIFICATION OF BOB (1 -> 0.5 -> 0.5) & MIKE (1+1 -> 2 -> 0.25)
    # ------------------------------------------------------------------
    # Bob deposits 1.0 BTC -> {0.50, 0.25, 0.25} vaults
    bob_vaults = []
    for amt in POLICY_VAULT_TIERS_SATS:
        bob_vaults.append((next_vault_id, amt))
        next_vault_id += 1
    # Alice deposits 1.0 BTC -> {0.50, 0.25, 0.25} vaults
    alice_vaults = []
    for amt in POLICY_VAULT_TIERS_SATS:
        alice_vaults.append((next_vault_id, amt))
        next_vault_id += 1
    mine_one_block([
        {"kind": "deposit", "user": "bob", "vaults": bob_vaults},
        {"kind": "deposit", "user": "alice", "vaults": alice_vaults},
    ])
    for _ in range(K - 1):
        mine_one_block([])
    assert users["bob"] == SAT and users["alice"] == SAT
    assert_solvency("after_bob_alice_deposits")

    # Bob spends 0.5 zBTC to Carol feelessly, then recovers 0.50 BTC via forced exit
    users["bob"] -= 50_000_000
    users["carol"] += 50_000_000
    counts["transfer"] += 1
    bob_eid = next_exit_id
    next_exit_id += 1
    mine_one_block([{"kind": "forced_exit", "user": "bob", "gross": 50_000_000, "exit_id": bob_eid}])
    for _ in range(K - 1):
        mine_one_block([])
    assert bob_eid in pending_exits and users["bob"] == 0
    # Operator 0 fronts Bob's 0.50 BTC and later claims Bob's 0.50 BTC vault
    mine_one_block([{"kind": "front_paid", "exit_id": bob_eid, "op_id": 0}])
    for _ in range(K - 1):
        mine_one_block([])
    assert bob_eid not in pending_exits and operators[0]["credit"] == 50_000_000
    mine_one_block([{"kind": "take_honest", "op_id": 0, "vault_id": bob_vaults[0][0], "amount": 50_000_000}])
    for _ in range(K - 1):
        mine_one_block([])
    assert operators[0]["credit"] == 0
    assert_solvency("after_bob_0.5_recovery")

    # Mike scenario: Alice (1 BTC) + Bob2 (1 BTC -> Carol transfers + new Bob deposit) -> Mike has 2.0 zBTC -> exits 0.25 BTC
    bob2_vaults = []
    for amt in POLICY_VAULT_TIERS_SATS:
        bob2_vaults.append((next_vault_id, amt))
        next_vault_id += 1
    mine_one_block([{"kind": "deposit", "user": "bob", "vaults": bob2_vaults}])
    for _ in range(K - 1):
        mine_one_block([])
    assert users["alice"] == SAT and users["bob"] == SAT
    users["alice"] -= SAT
    users["bob"] -= SAT
    users["mike"] += 2 * SAT
    counts["transfer"] += 2
    mike_eid = next_exit_id
    next_exit_id += 1
    # Mike posts 0x01 FORCED_EXIT directly on Bitcoin L1 (0 Zenon signer signatures!)
    mine_one_block([{"kind": "forced_exit", "user": "mike", "gross": 25_000_000, "exit_id": mike_eid}])
    for _ in range(K - 1):
        mine_one_block([])
    assert users["mike"] == 175_000_000 and mike_eid in pending_exits
    # Operator 1 fronts Mike's 0.25 BTC and claims a 0.25 BTC vault directly
    mine_one_block([{"kind": "front_paid", "exit_id": mike_eid, "op_id": 1}])
    for _ in range(K - 1):
        mine_one_block([])
    mine_one_block([{"kind": "take_honest", "op_id": 1, "vault_id": alice_vaults[1][0], "amount": 25_000_000}])
    for _ in range(K - 1):
        mine_one_block([])
    assert mike_eid not in pending_exits and operators[1]["credit"] == 0
    assert_solvency("after_mike_0.25_recovery")

    # ------------------------------------------------------------------
    # 2,000-STEP ADVERSARIAL RANDOMIZED SIMULATION (WITH REAL REORGS!)
    # ------------------------------------------------------------------
    actions = [
        "deposit", "transfer", "forced_exit", "front_paid", "front_grief",
        "exit_cancel", "take_honest", "disprove_dual_slash",
        "lamport_equivocation_slash", "topup_op", "mine_block", "reorg",
    ]
    weights = [10, 18, 12, 12, 6, 8, 10, 5, 5, 10, 26, 10]
    normal_users = ["alice", "bob", "mike", "carol", "dave"]

    for step in range(steps):
        act = rng.choices(actions, weights=weights, k=1)[0]

        if act == "deposit":
            cur_tvl = sum(confirmed_vaults.values())
            if cur_tvl + SAT <= cap_sats:
                u = rng.choice(normal_users)
                new_vs = []
                for amt in POLICY_VAULT_TIERS_SATS:
                    new_vs.append((next_vault_id, amt))
                    next_vault_id += 1
                mine_one_block([{"kind": "deposit", "user": u, "vaults": new_vs}])

        elif act == "transfer":
            rich = [u for u in normal_users if users[u] >= POLICY_MIN_EXIT_SATS]
            if rich:
                src = rng.choice(rich)
                dst = rng.choice([u for u in normal_users if u != src])
                amt = rng.randint(POLICY_MIN_EXIT_SATS, min(users[src], 50_000_000))
                users[src] -= amt
                users[dst] += amt
                counts["transfer"] += 1

        elif act == "forced_exit":
            rich = [u for u in normal_users if users[u] >= 25_000_000]
            if rich:
                u = rng.choice(rich)
                amt = rng.choice([25_000_000, 50_000_000]) if users[u] >= 50_000_000 else 25_000_000
                eid = next_exit_id
                next_exit_id += 1
                mine_one_block([{"kind": "forced_exit", "user": u, "gross": amt, "exit_id": eid}])

        elif act == "front_paid":
            open_exits = [eid for eid in pending_exits if eid not in unconf_spent_exits]
            active_ops = [oid for oid, op in operators.items() if not op["suspended"]]
            if open_exits and active_ops:
                eid = rng.choice(open_exits)
                oid = rng.choice(active_ops)
                unconf_spent_exits.add(eid)
                mine_one_block([{"kind": "front_paid", "exit_id": eid, "op_id": oid}])

        elif act == "front_grief":
            open_exits = [eid for eid in pending_exits if eid not in unconf_spent_exits]
            active_ops = [
                oid for oid, op in operators.items()
                if not op["suspended"] and op["b_zbtc"] >= POLICY_B_ZBTC_CUSTODY_SLICE_SATS + POLICY_EXIT_GRIEF_SLASH_SATS
            ]
            if open_exits and active_ops:
                eid = rng.choice(open_exits)
                oid = rng.choice(active_ops)
                unconf_spent_exits.add(eid)
                mine_one_block([{"kind": "front_grief", "exit_id": eid, "op_id": oid}])

        elif act == "exit_cancel":
            # Ensure some exits can reach 288-block cancel age realistically
            cur_h = current_tip_height()
            expired = [
                eid for eid, ex in pending_exits.items()
                if eid not in unconf_spent_exits and cur_h >= ex["created_h"] + POLICY_T_EXIT_CANCEL
            ]
            if expired:
                eid = rng.choice(expired)
                unconf_spent_exits.add(eid)
                mine_one_block([{"kind": "exit_cancel", "exit_id": eid}])

        elif act == "take_honest":
            free_vaults = [vid for vid in confirmed_vaults if vid not in unconf_claimed_vaults]
            eligible = [
                (oid, vid)
                for oid, op in operators.items()
                for vid in free_vaults
                if op["credit"] - unconf_pending_credit_used[oid] >= confirmed_vaults[vid]
            ]
            if eligible:
                oid, vid = rng.choice(eligible)
                vamt = confirmed_vaults[vid]
                unconf_claimed_vaults.add(vid)
                unconf_pending_credit_used[oid] += vamt
                mine_one_block([{"kind": "take_honest", "op_id": oid, "vault_id": vid, "amount": vamt}])

        elif act == "disprove_dual_slash":
            active_ops = [
                oid for oid, op in operators.items()
                if not op["suspended"] and op["b_zbtc"] >= POLICY_B_ZBTC_CUSTODY_SLICE_SATS
            ]
            if active_ops:
                oid = rng.choice(active_ops)
                mine_one_block([{"kind": "disprove_dual_slash", "op_id": oid}])

        elif act == "lamport_equivocation_slash":
            free_vaults = [vid for vid in confirmed_vaults if vid not in unconf_claimed_vaults]
            active_ops = [
                oid for oid, op in operators.items()
                if not op["suspended"] and op["b_zbtc"] >= POLICY_MAX_VAULT_DENOM_SATS + POLICY_B_ZBTC_EQUIV_BOUNTY_SATS
            ]
            if free_vaults and active_ops:
                oid = rng.choice(active_ops)
                vid = rng.choice(free_vaults)
                unconf_claimed_vaults.add(vid)
                mine_one_block([{"kind": "lamport_equivocation_slash", "op_id": oid, "vault_id": vid}])

        elif act == "topup_op":
            susp = [oid for oid, op in operators.items() if op["suspended"]]
            if susp:
                oid = rng.choice(susp)
                op = operators[oid]
                needed = max(0, POLICY_B_ZBTC_TOTAL_SATS - op["b_zbtc"])
                if op["free_zbtc"] >= needed:
                    op["free_zbtc"] -= needed
                    op["b_zbtc"] += needed
                    op["suspended"] = False
                    counts["topup_op"] += 1
                elif sum(confirmed_vaults.values()) + SAT <= cap_sats:
                    # Operator deposits fresh BTC to replenish B_zbtc (still 1:1 backed!)
                    v1, v2 = next_vault_id, next_vault_id + 1
                    next_vault_id += 2
                    confirmed_vaults[v1] = 50_000_000
                    confirmed_vaults[v2] = 50_000_000
                    op["free_zbtc"] += SAT
                    op["free_zbtc"] -= needed
                    op["b_zbtc"] += needed
                    op["suspended"] = False
                    counts["topup_op"] += 1

        elif act == "mine_block":
            mine_one_block([])

        elif act == "reorg":
            # GENUINE Bitcoin tip reorg of depth 1..min(K-1, len(tip_blocks))!
            # Actually pops unconfirmed blocks, discards their orphaned events, and mines empty replacement chain.
            if tip_blocks:
                depth = rng.randint(1, min(K - 1, len(tip_blocks)))
                orphaned = tip_blocks[-depth:]
                del tip_blocks[-depth:]
                ev_reverted = sum(len(b["events"]) for b in orphaned)
                counts["reorg"] += 1
                counts["reorg_blocks_reverted"] += depth
                counts["reorg_events_reverted"] += ev_reverted
                rebuild_unconf_locks()
                for _ in range(depth):
                    mine_one_block([])

        assert_solvency(f"step_{step}_{act}")

    # Guarantee EXIT_CANCEL path is exercised if random steps didn't hit a 288-block idle exit
    if counts["exit_cancel"] == 0:
        u = next(u for u in normal_users if users[u] >= 25_000_000) if any(users[u] >= 25_000_000 for u in normal_users) else "challenger_pool"
        eid = next_exit_id
        next_exit_id += 1
        mine_one_block([{"kind": "forced_exit", "user": u, "gross": 25_000_000, "exit_id": eid}])
        for _ in range(K + POLICY_T_EXIT_CANCEL):
            mine_one_block([])
        mine_one_block([{"kind": "exit_cancel", "exit_id": eid}])
        for _ in range(K):
            mine_one_block([])
        assert_solvency("post_exit_cancel")

    # Flush remaining tip blocks to K-deep finality
    for _ in range(K):
        mine_one_block([])
    assert_solvency("final")
    return counts


# ==============================================================================
# MAIN ASSERTION SUITE
# ==============================================================================
def main() -> None:
    print("================================================================================")
    print("zBTC v1 (v3.0.0-rfc) ZERO-FEDERATION CONSISTENCY & BOUNDS CHECKER")
    print("Note: Checks internal mathematical consistency against SOURCED_, POLICY_, and")
    print("      PRE_MAINNET_TARGET_ inputs. Not an empirical Signet benchmark or audit.")
    print("================================================================================")

    # --------------------------------------------------------------------------
    # 1. STAGE 0: COINBASE MIDSTATE 1- VS 2-BLOCK FINAL PADDING
    # --------------------------------------------------------------------------
    print("\n=== 1. STAGE 0: COINBASE MIDSTATE 1-/2-BLOCK SHA-256 PADDING ===")
    one_blk_count = 0
    two_blk_count = 0
    for rem in range(64):
        total_len = 128 + rem  # 2 full prefix blocks + remainder tail (realistic >= 128 B coinbase)
        cb_bytes = bytes((i * 37 + rem) & 0xFF for i in range(total_len))
        # Compute real midstate over first 128 bytes
        st = _SHA256_IV
        st = sha256_compress(st, cb_bytes[0:64])
        st = sha256_compress(st, cb_bytes[64:128])
        midstate = struct.pack(">8I", *st)
        tail = cb_bytes[128:]
        got_txid, final_blks = complete_midstate_double_sha256(midstate, tail, total_len)
        expected_txid = hashlib.sha256(hashlib.sha256(cb_bytes).digest()).digest()
        assert got_txid == expected_txid, f"Midstate mismatch at rem={rem}"
        if rem < 56:
            assert final_blks == 1
            one_blk_count += 1
        else:
            assert final_blks == 2
            two_blk_count += 1
    assert one_blk_count == 56 and two_blk_count == 8
    two_blk_pct = 100.0 * two_blk_count / 64.0
    assert abs(two_blk_pct - 12.5) < 1e-9
    # Verify CVE-2017-12842 64-byte leaf rejection
    try:
        complete_midstate_double_sha256(b"\x00" * 32, b"", 64)
        raise AssertionError("64-byte coinbase length must be rejected!")
    except AssertionError as e:
        assert "CVE-2017-12842" in str(e)
    print(
        f"  Verified all 64/64 remainders against real hashlib.sha256 double-SHA256: "
        f"{one_blk_count} use 1 final block (rem 0..55), {two_blk_count} use 2 final blocks "
        f"(rem 56..63 = {two_blk_pct:.1f}% of coinbases); len==64 rejected."
    )

    # --------------------------------------------------------------------------
    # 2. STAGE 0: HONEST go-zenon THROUGHPUT, SPV ORACLE & DYNAMIC PLASMA PINNING
    # --------------------------------------------------------------------------
    print("\n=== 2. STAGE 0: go-zenon THROUGHPUT, SPV ORACLE & DYNAMIC PLASMA PINNING ===")
    rollup_tx_plasma = (
        SOURCED_ZNN_ACCOUNT_BLOCK_BASE_PLASMA
        + PRE_MAINNET_TARGET_ROLLUP_TX_DATA_BYTES * SOURCED_ZNN_AB_BYTE_DATA_PLASMA
    )
    assert rollup_tx_plasma == 28_480
    rollup_tx_qsr = ceil_div(rollup_tx_plasma, SOURCED_ZNN_PLASMA_PER_QSR)
    assert rollup_tx_qsr == 14
    base_tx_qsr = ceil_div(SOURCED_ZNN_ACCOUNT_BLOCK_BASE_PLASMA, SOURCED_ZNN_PLASMA_PER_QSR)
    assert base_tx_qsr == 10

    tps_floor = (POLICY_PINNED_MAX_BASE_PLASMA_FLOOR / SOURCED_ZNN_ACCOUNT_BLOCK_BASE_PLASMA / 2.0) / SOURCED_ZNN_OBSERVED_MOMENTUM_SECS
    tps_default = (SOURCED_ZNN_DP_DEFAULT_MAX_BASE_PLASMA / SOURCED_ZNN_ACCOUNT_BLOCK_BASE_PLASMA / 2.0) / SOURCED_ZNN_OBSERVED_MOMENTUM_SECS
    tps_naive_2p1b = (SOURCED_ZNN_DP_UPPER_MAX_BASE_PLASMA / SOURCED_ZNN_ACCOUNT_BLOCK_BASE_PLASMA / 2.0) / SOURCED_ZNN_OBSERVED_MOMENTUM_SECS
    # Real wire/protobuf ceiling governed by MaxDetailedMomentumWireSize (~8.38 MB) & MaxMomentumContentBytes (8 MiB)
    real_blocks_low = SOURCED_ZNN_MAX_DETAILED_MOMENTUM_WIRE // SOURCED_ZNN_MIN_ACCOUNT_BLOCK_WIRE_HIGH
    real_blocks_high = SOURCED_ZNN_MAX_DETAILED_MOMENTUM_WIRE // SOURCED_ZNN_MIN_ACCOUNT_BLOCK_WIRE_LOW
    real_tps_low = (real_blocks_low / 2.0) / SOURCED_ZNN_OBSERVED_MOMENTUM_SECS
    real_tps_high = (real_blocks_high / 2.0) / SOURCED_ZNN_OBSERVED_MOMENTUM_SECS
    assert 4.3 < tps_floor < 4.5
    assert 8.7 < tps_default < 8.9
    assert 4_385 < tps_naive_2p1b < 4_387
    assert 1_000 < real_tps_low < 1_100 and 1_200 < real_tps_high < 1_260
    assert real_tps_high < tps_naive_2p1b / 3.5

    max_contract_blocks_floor = POLICY_PINNED_MAX_BASE_PLASMA_FLOOR // SOURCED_ZNN_EMBEDDED_SIMPLE_TIER
    assert max_contract_blocks_floor == 40

    # Stage 0 Pure SPV Event Oracle calls matching spec/02 §2.2 byte-for-byte (ZERO custodial minting!):
    # - SubmitHeaderBatch(bytes headers): 4 + 32(off) + 32(len) + 160(2*80) = 228 B
    # - StepReorg(): 4 B
    # - PruneStaleHeaders(bytes hashes): 4 + 32(off) + 32(len) + 64(2*32) = 132 B
    # - ProveTxInclusion(u64 blockHeight, u32 txIndex, u32 totalCbBytes, bytes32 midstate,
    #                    bytes strippedTx, bytes32[] txBranch, bytes cbTail, bytes32[] cbBranch):
    #     payload = 8 + 4 + 4 + 32 + 6,144 + 512 + 63 + 512 = 7,279 B
    #     ABI = 4 + 8*32 + (32+6144) + (32+512) + (32+64) + (32+512) = 260 + 7,360 = 7,620 B
    prove_payload = 8 + 4 + 4 + 32 + POLICY_STAGE0_MAX_STRIPPED_TX_BYTES + 16 * 32 + 63 + 16 * 32
    prove_abi = (4 + 8 * 32) + (32 + POLICY_STAGE0_MAX_STRIPPED_TX_BYTES) + (32 + 16 * 32) + (32 + 64) + (32 + 16 * 32)
    assert prove_payload == 7_279 and prove_abi == 7_620

    stage0_calls = [
        ("SubmitHeaderBatch(1..2 headers)", SOURCED_ZNN_EMBEDDED_SIMPLE_TIER, 160, 4 + 32 + 32 + 160, 8, 1),
        ("StepReorg()", SOURCED_ZNN_EMBEDDED_SIMPLE_TIER, 0, 4, 6, 1),
        ("PruneStaleHeaders(1..2 hashes)", SOURCED_ZNN_EMBEDDED_SIMPLE_TIER, 64, 4 + 32 + 32 + 64, 4, 1),
        ("ProveTxInclusion(<=6KiB tx + midstate)", SOURCED_ZNN_EMBEDDED_HEAVY_SPV_TIER, prove_payload, prove_abi, 8, 1),
    ]
    max_spv_plasma = 0
    for name, tier, plen, abi_len, storage_ops, cblocks in stage0_calls:
        plasma = abi_embedded_plasma(tier, abi_len)
        qsr = ceil_div(plasma, SOURCED_ZNN_PLASMA_PER_QSR)
        max_spv_plasma = max(max_spv_plasma, plasma)
        assert abi_len <= SOURCED_ZNN_MAX_DATA_LENGTH
        assert storage_ops <= POLICY_STAGE0_MAX_STORAGE_OPS
        assert plasma <= POLICY_PINNED_MAX_BASE_PLASMA_FLOOR
        assert 3 * cblocks <= max_contract_blocks_floor
        if name.startswith("SubmitHeaderBatch"):
            assert abi_len == 228 and plasma == 67_732 and qsr == 33
        elif name.startswith("StepReorg"):
            assert abi_len == 4 and plasma == 52_500 and qsr == 25
        elif name.startswith("PruneStaleHeaders"):
            assert abi_len == 132 and plasma == 61_204 and qsr == 30
        elif name.startswith("ProveTxInclusion"):
            assert abi_len == 7_620 and plasma == 591_388 and qsr == 282
        print(
            f"  Stage 0 {name:40s}: payload={plen:5d} B | ABI={abi_len:5d} B | "
            f"plasma={plasma:7,d} ({qsr:3d} QSR) | ops<={storage_ops:2d} | cblks={cblocks}"
        )
    assert POLICY_PINNED_MAX_BASE_PLASMA_FLOOR >= 3 * max_spv_plasma

    # 1-block 110B rollup send throughput (no receive block needed, spec/03 §2.2)
    rollup_tps_floor = (POLICY_PINNED_MAX_BASE_PLASMA_FLOOR / rollup_tx_plasma) / SOURCED_ZNN_OBSERVED_MOMENTUM_SECS
    rollup_tps_default = (SOURCED_ZNN_DP_DEFAULT_MAX_BASE_PLASMA / rollup_tx_plasma) / SOURCED_ZNN_OBSERVED_MOMENTUM_SECS
    assert 6.3 < rollup_tps_floor < 6.6 and 12.8 < rollup_tps_default < 13.1

    # Dynamic Plasma unpinned target/denominator explosion proof (spec/05 §2.2)
    price_unpinned = SOURCED_ZNN_MIN_RESOURCE_PRICE
    for _ in range(52):  # ~9.9 minutes @ 11.4s/Momentum
        price_unpinned = dp_next_price(
            price_unpinned,
            used_plasma=SOURCED_ZNN_ACCOUNT_BLOCK_BASE_PLASMA,
            target_plasma=1,
            max_change_pct=POLICY_PINNED_MAX_PRICE_CHANGE_PCT,
            denom=1,
        )
    explosion_mult = price_unpinned / SOURCED_ZNN_MIN_RESOURCE_PRICE
    assert explosion_mult > 100_000, f"Expected >100,000x unpinned explosion, got {explosion_mult:.1f}x"
    # Verify pinned targets (>=25% of 2.1M = 525,000) & denom >= 8 stay completely flat under single tx!
    price_pinned = SOURCED_ZNN_MIN_RESOURCE_PRICE
    pinned_target = (POLICY_PINNED_MAX_BASE_PLASMA_FLOOR * POLICY_PINNED_MIN_TARGET_SHARE_PCT) // 100
    assert pinned_target == 525_000
    for _ in range(52):
        price_pinned = dp_next_price(
            price_pinned,
            used_plasma=SOURCED_ZNN_ACCOUNT_BLOCK_BASE_PLASMA,
            target_plasma=pinned_target,
            max_change_pct=POLICY_PINNED_MAX_PRICE_CHANGE_PCT,
            denom=POLICY_PINNED_MIN_PRICE_DENOM,
        )
    assert price_pinned == SOURCED_ZNN_MIN_RESOURCE_PRICE
    print(
        f"  Plasma transfer costs: native=21,000 ({base_tx_qsr} QSR), 110B rollup tx={rollup_tx_plasma:,} ({rollup_tx_qsr} QSR) @ floor 1,000"
    )
    print(
        f"  Throughput @ {SOURCED_ZNN_OBSERVED_MOMENTUM_SECS}s/Mom: 2-blk floor(2.1M)={tps_floor:.1f} / default(4.2M)={tps_default:.1f} tx/s "
        f"| 1-blk rollup={rollup_tps_floor:.1f}/{rollup_tps_default:.1f} tx/s | REAL 8 MiB ceiling={real_tps_low:,.0f}-{real_tps_high:,.0f} tx/s (vs naive 2.1B={tps_naive_2p1b:,.0f})"
    )
    print(
        f"  Contract-block cap @ 2.1M floor={max_contract_blocks_floor} | "
        f"unpinned DP (target=1,denom=1,52 Moms) price mult={explosion_mult:,.0f}x (>100,000x) vs pinned={price_pinned//1000}x"
    )

    # --------------------------------------------------------------------------
    # 3. STAGE 0: PTLC & LN TIMELOCK SAFETY MARGINS (2.3x SLOW BLOCKS)
    # --------------------------------------------------------------------------
    print("\n=== 3. STAGE 0: PTLC & LN TIMELOCK SAFETY MARGINS (2.3x SLOW BLOCKS) ===")
    bob_deadline_blks = POLICY_PTLC_BTC_CSV_BLOCKS - POLICY_PTLC_BOB_CONFIRM_MARGIN_BLOCKS
    assert bob_deadline_blks == 66
    t_btc_worst_2x = round(POLICY_PTLC_BTC_CSV_BLOCKS * SOURCED_BTC_TARGET_BLOCK_SECS * SOURCED_JUNE2021_SLOW_WEEKLY_MULT)
    t_bob_confirm_2p3x = round(bob_deadline_blks * SOURCED_BTC_TARGET_BLOCK_SECS * SOURCED_JUNE2021_SLOW_DAILY_MULT)
    t_refund_2p3x = round(POLICY_PTLC_BTC_CSV_BLOCKS * SOURCED_BTC_TARGET_BLOCK_SECS * SOURCED_JUNE2021_SLOW_DAILY_MULT)
    alice_margin_2p3x_secs = POLICY_PTLC_ZNN_DURATION_SECS - t_bob_confirm_2p3x
    assert t_btc_worst_2x == 86_400
    assert t_bob_confirm_2p3x == 91_080      # 25.3 hours
    assert t_refund_2p3x == 99_360           # 27.6 hours
    assert POLICY_PTLC_ZNN_DURATION_SECS == 108_000  # 30.0 hours (passed as now + 108_000 Unix ts)
    assert alice_margin_2p3x_secs == 16_920  # 4.7 hours > 0
    assert 2 * POLICY_LN_DELTA_SAFETY_BLOCKS <= POLICY_PTLC_BTC_CSV_BLOCKS
    # Verify consistent Unix-second conversion for LN HTLC delta (no subtracting blocks from seconds!)
    ln_delta_secs_nominal = POLICY_LN_DELTA_SAFETY_BLOCKS * SOURCED_BTC_TARGET_BLOCK_SECS
    ln_delta_secs_2x = round(POLICY_LN_DELTA_SAFETY_BLOCKS * SOURCED_BTC_TARGET_BLOCK_SECS * SOURCED_JUNE2021_SLOW_WEEKLY_MULT)
    ln_delta_secs_2p3x = round(POLICY_LN_DELTA_SAFETY_BLOCKS * SOURCED_BTC_TARGET_BLOCK_SECS * SOURCED_JUNE2021_SLOW_DAILY_MULT)
    assert ln_delta_secs_nominal == 21_600   # 6.0h nominal (spec/03 §1.2)
    assert ln_delta_secs_2x == 43_200        # 12.0h @ 2.0x slow blocks
    assert ln_delta_secs_2p3x == 49_680      # 13.8h @ 2.3x slow blocks
    print(
        f"  PTLC: CSV={POLICY_PTLC_BTC_CSV_BLOCKS} blks (Bob confirms <= h_conf+{bob_deadline_blks}) | "
        f"2.0x=24.0h | 2.3x June-2021 Bob confirm={t_bob_confirm_2p3x/3600:.1f}h < T_znn={POLICY_PTLC_ZNN_DURATION_SECS/3600:.1f}h "
        f"(Alice margin={alice_margin_2p3x_secs/3600:.1f}h; absolute Unix ts = now + 108,000)"
    )

    # --------------------------------------------------------------------------
    # 4. STAGE 1A: THEOREM 2 CAPITAL PROOF (BitVM2 vs RIGHT-SIZED BitVMX n=8)
    # --------------------------------------------------------------------------
    print("\n=== 4. STAGE 1A: THEOREM 2 CAPITAL PROOF (BitVM2 vs RIGHT-SIZED BitVMX) ===")
    bitvm2_m3_low = 3 * PRE_MAINNET_TARGET_BITVM2_LANE_BOND_BTC_LOW
    bitvm2_m3_high = 3 * PRE_MAINNET_TARGET_BITVM2_LANE_BOND_BTC_HIGH
    bitvm2_m5_low = 5 * PRE_MAINNET_TARGET_BITVM2_LANE_BOND_BTC_LOW
    bitvm2_m5_high = 5 * PRE_MAINNET_TARGET_BITVM2_LANE_BOND_BTC_HIGH
    assert abs(bitvm2_m3_low - 39.90) < 1e-6 and abs(bitvm2_m5_high - 90.875) < 1e-6
    assert bitvm2_m3_low > SOURCED_ZNN_MCAP_BTC_HIGH, "BitVM2 minimal M=3 exceeds 100% of ZNN mcap!"

    assert POLICY_LANE_TOTAL_BOND_SATS == 260_000_000  # 2.60 BTC/lane
    verifier_standby_btc = (POLICY_BITVMX_N_VERIFIERS * POLICY_F_CHAL_SATS) / SAT
    assert abs(verifier_standby_btc - 2.80) < 1e-9
    for label, prof in POLICY_STAGE1A_PROFILES.items():
        m = prof["M"]
        bonds_btc = (m * POLICY_BITVMX_L_LANES * POLICY_LANE_TOTAL_BOND_SATS) / SAT
        total_btc = bonds_btc + prof["float_btc"] + verifier_standby_btc
        pct_low = 100.0 * total_btc / SOURCED_ZNN_MCAP_BTC_HIGH
        pct_high = 100.0 * total_btc / SOURCED_ZNN_MCAP_BTC_LOW
        if m == 3:
            assert abs(bonds_btc - 7.80) < 1e-9 and abs(total_btc - 12.80) < 1e-9
        if m == 5:
            assert abs(bonds_btc - 13.00) < 1e-9 and abs(total_btc - 18.80) < 1e-9
        assert total_btc < bitvm2_m3_low
        print(
            f"  BitVMX {label:18s}: bonds={bonds_btc:5.2f} + float={prof['float_btc']:4.2f} + "
            f"verifiers={verifier_standby_btc:4.2f} = {total_btc:5.2f} BTC ({pct_low:.1f}%-{pct_high:.1f}% of 25-33 BTC ZNN mcap)"
        )
    print(
        f"  BitVM2 contrast (M=3..5, L=1, bonds only): {bitvm2_m3_low:.2f}-{bitvm2_m5_high:.3f} BTC "
        f"(>100%-275%+ of ZNN mcap before fronting float!)"
    )

    # --------------------------------------------------------------------------
    # 5. STAGE 1A: BitVMX n=8 BISECTION & 100% BIP-431 TRUC v3 COMPLIANCE
    # --------------------------------------------------------------------------
    print("\n=== 5. STAGE 1A: BitVMX-CPU n=8 BISECTION & BIP-431 TRUC v3 COMPLIANCE ===")
    interm_hashes_per_tx = POLICY_BITVMX_N_BRANCH - 1  # 7 intermediate 20B OP_HASH160 hashes
    data_digits_per_hash = 160 // 4                    # 40 base-16 nibbles
    max_checksum = data_digits_per_hash * 15           # 600 <= 16^3 - 1 = 4,095 -> 3 checksum digits
    assert max_checksum <= 16**3 - 1
    digits_per_hash = data_digits_per_hash + 3         # 43 digits
    digits_per_prover_tx = interm_hashes_per_tx * digits_per_hash
    assert digits_per_prover_tx == 301
    prover_wots_wu = math.ceil(digits_per_prover_tx * PRE_MAINNET_TARGET_WOTS_DIGIT_WU)
    assert prover_wots_wu == 28_746
    prover_wots_vb = prover_wots_wu / 4.0
    assert abs(prover_wots_vb - 7_186.5) < 1e-9
    prover_step_vb = prover_wots_vb + PRE_MAINNET_TARGET_BISECTION_OVERHEAD_VB
    assert abs(prover_step_vb - 7_436.5) < 1e-9
    assert prover_step_vb <= SOURCED_BIP431_TRUC_MAX_VB, "n=8 prover bisection tx must fit TRUC v3!"

    # Verify why rejected n=16 failed TRUC v3:
    n16_wots_vb = math.ceil(15 * digits_per_hash * PRE_MAINNET_TARGET_WOTS_DIGIT_WU) / 4.0 + PRE_MAINNET_TARGET_BISECTION_OVERHEAD_VB
    assert n16_wots_vb > SOURCED_BIP431_TRUC_MAX_VB

    instructions_covered = POLICY_BITVMX_N_BRANCH ** POLICY_BITVMX_SEARCH_ROUNDS
    assert instructions_covered == 2**27 == 134_217_728
    seq_steps = 1 + POLICY_BITVMX_SEARCH_ROUNDS + POLICY_BITVMX_SEARCH_ROUNDS + 1
    assert seq_steps == 20

    prover_total_vb = (
        POLICY_BITVMX_SEARCH_ROUNDS * prover_step_vb
        + PRE_MAINNET_TARGET_START_TX_VB
        + PRE_MAINNET_TARGET_FINAL_TRACE_TX_VB
    )
    verifier_total_vb = (
        PRE_MAINNET_TARGET_CHALLENGE_TX_VB
        + POLICY_BITVMX_SEARCH_ROUNDS * PRE_MAINNET_TARGET_VERIFIER_CHOICE_VB
        + PRE_MAINNET_TARGET_EXECUTE_OPCODE_VB
    )
    assert prover_total_vb <= PRE_MAINNET_TARGET_PROVER_CONSERVATIVE_VB
    assert verifier_total_vb <= PRE_MAINNET_TARGET_VERIFIER_CONSERVATIVE_VB

    prover_fee_500 = PRE_MAINNET_TARGET_PROVER_CONSERVATIVE_VB * POLICY_DESIGN_SUSTAINED_FEE_SATVB
    verifier_fee_500 = PRE_MAINNET_TARGET_VERIFIER_CONSERVATIVE_VB * POLICY_DESIGN_SUSTAINED_FEE_SATVB
    prover_breakeven_satvb = POLICY_F_CHAL_SATS // PRE_MAINNET_TARGET_PROVER_CONSERVATIVE_VB
    assert prover_fee_500 == 37_500_000 <= POLICY_F_CHAL_SATS
    assert verifier_fee_500 == 7_500_000
    assert prover_breakeven_satvb == 533
    print(
        f"  n=8 bisection: {interm_hashes_per_tx} hashes x {digits_per_hash} digits = {digits_per_prover_tx} digits = "
        f"{prover_wots_wu:,} WU ({prover_wots_vb:,.1f} vB) + 250 = {prover_step_vb:,.1f} vB <= 10,000 vB TRUC v3 "
        f"(rejected n=16 = {n16_wots_vb:,.0f} vB > 10,000 vB)"
    )
    print(
        f"  9 rounds -> 8^9 = 2^27 = {instructions_covered:,} RV32IM ops | {seq_steps} sequential steps | "
        f"Prover={prover_total_vb:,.1f} vB (~75 kvB; {prover_fee_500/SAT:.3f} BTC <= F_chal=0.40 BTC @ 500 sat/vB, "
        f"break-even={prover_breakeven_satvb} sat/vB) | Verifier={verifier_total_vb:,.0f} vB (cap 15 kvB; 0.075 BTC @ 500 sat/vB)"
    )

    # --------------------------------------------------------------------------
    # 6. STAGE 1A: SIMULTANEOUS TIMELOCKS & 256-BIT LAMPORT TakeTx BOUNDS
    # --------------------------------------------------------------------------
    print("\n=== 6. STAGE 1A: TIMELOCK ORDERING & 256-BIT LAMPORT TakeTx BIP-342/TRUC BOUNDS ===")
    max_dispute_end = POLICY_T_CHAL_WINDOW + seq_steps * POLICY_T_STEP
    assert max_dispute_end == 1_104
    assert POLICY_T_CHAL_WINDOW < max_dispute_end < POLICY_T_TAKE < POLICY_T_COOLDOWN < POLICY_T_RETIRE
    assert POLICY_T_COOLDOWN - POLICY_T_TAKE == 144  # 24h Lamport equivocation slash window
    assert PRE_MAINNET_TARGET_DEPOSIT_CERTBLOB_BYTES == 104 <= SOURCED_BIP342_MAX_PUSH_BYTES

    # Exact 256-bit Lamport L_{j,l,r} Tapscript leaf:
    # 256 x (OP_HASH160 [1B] + PUSH20 [1B] + 20B hash + OP_EQUALVERIFY [1B]) + PUSH32 [1B] + 32B Q_setup + OP_CHECKSIG [1B]
    lamport_script_bytes = 256 * (1 + 1 + 20 + 1) + (1 + 32 + 1)
    assert lamport_script_bytes == 5_922
    lamport_preimages_bytes = 256 * (1 + 20)  # 256 x (len=0x14 + 20B preimage)
    assert lamport_preimages_bytes == 5_376
    # Control blocks: Stage 1A (M=5, R=64 -> 320 leaves -> depth 9) & Stage 2 (40 lanes * 64 -> 2,560 leaves -> depth 12)
    leaves_stage1a = POLICY_BITVMX_M_MAX * POLICY_BITVMX_L_LANES * POLICY_BITVMX_R_ROUNDS
    leaves_stage2 = POLICY_STAGE2_TOTAL_LANES * POLICY_BITVMX_R_ROUNDS
    depth_stage1a = math.ceil(math.log2(leaves_stage1a))
    depth_stage2 = math.ceil(math.log2(leaves_stage2))
    assert leaves_stage1a == 320 and depth_stage1a == 9
    assert leaves_stage2 == 2_560 and depth_stage2 == 12
    cb_stage1a = 1 + 32 + 32 * depth_stage1a
    cb_stage2 = 1 + 32 + 32 * depth_stage2
    assert cb_stage1a == 321 and cb_stage2 == 417
    # Peak stack: 256 preimages + 1 Schnorr sig + 1 pushed 20B hash during OP_HASH160 <H> OP_EQUALVERIFY
    lamport_peak_stack = 256 + 1 + 1
    assert lamport_peak_stack == 258 < SOURCED_BIP342_MAX_STACK_ITEMS
    # Total TakeTx weight (2 inputs: U_d Lamport leaf + VaultConnector_r CSV leaf; 2 outputs: P2TR + P2A)
    take_non_witness = 10 + 2 * 41 + 43 + 13  # 148 B -> 592 WU
    take_wit_ud_s2 = (
        compact_size_len(259)
        + (1 + 64)
        + lamport_preimages_bytes
        + compact_size_len(lamport_script_bytes) + lamport_script_bytes
        + compact_size_len(cb_stage2) + cb_stage2
    )
    take_wit_connector = 110  # Conservative VaultConnector_r CSV tapscript witness
    take_total_wu = take_non_witness * 4 + take_wit_ud_s2 + take_wit_connector
    take_total_vb = take_total_wu / 4.0
    assert take_total_vb <= 3_200 <= SOURCED_BIP431_TRUC_MAX_VB
    print(
        f"  Timelocks: chal=[0,{POLICY_T_CHAL_WINDOW}] | max_dispute={max_dispute_end} < T_take={POLICY_T_TAKE} "
        f"< T_cooldown={POLICY_T_COOLDOWN} < Retire={POLICY_T_RETIRE} (144-blk equivocation margin)"
    )
    print(
        f"  Lamport TakeTx: script={lamport_script_bytes:,} B | preimages={lamport_preimages_bytes:,} B | "
        f"CB(depth 9/12)={cb_stage1a}/{cb_stage2} B | peak_stack={lamport_peak_stack} (<1,000) | "
        f"TakeTx={take_total_vb:,.1f} vB (<=3,200 <=10,000 TRUC v3)"
    )

    # --------------------------------------------------------------------------
    # 7. STAGE 1A: COLLUDING-VERIFIER POSITIVE-EV MATRIX (k_collude = 0..6 of N=7)
    # --------------------------------------------------------------------------
    print("\n=== 7. STAGE 1A: COLLUDING-VERIFIER POSITIVE-EV MATRIX (N=7, k_collude=0..6) ===")
    assert POLICY_WINNING_VERIFIER_L1_SATS + POLICY_BURNED_BOND_SATS == POLICY_BOND_BTC_SATS
    other_challenger_share = POLICY_B_ZBTC_CUSTODY_SLICE_SATS // (POLICY_BITVMX_N_VERIFIERS - 1)
    assert other_challenger_share == 9_166_666  # 0.09166666 BTC
    honest_min_net_ev = other_challenger_share - verifier_fee_500
    assert honest_min_net_ev == 1_666_666 > 0   # +0.01666666 BTC (> +0.0167 rounded)

    for k_collude in range(POLICY_BITVMX_N_VERIFIERS):
        honest_count = POLICY_BITVMX_N_VERIFIERS - k_collude
        assert honest_count >= 1
        vault_stolen = 0  # Dual-input Disprove/TimeoutSlash spends Stake_r AND VaultConnector_r!
        # Worst case for protocol: colluding verifier captures 0.15 BTC L1 win (when k_collude >= 1)
        # AND (k_collude - 1) other colluders each capture 1/6 of 0.55 BTC B_zbtc slice!
        colluder_l1_recapture = POLICY_WINNING_VERIFIER_L1_SATS if k_collude >= 1 else 0
        colluder_zbtc_recapture = max(0, k_collude - 1) * other_challenger_share
        # Upper-bound attacker P&L (even ignoring attacker's own L1 fees):
        colluder_pnl = (
            vault_stolen
            - POLICY_BOND_BTC_SATS
            - POLICY_B_ZBTC_CUSTODY_SLICE_SATS
            + colluder_l1_recapture
            + colluder_zbtc_recapture
        )
        assert colluder_pnl < 0
        if k_collude == 0:
            assert colluder_pnl == -255_000_000  # -2.55 BTC (O_j alone)
        if k_collude == 1:
            assert colluder_pnl == -240_000_000  # -2.40 BTC (O_j + colluding V_1)
        if k_collude == 6:
            assert colluder_pnl == -194_166_670  # -1.9417 BTC (O_j + 6 of 7 verifiers!)
        print(
            f"  k_collude={k_collude} (honest={honest_count}): vault_stolen=0 | "
            f"honest_EV>={honest_min_net_ev/SAT:+.4f} BTC (@500 sat/vB) | "
            f"combined_attacker_PnL={colluder_pnl/SAT:+.4f} BTC"
        )

    # --------------------------------------------------------------------------
    # 8. STAGE 1A: MULTI-TIER VAULTS {0.50, 0.25, 0.25} & 100% BANK-RUN MATH
    # --------------------------------------------------------------------------
    print("\n=== 8. STAGE 1A: MULTI-TIER VAULTS & 100% BANK-RUN EXIT DURATION ===")
    cooldown_days = POLICY_T_COOLDOWN / SOURCED_BTC_BLOCKS_PER_DAY
    assert abs(cooldown_days - 9.0) < 1e-9
    avg_vault_multi_btc = (sum(POLICY_VAULT_TIERS_SATS) / len(POLICY_VAULT_TIERS_SATS)) / SAT
    avg_vault_half_btc = (sum(POLICY_VAULT_ALT_SPLIT_SATS) / len(POLICY_VAULT_ALT_SPLIT_SATS)) / SAT
    assert abs(avg_vault_multi_btc - (1.0 / 3.0)) < 1e-9
    assert abs(avg_vault_half_btc - 0.50) < 1e-9

    for label, prof in POLICY_STAGE1A_PROFILES.items():
        m = prof["M"]
        cap_btc = prof["cap_btc"]
        float_btc = prof["float_btc"]
        vaults_per_day = (m * POLICY_BITVMX_L_LANES) / cooldown_days
        btc_per_day_multi = vaults_per_day * avg_vault_multi_btc
        btc_per_day_half = vaults_per_day * avg_vault_half_btc
        # Discrete vault batches remaining after immediate fronting float:
        total_vaults_multi = int(round(cap_btc / avg_vault_multi_btc))
        fronted_vaults_multi = int(float_btc // avg_vault_multi_btc)
        rem_vaults_multi = total_vaults_multi - fronted_vaults_multi
        bank_run_days_multi = math.ceil(rem_vaults_multi / m) * cooldown_days
        bank_run_days_multi_cont = (cap_btc - float_btc) / btc_per_day_multi
        bank_run_days_half_cont = (cap_btc - float_btc) / btc_per_day_half
        if m == 3:
            assert abs(vaults_per_day - 1.0 / 3.0) < 1e-9
            assert abs(btc_per_day_multi - 1.0 / 9.0) < 1e-9
            assert 70.0 <= bank_run_days_multi_cont <= 72.0 and bank_run_days_multi == 72.0
            assert 46.0 <= bank_run_days_half_cont <= 48.0
        if m == 5:
            assert abs(vaults_per_day - 5.0 / 9.0) < 1e-9
            assert abs(btc_per_day_multi - 5.0 / 27.0) < 1e-9
            assert 64.0 <= bank_run_days_multi_cont <= 66.0
            assert 42.5 <= bank_run_days_half_cont <= 44.0
        print(
            f"  {label:18s}: {vaults_per_day:.3f} vaults/d ({btc_per_day_multi:.3f} BTC/d @ avg 0.333 BTC) | "
            f"100% bank run = ~{bank_run_days_multi_cont:.1f}d (batch={bank_run_days_multi:.0f}d) "
            f"[~{bank_run_days_half_cont:.1f}d w/ {{0.50,0.50}}]"
        )

    # Finite-round admission cap (spec/01 §6): N_live_vaults <= 0.50 * RemainingTotalRounds
    max_live_vaults_m5 = (POLICY_BITVMX_M_MAX * POLICY_BITVMX_L_LANES * POLICY_BITVMX_R_ROUNDS) // 2
    assert max_live_vaults_m5 == 160 and max_live_vaults_m5 * avg_vault_multi_btc > 15.0

    # --------------------------------------------------------------------------
    # 9. HALVING-INDEXED TVL-SCALED K PRIVATE-FORK INEQUALITY
    # --------------------------------------------------------------------------
    print("\n=== 9. HALVING-INDEXED TVL-SCALED K PRIVATE-FORK INEQUALITY (0.50*K*Sub > Cap) ===")
    for cap_btc in POLICY_TVL_TIERS_BTC:
        k_cfg = POLICY_CONFIGURED_K_2024[cap_btc]
        assert 0.50 * k_cfg * SOURCED_BTC_SUBSIDY_BY_ERA["2024-2028"] > cap_btc
        row_parts = []
        for era, sub in SOURCED_BTC_SUBSIDY_BY_ERA.items():
            k_min = int(math.floor((2.0 * cap_btc) / sub)) + 1
            assert 0.50 * k_min * sub > cap_btc
            assert 0.50 * (k_min - 1) * sub <= cap_btc + 1e-12
            if era in POLICY_CONFIGURED_K_BY_ERA:
                k_era_cfg = POLICY_CONFIGURED_K_BY_ERA[era][cap_btc]
                assert k_era_cfg >= k_min and 0.50 * k_era_cfg * sub > cap_btc
            row_parts.append(f"{era}:K>={k_min}")
        print(f"  Cap={cap_btc:3d} BTC (2024 cfg K={k_cfg:3d}): " + " | ".join(row_parts))

    # --------------------------------------------------------------------------
    # 10. STAGE 1B (clArk) ALTERNATIVE GATE: LIQUIDITY & log2(N) EXIT WEIGHTS
    # --------------------------------------------------------------------------
    print("\n=== 10. STAGE 1B (clArk) ALTERNATIVE GATE: LIQUIDITY & log2(N) BRANCH EXIT WEIGHTS ===")
    clark_liq_low, clark_liq_high = PRE_MAINNET_TARGET_CLARK_ACTIVE_LIQ_BTC
    assert clark_liq_low == 2.0 and clark_liq_high == 5.0
    assert clark_liq_high < 12.80  # Strictly below Stage 1A BitVMX M=3 capital floor
    # Exact BIP-341 P2TR internal branch tx: 10.5 (hdr) + 57.5 (P2TR keypath in) + 2*43 (2 P2TR outs) + 13 (P2A) = 167 vB
    clark_branch_tx_vb = 167.0
    clark_leaf_tx_vb = 154.0
    for n_vtxo in PRE_MAINNET_TARGET_CLARK_VTXO_COUNTS:
        depth = int(math.log2(n_vtxo))
        assert 2**depth == n_vtxo
        total_exit_vb = depth * clark_branch_tx_vb + clark_leaf_tx_vb
        fee_100 = int(total_exit_vb * 100)
        fee_500 = int(total_exit_vb * 500)
        assert total_exit_vb < SOURCED_BIP431_TRUC_MAX_VB
        print(
            f"  N={n_vtxo:4d} VTXOs (depth={depth:2d}): unilateral branch exit={total_exit_vb:6.0f} vB | "
            f"@100 sat/vB={fee_100:,} sats | @500 sat/vB={fee_500:,} sats ({fee_500/SAT:.5f} BTC)"
        )
    print(f"  Active ASP liquidity turnover range: {clark_liq_low:.1f}-{clark_liq_high:.1f} BTC (0 operator bonds; expiring VTXOs)")

    # --------------------------------------------------------------------------
    # 11. REAL 2,000-STEP RANDOMIZED STAGE 1A SOLVENCY SIMULATION (ZERO NO-OPS!)
    # --------------------------------------------------------------------------
    print("\n=== 11. REAL 2,000-STEP STAGE 1A SOLVENCY SIMULATION (WITH GENUINE REORGS) ===")
    counts = run_stage1a_solvency_sim(seed=20261128, steps=2_000)
    for k, v in counts.items():
        assert v > 0, f"Event type {k} was never exercised: {counts}"
    assert counts["reorg_blocks_reverted"] >= counts["reorg"] > 0
    assert counts["reorg_events_reverted"] > 0
    summary = ", ".join(f"{k}={v}" for k, v in counts.items())
    print(f"  Bob (1->0.5->exit 0.5) & Mike (1+1->2->exit 0.25) + 2,000 adversarial steps PASSED 1:1 solvency:")
    print(f"  {summary}")
    print("\nALL v1 (v3.0.0-rfc ZERO-FEDERATION) CONSISTENCY, WEIGHT, PLASMA, TIMELOCK & SOLVENCY CHECKS PASSED.")


if __name__ == "__main__":
    main()
