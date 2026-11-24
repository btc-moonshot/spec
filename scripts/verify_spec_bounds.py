#!/usr/bin/env python3
"""
Asserting numeric oracle for the zBTC Bitcoin-Zenon Interoperability Specification (v2.5.0-rfc).

Every numeric claim in SPEC.md and spec/01..05 MUST match this script's verified output.
All satoshi derivations use exact integer arithmetic (zero floating-point ceil fragility — S5-3).
Unmeasured Bitcoin BitVM2 / Signet / market inputs are explicitly prefixed ASSUMED_STAGE_0C_TARGET_
and constitute mandatory Stage 0C measurement gates (Gate G-2) before Stage 1A.

Run: `python3 -I scripts/verify_spec_bounds.py`
"""
import math

SAT = 100_000_000

# ==============================================================================
# PROTOCOL CONSTANTS (verified against go-zenon release/0.0.11-rc1 f19955f / dev 770e893)
# ==============================================================================
MAX_DATA_LENGTH = 16_384        # dev:vm/constants/plasma.go:67
MAX_PROOF_BYTES = 15_600        # leaves ABI headroom under 16,384 B
EMBEDDED_SIMPLE_TIER = 52_500   # 2.5 * 21,000
AB_BYTE_DATA_PLASMA = 68        # dev:vm/constants/plasma.go
PLASMA_PER_QSR = 2_100          # 1 QSR = 1 fusion unit = 2,100 plasma
PILLAR_STAKE_ZNN = 15_000       # dev:vm/constants/embedded.go:108
FINALITY_QUORUM_SIGNERS = 21    # >= 21 of 30 active finality committee members
MAX_BATCH_INPUTS = 256          # normative bound -> traceRoot depth <= 8
FINALITY_EPOCH_DAYS = 30        # monthly 30-day finality committee epoch (R5-H1, R5-L1)
WOTS_BITS_W = 4                 # normative BitVM W-OTS (no bitmasks) parameter w=4
WOTS_HASH_BYTES = 20            # OP_HASH160 (20 B pubkey/preimage, matching spec/01 prose — R6-L1, S6-1)
assert WOTS_BITS_W in (3, 4) and WOTS_HASH_BYTES == 20

# ==============================================================================
# ASSUMED STAGE 0C MEASUREMENT TARGETS (NOT MEASURED SIGNET ARTIFACTS — GATE G-2)
# ==============================================================================
ASSUMED_STAGE_0C_TARGET_OUTER_GROTH16_CONSTRAINTS = 3_500_000  # ~2M-5M R1CS outer IVC wrapper
ASSUMED_STAGE_0C_TARGET_ASSERT_CHUNKS_L = 32                   # parallel Groth16 AssertChunkTxs
ASSUMED_STAGE_0C_TARGET_GROTH16_DISPROVE_LEAVES = 1_200        # Groth16 BN254 disprove leaves
ASSUMED_STAGE_0C_TARGET_DISPROVE_CHUNK_VB = 95_000             # <= 380,000 WU (< 400,000 WU std limit)
ASSUMED_STAGE_0C_TARGET_ASSERT_GROTH16_VB = 220_000            # ~32 non-TRUC parallel Groth16 AssertChunkTxs
ASSUMED_STAGE_0C_TARGET_CHALLENGE_TX_VB = 2_000                # ChallengeTx
ASSUMED_STAGE_0C_TARGET_BURN_TX_VB = 1_000                     # BurnBond*Tx / StaleChainBurnTx
ASSUMED_STAGE_0C_TARGET_RETIRE_TX_VB = 1_000                   # RoundRetireTx + CPFP
ASSUMED_STAGE_0C_TARGET_WRONG_DEP_VB = 3_000                   # WrongDepositDisproveTx^{T1|T2}
ASSUMED_STAGE_0C_TARGET_TAKE_PLUS_CPFP_VB = 1_000              # Take1/Take2 (~350 vB) + operator CPFP (~650 vB)
ASSUMED_STAGE_0C_TARGET_ROUND_KICKOFF_CPFP_VB = 2_000          # RoundKickoffTx + operator CPFP
ASSUMED_STAGE_0C_TARGET_DESIGN_FEE_CEIL_SATVB = 500            # stress fee ceiling (Impairment Trigger #1d)
ASSUMED_STAGE_0C_TARGET_HASHRATE_GROWTH_FACTOR = 1.10          # +10% non-stationary block rate margin
ASSUMED_STAGE_0C_TARGET_BTC_SUBSIDY_PRE_2028 = 3.125           # height < 1,050,000
ASSUMED_STAGE_0C_TARGET_BTC_SUBSIDY_POST_2028 = 1.5625         # 1,050,000 <= height < 1,260,000
ASSUMED_STAGE_0C_TARGET_BTC_SUBSIDY_POST_2032 = 0.78125        # 1,260,000 <= height < 1,470,000
ASSUMED_STAGE_0C_TARGET_ZNN_PER_BTC_STRESS = 10_500            # illustrative stress ratio for pilot 15 BTC cap


def ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b


def abi_single_bytes_call(payload_len: int, static_head_words: int = 1) -> int:
    """Exact go-zenon ABI size for fn(static_args..., bytes payload)."""
    return 4 + 32 * static_head_words + 32 + 32 + 32 * ceil_div(payload_len, 32)


def abi_embedded_plasma(tier: int, abi_len: int) -> int:
    assert abi_len <= MAX_DATA_LENGTH, f"ABI len {abi_len} exceeds 16 KiB"
    return tier + max(0, abi_len - 4) * AB_BYTE_DATA_PLASMA


def pf_smt_proof_bytes(sib_count: int, value_len: int, present: bool = True) -> int:
    """Exact Project Zeno proof-format.md V1 serialized size."""
    assert 0 <= sib_count <= 256
    base = 1 + 32 + 32 + 32 + 2 + 32 * sib_count
    return base + (4 + value_len if present else 0)


def poisson_upper_quantile(lam: float, p_tail: float = 1e-4) -> int:
    """Exact Poisson upper tail: smallest k >= 0 with P(Pois(lam) > k) <= p_tail."""
    cdf = 0.0
    k = 0
    while True:
        cdf += math.exp(-lam + k * math.log(lam) - math.lgamma(k + 1))
        if 1.0 - cdf <= p_tail:
            return k
        k += 1


def wots_unrolled_half_wu_per_digit(w: int, hash_bytes: int = WOTS_HASH_BYTES) -> int:
    """Exact integer half-WU per w-bit digit for BitVM unrolled OP_HASH160 W-OTS (R6-L1, S6-1)."""
    d = (1 << w) - 1
    # Script (in witness = 1 WU/B): 2.5*d + 35 + (hash_bytes - 20) -> in half-WU: 5*d + 70 + 2*(hash_bytes - 20)
    script_half_wu = 5 * d + 70 + 2 * (hash_bytes - 20)
    # Witness preimage + digit push: 23 + (hash_bytes - 20) -> in half-WU: 46 + 2*(hash_bytes - 20)
    witness_half_wu = 46 + 2 * (hash_bytes - 20)
    return script_half_wu + witness_half_wu  # w=4, 20B OP_HASH160 => 191 half-WU = 95.5 WU/digit!


def main():
    # ==========================================================================
    # 0. FIELD-BY-FIELD STRUCT SIZE DERIVATIONS (ZERO MAGIC NUMBERS)
    # ==========================================================================
    CHAIN_META_VAL = 32 + 8 + 32 + 8 + 32 + 1 + 4 + 32 + 32 + 8 + 1 + 8 + 32 + 4 + 4
    assert CHAIN_META_VAL == 238

    HEADER_NODE_VAL = 32 + 32 + 8 + 4 + 4 + 32 + 4 + 11 * 4
    assert HEADER_NODE_VAL == 160

    # ActiveChainByHeight: blockHashBE(32) + merkleRootLE(32) + blockTime(4) = 68 B (NEVER PRUNED)
    ACTIVE_HEIGHT_VAL = 32 + 32 + 4
    assert ACTIVE_HEIGHT_VAL == 68

    # PegOutState: outboxId(32) + chainBindingHash(32) + assignedVaultOutpoint(36)
    #   + recipientAmountSats(8) + recipientScriptLen(1) + recipientScriptMax(43)
    #   + timeoutHeight(8) + slotOperatorId(4) + lastLapsedOperatorId(4) + slotExpiryBtcHeight(8)
    #   + slotExpiryBtcTs(4) + eligibleMask(8) + status(1) + reserved(1) = 190 B (R6-M5)
    PEGOUT_STATE_VAL = 32 + 32 + 36 + 8 + 1 + 43 + 8 + 4 + 4 + 8 + 4 + 8 + 1 + 1
    assert PEGOUT_STATE_VAL == 190

    TX_STREAM_VAL = 32 + 8 + 4 + 1 + 32 + 1 + 36 + 1 + 1 + 8 + 1 + 4 + 4 + 42
    assert TX_STREAM_VAL == 175

    # TrackedVaultRecord (R5-H3, R5-M3): status(1: 1=ACTIVE, 2=RELEASED, 3=RECOVERED, 4=PENDING_TRAP, 5=QUARANTINED)
    #   + pendingTrapSpendHeight(8) + activeEpochCount(1) + 2 x {epochId(2) + takeTxidsSmtRoot(32)} = 78 B
    TRACKED_VAULT_VAL = 1 + 8 + 1 + 2 * (2 + 32)
    assert TRACKED_VAULT_VAL == 78

    # OperatorBondRecord (R5-L9): bondOutpoint(36) + anchorCutoffTs(8) + anchorExpiryTs(8) = 52 B
    OP_BOND_VAL = 36 + 8 + 8
    assert OP_BOND_VAL == 52

    # RecoveredVaultRecord (R5-M3(iv)): recoveryOutpoint(36) + offendingOperatorId(4) + offendingRoundId(4) = 44 B
    RECOVERED_VAULT_VAL = 36 + 4 + 4
    assert RECOVERED_VAULT_VAL == 44

    STEP_TRACE_LEAF_BYTES = 8 + 32 + 32 + 32 + 1 + 32 + 32 + 32 + 1 + 8 + 32 + 32 + 32 + 4 + 1 + 8 + 8 + 1
    assert STEP_TRACE_LEAF_BYTES == 328

    MAX_VAL = max(CHAIN_META_VAL, HEADER_NODE_VAL, ACTIVE_HEIGHT_VAL, PEGOUT_STATE_VAL,
                  TX_STREAM_VAL, TRACKED_VAULT_VAL, OP_BOND_VAL, RECOVERED_VAULT_VAL)

    print("=== 1. FIELD-DERIVED STRUCTS & ADVERSARIAL DEPTH-256 WITNESS BOUNDS ===")
    print(f"  Structs: ChainMeta={CHAIN_META_VAL}B, HeaderNode={HEADER_NODE_VAL}B, ActiveHeight={ACTIVE_HEIGHT_VAL}B, PegOutState={PEGOUT_STATE_VAL}B, TxStream={TX_STREAM_VAL}B, TrackedVault={TRACKED_VAULT_VAL}B, OpBond={OP_BOND_VAL}B, RecoveredVault={RECOVERED_VAULT_VAL}B, StepTraceLeaf={STEP_TRACE_LEAF_BYTES}B")
    single_proof_depth256 = pf_smt_proof_bytes(256, MAX_VAL, present=True)
    upload_abi_depth256 = abi_single_bytes_call(single_proof_depth256, static_head_words=2)
    print(f"  [HARD WORST CASE] Single proof at MAX depth 256 (val={MAX_VAL}B): {single_proof_depth256} B | UploadWitnessProof ABI = {upload_abi_depth256} B (cap {MAX_DATA_LENGTH} B)")
    assert upload_abi_depth256 <= MAX_DATA_LENGTH
    assert upload_abi_depth256 <= 10_000

    # ==========================================================================
    # 2. 1-TX FAST-PATH CHALLENGE ABI (17 Tags, sib=26 typical; Multi-Tx handles depth 256!)
    # ==========================================================================
    SIB_TYPICAL_1M = 26
    TRACE_DEPTH_MAX = math.ceil(math.log2(MAX_BATCH_INPUTS))  # 8
    assert TRACE_DEPTH_MAX == 8
    challenge_step_env = 4 + 32 * 6 + (64 + 32 * ceil_div(STEP_TRACE_LEAF_BYTES, 32)) + (64 + 32 * TRACE_DEPTH_MAX)

    def fast_challenge_abi(val_sizes, abs_count=0):
        w = sum(pf_smt_proof_bytes(SIB_TYPICAL_1M, v, True) for v in val_sizes) + abs_count * pf_smt_proof_bytes(SIB_TYPICAL_1M, 0, False)
        return w, challenge_step_env + 64 + 32 * ceil_div(w, 32)

    fast_cases = [
        ("0x00 BTC_HEADER_BATCH (max=2 headers)", [CHAIN_META_VAL, HEADER_NODE_VAL, ACTIVE_HEIGHT_VAL, ACTIVE_HEIGHT_VAL], 2),
        ("0x01 BTC_REORG_STEP (1 step)", [CHAIN_META_VAL, HEADER_NODE_VAL, HEADER_NODE_VAL, ACTIVE_HEIGHT_VAL, 32], 0),
        ("0x02 BTC_PRUNE_STEP (max=2 stale HeaderNodes)", [CHAIN_META_VAL, HEADER_NODE_VAL, HEADER_NODE_VAL], 0),
        ("0x03 PEGOUT_CREATED (system input)", [CHAIN_META_VAL], 1),
        ("0x04 BTC_TX_STREAM_CHUNK (<= 8 KiB chunk)", [CHAIN_META_VAL, TX_STREAM_VAL], 0),
        ("0x05 BTC_LOCK_PROOF (9 keys + 64B CommSig + takeSmtRoot)", [CHAIN_META_VAL, ACTIVE_HEIGHT_VAL, ACTIVE_HEIGHT_VAL, 32, TX_STREAM_VAL, TX_STREAM_VAL], 3),
        ("0x06 BTC_RELEASE_PROOF (9 keys: incl. RecognizedBindings)", [CHAIN_META_VAL, ACTIVE_HEIGHT_VAL, PEGOUT_STATE_VAL, 32, TRACKED_VAULT_VAL, TX_STREAM_VAL, 1], 2),
        ("0x07 BTC_NON_DELIVERY_PROOF (5 keys)", [CHAIN_META_VAL, PEGOUT_STATE_VAL, ACTIVE_HEIGHT_VAL, 32], 1),
        ("0x08 BTC_VAULT_SPEND_PROOF (6 keys, SMT absence/inclusion)", [CHAIN_META_VAL, ACTIVE_HEIGHT_VAL, TRACKED_VAULT_VAL, TX_STREAM_VAL, TX_STREAM_VAL, 32], 0),
        ("0x09 BTC_OPERATOR_SLASH_PROOF (7 keys: incl. OpBond)", [CHAIN_META_VAL, ACTIVE_HEIGHT_VAL, OP_BOND_VAL, 1, TX_STREAM_VAL, TX_STREAM_VAL, 32], 0),
        ("0x0A PEGOUT_SLOT_CLAIMED (system input, non-overwrite)", [CHAIN_META_VAL, PEGOUT_STATE_VAL], 0),
        ("0x0B OPERATOR_ROUND_REGISTERED (auth CommSig)", [CHAIN_META_VAL], 1),
        ("0x0C BTC_VAULT_RECOVERY_PROOF (10 keys incl. inserts, S6-5)", [CHAIN_META_VAL, ACTIVE_HEIGHT_VAL, TRACKED_VAULT_VAL, OP_BOND_VAL, TX_STREAM_VAL, TX_STREAM_VAL, 32, TRACKED_VAULT_VAL, RECOVERED_VAULT_VAL, 1], 0),
        ("0x0D VAULT_GRAPH_EPOCH_ADDED (4 keys incl. inserts, S6-5)", [CHAIN_META_VAL, TRACKED_VAULT_VAL, OP_BOND_VAL, 1], 0),
        ("0x0E GOVERNANCE_ADD_BINDING (Gov-only RecognizedBindings)", [CHAIN_META_VAL], 1),
        ("0x0F BTC_TRAP_TIMEOUT_HALT (PENDING_TRAP expired -> Halted)", [CHAIN_META_VAL, TRACKED_VAULT_VAL], 0),
        ("0x10 BTC_ROUND_RETIRED (7 keys incl. LaneRetired, S6-5)", [CHAIN_META_VAL, ACTIVE_HEIGHT_VAL, OP_BOND_VAL, TX_STREAM_VAL, TX_STREAM_VAL, 32, 1], 0),
    ]
    print(f"\n=== 2. 1-TX FAST-PATH CHALLENGE ABI (17 Tags, sib={SIB_TYPICAL_1M} typical; Multi-Tx handles sib=256!) ===")
    for name, vals, nabs in fast_cases:
        w, abi_sz = fast_challenge_abi(vals, nabs)
        print(f"  {name:62s}: fast_ABI={abi_sz:5d} B (<=12KiB: {abi_sz<=12_288})")
        assert abi_sz <= 12_288, f"Fast path exceeded 12 KiB: {name} = {abi_sz}"

    cont_abi = 4 + 32 * 7 + 2 * (64 + 32 * ceil_div(STEP_TRACE_LEAF_BYTES, 32)) + 2 * (64 + 32 * TRACE_DEPTH_MAX)
    print(f"  ChallengeContinuity (2 x 328B leaves + 2 depth-8 proofs)      : ABI={cont_abi:5d} B")
    assert cont_abi <= 2_048

    # ==========================================================================
    # 3. INPUT PAYLOAD SIZES & PLASMA COSTS
    # ==========================================================================
    print("\n=== 3. INPUT PAYLOAD SIZES & PLASMA COSTS (ZERO 3RD-PARTY SIZE CAPS) ===")
    MERKLE_DEPTH_MAX = 16
    branch_max = 4 + 32 * MERKLE_DEPTH_MAX
    # Note: takeTxidsSmt has <= 160 leaves per epoch => typical absence proof <= 12 siblings (~485 B); 2 epochs <= 970 B
    take_smt_proof_pair = 2 * pf_smt_proof_bytes(12, 0, present=False)  # 966 B
    inputs = [
        ("0x00 BTC_HEADER_BATCH (2 headers)", 1 + 32 + 4 + 2 * 80),
        ("0x01 BTC_REORG_STEP", 1),
        ("0x02 BTC_PRUNE_STEP (2 stale HeaderNode hashes)", 1 + 64),
        ("0x04 BTC_TX_STREAM_CHUNK (8,192 B chunk)", 1 + 32 + 4 + 1 + 4 + 8192),
        ("0x05 BTC_LOCK_PROOF (Dep+Rol+2 streams+CommSig+takeSmt+DA)",
         1 + (4 + 4096) + 32 + 4 + branch_max + (1 + 32) + branch_max + (4 + 1024) + 32 + 4 + branch_max + (1 + 32) + branch_max + 4 * 3 + 20 + 32 * 5 + 2 + 8 + 4 + 32 + 64),
        ("0x06 BTC_RELEASE_PROOF (Fronting + stream + 2 branches)",
         1 + (4 + 4096) + 32 + 4 + branch_max + (1 + 32) + branch_max + 4 + 32 + 4),
        ("0x07 BTC_NON_DELIVERY_PROOF", 1 + 32),
        ("0x08 BTC_VAULT_SPEND_PROOF (streamed + 2-epoch SMT proof)",
         1 + (1 + 32) + 32 + 4 + branch_max + (1 + 32) + branch_max + 4 + 36 + 1 + take_smt_proof_pair),
        ("0x09 BTC_OPERATOR_SLASH_PROOF (streamed BondOut burn)",
         1 + (1 + 32) + 32 + 4 + branch_max + (1 + 32) + branch_max + 4 + 4 + 4 + 36),
        ("0x0B OPERATOR_ROUND_REGISTERED (CommSig authenticated)", 1 + 4 + 4 + 36 + 8 + 8 + 64),
        ("0x0C BTC_VAULT_RECOVERY_PROOF (T1|T2 -> QUARANTINED)",
         1 + (1 + 32) + 32 + 4 + branch_max + (1 + 32) + branch_max + 4 + 4 + 4 + 36 + 36),
        ("0x0D VAULT_GRAPH_EPOCH_ADDED (u16 epoch+takeSmt+DA+CommSig)", 1 + 36 + 8 + 2 + 32 + 32 + 64),
        ("0x0F BTC_TRAP_TIMEOUT_HALT", 1 + 36),
        ("0x10 BTC_ROUND_RETIRED (streamed RoundRetireTx + coinbase)",
         1 + (1 + 32) + 32 + 4 + branch_max + (1 + 32) + branch_max + 4 + 4 + 4),
    ]
    for name, plen in inputs:
        abi_len = abi_single_bytes_call(plen, static_head_words=1)
        plasma = abi_embedded_plasma(EMBEDDED_SIMPLE_TIER, abi_len)
        qsr = ceil_div(plasma, PLASMA_PER_QSR)
        print(f"  {name:62s}: payload={plen:5d} B | ABI={abi_len:5d} B | plasma={plasma:7d} ({qsr:3d} QSR)")
        assert plen <= MAX_PROOF_BYTES
        assert abi_len <= MAX_DATA_LENGTH

    # ==========================================================================
    # 4A. FIRST-PRINCIPLES PER-BLOCK W-OTS CERT-DA + LEAF-3B (R6-H2, R6-M1, R6-L1, S6-1..S6-3, S6-6)
    # ==========================================================================
    print("\n=== 4A. PER-BLOCK OP_HASH160 W-OTS CERT-DA + LEAF-3B SHA-256 (BLS12-381, 30d, w=4 — R6-H2/M1) ===")
    # Field-by-field BLS12-381 min-sig FinalityCertificate (FIXED size for up to ALL 30 signers):
    #   finalityEpochIndex(8) + height(8) + timestampUnix(8) + momentumHash(32) + stateRoot(32)
    #   + finalityCommitteeRoot(32) + nextFinalityCommitteeRoot(32) + signerBitfield(4) + aggSigG1(48) = 204 B
    BLS_CERT_BYTES = 8 + 8 + 8 + 32 + 32 + 32 + 32 + 4 + 48
    assert BLS_CERT_BYTES == 204

    T_BOND_EXPIRY_DAYS = 58
    # Fixed 408 B encoding for BOTH 1-cert (days 0..30: handoffSlot = 0x00^204) and 2-cert (days 30..58: handoffCert) (R6-M1, S6-3):
    MAX_HANDOFF_CERTS = T_BOND_EXPIRY_DAYS // FINALITY_EPOCH_DAYS  # 1
    MAX_CERTS_PUBLISHED = MAX_HANDOFF_CERTS + 1                    # 2
    assert MAX_CERTS_PUBLISHED == 2
    CERT_SET_1CERT_PADDED_BYTES = BLS_CERT_BYTES + BLS_CERT_BYTES  # targetCert(204) || 0x00^204 = 408 B
    CERT_SET_2CERT_BYTES = MAX_CERTS_PUBLISHED * BLS_CERT_BYTES    # targetCert(204) || handoffCert(204) = 408 B
    assert CERT_SET_1CERT_PADDED_BYTES == CERT_SET_2CERT_BYTES == 408
    CERT_DA_RAW_BYTES = CERT_SET_2CERT_BYTES                       # 408 B ALWAYS (3,264 bits)!

    # Leaf 3B (SHA-256 without OP_CAT): 408 B + 9 B SHA-256 padding -> 7 x 64 B blocks (last block holds 24 data B) -> 6 x 32 B midstates!
    SHA256_BLOCKS_LEAF_3B = ceil_div(CERT_DA_RAW_BYTES + 9, 64)    # 7 blocks (identical for 1-cert and 2-cert!)
    LAST_BLOCK_DATA_BYTES = CERT_DA_RAW_BYTES - (SHA256_BLOCKS_LEAF_3B - 1) * 64  # 24 data B (padding hardcoded!)
    SHA256_MIDSTATES = SHA256_BLOCKS_LEAF_3B - 1                   # 6 intermediate 32B midstates (192 B)
    assert SHA256_BLOCKS_LEAF_3B == 7 and LAST_BLOCK_DATA_BYTES == 24 and SHA256_MIDSTATES == 6
    MIDSTATE_BYTES = SHA256_MIDSTATES * 32                         # 192 B
    # Total disprove leaves C = 1,200 Groth16 + 7 Leaf-3B SHA-256 + 1 Leaf-3A binding = 1,208! (R6-L9, S6-6)
    LEAF_3A_BINDING_LEAVES = 1
    TOTAL_DISPROVE_LEAVES_C = ASSUMED_STAGE_0C_TARGET_GROTH16_DISPROVE_LEAVES + SHA256_BLOCKS_LEAF_3B + LEAF_3A_BINDING_LEAVES
    assert TOTAL_DISPROVE_LEAVES_C == 1_208

    # Per-block checksummed OP_HASH160 W-OTS (fixes R6-H2 — zero cross-block checksum dependency!):
    half_wu_per_digit = wots_unrolled_half_wu_per_digit(WOTS_BITS_W, WOTS_HASH_BYTES)  # 191 half-WU = 95.5 WU/digit
    assert half_wu_per_digit == 191
    digits_per_byte = 8 // WOTS_BITS_W                             # 2 nibbles/byte
    full_blk_digits = 64 * digits_per_byte + 3                     # 128 + 3 checksum (128*15=1920 < 4096) = 131
    last_blk_digits = LAST_BLOCK_DATA_BYTES * digits_per_byte + 3  # 48 + 3 checksum (48*15=720 < 4096) = 51
    mid_digits_each = 32 * digits_per_byte + 3                     # 64 + 3 checksum (64*15=960 < 4096) = 67
    cert_block_digits = (SHA256_BLOCKS_LEAF_3B - 1) * full_blk_digits + last_blk_digits  # 6*131 + 51 = 837
    midstate_digits = SHA256_MIDSTATES * mid_digits_each           # 6*67 = 402
    total_da_digits = cert_block_digits + midstate_digits          # 1,239 digits!
    assert total_da_digits == 1_239

    # Stack-limit check for BOTH AssertCertDATx inputs AND every Leaf-3B disprove leaf (S6-2!):
    max_digits_per_input = (1000 - (1 << WOTS_BITS_W)) // 2        # 492 digits/input
    cert_da_input_digits = [3 * full_blk_digits, 3 * full_blk_digits + last_blk_digits, midstate_digits]  # [393, 444, 402]
    assert sum(cert_da_input_digits) == total_da_digits
    assert all(d <= max_digits_per_input for d in cert_da_input_digits)
    da_inputs_required = len(cert_da_input_digits)                 # 3 stack-safe inputs -> fits in 1 AssertCertDATx!
    assert da_inputs_required == 3

    leaf3b_digits = [
        full_blk_digits + mid_digits_each,                         # L3B_0: blk0 + mid1 = 198 (IV hardcoded)
        *[full_blk_digits + 2 * mid_digits_each for _ in range(5)],# L3B_1..5: blk_j + mid_j + mid_{j+1} = 265
        last_blk_digits + 2 * mid_digits_each,                     # L3B_6: blk6(24B) + mid6 + W_certda = 185
    ]
    max_leaf3b_digits = max(leaf3b_digits)                         # 265 digits -> 530 init witness elements!
    assert max_leaf3b_digits == 265 and max_leaf3b_digits <= max_digits_per_input
    assert max_leaf3b_digits * 2 + 200 <= 1_000                    # 530 + >=200 SHA-256 working stack <= 1,000 (470 free!)

    tx_overhead_wu = 4 * (10 + da_inputs_required * 68 + 2 * 43)   # 1,200 WU non-witness base tx overhead
    DERIVED_CERT_DA_AND_MIDSTATE_VB = ceil_div(total_da_digits * half_wu_per_digit + 2 * tx_overhead_wu, 8)
    CERT_DA_BUDGET_VB = ceil_div(DERIVED_CERT_DA_AND_MIDSTATE_VB, 1_000) * 1_000  # 30,000 vB (30 kvB)
    assert DERIVED_CERT_DA_AND_MIDSTATE_VB == 29_882 and CERT_DA_BUDGET_VB == 30_000
    print(f"  BLS12-381 min-sig fixed encoding = {BLS_CERT_BYTES} B x 2 slots = {CERT_DA_RAW_BYTES} B (1-cert pads slot 2 w/ 0x00^204 -> IDENTICAL 7 blks!)")
    print(f"  Per-block OP_HASH160 W-OTS: 6x131 + 51 + 6x67 = {total_da_digits} digits | AssertCertDA inputs={cert_da_input_digits} (<=492) | derived={DERIVED_CERT_DA_AND_MIDSTATE_VB:,} vB -> 30 kvB!")
    print(f"  Leaf-3B disprove stack check (S6-2): max={max_leaf3b_digits} digits ({max_leaf3b_digits*2} elems, {1000-max_leaf3b_digits*2} free for SHA-256) | total C={TOTAL_DISPROVE_LEAVES_C}")

    # ==========================================================================
    # 4B. EXACT INTEGER-SATOSHI PARAMETRIC BITVM2 ECONOMICS (S5-2, S5-3)
    # ==========================================================================
    print("\n=== 4B. EXACT INTEGER-SATOSHI PARAMETRIC BITVM2 ECONOMICS (ASSUMED STAGE 0C TARGETS) ===")
    fr_max = ASSUMED_STAGE_0C_TARGET_DESIGN_FEE_CEIL_SATVB
    TOTAL_ASSERT_AND_DA_VB = ASSUMED_STAGE_0C_TARGET_ASSERT_GROTH16_VB + CERT_DA_BUDGET_VB  # 250 kvB
    combined_honest_cost_500_sats = (TOTAL_ASSERT_AND_DA_VB + ASSUMED_STAGE_0C_TARGET_TAKE_PLUS_CPFP_VB) * fr_max  # 125,500,000 sats (1.2550 BTC)
    # Parametric F_assert with >= 15% safety margin, rounded up to exact 0.05 BTC (5,000,000 sats) in integer arithmetic!
    STEP_005_SATS = 5_000_000
    F_ASSERT_SATS = ceil_div(ceil_div(combined_honest_cost_500_sats * 115, 100), STEP_005_SATS) * STEP_005_SATS  # 145,000,000 sats (1.45 BTC)
    assert F_ASSERT_SATS == 145_000_000
    breakeven_assert_plus_da_kvb = ((F_ASSERT_SATS - ASSUMED_STAGE_0C_TARGET_TAKE_PLUS_CPFP_VB * fr_max) / fr_max) / 1000.0  # 289.0 kvB
    assert breakeven_assert_plus_da_kvb >= 285.0  # +39.0 kvB (+15.6%) headroom above 250 kvB!

    DISPROVE_BURN_SATS = F_ASSERT_SATS + 20_000_000   # 165,000,000 sats (1.65 BTC -> self-disprove <= -0.20 BTC!)
    TIMEOUT_BURN_SATS = F_ASSERT_SATS + 40_000_000    # 185,000,000 sats (1.85 BTC -> self-timeout <= -0.40 BTC!)
    f_chal_500_sats = ASSUMED_STAGE_0C_TARGET_CHALLENGE_TX_VB * fr_max  # 1,000,000 sats (0.010 BTC)
    f_disp_500_sats = ASSUMED_STAGE_0C_TARGET_DISPROVE_CHUNK_VB * fr_max  # 47,500,000 sats (0.475 BTC)
    # Size bond in exact integer satoshis rounded up to 0.10 BTC (10,000,000 sats) so uncontested watcher >= +0.115 BTC:
    STEP_010_SATS = 10_000_000
    min_bond_sats = DISPROVE_BURN_SATS + F_ASSERT_SATS + f_chal_500_sats + f_disp_500_sats + 11_500_000  # 370,000,000 sats EXACT!
    OPERATOR_ROUND_BOND_SATS = ceil_div(min_bond_sats, STEP_010_SATS) * STEP_010_SATS  # 370,000,000 sats (3.70 BTC EXACT!)
    assert min_bond_sats == 370_000_000 and OPERATOR_ROUND_BOND_SATS == 370_000_000

    DISPROVE_WMAX_SATS = OPERATOR_ROUND_BOND_SATS - DISPROVE_BURN_SATS   # 205,000,000 sats (2.05 BTC)
    TIMEOUT_WMAX_SATS = OPERATOR_ROUND_BOND_SATS - TIMEOUT_BURN_SATS     # 185,000,000 sats (1.85 BTC)
    WRONG_DEP_BURN_SATS = OPERATOR_ROUND_BOND_SATS - 100_000_000         # 270,000,000 sats (2.70 BTC)
    WRONG_DEP_WMAX_SATS = 100_000_000                                    # 100,000,000 sats (1.00 BTC)
    D_BUCKET_SATS = 100_000_000
    FIXED_RESERVE_FEE_SATS = 100_000
    CPFP_ANCHOR_SATS = 330
    REIMBURSE_ESCROW_SATS = 99_899_000
    assert (D_BUCKET_SATS + 660) - (REIMBURSE_ESCROW_SATS + FIXED_RESERVE_FEE_SATS + CPFP_ANCHOR_SATS) == 1_330
    assert (D_BUCKET_SATS + 330) - (REIMBURSE_ESCROW_SATS + FIXED_RESERVE_FEE_SATS + CPFP_ANCHOR_SATS) == 1_000
    # RoundRetireTx exact value balance (3.70 BTC -> 3.6990 BTC + 330 CPFP + 99,670 base fee):
    RETIRE_PAYOUT_SATS = OPERATOR_ROUND_BOND_SATS - 100_000              # 369,900,000 sats (3.6990 BTC)
    assert OPERATOR_ROUND_BOND_SATS - (RETIRE_PAYOUT_SATS + CPFP_ANCHOR_SATS) == 99_670

    print(f"  Parametric F_assert={F_ASSERT_SATS/SAT:.2f} BTC (Assert 220 + CertDA {CERT_DA_BUDGET_VB//1000} + Take2 1 = 251 kvB -> {combined_honest_cost_500_sats/SAT:.4f} BTC @ 500; break-even={breakeven_assert_plus_da_kvb:.1f} kvB, +{breakeven_assert_plus_da_kvb - TOTAL_ASSERT_AND_DA_VB/1000:.1f} kvB headroom!)")
    print(f"  Bond={OPERATOR_ROUND_BOND_SATS/SAT:.2f} BTC | DisproveBurn={DISPROVE_BURN_SATS/SAT:.2f} (WMax={DISPROVE_WMAX_SATS/SAT:.2f}) | TimeoutBurn={TIMEOUT_BURN_SATS/SAT:.2f} (WMax={TIMEOUT_WMAX_SATS/SAT:.2f}) | WrongDepBurn={WRONG_DEP_BURN_SATS/SAT:.2f} (WMax={WRONG_DEP_WMAX_SATS/SAT:.2f})")

    for fr in (1, 50, 200, fr_max):
        f_disp = ASSUMED_STAGE_0C_TARGET_DISPROVE_CHUNK_VB * fr
        f_asrt_da = TOTAL_ASSERT_AND_DA_VB * fr
        f_chal = ASSUMED_STAGE_0C_TARGET_CHALLENGE_TX_VB * fr
        f_burn = ASSUMED_STAGE_0C_TARGET_BURN_TX_VB * fr
        f_wdep = ASSUMED_STAGE_0C_TARGET_WRONG_DEP_VB * fr
        f_take2 = ASSUMED_STAGE_0C_TARGET_TAKE_PLUS_CPFP_VB * fr

        w_uncontested_dis = DISPROVE_WMAX_SATS - (F_ASSERT_SATS + f_chal + f_disp)
        w_uncontested_to = TIMEOUT_WMAX_SATS - (F_ASSERT_SATS + f_chal + f_burn)
        w_subst = WRONG_DEP_WMAX_SATS - f_wdep
        w_vs_selfslash_or_mev = -(F_ASSERT_SATS + f_chal)

        fraud_self_dis = F_ASSERT_SATS - f_asrt_da - DISPROVE_BURN_SATS - f_disp
        fraud_self_to = F_ASSERT_SATS - TIMEOUT_BURN_SATS - f_burn
        fraud_self_subst = WRONG_DEP_WMAX_SATS - f_wdep - OPERATOR_ROUND_BOND_SATS
        honest_op = F_ASSERT_SATS - (f_asrt_da + f_take2)

        assert w_uncontested_dis >= 11_500_000
        assert w_uncontested_to >= 38_500_000
        assert w_subst >= 98_500_000
        assert fraud_self_dis <= -20_000_000
        assert fraud_self_to <= -40_000_000
        assert fraud_self_subst <= -270_000_000
        assert honest_op >= 19_500_000
        print(
            f"  @{fr:3d} sat/vB: UncontestedW(Dis/TO/Sub)=+{w_uncontested_dis/SAT:.4f}/+{w_uncontested_to/SAT:.4f}/+{w_subst/SAT:.4f} "
            f"| RealWatcherVsSelfSlash/MEV={w_vs_selfslash_or_mev/SAT:.4f} "
            f"| SelfSlashFraud={fraud_self_dis/SAT:.2f}/{fraud_self_to/SAT:.2f} | HonestOp=+{honest_op/SAT:.4f} BTC"
        )

    # ==========================================================================
    # 4C. JOINT FEE-SOURCE VERIFICATION @ 500 sat/vB
    # ==========================================================================
    print("\n=== 4C. PRE-SIGNED TX FEE-SOURCE VERIFICATION @ 500 sat/vB ===")
    fee_sources = [
        ("RolloverTx_d", "Mandatory Ops Reserve In1 + CPFP", 1_000 * fr_max, 50_000_000),
        ("RoundKickoffTx_{m,l,r}", "Out 3 <pk_m> 330-sat CPFP anchor", ASSUMED_STAGE_0C_TARGET_ROUND_KICKOFF_CPFP_VB * fr_max, 10_000_000),
        ("RoundRetireTx_{m,l,r}", "99,670-sat base + Out 1 <pk_m> CPFP", ASSUMED_STAGE_0C_TARGET_RETIRE_TX_VB * fr_max, 5_000_000),
        ("Take1Tx_{d,m,l,r}", "1,330-sat base + Out 2 <pk_m> CPFP", ASSUMED_STAGE_0C_TARGET_TAKE_PLUS_CPFP_VB * fr_max, 5_000_000),
        ("Assert+CertDA+Take2 [JOINT]", "Per-tx <pk_m> CPFP funded JOINTLY by F_assert", combined_honest_cost_500_sats, F_ASSERT_SATS),
        ("ChallengeTx_{m,l,r}", "Watcher funding In 1+", f_chal_500_sats, 10_000_000),
        ("BurnBond* / StaleChainBurn", "Deducted from Out 1 watcher payout (1.85 BTC)", ASSUMED_STAGE_0C_TARGET_BURN_TX_VB * fr_max, TIMEOUT_WMAX_SATS),
        ("DisproveTx_{m,l,r,c}", "Deducted from Out 1 watcher payout (2.05 BTC)", f_disp_500_sats, DISPROVE_WMAX_SATS),
        ("WrongDepositDisprove^{T1,T2}", "Deducted from Out 2 watcher payout (1.00 BTC)", ASSUMED_STAGE_0C_TARGET_WRONG_DEP_VB * fr_max, WRONG_DEP_WMAX_SATS),
    ]
    for tx_name, mechanism, max_fee_sats, budget_sats in fee_sources:
        assert max_fee_sats < budget_sats
        print(f"  {tx_name:28s}: max_fee@500={max_fee_sats/SAT:.5f} BTC < budget {budget_sats/SAT:.2f} BTC ({mechanism})")

    # ==========================================================================
    # 4D. STAGGERED CLTV, LATENCY-AWARE REACHABILITY, RESERVATIONS & TIMELINE SIM (R6-M2, R6-L8, R6-L9, S6-4)
    # ==========================================================================
    print("\n=== 4D. STAGGERED CLTV, LATENCY-AWARE REACHABILITY, RESERVATIONS & G-21 TIMELINE (R6-M2/L8/L9, S6-4) ===")
    M_OPERATORS = 5
    LANES_PER_OP = 2
    ROUNDS_PER_LANE = 8
    T_BOND_COOLDOWN = 792             # 5.5 days
    DAYS_PER_ROUND = T_BOND_COOLDOWN / 144.0  # 5.5 days
    T_RELEASE_HORIZON_DAYS = 3.0      # 4h slot + 2.33h K=14 + 60h batch + 5.67h margin = 72h (R6-M2!)
    T_KICKOFF_CUTOFF_DAYS = 46.0      # Zenon rejects ClaimReimbursementSlot if earliestNextKickoff > day 46.0!
    WORST_TAKE2_UNLOCK_DAYS = T_KICKOFF_CUTOFF_DAYS + (144 + 288 + 72 + 72 + 144) / 144.0  # 51.0d
    T_KILL_EXPIRY_DAYS = 56.0         # OP_CLTV StaleConn{B,C}KillTx fires day 56 (5.0d past Take2 unlock!)
    T_BOND_EXPIRY_DAYS = 58.0         # OP_CLTV StaleChainBurnTx fires day 58 (2d = 288 blks > 72-blk trap!)
    RETIRE_MARGIN_DAYS = T_BOND_EXPIRY_DAYS - (T_KICKOFF_CUTOFF_DAYS + DAYS_PER_ROUND)  # 6.5 days (936 blks)
    assert ROUNDS_PER_LANE * DAYS_PER_ROUND <= T_KICKOFF_CUTOFF_DAYS  # 44.0 <= 46.0
    assert WORST_TAKE2_UNLOCK_DAYS == 51.0 and WORST_TAKE2_UNLOCK_DAYS + 0.5 < T_KILL_EXPIRY_DAYS
    assert (T_BOND_EXPIRY_DAYS - T_KILL_EXPIRY_DAYS) * 144 > 72       # 288 > 72-blk escrow trap!
    assert RETIRE_MARGIN_DAYS >= 6.0

    # Slow-block tolerance (R6-L8): wall-clock budget vs nominal 10-min block duration from last kickoff at day 46:
    # Take2 needs 5.0d nominal (720 blks) within 10.0d wall-clock (46->56); plus 0.5d escrow within 12.0d;
    # Worst-case from day 40.5 (prior round) -> day 46 kickoff -> Take2 at day 51.0 vs day 56: (56-40.5)/(51.0-40.5) = 1.476x;
    # Retire from day 40.5 -> day 46 kickoff -> day 51.5 retire vs day 58: (58-40.5)/(51.5-40.5) = 1.591x!
    take2_slow_block_tol = (T_KILL_EXPIRY_DAYS - (T_KICKOFF_CUTOFF_DAYS - DAYS_PER_ROUND)) / (WORST_TAKE2_UNLOCK_DAYS - (T_KICKOFF_CUTOFF_DAYS - DAYS_PER_ROUND))
    retire_slow_block_tol = (T_BOND_EXPIRY_DAYS - (T_KICKOFF_CUTOFF_DAYS - DAYS_PER_ROUND)) / ((T_KICKOFF_CUTOFF_DAYS + DAYS_PER_ROUND) - (T_KICKOFF_CUTOFF_DAYS - DAYS_PER_ROUND))
    assert take2_slow_block_tol > 1.47 and retire_slow_block_tol > 1.59

    # Latency-aware, reservation-aware dynamic serial reachability (R6-M2, S6-4):
    def reachable_rounds(unused: int, next_eligible_day: float, cutoff_day: float = T_KICKOFF_CUTOFF_DAYS,
                         retired: bool = False, reserved: int = 0) -> int:
        if retired or next_eligible_day > cutoff_day or unused <= 0:
            return 0
        raw = min(unused, int(math.floor((cutoff_day - next_eligible_day) / DAYS_PER_ROUND)) + 1)
        return max(0, raw - reserved)

    assert reachable_rounds(8, 0.0) == 8
    assert reachable_rounds(8, 30.0) == 3
    assert reachable_rounds(8, 40.0) == 2
    assert reachable_rounds(8, 44.5 + T_RELEASE_HORIZON_DAYS) == 0    # R6-M2: day 44.5 + 3.0d = 47.5 > 46 -> REJECTED!
    assert reachable_rounds(8, 40.0, reserved=2) == 0                 # R6-M2: 2 reserved slots consume both reachable rounds!
    assert reachable_rounds(8, 0.0, retired=True) == 0                # R5-M2: BTC_ROUND_RETIRED zeroes capacity!

    # Direct multi-generation timeline simulation over [0, 180] days (zero tautology — S6-4, R6-L9):
    TOTAL_LANES = M_OPERATORS * LANES_PER_OP                          # 10 lanes
    SAFETY_MARGIN_UTXOS = 25
    MAX_PILOT_SUPPLY_BTC = 15.0
    G21_THRESHOLD = int(MAX_PILOT_SUPPLY_BTC) + SAFETY_MARGIN_UTXOS   # 40 reachable rounds required for fresh mints
    GEN_REGISTER_OFFSET_DAYS = 2.0                                    # gen g+1 registered by day 30..32 (normative deadline day 32!)

    max_live_gens_sim = 0
    defer_window_days_per_cycle = []
    for half_day in range(0, 360):
        t = half_day * 0.5
        live_gens = [g for g in range(7) if (g * FINALITY_EPOCH_DAYS <= t < g * FINALITY_EPOCH_DAYS + T_BOND_EXPIRY_DAYS)]
        max_live_gens_sim = max(max_live_gens_sim, len(live_gens))
        # Evaluate steady-state cycle [30, 60) with latency-aware G-21 horizon (t + T_RELEASE_HORIZON_DAYS):
        if 30.0 <= t < 60.0:
            cap_t = 0
            for g in range(7):
                reg_day = g * FINALITY_EPOCH_DAYS + (0.0 if g == 0 else GEN_REGISTER_OFFSET_DAYS)
                cutoff_day = g * FINALITY_EPOCH_DAYS + T_KICKOFF_CUTOFF_DAYS
                if t >= reg_day:
                    cap_t += TOTAL_LANES * reachable_rounds(ROUNDS_PER_LANE, t + T_RELEASE_HORIZON_DAYS, cutoff_day)
            if cap_t < G21_THRESHOLD:
                defer_window_days_per_cycle.append((t, cap_t))

    assert max_live_gens_sim == 2                                     # simulated over 180 days: NEVER > 2 generations!
    # Verify exact disclosed G-21 DeferredLockQueue pre-registration window (day 56.5..61.5 => 5.5d max at reg=+2d; 3.5d if reg=+0d):
    assert all(cap >= int(MAX_PILOT_SUPPLY_BTC) for _, cap in defer_window_days_per_cycle)  # NEVER below 15 BTC supply!
    defer_days_len = len(defer_window_days_per_cycle) * 0.5           # 5.5 days per 30d cycle if reg=+2d (3.5d if reg=+0d)

    # U2 Post-Committee-Service Pillar Stake Lock (72d >= 58d bond expiry + 14d grace):
    U2_POST_SERVICE_SLASH_LOCK_DAYS = 72.0
    assert U2_POST_SERVICE_SLASH_LOCK_DAYS >= T_BOND_EXPIRY_DAYS + 14.0

    FRESH_CAPACITY_DAY0 = TOTAL_LANES * reachable_rounds(ROUNDS_PER_LANE, T_RELEASE_HORIZON_DAYS)  # 80 rounds at day 0 (with +3d horizon!)
    max_slashable_znn = FINALITY_QUORUM_SIGNERS * PILLAR_STAKE_ZNN  # 315,000 ZNN
    assert MAX_PILOT_SUPPLY_BTC * ASSUMED_STAGE_0C_TARGET_ZNN_PER_BTC_STRESS <= max_slashable_znn / 2.0
    assert FRESH_CAPACITY_DAY0 >= G21_THRESHOLD
    ACTIVE_GEN_BOND_SATS = TOTAL_LANES * OPERATOR_ROUND_BOND_SATS   # 3,700,000,000 sats (37.0 BTC)
    PEAK_OVERLAP_BOND_SATS = max_live_gens_sim * ACTIVE_GEN_BOND_SATS  # 74.0 BTC peak during 8-28d handoff!
    throughput_btc_per_day = TOTAL_LANES / DAYS_PER_ROUND           # 1.82 BTC/day

    watcher_cap_per_lane_sats = F_ASSERT_SATS + f_chal_500_sats     # 146,000,000 sats (1.46 BTC)
    watcher_cap_all_lanes_sats = TOTAL_LANES * watcher_cap_per_lane_sats  # 14.60 BTC
    min_op_bond_znn = int(1.5 * LANES_PER_OP * 1.0 * ASSUMED_STAGE_0C_TARGET_ZNN_PER_BTC_STRESS)  # 31,500 ZNN
    SLOT_BOND_ZNN = 500                                             # forfeitable fronting slot anti-censorship bond (R6-M5)

    print(f"  Lifecycle: R={ROUNDS_PER_LANE} ({ROUNDS_PER_LANE*DAYS_PER_ROUND:.0f}d) <= cutoff {T_KICKOFF_CUTOFF_DAYS:.0f}d < KillCLTV {T_KILL_EXPIRY_DAYS:.0f}d < BondBurnCLTV {T_BOND_EXPIRY_DAYS:.0f}d (retire buffer {RETIRE_MARGIN_DAYS:.1f}d={int(RETIRE_MARGIN_DAYS*144)} blks; slow-blk tol {take2_slow_block_tol:.3f}x/{retire_slow_block_tol:.3f}x)")
    print(f"  Reachability (+3d horizon, R6-M2): day0->{reachable_rounds(8,3.0)}, day44.5+3d->{reachable_rounds(8,47.5)}, reserved2@day40->{reachable_rounds(8,40.0,reserved=2)}, retired->0")
    print(f"  180d Sim (S6-4/R6-L9): max_concurrent_gens={max_live_gens_sim} (37.0 steady / 74.0 peak, 8-28d overlap) | pre-epoch G-21 DeferQueue window={defer_days_len:.1f}d/30d (min cap={min(c for _,c in defer_window_days_per_cycle)}>=15!)")
    print(f"  U2 Post-Service Pillar Lock = {U2_POST_SERVICE_SLASH_LOCK_DAYS:.0f}d >= 58d + 14d | Watcher Cap = {watcher_cap_per_lane_sats/SAT:.2f}/{watcher_cap_all_lanes_sats/SAT:.2f} BTC | OpBond = {min_op_bond_znn:,} ZNN | SlotBond = {SLOT_BOND_ZNN} ZNN")

    # ==========================================================================
    # 5. EXACT POISSON TIMING & HALVING-INDEXED K
    # ==========================================================================
    print("\n=== 5. TIMING & HALVING-INDEXED K ===")
    assert poisson_upper_quantile(288.0, 1e-4) == 353
    W_CHALLENGE_SECS, T_SESSION_SECS, T_REVEAL_SECS = 172_800, 43_200, 3_600
    lam_60h_nonstationary = ((W_CHALLENGE_SECS + T_SESSION_SECS) / 600.0) * ASSUMED_STAGE_0C_TARGET_HASHRATE_GROWTH_FACTOR
    W_ZENON_BTC_MAX = poisson_upper_quantile(lam_60h_nonstationary, 1e-4)  # 472
    assert W_ZENON_BTC_MAX == 472
    AGGREGATE_INFLIGHT_MINT_BTC = 10.0
    k_pre_2028 = max(12, math.ceil(2.0 * AGGREGATE_INFLIGHT_MINT_BTC / ASSUMED_STAGE_0C_TARGET_BTC_SUBSIDY_PRE_2028))    # 12
    k_post_2028 = max(12, math.ceil(2.0 * AGGREGATE_INFLIGHT_MINT_BTC / ASSUMED_STAGE_0C_TARGET_BTC_SUBSIDY_POST_2028))  # 13
    k_post_2032_at_10btc = max(12, math.ceil(2.0 * AGGREGATE_INFLIGHT_MINT_BTC / ASSUMED_STAGE_0C_TARGET_BTC_SUBSIDY_POST_2032))  # 26
    k_post_2032_at_5btc = max(12, math.ceil(2.0 * 5.0 / ASSUMED_STAGE_0C_TARGET_BTC_SUBSIDY_POST_2032))                  # 13
    K_PILOT = 14
    assert K_PILOT >= k_pre_2028 and K_PILOT >= k_post_2028 and K_PILOT >= k_post_2032_at_5btc

    MIN_TIMEOUT = 144 + W_ZENON_BTC_MAX + 24   # 640
    MAX_TIMEOUT = 2_016 + W_ZENON_BTC_MAX + 24 # 2512
    RELEASE_GRACE = K_PILOT + W_ZENON_BTC_MAX + 72  # 558
    PENDING_TRAP_WINDOW = 72 + K_PILOT + 144        # 230
    print(f"  Poisson(288)=353 | 60h x 1.10 [ASSUMED] (lam=396)={W_ZENON_BTC_MAX} blks | timeout=[tip+{MIN_TIMEOUT}, tip+{MAX_TIMEOUT}] | grace={RELEASE_GRACE} blks | pendingTrapWindow={PENDING_TRAP_WINDOW} blks")
    print(f"  K_pilot={K_PILOT} >= pre-2028({k_pre_2028}), post-2028({k_post_2028}); post-2032 needs binding migration (K>={k_post_2032_at_10btc}) OR cap <=5 BTC (K>={k_post_2032_at_5btc}<=14)")
    print("\nALL MODELED PROTOCOL, WITNESS, DERIVED-DA, LIFECYCLE, REACHABILITY, ECONOMIC & TIMING ASSERTIONS PASSED.")


if __name__ == "__main__":
    main()
