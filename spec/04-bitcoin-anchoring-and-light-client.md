# Part 4: Bitcoin Anchoring & Zenon Light Client Infrastructure

> **Scope Notice (`v1`):** Part 4 specifies **Zenon Network finality and light-client infrastructure (Phases U1–U2)**. It is **NOT a `v1` activation gate** and is **NOT in the `v1` (`Tier F`) Bitcoin custody safety path**. No `v1` custody or peg-out claim depends on Part 4. These mechanisms serve consumer light clients and establish foundational infrastructure for the non-normative `v2` Research Track ([`spec/01 Appendix A`](./01-bitcoin-taproot-vault-enforcement.md#appendix-a-non-normative-v2-research-annex-path-a-trust-minimized-bitvm)).

**Document Class:** Normative Zenon History-Anchoring & Light-Client Specification (`v1` / `v3.0.0-rfc`)  
**Consistency Checker:** [`scripts/verify_spec_bounds.py`](../scripts/verify_spec_bounds.py)

---

## 1. Dual-Bounded History Model & Honest Light-Client Trust Statement (`H-7`)

### 1.1 Lower Bound: Genesis Bitcoin Anchor (Live on Mainnet)

Zenon Genesis Momentum (`Height = 1`, hash `9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0`, ts `1637755200`) embeds Bitcoin mainnet block `710,968` (`000000000000000000004dd040595540d43ce8ff5946eeaa403fb13d0e582d8f`) in `Momentum.Data` (`chain/genesis/embedded_genesis_string.go:6`).

### 1.2 Upper Bound: Mandatory Epoch-Handoff & Periodic Checkpoint Anchoring (`H-7`)

At every **30-day finality epoch handoff** (mandatory) and periodically every `360` Momentums (~68 minutes at observed `11.4s`/Momentum — **M-10**), canonical signer-subset-independent `finalityDigest` commitments are anchored onto Bitcoin L1:

```text
finalityDigest = SHA3-256(
    "ZNN_FINALITY_V2" || u64BE(chainId) || u64BE(finalityEpochIndex) ||
    u64BE(height) || u64BE(timestampUnix) || momentumHash(32B) ||
    stateRoot(32B) || finalityCommitteeRoot(32B) || nextFinalityCommitteeRoot(32B)
)
c_h = SHA256("ZNN_BTC_ANCHOR_V2" || finalityDigest)
```

Valid BIP-341/342 Bitcoin encodings:
1. **Mode A (OpenTimestamps):** OTS SHA-256 Merkle path into a Bitcoin `OP_RETURN`.
2. **Mode B (`OP_RETURN`):** `OP_RETURN <44 bytes: "ZNNA"(4B) || u64BE(height)(8B) || c_h(32B)>`.
3. **Mode C (Taproot):** `Q = P + H_{"TapTweak"}(xonly(P) || c_h) * G` OR Tapscript `OP_FALSE OP_IF <32B c_h> OP_ENDIF <32B pk> OP_CHECKSIG`. *(Bare `OP_RETURN` inside an executable Tapscript leaf is forbidden under BIP-342.)*

**Mandatory Handoff Anchoring Incentive (`H-7` Fixed):**
- Anchoring each 30-day epoch handoff within `24` hours of `h_trans(E+1)` is a **normative duty of the active finality committee** (rotating lead anchorer among the 30 committee Pillars).
- If the committee fails to anchor within `24` hours, a permissionless fallback bounty from the Operations/Anchoring Reserve pays any anchorer `2×` the confirmed Bitcoin transaction fee upon submitting a `K`-deep SPV proof of the handoff anchor.
- Under `v2` (Research Gate **R-2**), any epoch lacking a confirmed handoff anchor halts `v2` BitVM targets until anchored.

### 1.3 Honest Light-Client Trust Statement (`H-7`)

> **What a mobile light client actually verifies:** *"Your device checks that a 21-of-30 Zenon Pillar BLS12-381 committee signed this Zenon state root, and that the commitment was timestamped on Bitcoin before any competing certified branch."* **State validity comes from the 21-of-30 Pillar committee; Bitcoin provides immutable timestamp ordering and long-range tie-breaking, NOT execution validity.**

---

## 2. Canonical Shared State Tree (`common/trie` & `proof-format.md` V1)

- NIST FIPS-202 `SHA3-256`, full depth `256`, MSB-first (`0` → left, `1` → right), `LeafHash(path, val) = SHA3-256(path || val)`, both-zero interior short-circuit `zero32`.
- L1 `common/trie` pre-hashes DB keys, applies `FoldFilter` (excluding `{0}/{1}/{2}`), and folds empty values to deletion.
- Wire format (`SmtProof`, deepest-first `i = 0..255` ⇒ `depth = 255 - i`):
  `flags(u8) || key(32B) || leaf_hash(32B) || sibling_bitmap(32B) || sib_count(u16) || siblings(sib_count*32B) [|| value_len(u32) || value]`
- State-tree retention: `17,380` Momentums (`~2.3` days at observed `11.4s`/Momentum); historical proof availability beyond `~2.3` days requires archive nodes (`StateTreeArchive: true`) — explicitly disclosed as a light-client proof-availability assumption.

---

## 3. Hardened 30-Day BLS12-381 Finality Committee (`H-1`, `L-1`, `N-1`, `M-11`)

### 3.1 Epoch-Averaged Slashable Committee Selection (`H-1` Fixed)

`v0` selected the top 30 Pillars by free, instant `totalDelegatedZnn` at a single snapshot Momentum `h_trans(E)` — allowing cheap 1-Momentum seat rental where only the `15,000 ZNN` self-bond was slashable. Counting fixed `15,000 ZNN` self-bonds alone also fails because all Pillars tie and fall back to grindable `producerAddress asc`.

**`v1` U2 Committee Selection Rule (`H-1`):**
- **30-Day Epoch:** `consensusEpoch(m) = (m.TimestampUnix - genesis.TimestampUnix) / 86400`; `finalityEpochIndex(m) = consensusEpoch(m) / 30`.
- **Slashable-Only Weighting & Anti-Rental Selection:** Committee eligibility requires a valid BLS12-381 `min-sig` key registered with IETF Proof-of-Possession (distinct DSTs `"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_ZBTC_V1_"` and `"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_ZBTC_V1_"`). Seats (`K_fin = 30`) are assigned via one of two normative U2 modes (ratified in `A-PILLAR-1`):
  1. **Variable Slashable Self-Bond (Preferred):** Pillars may post voluntary additional slashable self-bond (`>= 15,000 ZNN`, locked for the full epoch + `72` days); weight is the **time-weighted average slashable self-bond over the entire preceding 30-day epoch** (zero unslashable delegation weight, zero single-snapshot capture); OR
  2. **Unbiased Beacon Sampling:** If Pillar self-bonds remain uniform (`15,000 ZNN`), select `30` active BLS-registered Pillars (that remained active for the full preceding epoch) uniformly at random without replacement using a verifiable epoch randomness beacon (`H(prevEpochRandao || "ZBTC_FIN_COMMITTEE_V1")`), preventing address grinding.
- **Fixed-Depth-5 SHA-256 Merkle Tree:** `FinalityCommitteeRoot(E)` commits the `30` selected `(producerAddress(20B) || blsPubKeyG2(96B) || slashableWeightU64BE(8B))` leaves (`slots 30..31 = zero32`), stamped in Momentum Tag 15. Fixed `204 B` `FinalityCertificate`.

### 3.2 Edge-Case Behavior (`L-1` Fixed)

- **Fewer than 21 BLS-Registered Pillars (`< 21`):** If fewer than `21` active eligible Pillars hold registered BLS keys at `h_trans(E)` (e.g., during initial U2 rollout or severe churn), `FinalityCommitteeRoot(E)` is stamped as `zero32`, U2 finality certification pauses cleanly (entering `FINALITY_DEGRADED` mode), and Zenon falls back to baseline Momentum consensus + `30`-Momentum chain-bridge rollback protection (`protocol/chain_bridge.go:293`) without halting block production. Certification resumes automatically at the next epoch with `>= 21` eligible Pillars (for `21 <= eligible < 30`, quorum threshold is `ceil(2 * eligible / 3)` and `popcount >= 21` where `eligible >= 21`).
- **Competing Certified Branches in U2 Fork Choice (`L-1`):** If an honest node observes two conflicting valid dual-supermajority `FinalityCertificate`s for the same height (or conflicting certified branches):
  1. The node immediately broadcasts `SubmitEquivocationProof` for all double-signing Pillars;
  2. For fork selection, the node prefers the branch with the **earliest Bitcoin-confirmed `c_h` anchor** (`K >= 6` confirmations); if neither is anchored yet, it freezes finality advancement (`FINALITY_HALTED`), refuses automatic reorg across the certified conflict, and alerts operators for coordinated recovery. *(Full adoption of Bitcoin-anchored fork choice in consensus is Gate **R-2** for `v2`.)*

### 3.3 Slashing Rules, Quorum-Only Impairment & Height Gap (`N-1`, `M-11`, `M-14`)

- **`SubmitEquivocationProof(certA, certB)`:** Slashes **`100%` of each double-signing Pillar's slashable self-bond (`>= 15,000 ZNN`)** (`M-14` explicitly stated!) and revokes the Pillar. **Quorum-Only Impairment (`N-1` Fixed):** A single rogue Pillar equivocating (`sub-quorum`) is slashed and removed cleanly **WITHOUT triggering any bridge halt or M0 downgrade**! Only **quorum-level equivocation or forgery** (`popcount >= 21` conflicting certs) constitutes a finality impairment trigger.
- **`SubmitInvalidCertProof(cert)`:** Verifies signature under historical Tag-15 committee matching `cert.FinalityCommitteeRoot`, then slashes `100%` of every signer's slashable self-bond on:
  - **Case A (`cert.Height <= frontier.Height`):** Any of the 7 certificate fields disagrees with canonical Zenon state at `cert.Height`.
  - **Case B (`cert.Height > frontier.Height + 60`):** Non-existent future Momentum `> 60` heights (~11.4 minutes) ahead of frontier.
  - **Height-Gap Closure (`M-11`):** Light clients (and any future `v2` consumer) MUST NOT accept a certificate at height `h` until `h` is covered by a subsequent certified Momentum (or `frontier >= h`), closing the `(frontier, frontier + 60]` stall gap. *(Note: Zenon chain liveness is an explicit precondition for all on-chain slashing.)*
- **`72`-Day Post-Service Lock (`A-PILLAR-1`):** Retained for U2 Pillars (`RequestExitCommittee()` allows clean withdrawal once `72` days after `LastFinalityCommitteeEpoch` elapses without waiting an extra `% 90d` revoke cycle). Non-blocking for `v1`.

---

## 4. Light Client Verification Protocol & Bitcoin Header Sources (`H-7`)

A compliant Zenon light client verifies:
1. **Bitcoin Header Source (`H-7` Specified):** The client obtains Bitcoin mainnet headers via BIP-157/158 Neutrino P2P peers, embedded checkpoint headers + PoW header sync, or multi-endpoint verified header relays, asserting cumulative work `>= minimumPostAnchorWork` (`K_pilot * blockWork(genesisAnchor.nBits)`).
2. **Anchor SPV Inclusion (`H-7` Specified):** Verifies a Bitcoin Merkle inclusion proof (plus CVE-2017-12842 coinbase midstate proof) of the `c_h` anchor transaction in a Bitcoin block with `>= 6` confirmations and `|cert.TimestampUnix - anchorHeader.nTime| <= 21,600s` (`6h`), confirming no earlier conflicting certified anchor exists.
3. **Committee Chain & State Proof:** Verifies the 30-day BLS12-381 `FinalityCertificate` chain from genesis/anchored checkpoint, verifies `proof-format.md` V1 `SmtProof` against `cert.StateRoot`, and recomputes `AccountBlock.ComputeHash()` (`dev:chain/nom/account_block.go:283`).
4. **Anti-Frontier Boundary:** $O(k)$ bounded-frontier verification is permitted ONLY for read-only consumer wallet UI hints; strictly prohibited for settlement, peg-in/peg-out accounting, or signer policy.
