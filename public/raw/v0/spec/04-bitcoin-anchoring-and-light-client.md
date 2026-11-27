# Part 4: Bitcoin Anchoring & Light Client Verification Specification

**Document Class:** Normative History-Anchoring, State-Proof & Light-Client Specification (`v2.5.0-rfc`, subject to Upstream Amendment `A-PILLAR-1`)  
**Upstream Baselines:** [`bigidea`](https://btc-moonshot.github.io/bigidea/), `Project Zeno/merkle-state/MERKLE_STATE_ROOT.md`, `MERKLE_STATE_L2_ALIGNMENT.md`, `Project Zeno/artifacts/proof-format.md`, `docs/architecture/bounded-verification-boundries.md`, `docs/specs/Minimum Verifier Spec.md`, `docs/research/bitcoin_anchoring.pdf`

---

## 1. Dual-Bounded History Model (Certified-AND-Anchored Light Clients + `56d`/`58d` BitVM2 Expiry)

### 1.1 Lower Bound: Genesis Bitcoin Anchor (Already Live on Mainnet)

Zenon Genesis Momentum (`Height = 1`, hash `9e204601d1b7b1427fe12bc82622e610d8a6ad43c40abf020eb66e538bb8eeb0`, ts `1637755200`) embeds Bitcoin block hash `000000000000000000004dd040595540d43ce8ff5946eeaa403fb13d0e582d8f` (Bitcoin mainnet block `710,968`, consistent with ts `1637755200`) inside `Momentum.Data` ([`chain/genesis/embedded_genesis_string.go:6`](https://github.com/zenon-network/go-zenon/blob/770e893a0aa78240685043c1d396c65caa1a6635/chain/genesis/embedded_genesis_string.go#L6), [`chain/genesis/embedded_genesis_test.go:11`](https://github.com/zenon-network/go-zenon/blob/770e893a0aa78240685043c1d396c65caa1a6635/chain/genesis/embedded_genesis_test.go#L11)).

### 1.2 Upper Bound: Periodic Checkpoint Anchoring (`finalityDigest`)

Every `360` Momentums (~1h) and at every **30-day finality epoch handoff**, permissionless anchorers commit the canonical signer-subset-independent `finalityDigest` onto Bitcoin L1:

```text
finalityDigest = SHA3-256(
    "ZNN_FINALITY_V2" ||
    u64BE(chainId) ||
    u64BE(finalityEpochIndex) ||    // 30-day monthly finality epoch (R5-H1, R5-L1!)
    u64BE(height) ||
    u64BE(timestampUnix) ||
    momentumHash(32B) ||
    stateRoot(32B) ||
    finalityCommitteeRoot(32B) ||
    nextFinalityCommitteeRoot(32B)
)
c_h = SHA256("ZNN_BTC_ANCHOR_V2" || finalityDigest)
```

Valid BIP-341/342 Bitcoin encodings:
1. **Mode A (OpenTimestamps)**: OTS SHA-256 Merkle path into a Bitcoin `OP_RETURN`.
2. **Mode B (`OP_RETURN`)**: `OP_RETURN <44 bytes: "ZNNA"(4B) || u64BE(height)(8B) || c_h(32B)>`.
3. **Mode C (Taproot)**: `Q = P + H_{"TapTweak"}(xonly(P) || c_h) * G` OR Tapscript `OP_FALSE OP_IF <32B c_h> OP_ENDIF <32B pk> OP_CHECKSIG`. *(Bare `OP_RETURN` inside an executable Tapscript leaf is forbidden under BIP-342.)*

### 1.3 Certified-AND-Anchored Fork Choice (Light Clients) & BitVM2 Long-Range Defense

- **Light Clients**: Uncertified anchors carry ZERO authority; accepted ONLY alongside a valid dual-supermajority BLS12-381 `FinalityCertificate` whose `finalityDigest` hashes to `c_h` and whose `|cert.TimestampUnix - anchorHeader.nTime| <= 21,600`s (`<= 6h`). Earliest Bitcoin block embedding a valid `c_h` wins conflicting certified histories; conflicts trigger `REFUSED` + on-chain equivocation evidence.
- **Stateless BitVM2 Verifiers (`R5-L2`, `R6-H1`)**: Do NOT rely on an unanchored in-SNARK Bitcoin header check. Instead, long-range protection rests on THREE coupled mechanisms (subject to Assumption #3 challenging invalid kickoffs): (i) **staggered Bitcoin `OP_CLTV` expiry (`56d` `StaleConnB/CKill`, `58d` `StaleChainBurn`, [`spec/01 §3.2, §3.4`](./01-bitcoin-taproot-vault-enforcement.md#L54-L97))**, (ii) **mandatory on-chain Bitcoin publication of the fixed `408 B` `targetCert || handoffSlot` across `7` per-block `OP_HASH160` W-OTS blocks + `6` midstates in `AssertCertDATx` (`29,882 vB → 30 kvB` derived, `G-23`)**, and (iii) **historical-root `SubmitInvalidCertProof` + U2 `72`-day post-committee-service Pillar stake lock** (`>= 58d + 14d` grace, §3.3 below), making every in-scope historical committee signer slashable on Zenon when challenged and published!

---

## 2. Canonical Shared State Tree (`common/trie` & `proof-format.md` V1)

Byte-exact reproduction of `Project Zeno/merkle-state/MERKLE_STATE_ROOT.md`, `MERKLE_STATE_L2_ALIGNMENT.md`, and `Project Zeno/artifacts/proof-format.md` §4:
- NIST FIPS-202 `SHA3-256`, full depth `256`, MSB-first (`0` → left, `1` → right), `LeafHash(path, val) = SHA3-256(path || val)`, both-zero interior short-circuit `zero32`.
- **L1 vs L2 Empty Semantics**: L1 `common/trie` pre-hashes DB keys, applies `FoldFilter` (excluding `{0}/{1}/{2}`), and folds empty values to deletion; L2 `smtcore` uses 32-byte paths directly and distinguishes present-empty (`SHA3-256(path)`) from absent (`zero32`).
- **Wire Format (`SmtProof`, deepest-first `i = 0..255` ⇒ `depth = 255 - i`)**:
  ```text
  flags(u8) || key(32B) || leaf_hash(32B) || sibling_bitmap(32B) || sib_count(u16) || siblings(sib_count*32B) [|| value_len(u32) || value]
  ```
- Never anchor cross-language proofs to `Momentum.ChangesHash` (`goleveldb.Batch.Dump()`).

---

## 3. 30-Day BLS12-381 `FinalityCommitteeRoot`, Economic Handoff Pin, Historical-Root Slashing & `72`-Day Lock (`R6-H1`, `R6-L7`, `A-PILLAR-1`)

### 3.1 Immutable 30-Day BLS12-381 `min-sig` `FinalityCommitteeRoot`

- **30-Day Finality Epoch Index** (derived from `dev:consensus/consensus.go:45,86` 24h consensus epochs without altering reward epochs): `consensusEpoch(m) = (m.TimestampUnix - genesis.TimestampUnix) / 86400`; **`finalityEpochIndex(m) = consensusEpoch(m) / 30`**, with **`finalityEpochStartTs(E) = genesis.TimestampUnix + E * 30 * 86400`**.
- **IETF BLS12-381 `min-sig` POP Scheme (`draft-irtf-cfrg-bls-signature-05`, `A-PILLAR-1`, `R6-L7`)**:
  - Signing DST: `"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_ZBTC_V1_"` (hash-to-G1 over `finalityDigest`, `48 B` compressed G1 sig, `96 B` compressed G2 pubkey).
  - Proof-of-Possession DST (`PillarContract.RegisterFinalityKey(blsPubKeyG2, popSigG1)`): **`"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_ZBTC_V1_"`** (distinct DST preventing rogue-key attacks!).
- **Exact `FinalityCommitteeRoot(E)` Merkle Tree (`R6-L7`)**: At exact transition Momentum `h_trans(E)` (first Momentum advancing `finalityEpochIndex` to `E`), consensus snapshots top `K_fin = 30` active registered Pillars (excluding `ExitCommitteeRequested == true`) ordered by `(totalDelegatedZnn desc, producerAddress asc)`, computes a **fixed-depth-5 (`32`-leaf, slots `30..31 = zero32`) SHA-256 Merkle tree** over `SHA256("ZBTC_COMMITTEE_LEAF_V1" || producerAddress(20B) || blsPubKeyG2(96B) || weightU64BE(8B))`, stamps Momentum Tag 15, records `HistoricalCommitteeRoot[FinalityCommitteeRoot(E)] = E` on-chain, and stamps `LastFinalityCommitteeEpoch = E` on each selected `PillarInfo`!
- **Fixed `204 B` `FinalityCertificate`** (even when ALL `30` of `30` Pillars sign!): `finalityEpochIndex(8) || height(8) || timestampUnix(8) || momentumHash(32) || stateRoot(32) || finalityCommitteeRoot(32) || nextFinalityCommitteeRoot(32) || signerBitfield(4) || aggSignatureG1(48)`. *(Note: `chainId` is bound implicitly via the signing digest `finalityDigest` above, NOT repeated inside the 204 B payload — `R6-L7`.)*

### 3.2 Canonical `nextFinalityCommitteeRoot` & Economic Handoff Pin (`R6-H1`)

- **Canonical Values Defined at EVERY Height `h`**:
  - At the **exact epoch-transition Momentum `h = h_trans(E + 1)`**: `canonicalSigningCommitteeRoot(h) = FinalityCommitteeRoot(E)` and **`canonicalNextCommitteeRoot(h) = FinalityCommitteeRoot(E + 1)`** (Momentum Tag 15 at `h_trans(E + 1)`).
  - At **EVERY non-transition height `h`** inside epoch `E`: `canonicalSigningCommitteeRoot(h) = FinalityCommitteeRoot(E)` and **`canonicalNextCommitteeRoot(h) = FinalityCommitteeRoot(E)`** (unchanged!).
- **No `CarryOverCertificate` & Honest Economic Enforcement (`R6-H1`)**: `CarryOverCertificate` is **DELETED** — every 30-day epoch deterministically snapshots `FinalityCommitteeRoot(E+1)` at `h_trans(E+1)`. Because the stateless BitVM2 circuit only pins `E_anchor_root` and has NO oracle for future `h_trans(E+1)` or `Root(E+1)`, the circuit verifies the fixed `408 B` `targetCert || handoffSlot` chain (`handoffSlot == 0x00^204` if `target.epoch == E_anchor`, else `handoffCert` chains `E_anchor_root → handoffCert.NextFinalityCommitteeRoot → targetCert`), while the transition-height pin is enforced **economically** via historical-root `SubmitInvalidCertProof` Case A below!

### 3.3 Finality Gadget, Historical-Root Full-Preimage Slashing & `72`-Day Post-Service Lock (`R6-H1`, `A-PILLAR-1`)

- **Dual Supermajority & U2 Finality Gadget**: Valid `FinalityCertificate` requires `popcount(signerBitfield) >= 21` (of 30) AND `sum(signedWeight) * 3 > 2 * sum(totalWeight)`, verified by BLS12-381 `FastAggregateVerify` over `finalityDigest` (with canonical `chainId` and signing DST). Honest Pillars sign ONLY at depth **`>= 6` Momentums**, and U2 consensus refuses `DeleteMomentum` across any dual-supermajority-certified Momentum.
- **Checkpoint Restriction for BitVM2**: Target certificates accepted by BitVM2 MUST sit at canonical checkpoint heights (`height % 30 == 0` OR transition height `h_trans`).
- **Two Comprehensive On-Chain Slashing Paths (`dev:vm/embedded/{definition,implementation}/pillars.go`, Phase U2)**:
  1. **`SubmitEquivocationProof(certA, certB)`**: Slashes any Pillar signing two conflicting `FinalityCertificate`s for the same `(finalityEpochIndex, height)` (unconditional even sub-quorum).
  2. **`SubmitInvalidCertProof(cert)` (Historical-Root Precondition + Full 7-Field Cert Check — Closing `R6-H1`!)**:
     - **Precondition (Historical Tag-15 Committee Lookup!)**: Looks up `E' := HistoricalCommitteeRoot[cert.FinalityCommitteeRoot]` (requiring `cert.FinalityCommitteeRoot` to be a real historical Tag-15 `FinalityCommitteeRoot` on Zenon!) and verifies that `cert` carries a valid dual-supermajority BLS12-381 `min-sig` aggregate signature under **committee `E'`** over `finalityDigest(canonicalChainId, cert)`! *(NEVER rejects merely because `cert.FinalityCommitteeRoot != canonicalSigningCommitteeRoot(cert.Height)`!)*
     - **Case A (`cert.Height <= frontier.Height`)**: Slashes `100%` of `15,000 ZNN` for EVERY signer in `cert.SignerBitfield` (from committee `E'`) whenever **ANY** of the 7 certificate fields disagrees with canonical Zenon state at `cert.Height`:
       `cert.FinalityEpochIndex != canonicalFinalityEpoch(h) || cert.Height != m.Height || cert.TimestampUnix != m.TimestampUnix || cert.MomentumHash != m.Hash || cert.StateRoot != m.StateRoot || cert.FinalityCommitteeRoot != canonicalSigningCommitteeRoot(h) || cert.NextFinalityCommitteeRoot != canonicalNextCommitteeRoot(h)`!
       *(Closes `R6-H1` completely: a committee-`E` cartel signing a forged handoff at `h_trans(E+1)+1` — OR signing a target inside epoch `E+1` — verifies under historical committee `E` and IMMEDIATELY slashes every signer via `cert.FinalityCommitteeRoot != canonicalSigningCommitteeRoot(h)` and/or `NextFinalityCommitteeRoot` mismatch!)*
     - **Case B (`cert.Height > frontier.Height + 60`)**: Immediately slashes dual-supermajority certificates signed under any historical committee `E'` for non-existent future Momentums (`> 10` minutes ahead of tip).
- **Post-Committee-Service Pillar Stake Lock & Clean Exit (`A-PILLAR-1`)**:
  - Overrides baseline `dev:vm/embedded/implementation/pillars.go:132-138,395-400` per-Pillar `% 90d` phase!
  - `PillarContract.RequestExitCommittee()` marks `ExitCommitteeRequested = true` so the Pillar is excluded from all future 30-day finality committee snapshots.
  - `PillarContract.Revoke` rejects withdrawal until **`now >= finalityEpochEndTs(pillar.LastFinalityCommitteeEpoch) + 72 days`** (`>= T_bond_expiry (58d) + 14d grace`). Once `ExitCommitteeRequested == true` AND the `72`-day post-service lock has elapsed, **`Revoke` permits immediate withdrawal without waiting an additional `% 90d` lock cycle**, guaranteeing both 100% slashability during active chains (when challenged and published) AND bounded exit for top-30 Pillars!

### 3.4 `Momentum.ContentRoot`

Domain-separated SHA3-256 Merkle root (`0x00` leaf / `0x01` interior, no odd-node duplication) over `AccountHeader.Bytes()`.

---

## 4. Light Client Verification Protocol & Anti-Frontier Rule

1. Verify explicit signed 30-day BLS12-381 `FinalityCertificate` chain from trusted genesis/anchored checkpoint + verify `|cert.TimestampUnix - anchorHeader.nTime| <= 6h` + zero conflicting certified anchors.
2. Verify `proof-format.md` V1 `SmtProof` against `cert.StateRoot` and recompute `AccountBlock.ComputeHash()` (`dev:chain/nom/account_block.go:283`) for every inspected account block.
3. Application-level client verdicts: `PROVEN` | `REJECTED` | `REFUSED` (with Refusal Closure).
4. **Anti-Frontier Rule** ([`docs/architecture/bounded-verification-boundries.md`](https://github.com/TminusZ/zenon-developer-commons/blob/37194528a69d260c22221f3764b21bda9892cf56/docs/architecture/bounded-verification-boundries.md)): $O(k)$ bounded-frontier verification is **PERMITTED ONLY** for read-only consumer wallet hints; **STRICTLY PROHIBITED** for bridge claim admission, Settlement mint/release/refund, operator fronting, or BitVM2 verification.
