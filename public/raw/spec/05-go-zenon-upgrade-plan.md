# Part 5: Detailed `go-zenon` Node Upgrade Specification

**Document Class:** Engineering Upgrade Blueprint (`v1` / `v3.0.0-rfc`)  
**Reference Codebase:** [`go-zenon`](https://github.com/zenon-network/go-zenon)  
- **Normative U0 Target (`M-3` Fixed):** First tagged `go-zenon` release containing commit **`0aa299e`** (which fixes `release/0.0.11-rc2` `b85ee94`'s regression `ad3b729` skipping post-VM hash verification for externally supplied blocks mutated by `ValidateSendBlock`). Neither `release/0.0.11-rc1` (`f19955f`) nor `release/0.0.11-rc2` (`b85ee94`) is a valid U0 baseline.  
- **Code Anchor Reference:** Symbol citations verified against `origin/dev` (`770e893`) + `0aa299e`; CI MUST verify citations by symbol name and function content hash on every release branch (**M-3**). Legacy `v0.0.10` (`e8986a6`) is reference only.

---

## 1. Baseline Delta Matrix & Simplified `v1` Phases

In `v1`, optimistic challenge sessions (`OptimisticRefereeSpork` / Phase U4) are **retired**, and direct-on-L1 trimmed SPV (`vm/embedded/btcspv/`) is compiled directly into lightweight Phase **U3**. Phases **U1–U2** (`StateRootSpork`, `CommitteeRootSpork`) continue as Zenon infrastructure and are **non-blocking for `v1` custody**.

| Capability | `v0.0.10` (`e8986a6`, legacy) | Post-`0aa299e` U0 Tag | Phase | Blocking for `v1` Stage 1B? |
|---|---|---|---|---|
| `PtlcSpork`, `DynamicPlasmaSpork` (`EmbeddedSendBasePlasma`, `acknowledgement_recency.go` #227), `EmbeddedRefundSpork`, `Libp2pSpork`, `EpochRewardTermsSpork`, `0aa299e` hash re-verify fix | Missing | Implemented | **Phase U0** | **YES (Hard Gate)** |
| Upstream issue `#239` (deterministic embedded failure provenance + bounded receive retries never stalling FIFO receive queue) | Open | Required before U3 | **Phase U0/U3 Gate (`B1`)** | **YES (Hard Gate)** |
| `MintedZbtcSpork` (`TreasuryTrancheEscrow`, `TokenContract.IssueMinted`, lightweight `SettlementContract`, panic-recovered direct L1 `btcspv`, pinned `MaxBasePlasmaInMomentum >= 2,100,000` floor `B2`) | Missing | Missing | **Phase U3** | **YES (Hard Gate)** |
| `GovernanceContract` + `MultisigContract` (replaces single-key `SporkAddress` & `CommunitySporkAddress`), `DeleteMomentum` WS reorg push, HTLC/PTLC local indexes | Missing | Missing | **Phase U5** | **YES (Hard Gate before Stage 1B)** |
| `StateRootSpork` (v3, `common/trie/smtcore`) & `CommitteeRootSpork` (v4, BLS12-381 finality w/ `H-1`, `L-1`, `N-1`, `M-11` fixes) | Missing | Missing | **Phases U1–U2** | **NO** *(Zenon infra / `v2` track)* |

---

## 2. Phase U0 — Mandatory Node Prerequisites (`M-3`, `L-3`, `B1`, `B2`)

1. Ship the first `go-zenon` release tag containing **`0aa299e`** (`re-verify externally supplied blocks mutated by VM execution`).
2. Activate **`DynamicPlasmaSpork`** (hard precondition for ALL `zBTC` sporks — **L-3, B2**):
   - Enables per-byte embedded send Plasma (`68/byte`, `vm/plasma.go:186-192`) so large SPV sends cannot bypass metering.
   - Enables stale-acknowledgement rejection (`chain/acknowledgement_recency.go`, issue `#227`) for user account blocks.
3. Activate `PtlcSpork`, `EmbeddedRefundSpork`, `Libp2pSpork`, and `EpochRewardTermsSpork`.
4. **Close Upstream Issue `#239` (`B1` Blocking Gate before U3):**
   - Embedded receives execute strictly FIFO per contract (`verifier/account_block.go` → `ErrABSequencerNotNext`). Today, if generating an embedded receive panics, `vm/supervisor.go` returns `ErrVmRunPanic` and `pillar/worker_contract_generator.go` aborts without advancing the queue, permanently halting the contract until a spork intervenes.
   - Definition of "#239 closed": every embedded contract failure is deterministically classified, and `rc2`'s bounded receive retries ALWAYS terminate in a deterministic failed receive (with refund), NEVER a skip or permanent FIFO stall.

---

## 3. Phase U3 — `MintedZbtcSpork` (Tranche-Isolated `zBTC` & Direct L1 `btcspv`)

### 3.1 Embedded Addresses, Spork Guards & B2 Plasma Floor

- **`common/types/address.go`:** Register `TreasuryTrancheEscrow` and `SettlementContract` in `EmbeddedContracts`.
- **`common/types/spork.go` & `vm/embedded/embedded.go`:** Add `MintedZbtcSpork` requiring **`IsDynamicPlasmaSporkEnforced() == true`** as an explicit runtime precondition (**B2, L-3**).
- **B2 Pinned `MaxBasePlasmaInMomentum` Floor (`vm/embedded/implementation/plasma.go`):** Once `MintedZbtcSpork` enforces, `PlasmaContract.SetVariables` MUST reject any `MaxBasePlasmaInMomentum < 2,100,000` (raising the unsafe `210,000` lower limit at `vm/embedded/definition/plasma.go:66`, which would lock out every SPV call `> 2,011 B` in `pillar/content_selector.go:328`) and MUST reject `MaxPriceChangePercent > 25`.

### 3.2 `TokenContract` & `TreasuryTrancheEscrow` (`H-8`, `B3c`)

1. **`TokenContract.IssueMinted(name, symbol, domain, decimals, maxSupply)`:**
   - Guard: `if sendBlock.Address != types.TreasuryTrancheEscrow { return nil, constants.ErrPermissionDenied }`.
   - Exempts `checkToken` regexes, requires `1 ZNN` fee, sets `TotalSupply = MaxSupply = 21M*10^8`, `IsMintable = false`, `IsBurnable = false`, `Owner = types.TreasuryTrancheEscrow`.
   - Emits descendant `ContractSend` carrying `21M*10^8 zBTC` with `Data = ABITrancheEscrow.PackMethod("ReceiveInitialTreasury")`.
2. **Sealing `TokenContract.Burn` & `TokenContract.UpdateToken`:** Reject whenever `context.IsMintedZbtcSporkEnforced() && tokenInfo.Owner == types.TreasuryTrancheEscrow`.
3. **`TreasuryTrancheEscrow` (`vm/embedded/{definition,implementation}/tranche_escrow.go`):**
   - Single-use `ReceiveInitialTreasury()`.
   - `ReleaseCapTranche(amount)` callable ONLY by `GovernanceContract` after `>= 14d` timelock + `>= k` federation co-sig; transfers `amount` to `SettlementContract.ReceiveTranche()`.
   - `ReclaimExcessTranche(amount)` accepts returns from `SettlementContract` when cap is lowered.

### 3.3 Lightweight `SettlementContract` & Direct L1 `vm/embedded/btcspv/` (`B1`, `B2`, `B4`)

- **Mandatory Panic Recovery (`B1`):** Every method in `SettlementContract` and `vm/embedded/btcspv/` MUST wrap execution with `defer func() { if r := recover(); r != nil { err = constants.ErrInvalidMethodParam } }()` and contain ZERO calls to `common.DealWithErr`.
- **Heavy SPV Send Tier (`B2`):** `SubmitSweepLockProof`, `SubmitReleaseProof`, and `SubmitConflictRefundProof` quote `EMBEDDED_HEAVY_SPV_TIER = 73,500` + `68/byte` on send to cover unmetered receive execution (`vm/plasma.go:147`) and enforce hard storage-op ceilings (`<= 24` reads/writes).
- **`vm/embedded/btcspv/`:** Pure Go (`btcec/v2`, `btcec/v2/schnorr`), trimmed to:
  - `header.go` (`SubmitHeaderBatch`, `StepReorg`, `PruneStaleHeaders`, `ActiveChainByHeight` 68 B never pruned),
  - `tx.go` (`<= 6,144 B` stripped federation tx parser, `len != 64`, `txIndex != 0`, CVE-2012-2459, coinbase SHA-256 midstate verifier — no streaming `0x04`),
  - `custody.go` (`BTC-CUSTODY-F1` Taproot vault script verification, `>= k` individual Schnorr federation signature verification, sweep total-output bound, `BatchIntent` release & conflict proof checks).
- **Phase U4 Retired:** `OptimisticRefereeSpork`, `BatchCommitmentV3`, `ChallengeStep`, Multi-Tx Witness Sessions, and the retired 100-slot `ChallengeDepositZnn` priority lane are removed from `v1`.

---

## 4. Phase U5 — Governance Decentralization (Stage 1B Hard Gate), Reorg Push & Indexes

1. **`GovernanceContract` & `MultisigContract` (Hard Gate before Stage 1B):**
   - **`MultisigContract` (Guardian `5-of-9` Ed25519):** Narrowing actions ONLY (`GuardianPause`, `GuardianLowerSupplyCap`).
   - **`GovernanceContract`:** Replaces single-key `types.SporkAddress` and `types.CommunitySporkAddress` (`vm/embedded/definition/spork.go:46-73`) for protocol sporks, `SetPlasmaVariables` (bounded above pinned `2.1M` floor), `ReleaseCapTranche` (`>= 14d` + `>= k` fed), `AddBinding` (`>= 14d` + `>= k` fed), `ResumeMinting` (`>= 48h` + `>= k` fed), and custody-relevant sporks (`>= 30d` timelock).
2. **`DeleteMomentum` Reorg Push (`rpc/api/subscribe/api.go`):** Emit `momentumsReverted` WebSocket event `{height, hash, previousHash}` so federation signers and wallets detect shallow Zenon reorgs immediately.
3. **HTLC/PTLC Local Indexer (`chain/index/`, `rpc/api/embedded/{htlc,ptlc}.go`):** `getByDestination`, `getByPointLock`, `getByHashLock`.

---

## 5. Phases U1–U2 — Zenon Finality Infrastructure *(Non-Blocking for `v1`)*

Retained for Zenon light clients (`spec/04`) and the `v2` Research Track (`spec/01 Appendix A`), with `v1` fixes incorporated:
- **U1 (`StateRootSpork`):** Momentum v3 (`Tag 14` `StateRoot`), `common/trie/smtcore` (`proof-format.md` V1), `17,380`-momentum retention (~2.3 days at `11.4s`/Momentum) + `StateTreeArchive` flag.
- **U2 (`CommitteeRootSpork`):** Momentum v4 (`Tag 15` `FinalityCommitteeRoot`, `Tag 16` `ContentRoot`), `H-1` epoch-averaged variable slashable bond / beacon selection, `L-1` `<21` Pillar `FINALITY_DEGRADED` fallback & competing certified branch handling, `N-1` quorum-only impairment trigger, `M-11` certified-depth acceptance, `100%` self-bond `SlashEquivocation`, and `A-PILLAR-1` `72`-day post-service lock.

---

## 6. Mandatory CI & Stage 0 Conformance Gates

1. **Citation Integrity CI (`M-3`):** Automated check verifying every `go-zenon` symbol and function content hash cited in Part 5 against the pinned U0 tag.
2. **Panic & FIFO-Stall Fuzz Gate (`B1`):** Continuous fuzzer feeding malformed/adversarial ABI inputs to all `SettlementContract` and `btcspv` methods, asserting ZERO panics, ZERO internal errors, and ZERO FIFO receive queue stalls.
3. **B2 Plasma Floor & Stale-Ack Vectors (`B2`, `L-3`):** MUST-fail tests verifying `MintedZbtcSpork` rejects activation before `DynamicPlasmaSpork`, `SetPlasmaVariables` rejects `MaxBasePlasmaInMomentum < 2,100,000`, and stale-acknowledgement user mint/burn sends fail deterministically (`#227`).
4. **Tranche Isolation & Conservation Tests (`H-8`, `B3b`, `G-11`):** Unit tests for `IssueMinted -> ReceiveInitialTreasury -> ReleaseCapTranche -> SettlementContract`, proving `SettlementContract` cannot mint beyond its held tranche and `TokenContract.Burn`/`UpdateToken` reject.
5. **Direct-L1 SPV & Conflict-Refund Vectors (`B4`):** All Part 2 §5 conformance vectors including coinbase midstate proofs, `ReorgActive`/`Halted` isolation, `BatchIntent` finality, `SubmitReleaseProof` (no upper deadline), and `SubmitConflictRefundProof`.
6. **PTLC & LN Adversarial Suite (`M-4`, `G-18`):** Signet↔Zenon tests for `>= 72`-block CSV, Bob confirmation `<= h_conf + 66` + CPFP, Alice `+6`-block abort, odd-$y(R')$ parity, BIP-327 `PartialSigAgg`, `hashType = 0` rejection, and LN Hold Invoice `ACCEPTED`-first + 5-min cancel TTL.
