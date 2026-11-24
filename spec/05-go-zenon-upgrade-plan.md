# Part 5: Detailed `go-zenon` Node Upgrade Specification

**Document Class:** Engineering Upgrade Blueprint (`v2.5.0-rfc`)  
**Inspected Ground-Truth Branches in [`go-zenon`](https://github.com/zenon-network/go-zenon):**
- `origin/release/0.0.11-rc1`: `f19955f3d28a35868b0488fd7010073241561a7f` *(Normative U0 release baseline)*
- `origin/dev`: `770e893a0aa78240685043c1d396c65caa1a6635` *(All `dev:` file & line citations below verified directly against `770e893` / `f19955f`)*
- `master`: `e8986a63f164259053e0342ceaf9a68cb85d649e` (`v0.0.10-alphanet`, legacy reference only)

---

## 1. Baseline Delta Matrix (`master` vs `release/0.0.11-rc1` / `dev` vs Upgrades)

| Capability | `master` (`e8986a6`) | `release/0.0.11-rc1` (`f19955f`) & `dev` (`770e893`) | Phase |
|---|---|---|---|
| `AcceleratorSpork`, `HtlcSpork`, `BridgeAndLiquiditySpork` | Active | Active | Live |
| `PtlcSpork` (`e59f1e97...`), `DynamicPlasmaSpork` (v2 + `EmbeddedSendBasePlasma` at `dev:vm/plasma.go:192`), `EmbeddedRefundSpork`, `Libp2pSpork`, `EpochRewardTermsSpork`, composable `embeddedVariants` (`dev:vm/embedded/embedded.go:246`) | Missing (16 KiB embedded bypass) | Implemented | **Phase U0** |
| `StateRootSpork` (v3, `common/trie/smtcore` + `proof-format.md` V1, `chain/state_tree.go`) | Missing | Missing | **Phase U1** |
| `CommitteeRootSpork` (v4: 30-day BLS12-381 `min-sig` `FinalityCommitteeRoot` w/ distinct POP DSTs & depth-5 SHA-256 tree, `ContentRoot`, U2 finality gadget, `pillars.go` `RegisterFinalityKey`+PoP, `RequestExitCommittee`, historical-root full-preimage `SubmitInvalidCertProof` + `SubmitEquivocationProof`, `72d` post-service stake lock, `A-PILLAR-1`) | Missing | Missing | **Phase U2** |
| `OffchainExecutionSpork` & `MintedZbtcSpork` (`SettlementContract`, `TokenContract.IssueMinted` → single-use `ReceiveTreasury()`, monotonic `batchId` + `domainInputSeq`, latency- & reservation-aware `G-21`, multi-gen `VaultUtxoSet`, aligned state machine + `RepointTrappedPegOut` + `ResetFailedReimbursementSlot` + `SlotBondZnn` + `SyncPendingTrapVault` + `SyncRetiredLane` + `SyncVaultGraphEpoch`, `ChallengeDepositZnn` priority lane) | Missing | Missing | **Phase U3** |
| `OptimisticRefereeSpork` (panic-free `vm/embedded/btcspv/` 17 tags incl. decoupled `0x06`, full-status SMT absence/inclusion `0x08`, strict multi-gen `0x0D` incl. `RELEASED`, `0x10`, bounded Multi-Tx Sessions + ancestor refunds, commit-reveal, streaming SHA-256 verifier) | Missing | Missing | **Phase U4** |
| `GovernanceContract` + `MultisigContract` (**HARD GATE before Stage 1B**), `DeleteMomentum` WS reorg push (`dev:rpc/api/subscribe/api.go:357`), HTLC/PTLC indexes, optional `BtcAnchorSpork` | Missing | Missing | **Phase U5** |

---

## 2. Phase U0 — Release `release/0.0.11-rc1` (`f19955f`) Prerequisites

1. Ship `origin/release/0.0.11-rc1` (`f19955f`) / `origin/dev` (`770e893`) to mainnet.
2. Calibrate `PlasmaVariables` (`dp/dp.go`, `PlasmaContract.SetVariables`) to prevent multi-month decay lockup and 2-heavy-tx saturation.
3. Verify `PtlcSpork` (`e59f1e97...`) on-chain status; activate `DynamicPlasmaSpork`, `EmbeddedRefundSpork`, `Libp2pSpork`, `EpochRewardTermsSpork`.

---

## 3. Phase U1 — `StateRootSpork` (Momentum Version 3 & `common/trie/smtcore`)

- **`common/trie/smtcore/`** (shared frozen core for L1 & `d_btc_asset`): `hash.go`, `compute.go`, `proof.go` implementing **`proof-format.md` V1 byte-exact** (`flags || key || leaf_hash || deepest-first bitmap || sib_count || siblings [|| value_len || value]`, `VerifyProofByPath`, `VerifyAbsenceByPath`).
- **`common/trie/`** (L1 Momentum adapter): `FoldFilter` (excludes `{0}/{1}/{2}`), empty-value-as-deletion convention, LevelDB `NodeTree`.
- **`chain/state_tree.go`**: `InitStateTree`, `UpdateStateTree`, `TruncateStateTreeTo`, `17,380`-momentum retention (`StateTreeArchive: true` disables pruning).
- **`chain/nom/protobuf.proto` & `momentum.go`**: Tag `14` (`types.HashProto stateRoot = 14`), `StateRootMomentumVersion = 3`, `rlp:"optional"`, appended in `ComputeHash()` iff `Version >= 3`.
- **`verifier/momentum.go` & `pillar/worker_momentum.go`**: Stamp/verify `StateRoot` (`ErrMStateRootInvalid`, `ErrMStateRootMustBeZero`).
- **`rpc/api/ledger.go`**: `ledger.getStateRoot(height)`, `ledger.getProof(height, key)`.

---

## 4. Phase U2 — `CommitteeRootSpork` (Momentum v4, 30-Day BLS12-381 Finality, Full-Preimage Slashing & `72`-Day Lock)

1. **`chain/nom/protobuf.proto` & `momentum.go`**:
   - Tag `15`: `types.HashProto finalityCommitteeRoot = 15;` (immutable per 30-day finality epoch)
   - Tag `16`: `types.HashProto contentRoot = 16;` (domain-separated Merkle root of `MomentumContent`)
   - `CommitteeRootMomentumVersion = 4`; both `rlp:"optional"`, appended in `ComputeHash()` iff `Version >= 4`.
2. **`consensus/finality_committee.go` (NEW)**:
   - Derived from `dev:consensus/consensus.go:45,86`: `finalityEpochIndex = consensusEpoch / 30` (`finalityEpochStartTs(E) = genesis.TimestampUnix + E * 30 * 86400`).
   - At exact transition Momentum `h_trans(E)`, snapshots top `30` active BLS12-381-registered Pillars (excluding `ExitCommitteeRequested == true`) by `(totalDelegatedZnn desc, producerAddress asc)`, records `LastFinalityCommitteeEpoch = E`, and defines canonical `nextFinalityCommitteeRoot(h)` at EVERY height `h` ([`spec/04 §3.2`](./04-bitcoin-anchoring-and-light-client.md#L69-L74)).
3. **`consensus/finality_cert.go` (NEW), BLS12-381 `min-sig`, Finality Gadget & `/zenon/finality/v1` topic**:
   - Fixed `204 B` BLS12-381 `min-sig` `FinalityCertificate` (`48 B` G1 agg sig + `4 B` bitfield for up to all 30 signers), signed ONLY at depth `>= 6` Momentums every `30` Momentums and at `h_trans(E)`.
   - **Finality Gadget (`chain/momentum_pool.go` & `chain/account_pool.go`)**: Refuse `DeleteMomentum` / fork switch across any Momentum backed by a valid dual-supermajority `FinalityCertificate`.
4. **Full-Preimage Slashing, BLS Key Registration & `72`-Day Lock (`dev:vm/embedded/{definition,implementation}/pillars.go`, `A-PILLAR-1`)**:
   - **`RegisterFinalityKey(blsPubKey96, popSig48)`**: Verifies BLS12-381 Proof-of-Possession (distinct IETF POP DST — `R6-L7`) before allowing finality committee eligibility.
   - **`RequestExitCommittee()`**: Opts Pillar out of future 30-day finality snapshots.
   - **`SubmitEquivocationProof(certA, certB)`**: Slashes conflicting signatures for same `(finalityEpochIndex, height)`.
   - **`SubmitInvalidCertProof(cert)` (`R6-H1`)**: Looks up historical Tag-15 committee matching **`cert.FinalityCommitteeRoot`**, verifies valid dual-supermajority BLS12-381 signature under THAT historical committee (NOT merely `canonicalSigningCommitteeRoot(cert.Height)`!), and checks **ALL 7 certificate fields** in Case A (`finalityEpochIndex`, `height`, `timestampUnix`, `momentumHash`, `stateRoot`, `finalityCommitteeRoot`, `nextFinalityCommitteeRoot` — slashing committee-`E` forged handoffs at `h_trans(E+1)+1` AND targets in epoch `E+1`!) plus Case B (`cert.Height > frontier.Height + 60`). Forfeits 100% of `15,000 ZNN` (`dev:vm/constants/embedded.go:108`), revokes Pillar, triggers Settlement pause.
   - **`72`-Day Post-Service Lock & Clean Exit**: Modifies `PillarContract.Revoke` (`dev:vm/embedded/implementation/pillars.go:132-138,395-400`) to hold `PillarStakeAmount` until `now >= finalityEpochEndTs(LastFinalityCommitteeEpoch) + 72 days`; once `ExitCommitteeRequested == true` and `72d` elapses, allows immediate withdrawal without waiting another `% 90d` cycle!
5. **`rpc/api/ledger.go`**: `ledger.getFinalityCommittee(finalityEpochIndex)`, `ledger.getFinalityCertificate(height)`, `ledger.getContentProof(height, accountBlockHash)`.

---

## 5. Phase U3 — `OffchainExecutionSpork` & `MintedZbtcSpork` (`SettlementContract` & Treasury `zBTC`)

### 5.1 Embedded Address, Sporks & Registry

- **`common/types/address.go`**: Add `SettlementContract = parseEmbedded("z1qxemdeddedxsettlementxxxxxxxxxxx<checksum>")` to `EmbeddedContracts`.
- **`common/types/spork.go`**: Add `OffchainExecutionSpork` (`...000A`) and `MintedZbtcSpork` (`...000B`).
- **`vm/embedded/embedded.go`**: Add spork bits at `dev:vm/embedded/embedded.go:246` wiring `SettlementContract` and `TokenContract.IssueMinted`.

### 5.2 Exact `TokenContract` Modifications (`dev` Ground Truth)

1. **`TokenContract.IssueMinted(name, symbol, domain, decimals, maxSupply)`**:
   - Guard: `if sendBlock.Address != types.SettlementContract { return nil, constants.ErrPermissionDenied }`.
   - Exempts `checkToken` regexes (`dev:vm/embedded/implementation/token.go:40,43`), requires `1 ZNN` fee, sets `TotalSupply = MaxSupply = 21M*10^8`, `IsMintable = false`, `IsBurnable = false`, `Owner = types.SettlementContract`.
   - Descendant `ContractSend` carrying `21M*10^8 zBTC` packs **`Data = ABISettlement.PackMethod("ReceiveTreasury")`** (`dev:vm/vm.go:204-226`).
2. **Sealing `TokenContract.Burn` (`dev:vm/embedded/implementation/token.go:330`) AND `TokenContract.UpdateToken`**:
   - Both reject if `context.IsMintedZbtcSporkEnforced() && tokenInfo.Owner == types.SettlementContract`.

### 5.3 `SettlementContract` Files & `ChallengeDepositZnn` Priority Lane

- `vm/embedded/definition/settlement.go`: ABI (`ABISettlement`, including `ReceiveTreasury()`, `ClaimInputDepositRefund()`, `DispatchDeferredLock()`, `ClaimFrontingSlot()`, `SlashLapsedSlot()`, `ClaimReimbursementSlot()`, `ResetFailedReimbursementSlot()`, `RepointTrappedPegOut()`, `RegisterOperatorRound()`, `SyncRetiredLane()`, `SlashOperatorBond()`, `SyncPendingTrapVault()`, `SyncRecoveredVaultOutpoint()`, `SyncVaultGraphEpoch()`, `QuarantineExpiredVault()`, `SyncOrphanedVaultOutpoint()`, `CommitChallenge()`, `ExpireChallengeCommit()`, `OpenChallenge()`, `UploadWitnessProof()`, `ExecuteChallenge()`, `ExpireChallengeSession()`, `RefundRejectedBatchChallenge()`, `ChallengeStep()`, `ChallengeContinuity()`), storage prefixes `0x01`–`0x17` ([`spec/03 §2.1`](./03-settlement-minted-zbtc-and-feeless-rails.md#L30-L56)), canonical binary codecs (`StepTraceLeaf` `328 B`, `BatchCommitmentV3`).
- `vm/embedded/implementation/settlement_core.go`: `RegisterDomain`, `SubmitInput` (ALWAYS open, contiguous `domainInputSeq`), `SubmitBatch` (monotonic `batchId`, `parentBatchId`, `PreStateRoot` chaining, `finalLeaf`, per-executor + aggregate caps, dispatch-only `dispatchFrozenByBatch`), `FinalizeBatch` (Shadow Mode active, freezing batch exempt, session/commit guard, exposure release), `ClaimInputDepositRefund` (`<= 16` global duplicates/batch).
- `vm/embedded/implementation/settlement_minted.go`: `InitiateMintedToken`, single-use `ReceiveTreasury`, `BindMintedAsset` (`GOVERNANCE_ADD_BINDING`), `RequestPegOut` (open during `DRAINING_*`, `+3.0d` latency-aware per-epoch eligibility), anti-censorship `ClaimFrontingSlot` (`500 ZNN` `SlotBondZnn`, reservation, no consecutive re-claim, single-authority expiry), `SlashLapsedSlot`, `RegisterOperatorRound` (`OperatorBond >= 31,500 ZNN`, `epoch < 4096`, exact `anchorExpiryTs == finalityEpochStartTs(epoch) + 58d`, `CommSig`), `SyncRetiredLane`, `ClaimReimbursementSlot`, `ResetFailedReimbursementSlot`, `RepointTrappedPegOut`, `SlashOperatorBond`, `SyncPendingTrapVault`, `SyncRecoveredVaultOutpoint`, `SyncVaultGraphEpoch` (`unrotatedVaultCount--` iff `UNROTATED`), `QuarantineExpiredVault` (`day >= T_cutoff + 60h`, `UNASSIGNED`/`ASSIGNED`), deterministic `SyncOrphanedVaultOutpoint`, closed handlers (`MINTED_LOCK_V1` latency-aware `G-21`, `MINTED_RELEASE_V1` keying strictly on domain `operatorId`, `MINTED_REFUND_V1`).
- **`chain/account_pool.go` Priority Lane**: Reserve `10` of `100` Momentum slots ordered by `ChallengeDepositZnn` descending; paired with 48h (`+12h` session) window.

---

## 6. Phase U4 — `OptimisticRefereeSpork` (`vm/embedded/btcspv/` & Bounded Multi-Tx Sessions)

- **`vm/embedded/btcspv/`** (pure Go, zero `common.DealWithErr` panics, imports `dev:go.mod:7` `btcec/v2` + `btcec/v2/schnorr` and `common/trie/smtcore`):
  - `header.go` (`ActiveChainByHeight` `68 B` incl. `blockTime`, `BTC_PRUNE_STEP` rejecting while `ReorgActive == 1`), `stream.go` (`BTC_TX_STREAM_CHUNK`), `tx.go` (`len != 64`, `txIndex != 0`, CVE-2012-2459), `taproot.go` (mandatory 2-in `RolloverTx`, BIP-68/112 CSV, `Q_vault_d`/`Q_rec_d` tweaks, `CommitteeIdentityKey` sig verification), `apply.go` (all 17 tags `0x00..0x10`, multi-epoch `TrackedVaultRecord`, SMT absence/inclusion `BTC_VAULT_SPEND_PROOF`, `BTC_ROUND_RETIRED`).
- **`vm/embedded/implementation/settlement_challenge.go`** (`OptimisticRefereeSpork` `...000C`): `CommitChallenge` (`T_reveal = 1h`), `ChallengeContinuity` (`1,700 B`), 1-tx `ChallengeStep`, bounded Multi-Tx Sessions (`T_session = 12h`, `UploadWitnessProof = 8,676 B` @ depth 256, `ExecuteChallenge` re-verifying `(batchId, traceRoot)`), blocking `FinalizeBatch` while open, and `RefundRejectedBatchChallenge`.

---

## 7. Phase U5 — Governance Decentralization (Stage 1B Hard Gate), Reorg Push & Indexes

1. **`GovernanceContract` & `MultisigContract` (Stage 1B Hard Gate)**:
   - **`MultisigContract`** (Guardian M-of-N Ed25519, e.g. `5-of-9`): Narrowing actions ONLY (`GuardianPause`, `GuardianLowerSupplyCap` on `> +10%` 24h TWAP deviation across `>= 3` venues, `GuardianBeginDrain` with mandatory `7-day` expiry timer).
   - **`GovernanceContract`** (Pillar stake-weighted voting replacing single `SporkAddress` at `dev:chain/genesis/embedded_genesis_string.go:7`): Proposal deposit, `>= 33%` quorum, `> 66%` approval, weekly supply-cap & `MinOperatorBondZnn` review cadence, pre-halving `K`/cap rule, `GOVERNANCE_ADD_BINDING` (`0x0E`), on-chain timelocks (`>= 48h` sporks/resume, `>= 7d` asset bind, cap raises, `ORPHANED` vault disposition, migrations). **Hard Gate before Stage 1B!**
2. **Fix `DeleteMomentum` Reorg Push (`dev:rpc/api/subscribe/api.go:357`)**: Emit `momentumsReverted` WebSocket event `{height, hash, previousHash}`.
3. **HTLC/PTLC Local Indexer (`chain/index/`, `rpc/api/embedded/{htlc,ptlc}.go`)**: `getByDestination`, `getByPointLock`, `getByHashLock`.
4. **Optional `BtcAnchorSpork` (`...000D`)**: Structured `<= 64 B` anchor receipts relaxing `dev:verifier/momentum.go:198` (`ErrMDataMustBeZero`) ONLY for valid receipts + `ledger.getLatestBtcAnchor()`.

---

## 8. Spork Release Flow & Automated Conformance Gates

Follows `dev:common/types/spork.go:17-34` 4-step choreography (placeholder → `CreateSpork` → pin real hash & upgrade `>= 90%` Pillars → `ActivateSpork` → `SporkMinHeightDelay = 6` Momentums; un-upgraded nodes halt via `dev:chain/momentum_pool.go:254-283`).

Mandatory CI & Testnet Gates before Stage 1A:
1. Full Genesis-to-Tip historical replay parity across v1 → v2 → v3 → v4.
2. `common/trie/smtcore` passes upstream `smt-v1-test-vectors.json` byte-for-byte.
3. **`go-zenon` unit test (G-11)**: `InitiateMintedToken` → `IssueMinted` → single-use `ReceiveTreasury()` → `BindMintedAsset` → atomic mint/burn/rollback + `Burn`/`UpdateToken` rejection.
4. 30-day BLS12-381 `FinalityCommitteeRoot` PoP (distinct DSTs) + depth-5 SHA-256 tree + U2 finality gadget reorg protection + **historical-root `SubmitInvalidCertProof` MUST-fail tests (`R6-H1`: committee-`E` forged handoff at `h_trans(E+1)+1` with canonical momentum/state ⇒ slashable; committee-`E` target in epoch `E+1` ⇒ slashable!)** + `72`-day post-service lock & `RequestExitCommittee` exit test.
5. All **15 MUST-fail bullets + 18 conformance vectors** (`MINTED` v0.1.1 §13–§14) + all **29 SPV vectors** + cross-store vault state machine tests (decoupled `BTC_RELEASE_PROOF` + `RepointTrappedPegOut`, `PENDING_TRAP` mirror, `unrotatedVaultCount` inc/dec without underflow, deterministic `SyncOrphanedVaultOutpoint`), latency- & reservation-aware `G-21` + `BTC_ROUND_RETIRED`, anti-censorship `ClaimFrontingSlot` (`500 ZNN` `SlotBondZnn` + `lastLapsedOperatorId`), bounded Multi-Tx Session at `T-1` + depth-256 ground-tree fuzzer (**G-9**).
6. Signet↔Zenon PTLC (Bob-locks-first, BIP-327 `PartialSigAgg`, odd-$y$) & HTLC (`hashType = 1`, LN Hold Invoice) adversarial swap suite (**G-18**).
