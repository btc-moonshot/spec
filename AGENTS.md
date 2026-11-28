# AGENTS.md — Instructions for AI Agents & Automated Reviewers

This repository hosts the **zBTC Bitcoin–Zenon Interoperability Protocol Specification (`v1` / `v3.0.0-rfc` — Zero-Federation Phased Architecture: Stage 0 Verify Bitcoin → Stage 1A Right-Sized `BitVMX` Sovereign ZK Rollup | Stage 1B `clArk` Gate → Stage 2 Zero-TTP Scale)**, its frozen byte-for-byte `v0` baseline (`versions/v0/`, `v2.5.0-rfc`), its executable Consistency & Bounds Checker (`scripts/verify_spec_bounds.py`), its full adversarial review trail (`reviews/HOSTILE_REVIEW_R1..R7*.md`), and the static site published at **https://btc-moonshot.github.io/spec/**.

## Quick Orientation

1. **Read the normative `v1` (`v3.0.0-rfc`) spec in authority-precedence order (`SPEC.md §2.1`)**:
   - `spec/01-bitcoin-taproot-vault-enforcement.md` (Highest precedence: zero-federation custody law, Stage 0 → Stage 1A right-sized `BitVMX` `n=8` deleted-key vaults & BIP-431 TRUC v3 dispute DAG, Stage 1B `clArk` gate, Stage 2 zero-TTP upgrade boundary)
   - `SPEC.md` (Master overview, zero-federation architecture, rejection of federated multisigs, honest threat model, Stage 0/1A/1B/2 gates, public claims alignment, and R7 Q&A)
   - `spec/02-btc-authorization-domain-and-spv.md` (Stage 0 direct-on-L1 Bitcoin SPV Event Oracle with 1-/2-block coinbase midstate + Stage 1A Bitcoin L1 DA & forced-inclusion inbox `0x00..0x07`)
   - `spec/03-settlement-minted-zbtc-and-feeless-rails.md` (Stage 0 non-custodial PTLC/LN swaps + Stage 1A Sovereign Rollup STF, feeless Zenon `AccountBlock.Data` sequencer rails, honest `8 MiB` throughput ceiling, and `clArk` VTXO rails)
   - `spec/04-bitcoin-anchoring-and-light-client.md` (Zenon 49% DPoS & >33.3% BFT impossibility proof, inverted Bitcoin-L1-first trust hierarchy giving `0-of-N` Zenon trust, optional non-custodial light-client infrastructure)
   - `spec/05-go-zenon-upgrade-plan.md` (Stage 0 `go-zenon` prerequisites — `#239` panic-stall closure, `DynamicPlasmaSpork` + full `SetPlasmaVariables` pinning, `PtlcSpork`, SPV oracle — plus Stage 1A/1B zero-hard-fork custody boundary)
2. **Always run BOTH the `v1` Consistency & Bounds Checker and the immutable `v0` manifest check before trusting or changing ANY number**:
   ```bash
   (cd versions/v0 && shasum -a 256 -c SHA256SUMS.txt)
   python3 -I scripts/verify_spec_bounds.py
   python3 -I versions/v0/scripts/verify_spec_bounds.py
   ```
3. **Strict Guardrails**:
   - **Zero federated signers:** Never introduce custodial `k`-of-`n` multisig federations into `v1`.
   - **Never edit anything under `versions/v0/`:** `versions/v0/` is frozen byte-for-byte from commit `7b47b8c` and SHA-256 verified in CI.
   - **Never leak local filesystem paths** (machine-specific absolute paths) or soften threat-model disclosures.
   - **Honest provenance:** `scripts/verify_spec_bounds.py` is a *Consistency & Bounds Checker* (never claim "oracle verified"); constants MUST stay explicitly prefixed `SOURCED_`, `POLICY_`, or `PRE_MAINNET_TARGET_` until empirically measured on Signet.

## Submitting Issues & Pull Requests

- **Filing a finding**: Use `.github/ISSUE_TEMPLATE/adversarial-finding.yml` (include severity, exact file/section citations, concrete step-by-step attack trace or Python reproduction, and minimal normative fix).
- **Opening a PR**:
  1. Update ALL affected `v1` spec files (`SPEC.md`, `spec/01..05`, `CHANGELOG.md`) AND `scripts/verify_spec_bounds.py` together so prose and checker never diverge.
  2. Run `npm run sync:spec` to regenerate `public/raw/` and `public/llms-full.txt` from the canonical root files (and verify `versions/v0/SHA256SUMS.txt`).
  3. Run `python3 -I scripts/verify_spec_bounds.py && python3 -I versions/v0/scripts/verify_spec_bounds.py && npm run build` and verify exit code `0`.
  4. Fill out `.github/PULL_REQUEST_TEMPLATE.md` honestly.
