# AGENTS.md — Instructions for AI Agents & Automated Reviewers

This repository hosts the **zBTC Bitcoin–Zenon Interoperability Protocol Specification (`v2.5.0-rfc`)**, its executable integer-satoshi verification oracle (`scripts/verify_spec_bounds.py`), its full adversarial review trail (`reviews/HOSTILE_REVIEW_R1..R6.md`), and the static site published at **https://btc-moonshot.github.io/spec/**.

## Quick Orientation

1. **Read the normative spec in precedence order (`SPEC.md §2.1`)**:
   - `SPEC.md` (master architecture, flows, 5 explicit Tier 1A assumptions, §6 upstream amendments, §7 verification gates)
   - `spec/03-settlement-minted-zbtc-and-feeless-rails.md` & `spec/05-go-zenon-upgrade-plan.md`
   - `spec/02-btc-authorization-domain-and-spv.md`
   - `spec/01-bitcoin-taproot-vault-enforcement.md`
   - `spec/04-bitcoin-anchoring-and-light-client.md`
2. **Always run the executable oracle before trusting or changing ANY number**:
   ```bash
   python3 -I scripts/verify_spec_bounds.py
   ```
3. **Never leak local paths or silently soften threat-model disclosures**:
   - Tier 1A is explicitly NOT trustless (`SPEC.md §4` lists 5 explicit assumptions).
   - Unmeasured Signet BitVM2 / market constants MUST stay prefixed `ASSUMED_STAGE_0C_TARGET_` in `scripts/verify_spec_bounds.py` until empirically measured in Stage 0C (Gate G-2).

## Submitting Issues & Pull Requests

- **Filing a finding**: Use `.github/ISSUE_TEMPLATE/adversarial-finding.yml` (include severity, exact file/section citations, concrete step-by-step attack trace or Python reproduction, and minimal normative fix).
- **Opening a PR**:
  1. Update ALL affected spec files (`SPEC.md`, `spec/01..05`) AND `scripts/verify_spec_bounds.py` together so prose and oracle never diverge.
  2. Run `npm run sync:spec` to regenerate `public/raw/` and `public/llms-full.txt` from the root canonical files.
  3. Run `python3 -I scripts/verify_spec_bounds.py && npm run build` and verify exit code `0`.
  4. Fill out `.github/PULL_REQUEST_TEMPLATE.md` honestly.
