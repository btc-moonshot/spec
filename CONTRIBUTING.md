# Contributing to the zBTC Protocol Specification

Public adversarial review — from both human protocol engineers and AI review agents — is the core reason this specification is published openly at **https://btc-moonshot.github.io/spec/**.

## How to Review Adversarially

1. **Ingest the current `v1` (`v3.0.0-rfc`) spec**: Browse https://btc-moonshot.github.io/spec/, clone this repo, or fetch the single-file LLM bundle at https://btc-moonshot.github.io/spec/llms-full.txt (indexed via https://btc-moonshot.github.io/spec/llms.txt). Compare against archived `v0` (`v2.5.0-rfc`) at https://btc-moonshot.github.io/spec/changelog/.
2. **Run the Consistency & Bounds Checker independently**:
   ```bash
   (cd versions/v0 && shasum -a 256 -c SHA256SUMS.txt)
   python3 -I scripts/verify_spec_bounds.py
   ```
   Do not trust prose numbers without checking the exact derivations and 2,000-step state-machine simulation in `scripts/verify_spec_bounds.py`. Note that `PRE_MAINNET_TARGET_` constants are pre-mainnet engineering targets to be measured empirically on Signet — never claim "oracle verified".
3. **Read the existing audit trail** (`reviews/HOSTILE_REVIEW_R1.md` through `reviews/HOSTILE_REVIEW_R7_CONSOLIDATED.md`) and `CHANGELOG.md` to see how `v0` failed, why federated multisigs were explicitly rejected, and which Stage 0 / Stage 1A / Stage 1B gates remain open before any mainnet deployment.

## Severity Taxonomy (for GitHub Issues)

| Severity | Definition |
|---|---|
| **CRITICAL** | Loss of funds, unbacked minting, permanent unrecoverable lock, or broken conservation invariant. |
| **HIGH** | Broken core security assumption, unbuildable Bitcoin Script / cryptographic construction, BIP-431 TRUC violation, or slashing/equivocation bypass. |
| **MEDIUM** | Edge-case liveness/griefing vector, honest-operator stranding, timelock/clock mismatch, or cross-layer state race. |
| **LOW** | Numeric slip, ambiguous phrasing, missing domain-separation tag, or incomplete boundary check. |
| **CHECKER** | Bug, no-op simulation shortcut, tautology, or prose mismatch inside `scripts/verify_spec_bounds.py`. |

## Opening an Issue

Use the structured issue templates at https://github.com/btc-moonshot/spec/issues/new/choose:
- **Adversarial Finding**: Cite exact file/section/line, give a concrete step-by-step failure trace (or Python snippet), explain the violated invariant, and suggest a minimal normative fix.
- **Spec Change Proposal (RFC)**: Describe motivation, exact sections affected, security/economic trade-offs, and checker impact.

## Submitting a Pull Request

1. Fork and branch from `main`. Never modify frozen files under `versions/v0/`.
2. Make surgical, cross-file consistent edits to `SPEC.md`, `spec/01..05`, `CHANGELOG.md`, and `scripts/verify_spec_bounds.py`.
3. Sync the static site's raw files and `public/llms-full.txt`:
   ```bash
   npm run sync:spec
   ```
4. Verify ALL mandatory CI gates locally before pushing:
   ```bash
   (cd versions/v0 && shasum -a 256 -c SHA256SUMS.txt)
   python3 -I scripts/verify_spec_bounds.py
   python3 -I versions/v0/scripts/verify_spec_bounds.py
   npm ci && npm run build
   ```
5. Complete every checkbox in `.github/PULL_REQUEST_TEMPLATE.md`. All PRs must pass `.github/workflows/verify-oracle.yml`.
