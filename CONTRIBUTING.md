# Contributing to the zBTC Protocol Specification

Public adversarial review — from both human protocol engineers and AI review agents — is the core reason this specification is published openly at **https://btc-moonshot.github.io/spec/**.

## How to Review Adversarially

1. **Ingest the spec**: Browse https://btc-moonshot.github.io/spec/, clone this repo, or fetch the single-file LLM bundle at https://btc-moonshot.github.io/spec/llms-full.txt (indexed via https://btc-moonshot.github.io/spec/llms.txt).
2. **Verify the numeric oracle independently**:
   ```bash
   python3 -I scripts/verify_spec_bounds.py
   ```
   Do not trust prose numbers without checking the exact integer derivations in `scripts/verify_spec_bounds.py`.
3. **Read the existing audit trail** (`reviews/HOSTILE_REVIEW_R1.md` through `reviews/HOSTILE_REVIEW_R6.md`) to see what attacks were already tried, resolved, or explicitly scoped as Stage-0C measurement gates (`G-1`, `G-2`, `G-9`, `G-11`, `G-18`, CRS ceremony, and §6 upstream amendments).

## Severity Taxonomy (for GitHub Issues)

| Severity | Definition |
|---|---|
| **CRITICAL** | Loss of funds, unbacked minting, permanent unrecoverable lock, or broken conservation invariant. |
| **HIGH** | Broken core security assumption, unbuildable Bitcoin Script / cryptographic construction, or slashing bypass. |
| **MEDIUM** | Edge-case liveness/griefing vector, honest-operator stranding, or cross-store state race. |
| **LOW** | Numeric slip, ambiguous phrasing, missing domain-separation tag, or incomplete boundary check. |
| **ORACLE** | Bug, tautology, or prose mismatch inside `scripts/verify_spec_bounds.py`. |

## Opening an Issue

Use the structured issue templates at https://github.com/btc-moonshot/spec/issues/new/choose:
- **Adversarial Finding**: Cite exact file/section/line, give a concrete step-by-step failure trace (or Python snippet), explain the violated invariant, and suggest a minimal normative fix.
- **Spec Change Proposal (RFC)**: Describe motivation, exact sections affected, security/economic trade-offs, and oracle impact.

## Submitting a Pull Request

1. Fork and branch from `main`.
2. Make surgical, cross-file consistent edits to `SPEC.md`, `spec/01..05`, and `scripts/verify_spec_bounds.py`.
3. Sync the static site's raw files and `public/llms-full.txt`:
   ```bash
   npm run sync:spec
   ```
4. Verify BOTH mandatory CI gates locally before pushing:
   ```bash
   python3 -I scripts/verify_spec_bounds.py
   npm ci && npm run build
   ```
5. Complete every checkbox in `.github/PULL_REQUEST_TEMPLATE.md`. All PRs must pass `.github/workflows/verify-oracle.yml`.
