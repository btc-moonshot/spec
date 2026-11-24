# zBTC: Bitcoin–Zenon Interoperability Protocol Specification (`v2.5.0-rfc`)

> **Public RFC** — Pre-implementation technical specification open for adversarial human & AI-agent review.
>
> - **Read the Full Spec:** <https://btc-moonshot.github.io/spec/>
> - **LLM / Agent Manifest & Review Protocol:** <https://btc-moonshot.github.io/spec/llms.txt>
> - **Single-Fetch Complete Spec Bundle:** <https://btc-moonshot.github.io/spec/llms-full.txt>
> - **Vision Essay:** <https://btc-moonshot.github.io/bigidea/>

## Repository Layout

| Path | Description |
|---|---|
| [`SPEC.md`](./SPEC.md) | Master overview, end-to-end flows, 5-assumption honest threat model (§4), upstream amendment register (§6), and verification gates (§7) |
| [`spec/01-bitcoin-taproot-vault-enforcement.md`](./spec/01-bitcoin-taproot-vault-enforcement.md) | Part 1 — Hash-pinned BitVM2 Taproot Vault Enforcement (`BTC-ENFORCEMENT-V1`) |
| [`spec/02-btc-authorization-domain-and-spv.md`](./spec/02-btc-authorization-domain-and-spv.md) | Part 2 — Bitcoin Authorization Domain (`d_btc_asset`) & Adversarially-Bounded SPV Verifier |
| [`spec/03-settlement-minted-zbtc-and-feeless-rails.md`](./spec/03-settlement-minted-zbtc-and-feeless-rails.md) | Part 3 — Settlement Contract, Atomic Treasury `zBTC`, Plasma & Peg-Free PTLC/LN Rails |
| [`spec/04-bitcoin-anchoring-and-light-client.md`](./spec/04-bitcoin-anchoring-and-light-client.md) | Part 4 — Bitcoin Anchoring, 30-Day BLS12-381 Finality Committees & Light Client Verification |
| [`spec/05-go-zenon-upgrade-plan.md`](./spec/05-go-zenon-upgrade-plan.md) | Part 5 — Detailed `go-zenon` Node Upgrade Plan (verified against `dev` `770e893` / `release/0.0.11-rc1` `f19955f`) |
| [`scripts/verify_spec_bounds.py`](./scripts/verify_spec_bounds.py) | Executable integer-satoshi asserting oracle verifying every modeled bound |
| [`reviews/`](./reviews/) | Complete transparent archive of Hostile Peer Reviews Rounds 1–6 |
| [`AGENTS.md`](./AGENTS.md) & [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Instructions for human reviewers and AI agents on auditing, filing issues, and opening PRs |
| `src/` & `public/` | Static Astro site deployed to GitHub Pages (matching `btc-moonshot/bigidea`) |

## Verify the Numeric Oracle

Zero third-party dependencies (standard library Python 3):

```bash
python3 -I scripts/verify_spec_bounds.py
```

## Build the Specification Site Locally

```bash
npm ci
npm run sync:spec
npm run build
```

## Review, File Issues, or Open a PR

Found a flaw, edge case, or improvement? Open an [Adversarial Finding](https://github.com/btc-moonshot/spec/issues/new?template=adversarial-finding.yml) or [Spec Change Proposal](https://github.com/btc-moonshot/spec/issues/new?template=spec-change-proposal.yml), or submit a PR following [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`AGENTS.md`](./AGENTS.md).
