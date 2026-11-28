# zBTC: Bitcoin–Zenon Interoperability Protocol Specification (`v1` / `v3.0.0-rfc`)

> **Public RFC (`v1` / `v3.0.0-rfc`)** — Zero-Federation Phased Architecture (**Stage 0 Verify Bitcoin → Stage 1A Right-Sized `BitVMX` Sovereign ZK Rollup | Stage 1B `clArk` Alternative Gate → Stage 2 Zero-TTP Scale**). Pre-implementation technical specification open for adversarial human & AI-agent review. Supersedes archived [`v0` (`v2.5.0-rfc`)](./versions/v0/SPEC.md).
>
> - **Read the Full Spec:** <https://btc-moonshot.github.io/spec/>
> - **Changelog & Diffs (`v0 → v1`):** <https://btc-moonshot.github.io/spec/changelog/>
> - **Archived `v0` (`v2.5.0-rfc`):** <https://btc-moonshot.github.io/spec/v0/>
> - **LLM / Agent Manifest & Review Protocol:** <https://btc-moonshot.github.io/spec/llms.txt>
> - **Single-Fetch Complete Spec Bundle:** <https://btc-moonshot.github.io/spec/llms-full.txt>
> - **Vision Essay:** <https://btc-moonshot.github.io/bigidea/>

## Repository Layout

| Path | Description |
|---|---|
| [`SPEC.md`](./SPEC.md) | Master overview, zero-federation phased architecture (Stage 0 → Stage 1A `BitVMX` / Stage 1B `clArk` → Stage 2), honest threat model, verification gates, public claims alignment, and `R7` Q&A |
| [`spec/01-bitcoin-taproot-vault-enforcement.md`](./spec/01-bitcoin-taproot-vault-enforcement.md) | Part 1 (Highest Precedence) — Zero-Federation Bitcoin Custody Enforcement: right-sized `BitVMX` (`n=8`, 100% BIP-431 TRUC v3, deleted-key `{0.50, 0.25, 0.25}` BTC vaults, Lamport `TakeTx`, dual-input slashing), `clArk` alternative gate, and Stage 2 zero-TTP upgrade boundary |
| [`spec/02-btc-authorization-domain-and-spv.md`](./spec/02-btc-authorization-domain-and-spv.md) | Part 2 — Stage 0 Direct-on-L1 Bitcoin SPV Event Oracle (1-/2-block coinbase midstate, panic-recovered) & Stage 1A Bitcoin L1 DA / Forced-Inclusion Inbox (`0x00..0x07`) |
| [`spec/03-settlement-minted-zbtc-and-feeless-rails.md`](./spec/03-settlement-minted-zbtc-and-feeless-rails.md) | Part 3 — Stage 0 Non-Custodial PTLC/LN Swaps & Stage 1A Sovereign Rollup STF, Feeless Zenon `AccountBlock.Data` Sequencer Rails (`8 MiB` honest ceiling), `B_zbtc` Accounting, and Stage 1B `clArk` Rails |
| [`spec/04-bitcoin-anchoring-and-light-client.md`](./spec/04-bitcoin-anchoring-and-light-client.md) | Part 4 — Zenon 49% DPoS & >33.3% BFT Impossibility Proof, Inverted Bitcoin-L1-First Trust Hierarchy (`0-of-N` Zenon Trust), and Optional Non-Custodial Light-Client Infrastructure |
| [`spec/05-go-zenon-upgrade-plan.md`](./spec/05-go-zenon-upgrade-plan.md) | Part 5 — Stage 0 `go-zenon` Prerequisites (`#239` FIFO gate, `DynamicPlasmaSpork` + full `SetPlasmaVariables` pinning, `PtlcSpork`, SPV oracle) & Stage 1A/1B Zero-Hard-Fork Custody Boundary |
| [`CHANGELOG.md`](./CHANGELOG.md) | Complete finding-by-finding `v0 → v1` disposition of Consolidated Hostile Review `R7` (`C-1..C-4`, `H-1..H-8`, `M-1..M-15`, `L-1..L-4`) without federated multisigs |
| [`scripts/verify_spec_bounds.py`](./scripts/verify_spec_bounds.py) | Deterministic Python 3 Consistency & Bounds Checker (`SOURCED_`, `POLICY_`, `PRE_MAINNET_TARGET_` inputs + non-no-op 2,000-step state-machine & reorg simulation) |
| [`versions/v0/`](./versions/v0/) | Immutable byte-for-byte archive of `v0` (`v2.5.0-rfc`, commit `7b47b8c`, SHA-256 verified in `versions/v0/SHA256SUMS.txt`) |
| [`reviews/`](./reviews/) | Complete unedited archive of Hostile Peer Reviews Rounds 1–7 (`R7` consolidated NO-GO of `v0`) |
| [`AGENTS.md`](./AGENTS.md) & [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Instructions for human reviewers and AI agents on auditing, filing issues, and opening PRs |
| `src/` & `public/` | Static Astro site deployed to GitHub Pages (with version switcher & word-level `v1` vs `v0` diffs) |

## Verify the Consistency & Bounds Checker

Zero third-party dependencies (standard library Python 3):

```bash
(cd versions/v0 && shasum -a 256 -c SHA256SUMS.txt)
python3 -I scripts/verify_spec_bounds.py
python3 -I versions/v0/scripts/verify_spec_bounds.py
```

## Build the Specification Site Locally

```bash
npm ci
npm run sync:spec
npm run build
```

## Review, File Issues, or Open a PR

Found a flaw, edge case, or improvement? Open an [Adversarial Finding](https://github.com/btc-moonshot/spec/issues/new?template=adversarial-finding.yml) or [Spec Change Proposal](https://github.com/btc-moonshot/spec/issues/new?template=spec-change-proposal.yml), or submit a PR following [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`AGENTS.md`](./AGENTS.md).
