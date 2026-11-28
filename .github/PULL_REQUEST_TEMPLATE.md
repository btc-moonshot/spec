## Summary

- **Related Issue(s):** #
- **Spec Files Modified:** (`SPEC.md`, `spec/01..05`, `CHANGELOG.md`, `scripts/verify_spec_bounds.py`)
- **Summary of Normative Change:**

## Mandatory Verification Checklist

- [ ] `versions/v0/` is untouched and `(cd versions/v0 && shasum -a 256 -c SHA256SUMS.txt)` passes 100%.
- [ ] `python3 -I scripts/verify_spec_bounds.py` and `python3 -I versions/v0/scripts/verify_spec_bounds.py` both pass with exit code `0`, and EVERY number changed in prose matches the checker's exact output.
- [ ] All cross-file references (`SPEC.md`, `spec/01..05`, `CHANGELOG.md`) are updated consistently with zero stale numbers, zero federated multisig regressions, and zero local filesystem paths.
- [ ] Any new trust assumption or unmeasured empirical parameter is disclosed explicitly in `SPEC.md §4` / `SPEC.md §7` and prefixed `SOURCED_`, `POLICY_`, or `PRE_MAINNET_TARGET_` in `scripts/verify_spec_bounds.py`.
- [ ] Ran `npm run sync:spec` so `public/raw/` and `public/llms-full.txt` match the root Markdown & Python files.
- [ ] `npm run build` succeeds cleanly.
