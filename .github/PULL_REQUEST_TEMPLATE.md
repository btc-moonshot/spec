## Summary

- **Related Issue(s):** #
- **Spec Files Modified:** (`SPEC.md`, `spec/01..05`, `scripts/verify_spec_bounds.py`)
- **Summary of Normative Change:**

## Mandatory Verification Checklist

- [ ] `python3 -I scripts/verify_spec_bounds.py` passes with exit code `0`, and EVERY number changed in prose matches the oracle's exact output.
- [ ] All cross-file references (`SPEC.md` and `spec/01..05`) are updated consistently with zero stale numbers or local filesystem paths.
- [ ] Any new trust assumption or unmeasured empirical parameter is disclosed explicitly in `SPEC.md §4` / `SPEC.md §7` and prefixed `ASSUMED_STAGE_0C_TARGET_` in the oracle.
- [ ] Ran `npm run sync:spec` so `public/raw/` and `public/llms-full.txt` match the root Markdown & Python files.
- [ ] `npm run build` succeeds cleanly.
