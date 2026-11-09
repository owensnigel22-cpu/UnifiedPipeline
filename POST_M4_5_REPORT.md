# POST-M4.5 Report — BIP-174 Transaction Extraction (Extractor role)

**Milestone:** M4.5 — PSBT Extractor role (P2WPKH, P2SH-P2WPKH) + BIP-144 serialization
**PR:** [#22](https://github.com/owensnigel22-cpu/UnifiedPipeline/pull/22) — **merged**
**Merge hash on `main`:** `dfa5a6f` (`dfa5a6ff862ebfc4dd125e6e47ee32a542ab6177`)
**Base before merge:** `7fc23f8` → fast-forward (linear history preserved)
**Date:** 2026-11-04

---

## 1. Merge outcome

- PR #22 fast-forwarded `main` from `7fc23f8` to `dfa5a6f` (single commit,
  `feat(psbt): BIP-174 Extractor role + BIP-144 tx serialization (M4.5)`).
- GitHub reports PR #22 `state=closed merged=True merge_commit=dfa5a6f`.
- No merge commit, no rebase of other PRs. The only other open PR is the deferred
  Dependabot coincurve bump (#3).
- **Final-review verification before merge:** 11/11 CI green; `mergeable_state=clean`;
  diff limited to the extractor, its test, the approved `serialize_transaction`
  in `transaction.py`, and docs/audit/security/changelog/benchmark/vectors —
  **no scope creep** (no broadcast/combine/merge/wallet code, no second
  transaction or PSBT model, no second serializer).

## 2. CI evidence on `main` (all 11 jobs)

Polled against `main` head `dfa5a6ff862ebfc4dd125e6e47ee32a542ab6177`:

| Job | Status |
|---|---|
| lint (ruff, mypy ratchet, docs, vectors) | ✅ success |
| full-extras (every backend, coverage) | ✅ success |
| bench-smoke (pure Python) | ✅ success |
| test (ubuntu-latest, 3.11 / 3.12 / 3.13 / 3.14) | ✅ success ×4 |
| test (windows-latest, 3.11 / 3.12 / 3.13 / 3.14) | ✅ success ×4 |

**ALL_DONE: True | JOBS: 11 | FAILURES: none.** Ubuntu 3.11–3.14 green; Windows
3.11–3.14 green; `full-extras` green; `bench-smoke` green.

## 3. Extraction evidence

- New `keylab/psbt/extractor.py` implements the BIP-174 **Extractor** role for
  **P2WPKH** and **P2SH-P2WPKH**: it assembles the final `Transaction` from a
  finalized PSBT by injecting each input's `PSBT_IN_FINAL_SCRIPTSIG` (`0x07`)
  into `script_sig` and the decoded `PSBT_IN_FINAL_SCRIPTWITNESS` (`0x08`) into
  the witness, then serializes it.
- New `serialize_transaction` in `keylab.encoding.transaction` (the single
  transaction model) — legacy, or BIP-144 SegWit when any input has witness data
  — the **exact inverse of `parse_transaction`** (round-trip verified on the
  official BIP-143 transactions and the legacy unsigned form).
- **Byte-exact official known-answers:** sign → finalize → extract reproduces the
  BIP-143 worked-example final signed transactions **byte-for-byte** for both
  types (`final_tx` fields added to `tests/vectors/bip143_signing_vectors.json`,
  pinned to the same BIP-143 commit `24e96e8…`; `vectors.py verify` → 11/11).
- **No cryptography:** the extractor never signs, verifies, or alters the
  transaction's contents; it requires every input finalized (raises
  `PsbtExtractError` otherwise), rejects malformed finalized witnesses, and never
  mutates the input PSBT.
- Public API: `extract`, `extract_transaction`, `PsbtExtractError`.
- Reuses `keylab.psbt`, `keylab.psbt.signer`, `keylab.psbt.finalizer`, and
  `keylab.encoding.transaction` — one transaction model, one PSBT model.
- Tests: `tests/test_psbt_extractor.py`, **16 tests**. Full suite: **1684 passed,
  14 skipped**; `validate_all()` = 0.

## 4. Benchmark summary

- `keylab.benchmarks.benchmark_psbt_extract` — correctness-gated; times
  **single-input** (P2SH-P2WPKH) and **multi-input** (P2WPKH example) extraction,
  asserting the output equals the official `final_tx`. `outputs_match_vectors:
  true`; ~0.2 ms/extract in pure Python locally. `bench-smoke` green. No
  optimization work.

## 5. Coverage impact

- `full-extras` coverage gate **green** (floor held; baseline ≈ 81.33%). The new
  `extractor.py` and `serialize_transaction` are exercised end-to-end by the 16
  tests across the happy path and every negative branch.

## 6. Security review

- SECURITY.md updated: the extractor performs **no cryptography** — never signs,
  verifies, or alters transaction contents; never mutates the input PSBT; returns
  bytes only (no broadcast). `keylab.psbt` still does **not** broadcast, combine,
  or merge, and does not handle P2WSH/Taproot/multisig.
- `feature_audit` gains an Extractor row; all 59 rows have `implementation_present`.
- No key material is logged or printed.

## 7. Final repository state

- `main` = **`dfa5a6f`**.
- **Merged:** M4.0 BIP-39, M4.1 BIP-143, M4.2 PSBT parse/validate/serialize,
  M4.3 PSBT signing, M4.4 PSBT finalization, **M4.5 transaction extraction**,
  research.ecdlp, research.hnp_lattice.
- **Open:** PR #3 (Dependabot coincurve) — still deferred.
- Validation: 1684 passed / 14 skipped · `validate_all()` = 0 · 11/11 CI green on
  `main` · coverage gate green · mypy baseline 99 maintained · API docs current ·
  11/11 fixtures verified.

---

## Next milestone

**M4.6 — PSBT Combine** (BIP-174 Combiner role) — planning document written to
`M4_6_PSBT_COMBINE_PLAN.md`. Implementation not started; awaiting planning review.

**M4.5 COMPLETE — MERGED TO MAIN, 11/11 CI GREEN.**
