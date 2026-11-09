# POST-M4.6 Report — BIP-174 PSBT Combine (Combiner role)

**Milestone:** M4.6 — PSBT Combiner role
**PR:** [#23](https://github.com/owensnigel22-cpu/UnifiedPipeline/pull/23) — **merged**
**Merge hash on `main`:** `1073caa` (`1073caa26aed89d14695f59db582c070f83597d5`)
**Base before merge:** `dfa5a6f` → fast-forward (linear history preserved)
**Date:** 2026-11-04

---

## 1. Merge outcome

- PR #23 fast-forwarded `main` from `dfa5a6f` to `1073caa` (single commit,
  `feat(psbt): BIP-174 Combiner role (M4.6)`).
- GitHub reports PR #23 `state=closed merged=True merge_commit=1073caa`.
- No merge commit, no rebase of other PRs. The only other open PR is the
  deferred Dependabot coincurve bump (#3).
- **Pre-merge verification:** `main` was `dfa5a6f` (M4.6 not merged, not
  superseded); PR #23 `mergeable_state=clean`; 11/11 CI green on `1073caa`;
  clean single-commit fast-forward; diff limited to the combiner, its test, the
  combiner fixture, and docs/audit/security/changelog/benchmark — **no scope
  creep** (no change to `transaction.py`, no merge/broadcast/wallet code, single
  PSBT and transaction model).

## 2. CI evidence on `main` (all 11 jobs)

Polled against `main` head `1073caa26aed89d14695f59db582c070f83597d5`:

| Job | Status |
|---|---|
| lint (ruff, mypy ratchet, docs, vectors) | ✅ success |
| full-extras (every backend, coverage) | ✅ success |
| bench-smoke (pure Python) | ✅ success |
| test (ubuntu-latest, 3.11 / 3.12 / 3.13 / 3.14) | ✅ success ×4 |
| test (windows-latest, 3.11 / 3.12 / 3.13 / 3.14) | ✅ success ×4 |

**ALL_DONE: True | JOBS: 11 | FAILURES: none.** Ubuntu 3.11–3.14 green; Windows
3.11–3.14 green; `full-extras` green; `bench-smoke` green.

## 3. Combine evidence

- New `keylab/psbt/combiner.py` implements the BIP-174 **Combiner** role:
  `combine(psbts, *, strict=True)` merges two or more structurally valid PSBTs
  that carry a byte-identical `PSBT_GLOBAL_UNSIGNED_TX` into the per-map union of
  their key-value pairs — deduplicating identical records, applying the BIP-174
  first-value rule on benign conflicts, rejecting conflicting finalized fields
  (`0x07`/`0x08`) in strict mode (default; `strict=False` downgrades to
  first-value), and preserving unknown/proprietary keys.
- **Official vector match:** combining the two official BIP-174 signer PSBTs
  yields the spec's expected combined PSBT as a **key/value set per map**,
  byte-length-identical (1332 B). BIP-174 v0 does not mandate intra-map record
  order, so set-equality is the spec-faithful oracle.
- **Cross-role:** `combine(empty, signed) → finalize → extract` reproduces the
  BIP-143 final transaction; order-independence and idempotence verified;
  `validate_all()` = 0.
- **No cryptography / no mutation:** the combiner interprets no value, creates no
  signature, and never mutates its inputs.
- Public API: `combine`, `PsbtCombineError`. Single PSBT and transaction models
  — no change to `keylab.encoding.transaction`.
- Tests: `tests/test_psbt_combiner.py`, **17 tests**. Full suite: **1701 passed,
  14 skipped**.

## 4. Benchmark summary

- `keylab.benchmarks.benchmark_psbt_combine` — correctness-gated: combines the
  official two-signer vector, asserts the key/value-set match, then times
  `combine`. `outputs_match_vectors: true`; ~0.15 ms/combine in pure Python
  locally. `bench-smoke` green. No optimization work.

## 5. Coverage impact

- `full-extras` coverage gate **green** (floor held; baseline ≈ 81.33%). The new
  `combiner.py` is exercised end-to-end across union/dedup/conflict/negative
  branches.

## 6. Security review

- SECURITY.md updated: the combiner performs **no cryptography**, interprets no
  value, and never mutates inputs; it is the BIP-174 v0 Combiner only — **not** a
  BIP-370 merge of differing transactions, and it does not broadcast.
- `feature_audit` gains a Combiner row; all 60 rows have `implementation_present`.
- No key material is logged or printed.

## 7. Final repository state

- `main` = **`1073caa`**.
- **Merged:** M4.0 BIP-39, M4.1 BIP-143, M4.2 PSBT parse/validate/serialize,
  M4.3 PSBT signing, M4.4 PSBT finalization, M4.5 transaction extraction,
  **M4.6 PSBT combine**, research.ecdlp, research.hnp_lattice.
- **Open:** PR #3 (Dependabot coincurve) — still deferred.
- Validation: 1701 passed / 14 skipped · `validate_all()` = 0 · 11/11 CI green on
  `main` · coverage gate green · mypy baseline 99 maintained · API docs current ·
  12/12 fixtures verified.

---

## Next milestone

**PSBT merge** (the directive's path after combine), then wallet-workflow
evaluation. No milestone is started; awaiting explicit direction.

**M4.6 COMPLETE — MERGED TO MAIN, 11/11 CI GREEN.**
