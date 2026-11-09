# POST-M4.4 Report — BIP-174 PSBT Finalization (Finalizer role)

**Milestone:** M4.4 — PSBT Finalizer role (P2WPKH, P2SH-P2WPKH)
**PR:** [#21](https://github.com/owensnigel22-cpu/UnifiedPipeline/pull/21) — **merged**
**Merge hash on `main`:** `7fc23f8` (`7fc23f80ace014ec860dddc32a5d7aa6a35046de`)
**Base before merge:** `f0f40f7` → fast-forward (linear history preserved)
**Date:** 2026-11-04

---

## 1. Merge outcome

- PR #21 fast-forwarded `main` from `f0f40f7` to `7fc23f8` (single commit,
  `feat(psbt): BIP-174 Finalizer role for P2WPKH and P2SH-P2WPKH (M4.4)`).
- GitHub reports PR #21 `state=closed merged=True merge_commit=7fc23f8`.
- No merge commit, no rebase of other PRs. The only other open PR is the
  deferred Dependabot coincurve bump (#3).
- **Final-review verification before merge:** 11/11 CI green; `mergeable_state=clean`;
  diff limited to the finalizer, its test, and docs/audit/security/changelog/
  benchmark/vectors — **no scope creep** (no change to `transaction.py`, no
  extraction/broadcast/wallet code, no second transaction or PSBT model).

## 2. CI evidence on `main` (all 11 jobs)

Polled against `main` head `7fc23f80ace014ec860dddc32a5d7aa6a35046de`:

| Job | Status |
|---|---|
| lint (ruff, mypy ratchet, docs, vectors) | ✅ success |
| full-extras (every backend, coverage) | ✅ success |
| bench-smoke (pure Python) | ✅ success |
| test (ubuntu-latest, 3.11 / 3.12 / 3.13 / 3.14) | ✅ success ×4 |
| test (windows-latest, 3.11 / 3.12 / 3.13 / 3.14) | ✅ success ×4 |

**ALL_DONE: True | JOBS: 11 | FAILURES: none.** Ubuntu 3.11–3.14 green; Windows
3.11–3.14 green; `full-extras` green; `bench-smoke` green.

## 3. Coverage

- `full-extras` coverage gate **green** (floor held; baseline ≈ 81.33%). The new
  `keylab/psbt/finalizer.py` is exercised end-to-end by 22 tests covering the
  happy path and every negative branch.

## 4. Finalization evidence

- New `keylab/psbt/finalizer.py` implements the BIP-174 **Finalizer** role for
  **P2WPKH** and **P2SH-P2WPKH** inputs: locates the partial signature keyed by
  the input's own public key, verifies it against the BIP-143 sighash, then
  builds the final `scriptWitness` (type `0x08`, count-prefixed `<sig> <pubkey>`)
  and, for P2SH-P2WPKH, the final `scriptSig` (type `0x07`, the redeemScript
  data-push). It removes the now-redundant signing fields (`0x02` partial sig,
  `0x03` sighash type, `0x04` redeem, `0x05` witness script, `0x06` BIP-32
  derivation) and keeps the UTXO, the finals, and proprietary/unknown records.
- **Byte-exact official known-answers:** reproduces the BIP-143 worked-example
  final `scriptSig` and `scriptWitness` for both supported types exactly
  (fixture fields added to `tests/vectors/bip143_signing_vectors.json`, pinned to
  the same BIP-143 commit `24e96e8…` already in `SOURCES.json`;
  `scripts/vectors.py verify` → 11/11).
- Public API: `finalize`, `finalize_input`, `is_finalized`, `PsbtFinalizeError`.
- **Safety invariants:** consumes existing signatures only (never creates one);
  never alters the unsigned transaction; never mutates the input PSBT or
  unrelated inputs; rejects missing partial sig, wrong public key, incorrect
  signature, missing UTXO/redeem data, and already-finalized inputs.
- Reuses `keylab.psbt`, `keylab.psbt.signer`, and `keylab.encoding.transaction`
  — one transaction model, one PSBT model.
- Tests: `tests/test_psbt_finalizer.py`, **22 tests** (all 10 required cases +
  Hypothesis + regression + negative). Full suite: **1668 passed, 14 skipped**.

## 5. Benchmark summary

- `keylab.benchmarks.benchmark_psbt_finalize` — correctness-gated; times a
  **single-input** (P2SH-P2WPKH) and a **multi-input** (P2WPKH example) finalize.
  `outputs_match_vectors: true`; ~1.1 ms/finalize in pure Python locally.
  `bench-smoke` green. No optimization work.

## 6. Security review

- SECURITY.md updated: the finalizer **consumes existing signatures only** — it
  never creates a signature, never alters the unsigned transaction, verifies each
  partial signature before finalizing, and leaves unrelated inputs and unknown
  fields untouched. `keylab.psbt` still does **not** extract, broadcast, or
  combine/merge, and does not handle P2WSH/Taproot/multisig; not production
  wallet software.
- `feature_audit` gains a Finalizer row; all 58 rows have `implementation_present`.
- No key material is logged or printed.

## 7. Final repository state

- `main` = **`7fc23f8`**.
- **Merged:** M4.0 BIP-39, M4.1 BIP-143, M4.2 PSBT parsing/validation/
  serialization, M4.3 PSBT signing, **M4.4 PSBT finalization**, research.ecdlp,
  research.hnp_lattice.
- **Open:** PR #3 (Dependabot coincurve) — still deferred.
- Validation: 1668 passed / 14 skipped · 11/11 CI green on `main` · coverage gate
  green · mypy baseline 99 maintained · API docs current · 11/11 fixtures
  verified.

---

## Next milestone

**M4.5 — Transaction Extraction** (BIP-174 Extractor role) — planning document
written to `M4_5_TRANSACTION_EXTRACTION_PLAN.md`. Implementation not started;
awaiting planning review.

**M4.4 COMPLETE — MERGED TO MAIN, 11/11 CI GREEN.**
