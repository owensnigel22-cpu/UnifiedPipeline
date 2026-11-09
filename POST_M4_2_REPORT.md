# POST-M4.2 Report — BIP-174 PSBT (parse / validate / serialize)

**Milestone:** M4.2 — PSBT structural support (BIP-174)
**PR:** [#19](https://github.com/owensnigel22-cpu/UnifiedPipeline/pull/19) — **merged**
**Merge commit on `main`:** `721aa45`
**Base before merge:** `4ba25ac` → fast-forward (linear history preserved)
**Date:** 2026-11-04

---

## 1. Merge outcome

- PR #19 fast-forwarded `main` from `4ba25ac` to `721aa45` (single commit,
  `feat(psbt): BIP-174 PSBT parsing, validation, and serialization (M4.2)`).
- GitHub reports PR #19 `state=closed merged=True merge_commit=721aa45`.
- No divergence, no merge commit, no rebase of other PRs required (no open PRs
  depended on this branch).

## 2. CI status on `main` (all 11 jobs)

Polled against `main` head `721aa4502f22bd4a7053ee48d2075b45174bde22`:

| Job | Status |
|---|---|
| lint (ruff, mypy ratchet, docs, vectors) | ✅ success |
| full-extras (every backend, coverage) | ✅ success |
| bench-smoke (pure Python) | ✅ success |
| test (ubuntu-latest, 3.11 / 3.12 / 3.13 / 3.14) | ✅ success ×4 |
| test (windows-latest, 3.11 / 3.12 / 3.13 / 3.14) | ✅ success ×4 |

**ALL_DONE: True | JOBS: 11 | FAILURES: none.** The 11 green jobs on `main` are
the same check-runs that passed on the PR head (identical SHA via fast-forward).

## 3. What landed

New `keylab.psbt` package, strictly parse / validate / serialize:

- `model.py` — `PSBT_MAGIC`, BIP-174 key-type constants, `PsbtError`,
  `KeyPair` (key/value with `key_type`/`key_data` accessors), `PsbtMap`
  (ordered pairs, `get`/`types`), `Psbt` (global + per-input + per-output maps,
  `unsigned_tx_bytes`), canonical CompactSize reader.
- `parser.py` — `deserialize(raw) -> Psbt`: magic check, global map, required
  unsigned-tx record, per-input/per-output maps sized from the parsed tx,
  duplicate-key rejection, trailing-byte rejection; wraps low-level errors as
  `PsbtError`.
- `serializer.py` — `serialize(psbt) -> bytes`: exact record re-emission with
  `0x00` separators.
- `validator.py` — `validate(psbt)`: unsigned-tx present / non-witness-
  serialized / unsigned; map-count agreement; singleton-key no-keydata rules;
  pubkey-keyed records carry 33/65-byte keys; unknown types allowed.
- `__init__.py` — re-exports + `parse(raw) = deserialize + validate`.

**Reuse, not duplication:** all transaction handling delegates to the existing
`keylab.encoding.transaction` (`parse_transaction`, `Transaction`,
`compact_size`, `ser_string`). No second transaction model and no second PSBT
model were introduced.

## 4. BIP-174 vector evidence

- Fixture `tests/vectors/bip174_psbt_vectors.json`: **14 valid** + **20 invalid**
  official vectors extracted from `bip-0174.mediawiki`.
- Provenance pinned in `tests/vectors/SOURCES.json` (40-char commit pin +
  CRLF→LF-normalized sha256, `mode: extracted`); `scripts/vectors.py verify`
  passes (10 fixtures total) — enforced by the `lint` job.
- All 14 valid vectors parse, validate, and **round-trip byte-exact**
  (`serialize(parse(x)) == x`). All 20 invalid vectors are rejected with
  `PsbtError`.
- Signing/finalization worked-examples in the BIP were **deliberately excluded**
  — they belong to the Signer role (M4.3), which is out of M4.2 scope.

## 5. Correctness evidence (oracles)

- **Primary oracle — official vectors:** 34/34 pass as above ("the vectors win").
- **Secondary oracle — existing transaction parser / BIP-143:** the unsigned tx
  inside each PSBT is parsed with the already-tested `parse_transaction`, and
  input/output map counts are checked against it.
- Witness-serialization of the unsigned tx is detected by re-serializing the
  parsed tx in legacy form and comparing, avoiding the 0-input segwit-marker
  ambiguity.

## 6. Test evidence

- New `tests/test_psbt.py`: **56 tests** — parametrized valid/invalid vectors,
  bad magic, missing/duplicate/truncated records, trailing bytes, non-canonical
  CompactSize, type errors, unknown-key preservation, boundary-length values
  `[0, 1, 252, 253, 254, 65535, 65536]`, `KeyPair` accessors, a structural
  regression (first valid vector: 1 input map, 2 empty output maps), and 2
  Hypothesis properties.
- Full local suite: **1618 passed, 14 skipped**; `validate_all()` returns 0.
- CI `test` matrix (8 cells) and `full-extras` all green — the authoritative
  gate.

## 7. Coverage impact

- `full-extras` (coverage gate) is green on `main`; the coverage floor held.
  The new package is exercised end-to-end by the 56 tests (parse/validate/
  serialize paths, plus negative branches and property tests).

## 8. Security review

- `SECURITY.md` "Not a wallet" section updated: `keylab.psbt` parses, validates,
  and re-serializes PSBTs **for study and test-vector verification only — it
  does not sign, finalize, extract, combine, or broadcast, and is not production
  wallet software.**
- `feature_audit` gained a PSBT row (`implementation: src/keylab/psbt/__init__.py`,
  `test_source: tests/test_psbt.py`); `test_feature_audit` passes
  (`implementation_present` true via `.is_file()`).
- No signing, no key handling, no network, no broadcast surface introduced.
- `CHANGELOG.md` updated under `[Unreleased] / Added`.

## 9. Benchmark summary

- `keylab.benchmarks.benchmark_psbt(count=200)` added — **correctness-gated**
  round-trip over the valid vectors, timing deserialize / serialize / validate.
- `bench-smoke` CI job green. No optimization work was undertaken; the benchmark
  is measurement only.

## 10. API / docs

- `docs/api.md` regenerated; `keylab.psbt` section added
  (`gen_api_docs.py --check` clean, enforced by `lint`).
- Public names: `PSBT_MAGIC`, `KeyPair`, `Psbt`, `PsbtError`, `PsbtMap`,
  `deserialize`, `parse`, `serialize`, `validate` (plus BIP-174 key-type
  constants from `keylab.psbt.model`).

## 11. Scope adherence & residual risk

- **Scope held:** parser, serializer, validator, round-trip only. No signing,
  finalizing, extraction, combining, broadcasting; none of the M4.2
  DO-NOT-START items were touched.
- **Residual risk / known limits (by design, not defects):**
  - PSBT **v2** (BIP-370) is not supported — v0 (`PSBT_GLOBAL_UNSIGNED_TX`) only.
  - No semantic validation of script/UTXO *contents* beyond BIP-174 structural
    rules (that is Signer/Updater territory, deferred).
  - mypy baseline unchanged (local mypy version reports a lower count than the
    CI-pinned 2.4.1; the ratchet baseline was never lowered — version artifact
    only, CI `lint` is authoritative and green).

---

## Recommended next milestone

**M4.3 — PSBT Signing (BIP-174 Signer role).** Plan written to
`M4_3_PSBT_SIGNING_PLAN.md`. Scope: compute and attach partial ECDSA signatures
only — **no** finalization, extraction, wallet workflows, or research tooling.
Awaiting explicit approval to begin implementation.

**M4.2 COMPLETE — MERGED TO MAIN, 11/11 CI GREEN.**
