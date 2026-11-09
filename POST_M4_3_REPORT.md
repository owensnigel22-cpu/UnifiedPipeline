# POST-M4.3 Report — BIP-174 PSBT Signing (Signer role)

**Milestone:** M4.3 — PSBT Signer role (P2WPKH, P2SH-P2WPKH)
**PR:** [#20](https://github.com/owensnigel22-cpu/UnifiedPipeline/pull/20) — **merged**
**Merge hash on `main`:** `f0f40f7` (`f0f40f7bf28f1716c3308fafe039b8dcb4c9b05f`)
**Base before merge:** `721aa45` → fast-forward (linear history preserved)
**Date:** 2026-11-04

---

## 1. Merge outcome

- PR #20 fast-forwarded `main` from `721aa45` to `f0f40f7` (single commit,
  `feat(psbt): BIP-174 Signer role for P2WPKH and P2SH-P2WPKH (M4.3)`).
- GitHub reports PR #20 `state=closed merged=True merge_commit=f0f40f7`.
- No merge commit, no rebase of other PRs required. The only other open PR is
  the deferred Dependabot coincurve bump (#3).

## 2. CI evidence on `main` (all 11 jobs)

Polled against `main` head `f0f40f7bf28f1716c3308fafe039b8dcb4c9b05f`:

| Job | Status |
|---|---|
| lint (ruff, mypy ratchet, docs, vectors) | ✅ success |
| full-extras (every backend, coverage) | ✅ success |
| bench-smoke (pure Python) | ✅ success |
| test (ubuntu-latest, 3.11 / 3.12 / 3.13 / 3.14) | ✅ success ×4 |
| test (windows-latest, 3.11 / 3.12 / 3.13 / 3.14) | ✅ success ×4 |

**ALL_DONE: True | JOBS: 11 | FAILURES: none.** Ubuntu 3.11–3.14 green;
Windows 3.11–3.14 green; `full-extras` green; `bench-smoke` green. These are the
same check-runs that passed on the PR head (identical SHA via fast-forward).

## 3. Gate verification

- **Coverage gate:** ✅ `full-extras` green — floor held (baseline ≈ 81.33%); the
  new signer module is exercised end-to-end by 28 tests (happy path + every
  negative branch).
- **Skip gate:** ✅ 14 skipped, unchanged from M4.2 — all backend-dependent skips
  (differential tests when a reference lib is absent); `full-extras` additionally
  requires the libsecp256k1 + fastecdsa backends via `scripts/check_backends.py`.
- **Fixtures:** ✅ `scripts/vectors.py verify` → 11/11 fixtures match pinned
  provenance (enforced in `lint`).
- **API docs:** ✅ `gen_api_docs.py --check` clean (enforced in `lint`); the
  `keylab.psbt` reference lists `sign`, `sign_input`, `signable_inputs`,
  `PsbtSignError`.
- **mypy baseline:** ✅ unchanged at 99 (CI-pinned mypy 2.4.1); clean on the
  `keylab.psbt` package; the ratchet was not lowered.

## 4. PSBT-signing evidence

- New `keylab/psbt/signer.py` implements the BIP-174 **Signer** role for
  **P2WPKH** and **P2SH-P2WPKH** inputs only: reads the witness UTXO (and, for
  P2SH, the redeem script), derives the implied P2PKH `script_code`, computes the
  BIP-143 sighash via `keylab.encoding.transaction.bip143_sighash`, signs with
  the deterministic (RFC 6979, low-S) `keylab.ec.secp256k1.ecdsa_sign_digest`,
  DER-encodes `(r,s)` + the sighash flag, and inserts a `PSBT_IN_PARTIAL_SIG`
  record.
- Public API: `sign`, `sign_input`, `signable_inputs`, `PsbtSignError`.
- **Byte-exact official known-answers:** reproduces the BIP-143 worked-example
  signatures for both supported types exactly (new fixture
  `tests/vectors/bip143_signing_vectors.json`, pinned to the same BIP-143 commit
  `24e96e8…` already in `SOURCES.json`).
- **Verify-before-emit:** every signature is checked with `ecdsa_verify_digest`
  and asserted low-S before it is inserted; the sighash is cross-checked against
  the independently-tested `bip143_sighash`.
- **Safety invariants:** input PSBT never mutated (deep-copied); existing records
  and unknown keys preserved; duplicate partial sigs, wrong keys, missing
  UTXO/redeem data, unsupported types, and out-of-range indices are rejected.
- **BIP-39/BIP-32 interaction:** demonstrated end-to-end
  (`mnemonic_to_seed` → `derive_private_path` → sign) in the test suite; signing
  consumes a caller-supplied private scalar and holds no key state.
- Tests: `tests/test_psbt_signer.py`, **28 tests** (known-answer, deterministic,
  insertion, preservation, wrong-key, missing-UTXO, missing-redeem, invalid
  index/key, duplicate, round-trip, unsupported-type, HD-derived, regression,
  benchmark gate, 2 Hypothesis properties). Full suite: **1646 passed,
  14 skipped**.

## 5. Benchmark summary

- `keylab.benchmarks.benchmark_psbt_sign` — correctness-gated; times a
  **single-input** (P2SH-P2WPKH) and a **multi-input** (P2WPKH example,
  2 inputs / 1 signable) signing path. `outputs_match_vectors: true`;
  ~0.8–1.2 ms/sign in pure Python locally. `bench-smoke` green. No optimization
  work — measurement only.

## 6. Security review

- SECURITY.md updated: `keylab.psbt` now signs **partial** ECDSA signatures for
  P2WPKH / P2SH-P2WPKH **for study and test-vector verification only**. It does
  **not** finalize, extract, combine, or broadcast; it does not sign P2WSH,
  Taproot, or multisig; and it is not production wallet software.
- Deterministic nonces only (RFC 6979) — no RNG nonce path. Verify-before-emit.
  No key export, WIF recovery, or encrypted storage added. No key material is
  logged or printed.
- `feature_audit` gains a Signer row; all 57 rows have `implementation_present`.

## 7. Final repository state

- `main` = **`f0f40f7`**.
- **Merged:** M4.0 BIP-39, M4.1 BIP-143, M4.2 PSBT parsing/validation/
  serialization, M4.3 PSBT signing, research.ecdlp, research.hnp_lattice.
- **Open:** PR #3 (Dependabot coincurve) — still deferred.
- Validation: 1646 passed / 14 skipped · 11/11 CI green on `main` · coverage gate
  green · mypy baseline 99 maintained · API docs current · 11/11 fixtures
  verified.

---

## Recommended next milestone

**M4.4 — PSBT finalization** (BIP-174 Finalizer role: build
`PSBT_IN_FINAL_SCRIPTSIG` / `PSBT_IN_FINAL_SCRIPTWITNESS` from collected partial
signatures), followed by transaction extraction as a distinct step. Both remain
out of scope until explicitly requested.

**M4.3 COMPLETE — MERGED TO MAIN, 11/11 CI GREEN.**
