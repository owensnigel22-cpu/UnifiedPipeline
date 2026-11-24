# KeyLab Milestone 8 — BIP-340 Verification Paths, Native Backend & Differential Validation

**Date:** 2026-11-24 · **Branch:** `docs/architecture-audit` · **HEAD:** `48c4b49` · **PR #46:** OPEN / unmerged
**Scope:** investigation + benchmarks + tests only. **No production cryptographic code was modified; no commit/push/merge occurred.**
**Environment:** Python 3.14.7, Windows-10-10.0.19045; backends present: `coincurve 19.0.1` (libsecp256k1), `ecdsa 0.19.2`, `gmpy2 2.3.2`; **`fastecdsa` absent**. Benchmark config: `seed=20261122`, `repetitions=5`, `component-repetitions=20`, `iterations=1`, batch sizes `1,2,4,8,16,32,64,128,256`.

## A. Architecture

| Path | Status | Implementation |
|---|---|---|
| A — Python individual | present (independent reference) | `keylab.ec.schnorr.schnorr_verify` |
| B — Python randomized batch | present, sound | `schnorr_verify_batch` + `_batch_coefficients` |
| C — Native individual | available | `coincurve.keys.PublicKeyXOnly.verify` (libsecp256k1) |
| D — Native batch | **NOT available** | Coincurve 19.0.1 exposes no batch verify and no MSM primitive |

- **Python individual** reconstructs `R = sG − eP` with `e = tagged_hash("BIP0340/challenge", r‖pk‖m) mod n`, and accepts only when `R ≠ ∞`, `R.y` even, `R.x == r`, with `0 ≤ r < p`, `0 ≤ s < n`, and a liftable even-`y` public key. It remains the independent mathematical oracle.
- **Python batch** forms the identity `(Σ aᵢsᵢ)G − Σ aᵢRᵢ − Σ aᵢeᵢPᵢ == ∞` as a single multi-scalar multiplication; `a₁ = 1` and the rest are CSPRNG-random. It equals the AND of the individual verifies.
- **Native backend:** `PublicKeyXOnly` exposes `{format, from_secret, from_valid_secret, tweak_add, verify}`. API inspection finds **no** symbol containing "batch" and **no** exposed multi-scalar multiplication. Evidence recorded by the harness: `"Coincurve/PublicKeyXOnly exposes only individual verify; no native batch API was found."` Native batch is therefore reported as unavailable and is **not** simulated by looping individual native verifies.

## B. Correctness

- **Differential corpus (native vs Python):** across the full benchmark corpus the independent Coincurve preflight recorded **3,057 checked agreements, 18 malformed inputs classified separately (`malformed_signature_length`), and 0 disagreements**. The preflight raises `ArithmeticError` on any native/Python mismatch (never suppressed); a parser/API rejection is recorded under `unsupported_or_parser_rejected` and is **never** counted as an agreement.
- **BIP-340 official vectors:** all **19** vectors (9 accepted, 10 rejected) match between KeyLab, the official expected outcomes, and libsecp256k1 via Coincurve (invariant harness **25/25**; `test_bip340_vectors.py` green).
- **Input-category differential (new test `test_differential_schnorr_input_categories_python_and_native`):** valid distinct, repeated public keys, repeated messages, empty batch, single-item batch, mixed valid/invalid, out-of-range `r` (= p), out-of-range `s` (= n), malformed signature length, malformed x-only key length, and non-liftable/out-of-field x. For every case: Python batch == AND of Python individual; native never disagrees on a parseable item; malformed inputs are classified as unsupported, not as agreements.
- **Unresolved issues:** none. No disagreement was observed between the independent Python reference and libsecp256k1.

## C. Performance

Median per-operation latency for `valid-distinct`, by batch size (ms):

| size | Python individual | Python batch (CSPRNG) | Native individual | native speedup vs py-individual | py-batch vs py-individual |
|---:|---:|---:|---:|---:|---:|
| 1 | 0.388 | 0.620 | 0.052 | 7.5× | 1.60× slower |
| 2 | 0.781 | 1.224 | 0.104 | 7.5× | 1.57× slower |
| 4 | 1.538 | 2.601 | 0.203 | 7.6× | 1.69× slower |
| 8 | 3.142 | 4.787 | 0.864 | 3.6× | 1.52× slower |
| 16 | 8.082 | 10.526 | 1.005 | 8.0× | 1.30× slower |
| 32 | 13.457 | 20.052 | 1.681 | 8.0× | 1.49× slower |
| 64 | 25.827 | 40.460 | 3.407 | 7.6× | 1.57× slower |
| 128 | 62.078 | 79.544 | 6.974 | 8.9× | 1.28× slower |
| 256 | 106.932 | 160.821 | 14.592 | 7.3× | 1.50× slower |

Key observations:
- **Native individual (libsecp256k1) is the fastest path** — ~7–9× faster than Python individual and ~10× faster than Python batch — at every size.
- **Pure-Python randomized batch is *slower* than pure-Python individual at all tested sizes** (1.3–1.7×). The observed crossover vs individual is **none** (`null`) for both CSPRNG and fixed-coefficient batch. The batch MSM in pure Python does not amortize enough to beat N independent verifies.
- **Parsing / point-lifting dominates the Python cost.** Component profile at size 256 (median ms): full signature+point parsing **125.3**, public-key parsing 48.3, nonce-MSM 27.5, public-key-MSM 28.6, individual end-to-end 100.4, batch-CSPRNG end-to-end 153.3, challenge 0.6, coefficient generation 0.4 — versus **native individual verify 15.6** and native public-key parsing 2.0. Native acceleration wins precisely because it avoids Python-level field/point work, not merely because EC ops are faster.
- **Invalid batches do not early-exit:** `invalid_batch_degradation` ratios are ≈1.0 across positions (first/middle/last/malformed), i.e. an invalid batch costs about the same as a valid one — expected for a single-MSM batch check.
- Cold-vs-warm: the harness records warmup operations and reports median/mean/min/max/stdev per row (see JSON/CSV).

Artifacts (reproducible):
- `benchmarks/milestone8_schnorr_msm.json`
- `benchmarks/milestone8_schnorr_msm.csv`
- `benchmarks/milestone8_console.txt`
Reproduce: `python scripts/benchmark_msm_schnorr_batch.py --json-output benchmarks/milestone8_schnorr_msm.json --csv-output benchmarks/milestone8_schnorr_msm.csv`

## D. Security

- **Random coefficient generation:** `_batch_coefficients` uses `secrets` (CSPRNG) with `a₁ = 1` fixed and `aᵢ ∈ [1, N−1]`; it never falls back to `random.Random`, never caches, and is not reused across calls. This satisfies the BIP-340 randomized-batch soundness requirement (an invalid batch passes only with negligible probability). **Unchanged by Milestone 8.**
- **Fixed coefficients** appear only in diagnostic/reproducible tests and the labeled `deterministic_batch` benchmark component — never in production verification. The `coefficients=` parameter of `schnorr_verify_batch` is documented as test-only.
- **Backend behavior:** availability is detected with `find_spec`; unsupported inputs are classified explicitly; a parser/API exception is a rejection, never converted into a successful verification. No native batch "soundness" question arises because no native batch exists. No global mutable cryptographic state or unsafe cache was introduced.
- **Boundary preserved:** native results are compared *against* the Python reference, which remains the oracle; the native path is not the sole correctness authority. No new side-channel/constant-time claims are made.

## E. Recommendation

**Option 4 — retain both the Python reference and an optional native *individual* backend, with explicit backend selection; do not add native batch.**

Justification from the measurements and sources:
- Native individual verification is ~7–9× faster and agrees with the Python reference on 3,057 corpus checks and all 19 BIP-340 vectors (0 disagreements), so it is a safe optional accelerator.
- Native batch verification cannot be added honestly: Coincurve 19.0.1 / the exposed libsecp256k1 Python API provides no batch verify and no MSM, and simulating it would misrepresent the security/performance model.
- Pure-Python batch should be **retained as an independent randomized-batch reference**, but documented as **not a performance optimization** (it is slower than individual verification in pure Python). Its value is mathematical independence and the all-or-nothing single-MSM check, not throughput.

## F. Change inventory

**Modified (untracked; benchmark/test only — no production code):**
- `scripts/benchmark_msm_schnorr_batch.py` — lint corrections: `B023` (bind loop variable `items` via default arg in `native_public_key_parsing` / `native_individual_verification`) and `SIM103` (return `bool(unsupported)` directly). No behavioral change to measurements.
- `tests/test_msm_schnorr_batch_benchmark.py` — `I001` import sort; added `test_differential_schnorr_input_categories_python_and_native` and `_assert_complete_native_classification`.

**Created (untracked):**
- `benchmarks/milestone8_schnorr_msm.json`, `benchmarks/milestone8_schnorr_msm.csv`, `benchmarks/milestone8_console.txt`
- `KEYLAB_MILESTONE8_REPORT.md` (this file)

**Production cryptographic code:** unchanged. **No defect** requiring a production change was discovered.

## Validation results (M8 §10)

| Check | Result |
|---|---|
| Focused BIP-340 + ECC differential + M8 bench tests | 234 passed, 13 skipped (fastecdsa absent) |
| Milestone 8 benchmark tests | 11 passed |
| Invariant harness (`scripts/verify_invariants.py`) | **25/25** |
| CLI self-test | **25/25** PASS |
| Ruff (whole repo, incl. the harness) | clean |
| mypy (`src`, ratchet scope) | unaffected (harness/tests out of mypy scope) |
| `docs/api.md` up to date | yes |
| `git diff --check` | clean |
| Full default suite (this environment) | 2,518 passed, 14 skipped, 9 deselected |

**Baseline reconciliation (M8 §10):** the cited baseline (2,531 passed / 0 skipped) was recorded with **both** `coincurve` and `fastecdsa` installed. This environment lacks `fastecdsa`, so 14 native-differential tests (12+1 in `test_ecc_differential.py`, 1 in `test_generator_table.py`) **skip** instead of passing — accounting for the lower passed count and the 14 skips. No failures and no regressions; installing `fastecdsa` would convert those skips back to passes. Per instruction, dependency declarations were **not** changed to eliminate the skips.

## Final Git state

- Branch `docs/architecture-audit`, HEAD `48c4b49`, in sync with `origin`; **PR #46 OPEN / unmerged**.
- No commit, push, merge, branch change, or working-tree reset performed.
- Untracked: `benchmarks/`, `scripts/benchmark_msm_schnorr_batch.py`, `tests/test_msm_schnorr_batch_benchmark.py`, `KEYLAB_MILESTONE8_REPORT.md`. No tracked files modified.
