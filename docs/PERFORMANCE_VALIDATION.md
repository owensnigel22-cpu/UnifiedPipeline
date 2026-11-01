# Performance validation

How KeyLab proves that a faster implementation is still a correct one. Every
change to curve arithmetic (M2 and later: batch normalization, generator
tables, GLV/wNAF, Straus, multi-scalar multiplication, Pippenger) must meet
the acceptance criteria at the end of this page before it is merged.

## The validation contract

Four implementations are compared. Each is selectable by name through
`scalar_mult(scalar, point, backend=...)`:

| Name | What it is | Role |
|---|---|---|
| `python-reference` | `keylab.ec.reference`: affine chord-and-tangent formulas, one modular inversion per operation, left-to-right double-and-add, its own copy of the curve constants, no imports from the rest of KeyLab | **The oracle.** Frozen: never optimized, changed only to fix a demonstrated bug |
| `python-optimized` | Exactly what `scalar_mult(backend="auto")` runs when no native backend is installed (`_scalar_mult_pure_python`) | **The code under change.** Optimizations go here |
| `coincurve` | libsecp256k1, the library Bitcoin Core uses | Independent native check, whenever installed |
| `fastecdsa` | A second, unrelated native implementation | Independent native check, whenever installed |

The other pure-Python strategies (`python`, `python-affine-window`,
`python-glv`, `python-wnaf`) are validated alongside these.

The oracle is itself checked against external evidence only
(`tests/test_ec_reference.py`): the SEC 2 constants, the published 2G and 3G,
and the public keys in the official BIP-340 vectors. It shares no code with the
paths it validates, so one bug cannot be present on both sides of a comparison.

## Correctness requirements

`keylab.ec.validation` provides one check per family of operations. Each
returns a list of `Mismatch` records (empty means agreement);
`assert_no_mismatches` turns a non-empty list into a readable failure.

| Check | Compares with the reference |
|---|---|
| `diff_scalar_mult` | `scalar_mult` for every available backend, on every edge scalar × every edge point |
| `diff_group_operations` | Affine addition and negation; Jacobian `point_add`, `point_double`, mixed addition; `_to_jacobian`/`_to_affine`, using Jacobian inputs with Z = 1 and three non-trivial Z values; all over the edge points, their negations, and infinity |
| `diff_serialization` | SEC1 compressed and uncompressed encoding, x-only encoding, `parse_sec1`, `decompress_pubkey`, `lift_x`, and rejection of invalid encodings (the same exception type) |
| `diff_infinity` | Scalars 0, N, 2N; `scalar_mult(k, None)`; negative scalars rejected; G + (−G); infinity as an operand; Jacobian infinity; encodings of infinity rejected |
| `diff_batch_normalization` | `batch_to_affine` on one mixed batch (edge points and negations in four Jacobian forms, affine points, `None`, Z ≡ 0) and on sub-batches of 0, 1, and 2; per-point `_to_affine` on the same inputs |
| `validate_all` | All five |

**Edge scalars** (`EDGE_SCALARS`, 36 values): 0; small values around 4- and
5-bit window boundaries; N−3 … N+2; 2N−1 … 2N+1; (N±1)/2; the GLV eigenvalue
λ, N−λ, and λ² mod N; powers of two around 2^128 (GLV half-length) and 2^256;
and 2^300+12345 (wider than the field).

**Edge points** (`edge_points()`): G, −G, 2G, λG = (βx, y) (the endomorphism
image), and four deterministic hashed multiples of G.

Results must be **identical**, not merely equivalent: the same affine
coordinates, `None` for infinity, and the same exception type for invalid input.

### Property-based coverage

`tests/test_validation_framework.py` adds Hypothesis tests over random input:
- random scalars up to 2^300, mixed with the edge scalars, times random points, for every backend;
- random Jacobian representations (random Z) through addition, doubling, mixed addition, and normalization;
- random points through every encoding and parser.

### The framework must catch bugs

The framework is itself tested. A deliberately wrong multiplication (off by one
for one scalar), a corrupted Jacobian addition, and a wrong encoding prefix must
each be reported (`test_a_wrong_*_is_reported`). If a refactor of the framework
stops detecting them, those tests fail.

## Differential validation procedure

For any change to `keylab.ec.secp256k1` arithmetic:

1. **Before changing code**, record outputs and timings on `main`:
   ```bash
   python scripts/bench_micro.py > before-pure.json          # in an environment without coincurve
   keylab benchmark-signatures --count 16 --repetitions 5 --backend keylab --json > before-sig.json
   ```
2. Make the change in `_scalar_mult_pure_python` or the functions it calls.
   Never edit `keylab/ec/reference.py` as part of an optimization.
3. Run the gate locally, with coincurve and fastecdsa installed:
   ```bash
   python -c "from keylab.ec import validation as v; v.assert_no_mismatches(v.validate_all())"
   pytest tests/test_validation_framework.py tests/test_ec_reference.py tests/test_ecc_differential.py tests/test_ecc_properties.py
   pytest -rs          # full suite: 0 skips with every backend installed
   ```
4. Measure after, with the same scripts and machine (see *Benchmark requirements*).
5. Push. CI must be green on every job (below).

The benchmarks enforce the same contract at run time. `benchmark-ec` checks
every method against `python-reference` before timing (its report records
`reference_implementation: keylab.ec.reference`). `benchmark-signatures`
checks every corpus public key and the MuSig2 coefficient sum against the
reference, and verifies every signature. A mismatch aborts the run.

## Benchmark requirements

- **Two environments**, both on the same machine and Python version:
  - *pure*: no native backend (the environment optimizations target);
  - *native*: coincurve installed, where `auto` must keep using libsecp256k1.
- **Tools:**
  - `scripts/bench_micro.py`, which covers primitives, each multiplication strategy, and the verify/sign/tweak paths;
  - `keylab benchmark-signatures --backend keylab --json`;
  - `keylab benchmark-ec` for generator multiplication.
- **Statistics:** every tool reports the median of its repetitions. Run `bench_micro.py` three times and compare per-metric medians of the runs.
- **Noise:** run-to-run variation on a desktop reaches about 1.3× (up to 1.8× on single metrics; see `performance_baseline_v0.2.0.md`). Differences below 1.3× are not evidence. To check for a regression, interleave old and new code in one session in a balanced order (A/B/B/A, repeated), never always running one version first: an M2.2 run that always ran the new code second showed a spurious 0.6× that disappeared under ABBA ordering.
- **Baseline:** `docs/performance_baseline_v0.2.0.md`, plus its *Progress* section, which each M2 step extends with its before/after table.

## Acceptance criteria for an optimization

A change to curve arithmetic is accepted only if **all** of these hold:

1. **Exactness.** `validate_all()` returns no mismatches with coincurve and
   fastecdsa installed, and `tests/test_validation_framework.py` passes,
   including the Hypothesis tests and the bug-detection tests.
2. **Oracle untouched.** `keylab/ec/reference.py` is unchanged, or changed in a
   separate commit that fixes a demonstrated bug, with a test that fails before
   the fix.
3. **Full CI green.** All 11 jobs: lint (ruff, the mypy ratchet at or below
   the baseline, API docs, vector checksums); Ubuntu and Windows on Python
   3.11–3.14 with the skip gate; full-extras with zero skips and the coverage
   floors (global ≥ 79%, `ec`/`encoding`/`hd` ≥ 85%); bench-smoke.
4. **Measured gain.** Before/after numbers from the procedure above, in the
   pure environment, meeting the M2 target for the step (see the *What M2 must
   show* section of the baseline), with the table added to the baseline's
   *Progress* section.
5. **No native regression.** An interleaved A/B run in the native environment
   shows the new median at or below the old one, within noise, for every
   `benchmark-signatures` operation.
6. **No API change.** The public names and signatures in `docs/api.md` are
   unchanged, except for documented additions.
7. **Readable reference paths stay.** Optimizations add strategies; they do not
   delete the existing readable implementations, which remain selectable by
   their backend names.

## Future-optimization requirements

Additional differential checks each later M2 step must add to the framework and
pass (against `python-reference`, `python-optimized`, `coincurve`, and
`fastecdsa`) before it is accepted. These are specified now; the code comes
later, in its own milestone.

### GLV (M2 GLV + wNAF)

- **Decomposition identity.** For the split `k -> (k1, k2)`, assert
  `scalar_mult(k, P) == point_add(scalar_mult(k1, P), scalar_mult(k2, phi(P)))`
  where `phi(P) = (BETA * x mod P, y)` and `phi(P) == scalar_mult(LAMBDA, P)`,
  over the edge points and random points.
- **Decomposition bounds.** Assert `k == (k1 + k2 * LAMBDA) mod N` and that both
  `|k1|` and `|k2|` fit in about `ceil(bitlen(N) / 2) + 1` bits, for edge and
  random scalars; a split that exceeds the bound is a failure even if the
  product still verifies.
- **Lambda edge cases.** `k in {0, 1, N-1, LAMBDA, LAMBDA^2 mod N, N-LAMBDA}`;
  `k1` or `k2` zero or negative; the point being infinity; `phi(infinity)`.
- End-to-end: GLV `scalar_mult` equals the reference on `EDGE_SCALARS` x
  `edge_points()` and on Hypothesis-random inputs.

### Multi-scalar multiplication

`multi_scalar_mult(pairs, *, method=...)` returns `sum(k_i * P_i)`. Every
`method` (and every `backend`) must equal `keylab.ec.reference.multi_scalar_mult`
-- naive accumulation -- on all of these. `diff_msm` in the validation framework
checks them; `tests/test_msm.py` adds the sweep and Hypothesis.

- **Empty input** -> infinity (`None`).
- **Singleton** -> equals `scalar_mult(k, P)`.
- **Duplicate points** `[(a, P), (b, P)]` -> equals `scalar_mult((a + b) % N, P)`.
- **Duplicate scalars** `[(a, P), (a, Q)]`.
- **Zero scalars** contribute nothing; an all-zero batch is infinity.
- **Infinity inputs**: terms `(k, None)` are skipped.
- **Cancellation to infinity**: `[(k, P), (N - k, P)]` and `[(k, P), (k, -P)]`.
- **Malformed input** rejected with `ValueError`: a non-(scalar, point) pair, a
  wrong-length tuple, a negative or non-int scalar, an unknown `method`.
- **Threshold / boundary cases** around whatever size switches strategy (Straus
  vs Pippenger / bucket count): sizes `n-1, n, n+1` at each crossover.
- Scalars drawn from `EDGE_SCALARS` (including `0`, `N`, `>N`); random and
  Hypothesis batches of mixed sizes; sizes 1, 2, 4, 8, 16, 32, 64, 128.

**Status.** The M2.6 foundation (`method="naive"`, the current `"auto"`) meets
all of these; it is linear in the number of terms. The Straus/Shamir and
Pippenger methods below extend `MSM_METHODS` behind this signature and must pass
the same `diff_msm` cases, including the threshold cases around their crossover.

### Straus / Shamir (later M2)

Simultaneous multiplication sharing one doubling chain across all terms.

- Equals the reference and the naive MSM on every `diff_msm` case.
- Interleaved wNAF tables: one odd-multiple table per point, built and
  normalized together (shared inversion); duplicate points may share a table but
  the result must be unchanged.
- Correct for a single term (equals `scalar_mult`) and for the empty batch.
- Measured gain over naive MSM for `n >= 2` recorded in the baseline's Progress
  section, with the crossover where it overtakes naive.

### Pippenger (later M2)

Bucket method for large `n`.

- Equals the reference on every `diff_msm` case and on random large batches.
- **Bucket-boundary cases**: `n` and window `c` chosen so the top window is
  partially filled; empty buckets; a bucket that receives exactly one point;
  all points landing in one bucket.
- **Infinity cancellation** inside a bucket (a bucket summing to infinity).
- Automatic `method="auto"` selects Straus below and Pippenger above a measured
  crossover; sizes `n-1, n, n+1` at that crossover all match the reference.
- The crossover size is documented in the baseline.

### BIP-340 batch verification (later M2)

`schnorr_verify_batch(items)` must agree with per-item `schnorr_verify`:

- **Batch == individual.** For any set of items, the batch result equals
  `all(schnorr_verify(m, s, pk) for ...)`; checked on the official BIP-340
  vectors and random valid batches.
- **One bad apple.** A batch with exactly one invalid signature returns
  `False`; verified for the invalid item at the first, middle, and last
  position.
- **Malformed keys / signatures.** Non-32-byte x-only keys, x-only keys that
  do not lift to a curve point, signatures of the wrong length, and `r`/`s`
  out of range are rejected (return `False`), never raised, matching
  `schnorr_verify`.
- **Deterministic coefficient test.** The random batch coefficients must come
  from `secrets`, never a seeded PRNG. A test injects a known coefficient
  source to confirm a forged batch (two signatures swapped) is rejected, so a
  pass cannot come from coefficients that happen to cancel. The first
  coefficient is fixed at 1, per the standard construction.
- Empty batch -> `True`; singleton batch -> equals the single `schnorr_verify`.
