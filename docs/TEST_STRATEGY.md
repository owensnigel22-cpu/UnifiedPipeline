# ECDSA research subsystem test strategy

**Status:** Proposed tests for the v0.4.0 / M5 design. These are plans, not
tests currently present or passing.

## Test layers

### Unit tests

**Parsing and schemas**

- Valid/minimal JSONL and CSV records for each supported schema version.
- Invalid hex, wrong digest/key lengths, invalid SEC1 keys, `r`/`s` equal to
  zero or `N`, values above range, booleans/floats where integers are
  required, duplicate sample IDs, missing required provenance, and unknown
  fields/version handling.
- Explicit digest semantics: reject text or arbitrary-length input rather
  than hash/truncate it silently.
- Partial-leak metadata: MSB/LSB direction, bit count, interval endpoints,
  signed/negated nonce semantics, inconsistent or ambiguous models.
- Timing metadata: units, nonpositive duration if disallowed, missing group,
  malformed covariates, and duplicate measurement identity.
- Bounded resource behavior for file bytes, row count, basis dimension, degree,
  and integer size.

**Exact nonce reuse**

- Two independently generated valid signatures with a deliberately reused
  nonce produce a candidate that matches the known public key and verifies
  both signatures.
- Reuse with nonce sign differences and low-S normalization.
- Same `r` with wrong digest, altered signature, wrong public key, or malformed
  record must not become a validated finding.
- Repeated `r` groups with three or more members, duplicate identical rows,
  conflicting encodings, and deterministic report ordering.
- Same `r` is not sufficient by itself; prove the finding stays unvalidated
  until the mathematical checks pass.
- Boundary values around scalar/order ranges and digest values `0`, `N-1`,
  and full-width values.

**Polynomial/repeated-pattern hypotheses**

- Planted relationship under an explicitly declared model, and cases that
  violate the model by one sample.
- Degree zero/one boundaries, maximum supported degree, too few samples,
  duplicate observations, rank deficiency, and inconsistent coefficient
  metadata.
- A result reports only the tested hypothesis; no implicit degree escalation.
- Multiple-hypothesis correction is reflected in report fields and test
  expectations.

**Timing/statistical diagnostics**

- Synthetic null distributions, planted shifted distributions, unequal group
  sizes, outliers, missing samples, ties, constant timings, and imbalanced
  labels.
- Effect size and interval calculations against hand-computed small examples.
- Seeded permutation/bootstrap procedures reproduce exactly.
- Small-sample warnings, multiple-testing correction, and undefined
  statistics are explicit rather than coerced to zero or success.
- A statistically significant association does not set a `compromised` or
  `exploitable` status.
- RNG-bias indicators require explicit nonce observations or a declared
  leakage channel; add a regression test that `r`-only records cannot trigger
  a nonce-bias conclusion.
- Calibrated confidence scores reproduce from the same calibration set and
  version; when calibration is absent, the score is absent rather than a
  fallback value.

**Lattice model**

- Hand-computable toy-modulus bases and congruence checks.
- Assert documented basis dimensions, row widths, scaling, determinant
  metadata, and exact relation to the declared HNP equations.
- Reject rank-deficient or malformed input with intentional diagnostics.
- Insufficient leakage, wrong sign convention, incorrect bit orientation, and
  out-of-bound residuals must not be reported as a validated experiment.
- Candidate validation checks range, public-key derivation, and every
  signature; reports redact candidate scalar by default.
- Reduction timeout, backend import failure, iteration limit, or resource cap
  is an explicit incomplete/failed status, never an empty success.

### Differential tests

- Compare public-key derivation and ECDSA verification with the existing
  frozen `python-reference` path and libsecp256k1 through coincurve for valid
  candidate-validation cases.
- Compare parsing/serialization with KeyLab SEC1 helpers and coincurve where
  the external API has equivalent semantics.
- Compare lattice basis calculations against independently written tiny
  integer examples, not a second call to the production builder.
- Statistical outputs may be compared against SciPy only in an optional test
  extra; core expected values should use analytically tractable fixtures to
  avoid shared-algorithm agreement as the sole oracle.
- Do not claim coincurve/fastecdsa differential coverage for statistical or
  lattice behavior they do not implement.

### Property-based tests

Use Hypothesis with deterministic example database conventions already used
by KeyLab. Generate valid values from `N`, `P`, and canonical encodings, plus
malformed values near boundaries.

- Parse/serialize round trips preserve validated records and report digests.
- Reordering observations preserves order-independent detector conclusions
  and yields canonically ordered reports.
- Adding an unrelated valid sample does not make a previously invalid
  signature pair validated.
- Nonce-reuse finding invariance under stable sample ordering; invalid rows
  are surfaced, not silently ignored.
- HNP basis rows satisfy the declared modular relations for all generated
  bounded toy instances.
- Timing reports maintain documented range/finite-value invariants under
  generated durations and group labels.
- Report JSON round trips preserve schema and deterministic fields.

Strategies must be bounded and avoid constructing large integers or basis
matrices that can make test runtime unbounded.

### Reproducibility tests

- Fixed input + seed + package/backend version yields byte-identical
  canonical reports, except documented runtime/environment fields.
- Explicitly separate deterministic analysis from timing values or
  environment metadata that cannot be reproducible.
- Seeded synthetic data and planted leakage fixtures are reproducible across
  supported Python versions.
- Dataset checksum, schema version, source citation, and transformation
  records are retained through load/export.
- A second run from the exported normalized representation matches the
  original analysis.

### Regression and safety tests

- Feature audit distinguishes source presence, test-source presence, and
  executed benchmark evidence.
- Public API snapshots ensure existing KeyLab APIs and CLI behavior do not
  change.
- No default output contains a candidate private scalar, secret nonce, raw
  trace, or user-supplied record payload.
- Test logs and benchmark JSON contain no raw sensitive values.
- Resource-limit and timeout tests fail explicitly and safely.
- Deliberately corrupted nonce candidate, relationship, timing label, and
  lattice row are detected by independent verification checks.
- Known statistical null fixtures check expected false-positive rates over a
  fixed simulation budget; thresholds use predeclared confidence bands, not a
  single lucky seed.

## Dataset validation

Every checked-in fixture needs:

1. an upstream citation and version/date;
2. a license and redistribution review;
3. a SHA-256 checksum and byte/record count;
4. an explicit schema and units;
5. a data card describing device, collection method, leakage claim, missing
   values, transformations, and known limitations;
6. a parser test for valid and intentionally malformed records;
7. a test that verifies no unexpected fields or rows were silently dropped.

Prefer tiny synthetic fixtures in the default suite. Large research datasets
must be opt-in, not downloaded by CI, and should be tested via checksums plus
small public excerpts only where licensing permits.

## CI and coverage plan

- Place tests in focused `tests/test_ecdsa_research_*.py` modules.
- Keep core tests free of optional scientific/lattice packages.
- Install optional extras in the full-extras job and require their tests to
  run rather than silently skip in that job.
- Make skip reasons specific and add them to the skip gate allowlist only
  when an OS limitation is documented.
- Add a `keylab/research` coverage floor after the new package stabilizes;
  maintain explicit branch coverage for input validation and error statuses.
- Run lint, mypy ratchet, API docs check if exported API is added, complete
  pytest matrix, skip checks, coverage report, and benchmark smoke.

## Benchmark correctness gate

Every benchmark corpus must first pass schema validation and a correctness
check appropriate to the operation. Parsing/load benchmarks compare records
and provenance after round-trip; detector benchmarks compare structured
findings to known expected results; lattice benchmarks verify basis
invariants and synthetic candidates before timing; statistical benchmarks
check known-answer summaries.

Do not benchmark private keys, live devices, or user-provided timing files
inside CI. Keep timing assertions out of ordinary unit tests.
