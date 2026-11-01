# ECDSA research subsystem architecture

**Status:** Proposed design for the v0.4.0 / M5 roadmap. No implementation is
included in this document set. Nothing described here should be treated as
implemented, validated, or ready for real-key use.

## Goals and non-goals

The subsystem will provide reproducible, auditable analysis of ECDSA nonce
reuse, declared nonce leakage, nonce-pattern hypotheses, timing observations,
and explicitly bounded synthetic or published research datasets. It will
reuse KeyLab's secp256k1 constants, point/scalar validators, signature
verification, deterministic test conventions, feature audit, CI, and
benchmark methodology.

The subsystem is an experimental analysis layer, not a signing implementation,
wallet, device-testing agent, or general-purpose private-key recovery service.
It must not silently convert a weak statistical signal into a claim of
compromise, or turn arbitrary input signatures into an unconstrained
key-search job.

## Proposed package

```text
src/keylab/research/ecdsa/
    __init__.py
    models.py              # immutable records, enums, report schema/version
    datasets.py            # validated import/export and provenance
    nonce_reuse.py         # exact repeated-r and recovery-evidence analysis
    polynonce.py           # explicitly parameterized relationship testing
    timing_analysis.py     # timing/leakage statistics and diagnostics
    lattice.py             # HNP model, basis construction, bounded experiments
    diagnostics.py         # common validation, confidence, and warning records
```

The required module names are present; `models.py` is the small shared schema
owner. Keep modules cohesive and avoid importing the research package from the
protocol/curve layers.

### Dependency direction

```text
datasets ──► models, diagnostics
nonce_reuse ──► models, diagnostics, keylab.ec.secp256k1 / ECDSA verification
polynonce ──► models, diagnostics, nonce-reuse input validation
timing_analysis ──► models, diagnostics, datasets
lattice ──► models, diagnostics, datasets, keylab.ec.secp256k1 constants

feature_audit / CLI / benchmarks / tests ──► research.ecdsa public API
```

The new package may depend on the existing ECDSA verifier and shared
secp256k1 validation functions. Existing `keylab.ec`, signing, BIP-340,
BIP-341, BIP-32, and MuSig2 modules must not depend on research code. Research
code must never be selected implicitly by `scalar_mult`, signing, verification,
or address derivation.

## Responsibilities and contracts

### `models.py`

Define immutable, typed records for validated ECDSA observations, leakage
metadata, dataset provenance, detector findings, analysis diagnostics, and
experiment results. Every serialized report includes a schema version and
algorithm/configuration identifiers. Distinguish:

- input validity;
- mathematical evidence (for example, two signatures yield a candidate
  consistent with the same public key);
- statistical evidence (a measured distribution differs from a stated null);
- experimental success on a known synthetic fixture.

Never use one boolean `success` field to collapse these different outcomes.

### `datasets.py`

Support documented, versioned JSONL and CSV schemas with explicit column
mapping. Parse bounded local files only. Do not fetch a URL, execute a dataset
payload, or infer missing signature semantics. Preserve source, license,
citation, dataset version, acquisition date, checksum, record count, parser
version, units, and any transformations. Retain the original bytes only when
the caller explicitly requests a local research copy; reports should normally
include a content digest and provenance rather than sensitive raw data.

### `nonce_reuse.py`

Detect repeated `r` values and test mathematically derived candidate
interpretations against the supplied public key and both signatures. A
repeated `r` is a lead, not proof: same `r` can occur through encoding,
normalization, malformed records, or rare collision. Handle high-S/low-S
normalization by evaluating documented sign alternatives, deduplicating
candidates, and requiring forward verification. A result should say
`candidate_validated`, `candidate_not_validated`, or `insufficient_evidence`,
not simply `recovered`.
Repeated-pattern detection should also be distinct from exact reuse: test only
declared, bounded pattern hypotheses and do not infer nonce equality from an
arbitrary signature similarity.

### Partial exposure and RNG-bias indicators

Represent a partial-exposure observation separately from a signature record:
include which nonce representation is observed, its bit/interval semantics,
measurement uncertainty, provenance, and whether the observation is direct,
simulated, or inferred from timing. An indicator means only that supplied
metadata or observations fit a stated leakage model; it does not prove that a
signing implementation leaks those values.

RNG-bias diagnostics operate only on explicit nonce samples or declared
leakage observations. They may report pre-registered frequency, run, or
distribution checks with sample-adequacy and multiple-testing caveats. They
must not claim nonce bias from `r` values alone without a validated model.

### `polynonce.py`

Accept an explicit, finite relationship hypothesis: polynomial degree,
coefficient/source model, sample selection, and any known bounds. Keep
relationship detection separate from any lattice experiment. Report the
hypothesis tested, data sufficiency, residuals, fit diagnostics, rejected
alternatives, and correction for multiple hypotheses. No automatic search
over unconstrained polynomial families or hidden key/nonce variables.

### `timing_analysis.py`

Analyze supplied timing observations for effect size and evidence of an
association with declared features such as nonce bit length, operation class,
or experimental condition. Reports must record units, sample counts, grouping,
missingness, outlier policy, null hypothesis, statistical test, confidence
interval, p-value (if used), multiplicity handling, and seed. Include
confounder checks, group imbalance warnings, and a clear statement that
correlation is not proof of a side channel or exploitability.

### `lattice.py`

Separate model/basis construction, diagnostics, and experiment evaluation.
Record curve/order, sample set digest, assumed leakage model, unknown and
known-bit positions or interval bounds, basis shape and determinant metadata
when defined, scaling, reduction algorithm/version, precision settings,
seed, resource caps, and validation outcome. The initial API should prioritize
basis inspection and synthetic known-answer experiments. Any future reduction
backend must be optional and isolated; it must not make fpylll, SageMath, or
gmpy2 a mandatory runtime dependency.

The model must state assumptions in machine-readable metadata and refuse
ambiguous or insufficient input. A reduced basis is not evidence that a key
was found. A candidate is only an experimental result after checking scalar
range, deriving the corresponding public key, and verifying every supplied
signature. Reports should not print candidates by default.

### `diagnostics.py`

Own shared input diagnostics, warning codes, confidence labels, and result
status definitions. Confidence is an evidence-strength classification, not a
probability of compromise. Deterministic mathematical checks may be marked
`verified`; statistical indications should be `exploratory` and include
uncertainty and sample adequacy. No score may imply operational risk without
stating its model and calibration evidence.

Where a caller requests a confidence score, return a versioned evidence score
only when its scoring rubric has been calibrated against declared positive
and null controls for that detector. Include the score components, calibration
fixture/version, threshold, and limitations; leave the score absent when
calibration is unavailable. A score is not a probability that a key is
compromised. For exact nonce-reuse validation, report the deterministic
verification state instead of manufacturing a statistical score.

## Shared input and output formats

An ECDSA observation should minimally identify:

| Field | Contract |
|---|---|
| `schema_version` | Explicit supported version |
| `curve` | `secp256k1` only in the first version |
| `public_key` | SEC1 bytes in hex; parse and validate on import |
| `r`, `s` | Integers or fixed-width 32-byte hex; enforce `1 <= r,s < N` |
| `message_digest` | Exactly 32 bytes, explicit hex; never silently hash text |
| `sample_id` | Stable, non-secret identifier |
| `source` | Provenance/citation identifier |

Nonce leakage records must additionally define the representation and
semantics of the observation (for example, known bits versus an interval),
whether bit positions count from the most- or least-significant end, and
whether the claim applies to `k`, `-k mod N`, or an implementation-specific
intermediate. Timing records include a monotonic duration and unit, sample
group, device/software metadata, run order, environmental covariates, and
measurement method. Never infer these fields from a CSV header guess.

Reports are JSON-serializable, stable-schema records with input digest,
tool/package version, algorithm/configuration, result state, evidence,
warnings, and provenance. Raw private candidates, secret traces, and original
timing records are excluded by default.

## Integration points

- **Existing cryptography:** Use `require_scalar`, `require_point`,
  `is_on_curve`, SEC1 parsing, and ECDSA verification. Do not duplicate curve
  constants or invent an alternate signature parser.
- **Feature audit:** Add rows for each implemented detector/analysis family,
  test-source presence, benchmark command, and explicit limitations. Keep
  implementation presence distinct from tests passing and benchmarks run.
  The existing `partial_nonce_hnp` status remains `implemented: false` and
  `tested: false` until the corresponding implementation and tests actually
  land; this design document is not implementation evidence.
- **CI:** Add focused tests to normal pytest. Optional reduction/statistics
  integrations must have explicit extras and skip reasons; the core suite must
  run without them. Keep OS/Python matrix and skip gate intact.
- **Validation philosophy:** Build independent small known-answer oracles;
  property-test serialization, group-level verification and detector
  invariants; compare arithmetic only with independent reference paths. Do not
  claim independent validation when both sides call the same KeyLab helper.
- **Benchmarks:** Add seeded, non-secret, correctness-gated measurements
  following `docs/benchmarks.md`: warm-up excluded, method order shuffled,
  medians reported, no secrets or raw observations in output. Timings are
  descriptive and not CI performance thresholds.
- **Public API:** Expose stable names from the research package only after
  their schema, error behavior, and test coverage are reviewed. Keep
  experimental features clearly marked; do not expose them as production
  ECDSA APIs.

### Benchmark plan

Provide small reproducible benchmark cases for each independently measurable
layer:

| Workload | Reported measures | Correctness gate |
|---|---|---|
| Record parsing | records/s, elapsed time, valid/invalid counts | canonical records and rejection categories match fixtures |
| Dataset loading | rows/s, bytes/s, peak-memory estimate if portable, parse/validation time separately | normalized data, provenance, and input digest match expected output |
| Detectors | records/s and elapsed time by detector and input shape | exact expected findings on planted and null fixtures |
| Lattice construction | basis-build time, dimensions, nonzero count/density, determinant metadata when available | basis dimensions and every encoded HNP relation match independent small examples |
| Statistical analysis | elapsed time by sample count and selected method | fixed-seed summaries match known-answer fixtures and all reported statistics are finite/in-range |

Use public/synthetic seeded data only, report package/Python/backend versions,
exclude setup and warm-up from measured operations, randomize method order,
and report all samples plus the median. Parsing/loading should have cold and
warm runs distinguished; never let a benchmark silently exclude malformed
rows. Benchmarks must not collect live device timings, import secrets, or
assert machine-specific speed thresholds in ordinary CI.

## Failure behavior and resource limits

Reject malformed or ambiguous data with actionable validation errors. Do not
silently drop invalid records: provide a bounded, structured per-record error
report and fail the requested analysis unless the caller explicitly selects a
documented quarantine policy. Apply limits to file size, row count, sample
count, polynomial degree, basis dimension, integer magnitude, reduction
iterations, and wall-clock budget. Include resource-limit outcomes in the
report; never return a success-shaped empty result after an error.

## References within KeyLab

- [Architecture](architecture.md)
- [Security policy](../SECURITY.md)
- [Performance validation](PERFORMANCE_VALIDATION.md)
- [Benchmark methodology](benchmarks.md)
- [Feature audit implementation](../src/keylab/feature_audit.py)
