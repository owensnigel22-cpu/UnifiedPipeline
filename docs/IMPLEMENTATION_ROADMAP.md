# ECDSA research subsystem implementation roadmap

**Status:** Proposed v0.4.0 / M5 roadmap. This is a staged plan, not a claim
that any listed capability currently exists.

## Operating principles

1. Establish schemas, provenance, scope, and safeguards before implementing
   detectors.
2. Deliver useful detection and diagnostics before lattice reduction.
3. Keep the protocol and signing surfaces unchanged.
4. Require an independent correctness argument and reproducible fixture for
   every mathematical detector.
5. Promote a capability from experimental to supported only after tests,
   audit integration, docs, and validation gates agree.

## Milestones

### M5.0 — Package contract and data model

- Add package skeleton and immutable versioned records.
- Specify observation, timing sample, leak model, provenance, diagnostic, and
  report schemas.
- Add strict parsers and JSONL/CSV import-export with bounded file/record
  limits; no network fetch.
- Add feature-audit entries marked not implemented until code and tests land.
- Add documentation and security review.

**Exit:** malformed-value matrix is covered; round trips are deterministic;
no protocol module imports the research package; no secret values appear in
default diagnostics or logs.

### M5.1 — Exact nonce-reuse analysis

- Detect repeated `r` groups, then test candidate interpretations against
  public key and signatures.
- Model `s` normalization explicitly and verify all candidates by forward
  derivation and signature checks.
- Add report status distinctions for a repeated value, validated mathematical
  relation, and inconclusive evidence.
- Add seeded synthetic fixtures and external-reference differentials where
  the behavior is supported by a reference implementation.

**Exit:** known-answer and adversarial encodings pass; no result is reported
as valid without independent forward verification; public APIs remain intact.

### M5.2 — Statistical and timing diagnostics

- Implement exploratory distribution and correlation tests with configurable,
  explicit null hypotheses.
- Add RNG-bias indicators only for explicit nonce samples or declared leakage
  observations; do not infer bias from signature `r` values alone.
- Record effect sizes, confidence intervals, sample adequacy, multiple-testing
  correction, random seed, assumptions, and caveats.
- Separate data quality diagnostics from leakage indicators.
- Build synthetic positive/negative controls and null simulations.

**Exit:** false-positive behavior is measured on null fixtures; reports
reproduce exactly for a fixed seed and input; no performance/security claim is
inferred from a p-value alone.

### M5.3 — Partial nonce and bounded polynomial hypotheses

- Define exact leak semantics and only then support partial exposure models.
- Add constrained polynomial-relation hypothesis checks with bounded degree
and explicit sample selection.
- Link validated leak metadata to a research experiment; no implicit search
or solver invocation.
- Document limits, supported models, and excluded leakage conventions.

**Exit:** leak model transformations have independent known-answer tests;
edge cases include high-S normalization, bit-order ambiguity, insufficient
samples, repeated/duplicate records, and conflicting metadata.

### M5.4 — Lattice model and diagnostics

- Implement HNP instance validation and transparent basis construction.
- Add basis metadata, dimensional/resource guards, and diagnostics.
- Add seeded toy-curve or deliberately weak synthetic-key experiments with a
  known planted secret and forward verification.
- Keep reduction backends optional, version-pinned in reports, and disabled
  unless the user explicitly selects the research experiment.
- Do not add general secret-search commands or claim practical secp256k1
  recovery.

**Exit:** generated bases match independently derived small examples;
property tests validate the modeled congruences; every synthetic candidate
is range-checked, public-key-checked, and signature-checked; resource limits
are tested.

### M5.5 — Polynonce, dataset profiles, and research diagnostics

- Implement published-dataset adapters only when schema, license, checksum,
  and provenance are documented.
- Keep adapters read-only and local; no automatic download.
- Add bounded repeated-pattern/polynomial diagnostics and clear
  `hypothesis-tested` vs `hypothesis-validated` status.
- Add fixture checksums and data-card documentation.

**Exit:** adapters reject malformed/truncated/unknown versions, preserve
record identity, do not silently discard rows, and reproduce report metadata.

### M5.6 — CI, benchmark, and release gate

- Add new package tests to the normal matrix and full-extras coverage job.
- Add explicit optional-dependency tests and skip reasons.
- Add `feature_audit` rows with implementation, tests, limitations, and
  benchmark identifiers.
- Add benchmark commands or API entry points for parsing, loading, detectors,
  basis construction, and statistical analysis.
- Update docs, API-generation checks if public exports are added, and release
  notes.

**Exit:** full CI green on supported OS/Python versions; skip gate passes;
coverage floors include the research package once there is adequate, stable
coverage; seeded benchmark results are correctness-gated and have no
machine-dependent assertion in standard unit tests.

The five benchmark families and their correctness gates are specified in
[RESEARCH_SUBSYSTEM_ARCHITECTURE.md](RESEARCH_SUBSYSTEM_ARCHITECTURE.md).

## Dependency policy

Core parsing, exact nonce-reuse analysis, diagnostics, and basic descriptive
statistics should use the standard library and existing KeyLab primitives
where practical. Hypothesis remains a development dependency, consistent with
the existing test suite.

Potential optional integrations:

- `fpylll` or SageMath for lattice reduction experiments;
- `gmpy2` for explicitly optional fast integer arithmetic (KeyLab already has
  a number-theory extra);
- NumPy/SciPy only if an identified statistical method requires them and the
  maintenance cost is justified.

Do not install or add any of these as required dependencies before a specific
feature, platform matrix, license, version range, and optional-test strategy
are agreed. Reports must record backend and version. Pure-Python reference
calculations and small test fixtures should remain available.

## API compatibility and rollout

- No change to existing ECDSA, BIP-340, BIP-341, BIP-32, MuSig2, or CLI
  behavior.
- New research APIs are namespaced under `keylab.research.ecdsa`.
- Experimental APIs may change before a declared stability milestone.
- A new capability is not listed as implemented/tested by feature audit until
  its code and corresponding tests are present.
- No versioned public dataset or vector is checked in without provenance,
  redistribution permission, checksum, schema, and a validation test.

## Decision gates before implementation

Before M5.0, decide whether the first release includes a reduction backend or
only basis generation/diagnostics; identify the authoritative VUSI dataset
and license; define which published datasets can be redistributed; and review
the candidate-recovery disclosure policy. If these decisions are unresolved,
defer those features rather than guessing.
