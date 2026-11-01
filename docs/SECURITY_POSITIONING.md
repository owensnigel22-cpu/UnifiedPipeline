# ECDSA research subsystem: security and ethics positioning

**Status:** Required design constraints for the proposed v0.4.0 / M5
subsystem. This document does not assert that the subsystem exists.

## Purpose and intended use

The proposed `keylab.research.ecdsa` package is for education, controlled
cryptographic research, reproducibility of published analysis, and testing
against synthetic or explicitly authorized datasets. It studies failure modes
of ECDSA nonce generation and side-channel measurement; it is not intended to
attack third-party systems or recover keys controlling real value.

All interfaces, reports, CLI help, examples, and benchmark outputs must state
that:

- analyses are exploratory unless a deterministic mathematical check proves a
  narrowly stated relationship;
- statistical association is not evidence by itself of a practical side
  channel, exploitability, or compromise;
- lattice results depend on a specified leakage model and sufficient,
  correctly measured observations;
- a research experiment is not a guarantee of key recovery;
- KeyLab remains non-constant-time and unsuitable for production secret-key
  operations.

## Prohibited product posture

Do not add:

- unconstrained key-search or arbitrary private-scalar enumeration APIs;
- network scanning, device probing, remote timing collection, or automatic
  dataset download;
- a command that silently runs lattice recovery on arbitrary signatures;
- interfaces that accept real wallet/WIF/seed inputs for these experiments;
- default output that displays candidate private keys or nonce values;
- claims such as “key recovered,” “exploitable,” or “compromised” based only
  on repeated `r`, a p-value, a lattice reduction result, or a heuristic
  confidence score;
- production signing recommendations based on KeyLab's Python implementation.

Any future candidate-recovery experiment must be explicitly opted into, have
bounded samples/dimensions/time/memory, declare the leakage model and
authorization context, and validate candidates forward against the supplied
public key and signatures. Synthetic examples should be the default. Candidate
scalars should remain internal to validation and be redacted from routine
reports.

## Data handling

- Process data locally; no network access is part of the package.
- Prefer synthetic fixtures and public, licensed datasets with provenance.
- Never ask users to upload private keys, wallet backups, real signing traces,
  or secrets from production systems.
- Do not log raw records, signatures, nonce estimates, timing traces, or
  candidates by default.
- Reports should use sample IDs and an input digest; include raw values only
  when explicitly requested and justified for a local controlled experiment.
- Do not include real third-party key/signature datasets without clear
  redistribution rights and a documented ethical basis.
- Reject input with secret-bearing fields not required by the schema instead
  of silently retaining them.

## Confidence and reporting

Confidence must be evidence-based and have a defined meaning. Use categorical
states such as:

- `invalid_input`;
- `insufficient_data`;
- `indicator`;
- `hypothesis_supported`;
- `mathematically_validated`;
- `experiment_incomplete`.

Do not publish an uncalibrated numeric “probability of compromise.” If a
statistical confidence interval or p-value is reported, include method,
assumptions, sample count, effect size, uncertainty, multiple-testing
handling, and reproducibility seed. A validated nonce-reuse relation means
only that the supplied records support the relation under stated semantics;
it does not authorize use of a corresponding key.

## Responsible research

Before analyzing non-synthetic device data, users must have authorization to
collect and analyze it and must follow applicable disclosure, privacy,
contractual, and data-retention requirements. Published attack papers are
scientific context, not permission to test systems. Device acquisition,
remote measurement, and vendor coordination are intentionally out of scope.

If an analysis suggests an implementation weakness, preserve only the
minimum evidence needed, avoid publishing secrets, and use the affected
vendor's coordinated vulnerability disclosure process. Do not add secrets or
private traces to issues, pull requests, CI artifacts, or benchmark reports.

## Safeguards required before release

1. Security review of schemas, parsers, resource limits, candidate handling,
   logs, and reports.
2. Tests that prove secret candidates and raw traces are redacted by default.
3. File, row, dimension, degree, integer-size, runtime, and memory bounds.
4. No automatic network access or unsafe deserialization.
5. Explicit experimental warnings in module docs, API docs, and CLI surfaces.
6. Audit entries that identify limits and do not imply tests were executed.
7. Separate review of data licensing and provenance for every non-synthetic
   fixture.
8. No change to existing KeyLab signing, verification, key derivation, or
   serialization API behavior.

## Relationship to KeyLab's existing security policy

This design supplements, and does not replace, [SECURITY.md](../SECURITY.md).
KeyLab is not constant-time, is not independently audited, and is not a
wallet. The proposed research subsystem must make those existing limitations
more visible, not obscure them behind a “recovery” or “analysis” label.
