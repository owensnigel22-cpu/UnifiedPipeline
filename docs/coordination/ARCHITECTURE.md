# Architecture Overview

This overview records repository structure visible in `src/keylab/`, `dashboard/`, `scripts/`, `tests/`, `pyproject.toml`, `README.md`, and `docs/architecture.md`. It is not a replacement for the detailed architecture and security documents.

## Major Components

| Component | Responsibility and boundary |
|---|---|
| `src/keylab/cli.py`, `advanced_suite.py` | Command-line entry points (`keylab` and `keylab-advanced`). The advanced suite contains teaching/demo functionality and delegates shared curve helpers as documented in `docs/architecture.md`. |
| `src/keylab/ec/` | Elliptic-curve and protocol-related implementations, including secp256k1, Schnorr, ECDSA recovery, and MuSig2 public-key operations. Shared curve arithmetic and validation live in `ec/secp256k1.py`. |
| `src/keylab/encoding/` | Base encodings, addresses, SEC1/WIF and transaction-related parsing/serialization, including Taproot and signature-hash helpers. |
| `src/keylab/hd.py`, `mnemonic.py` | HD key derivation and BIP-39-related operations. These are reference implementations with the limitations in `SECURITY.md`. |
| `src/keylab/psbt/` | PSBT v0 data model and documented parser/validator/serializer and workflow roles. The signer/finalizer/extractor/combiner support remains scoped; the separate experimental M12 wallet workflow uses only supported P2WPKH and P2SH-P2WPKH inputs on testnet/regtest. |
| `src/keylab/research/` | Experimental and educational research, including elliptic-curve, ECDLP, HNP, and signature-analysis work. It is not selected by normal signing or verification paths, per project security/architecture docs. |
| `src/keylab/sat/`, `numtheory/` | SAT/CNF and number-theory utilities used by educational and research workflows. Optional solver integrations are described by extras in `pyproject.toml`. |
| `src/keylab/backends.py`, `benchmarks.py`, `feature_audit.py` | Backend discovery/integration, benchmark functions, and feature-presence/test-source auditing. Presence is not evidence that a test passed. |
| `dashboard/` | Optional dashboard package; `pyproject.toml` defines a `dashboard` extra including Streamlit and pandas. |
| `scripts/`, `fuzz/`, `tests/` | Benchmark/reproduction and utility scripts; parser fuzz harnesses; unit, property, vector, regression, and integration tests. |

## Dependencies and Packaging

`pyproject.toml` uses setuptools with `src` package discovery, requires Python `>=3.11`, and declares `pycryptosat>=5.11` as a required dependency. Development tools and additional backends are grouped into optional extras such as `dev`, `dashboard`, `crypto`, `secp256k1`, `number-theory`, `sat-native`, `sat-certified`, `fuzz`, and `performance`. Do not infer that an optional backend is installed or used on a particular path; verify runtime selection and test evidence.

## Data Flow and Boundaries

- The CLI and library APIs call package functionality; cryptographic/protocol code uses shared curve, hashing, encoding, and transaction primitives as detailed in `docs/architecture.md`.
- `docs/architecture.md` describes downward dependency direction for core layers and identified lazy imports that avoid cycles (`hd` to Taproot; Taproot to Schnorr signing).
- Research modules are separate from normal protocol/signing/verification entry points. Maintain that separation unless a project-owner-approved design explicitly changes it.
- Benchmarks should compare outputs against a correctness reference before timing. Use the methodology in `docs/benchmarks.md`; benchmark code must not print secrets.
- Tests and official vectors are evidence for specified behavior, not a general security audit.

## Interfaces and Sources of Truth

Use the source-of-truth table in `docs/architecture.md` for shared field/point/hash/address helpers. Use `docs/api.md` and module docstrings for exported interfaces. For PSBT scope, consult `SECURITY.md`, the `keylab.psbt` source and tests, and current milestone docs. This page intentionally avoids restating undocumented function signatures or guarantees.
