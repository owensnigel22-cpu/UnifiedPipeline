# Project Status

**Snapshot date:** 2026-11-10
**Repository:** `UnifiedPipeline` (the Python distribution/import package is `keylab`)  
**Observed remote baseline:** `origin/main` at `152f0e64554a8c0e1f75afc485b2c10156d1a758`, fetched locally on 2026-11-10. This status is a dated snapshot, not a live GitHub feed.

**Milestone update (2026-11-10):** M10 is present on `main`. M11 release
preparation is complete in commit `152f0e64554a8c0e1f75afc485b2c10156d1a758`
(`docs: complete M11 release preparation`), which adds the CycloneDX CBOM
baseline, README updates, and generated API documentation. M12 remains in
progress on `docs/m12-broadcast-plan`; implementation is complete and owner
review is pending. This branch is restricted to testnet/regtest transaction
broadcasts and has a hard mainnet rejection. The end-to-end regtest test uses
mocked RPC calls; no live node or real funds are used.

## Purpose

Keylab is a Python research and teaching library for Bitcoin key/signature standards and cryptographic analysis. Its goals include understandable reference implementations checked against published specifications and vectors, constrained reproducible research, separated protocol and experimental layers, and reproducible correctness-gated benchmarks. It is not production wallet software and must not be used to protect real funds.

## Development Stage

The repository is actively developed on `main`; the local branch list includes a `release/v0.2.0` branch and `chore/0.3.0-dev`. The inspected `main` history includes merged PR #33, titled “M4 ECDSA/Schnorr signature-attack recoveries (nonce reuse, HNP, nonce pre-image).” Branch names and history do not certify a release or production readiness.

The package requires Python 3.11 or newer. It is packaged with setuptools using a `src` layout. Core functionality includes Bitcoin encodings and key/signature standards, PSBT v0 roles, command-line tools, SAT/hash and number-theory components, and research modules. Optional extras cover development, dashboard, cryptography/backends, SAT solvers, fuzzing, and performance tools.

## Completed Work (Evidence at Snapshot)

- The current `main` includes merged milestone work through the changes represented by PR #33; verify source and tests for individual capability claims.
- The documented PSBT v0 implementation includes parsing, validation, serialization, signing, finalization, transaction extraction, and combining for its documented scope. The M12 wallet path is separate and experimental, limited to supported P2WPKH and P2SH-P2WPKH inputs on testnet/regtest.
- Official vectors, differential tests, property tests, fuzzing, and reproducible benchmarks are part of the repository's validation approach.
- Security limitations and research results are recorded in `SECURITY.md`, `SEC_STATE_JOURNAL.md`, benchmark reports, and `docs/`.

## Active Work and Open PRs

The online GitHub listing inspected on 2026-11-08 showed three open Dependabot PRs, all against `main`; no open feature-implementation PR was listed:

| PR | Topic | Head branch | Snapshot status |
|---|---|---|---|
| #31 | `actions/upload-artifact` 4 to 7 | `dependabot/github_actions/actions/upload-artifact-7` | Open; owner review required |
| #30 | `actions/cache` 4 to 6 | `dependabot/github_actions/actions/cache-6` | Open; owner review required |
| #3 | `coincurve` requirement range update | `dependabot/pip/coincurve-gte-19.0.1-and-lt-22.0` | Open; owner review required |

Do not infer that any of these are approved or merge-ready from their open status. Consult GitHub for current state before acting.

## Plans and Outstanding Work

Local documents describe plans, not active implementation ownership. In particular, `M4_7_UPDATER_PLAN.md` scopes a BIP-174 Updater; `docs/IMPLEMENTATION_ROADMAP.md` describes a proposed ECDSA research roadmap; and `SEC_M5_SHA256_PREIMAGE_PLAN.md` is a plan. The inspected task docs state planning-only or propose future work. They must not be treated as approved implementation tasks without project-owner assignment. See `CURRENT_TASKS.md` for the initial ownership register.

## Known Limitations

- Python cryptographic arithmetic and secret-dependent paths are variable-time and not side-channel hardened.
- The project is not safe for real funds, is not a Bitcoin consensus implementation, and is not independently audited. M12 wallet and broadcast features are test-network-only.
- The implemented PSBT subset does not support all script types or a complete wallet lifecycle; see `SECURITY.md` and the relevant PSBT docs for exact scope.
- Research and benchmark results have explicit resource, model, and environment limitations. An infeasible or failed experiment is not evidence of an implementation defect or a security break.
- Optional backends and extras may be absent; a skipped test is not a passing test.

## Production Readiness

**Cryptographic production readiness: not established.** `SECURITY.md` expressly says not to use Keylab for real funds or real secret-key protection. Test-vector correctness and reference implementations are not an audit or a production security guarantee. This coordination documentation does not change that status.

## Research Status

Research, experiments, benchmark programs, test vectors, reproducibility scripts, and negative findings are first-class deliverables. Preserve distinctions among implemented, experimental, optional, proposed, measured, extrapolated, and not-run work. See `RESEARCH_REGISTER.md` and the append-only `SEC_STATE_JOURNAL.md`.
