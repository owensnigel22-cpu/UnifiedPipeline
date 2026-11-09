# Research Register

Inventory snapshot as of 2026-11-08. Entries are a navigation aid, not a claim that every tool was run, reviewed, or promoted. Keep measured, extrapolated, impossible, and not-run results distinct, as required by `SEC_STATE_JOURNAL.md`.

| Area | Verified location/evidence | Status and known limits |
|---|---|---|
| Elliptic-curve transformations | `src/keylab/ec/`; `docs/point_halving.md`; `tests/test_ec_research.py` | Educational/research math adjacent to curve primitives. The project states these transformations do not reveal discrete logarithms. |
| Bounded/full-group ECDLP experiments | `src/keylab/research/ecdlp/`; `scripts/benchmark_ecdlp.py`; `docs/research/ecdlp_benchmark.md`; `SEC_STATE_JOURNAL.md` | Includes bounded-interval methods and measurement tooling. Journal records a 60-second full-group kangaroo attempt with no solution (1,240,000 hops at about 20,554 hops/s in that environment); this is a measured, environment-specific illustration of infeasibility, not a security benchmark or universal throughput claim. |
| Toy HNP lattice work | `src/keylab/research/hnp_lattice/`, `research/hnp-lattice` branch history, and local toy demonstration material where present | Toy-modulus/educational experiments are not evidence of practical secp256k1 recovery. Verify current source and branch before relying on any demo artifact. |
| ECDSA/Schnorr signature analysis | `src/keylab/research/` and `SEC_M4_RHO_SIGNATURE_ATTACKS_PLAN.md`; merged PR #33 in local main history | Existing work is constrained to supplied/leaked data and research assumptions. Verify exact APIs and tests in source; do not infer general key recovery from the feature name. |
| SAT/CNF and hash experiments | `src/keylab/sat/`; `scripts/smt_ecdlp.py`; README/API docs and `SEC_M5_SHA256_PREIMAGE_PLAN.md` | Research/teaching encodings and solver-dependent experiments. Reduced-round or fixed-input checks do not establish full-hash inversion. The API docs label a SAT encoding experiment a measured dead-end; preserve its negative result and provenance. |
| Benchmarks and reproducibility | `scripts/bench_micro.py`, `scripts/bench_smoke.py`, `scripts/benchmark_ecdlp.py`, `benchmark_reports/`, `state/`, `docs/benchmarks.md` | Results are machine/backend/corpus dependent. Preserve inputs or seeds, commands, environment, correctness checks, raw output, and caveats. Do not treat old throughput as current. |
| Parser fuzzing | `fuzz/`, `docs/fuzzing.md`, `.github/workflows/` | Development/CI tooling; retain corpus seeds and distinguish time-bounded smoke runs from exhaustive coverage. |
| Test vectors | `tests/vectors/README.md`, `tests/vectors/` | Published vectors and provenance are core reproducibility assets. Preserve attribution, checksums/provenance, and licensing notes. |

## Negative and Infeasible Results

`SEC_STATE_JOURNAL.md`, research benchmark reports, state JSON files, and docs are part of the evidence record. Do not delete or silently rewrite negative outcomes. An extrapolation is not an executed measurement; a timeout/unknown is not an UNSAT result; an infeasibility estimate is not an observed run. Append corrections with provenance rather than erasing prior evidence.

## Promotion Criteria

A research capability may be described as supported only after its scope and assumptions are explicit; correctness has an independent argument and focused tests/fixtures; applicable resource limits and optional-dependency behavior are covered; feature audit and user-facing docs agree with source; reproducibility data are available; and required security/owner review is complete. These are criteria, not automatic promotion. Follow `docs/IMPLEMENTATION_ROADMAP.md` for the proposed ECDSA roadmap and its decision gates. No promotion or approval is recorded by this register.
