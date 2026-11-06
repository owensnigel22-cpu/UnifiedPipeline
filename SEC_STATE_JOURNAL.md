# Security / research state journal

Append-only record of milestone state and every infeasible iteration, so a wall
we already documented is never re-discovered. Reviewed on PR like any other doc.

**Entry kinds (the distinction is load-bearing):**
- **attempted** — ran; we have *observed* cost.
- **extrapolated** — did not run; we have a *computed* cost + formula.
- **impossible** — mathematically infeasible, cited, never attempted.

Conflating *attempted* and *extrapolated* loses information ("did we try, or just
assume?"). Every entry states its kind explicitly.

Entry format:

```
## YYYY-MM-DD — M<n>: <title>
- Kind: attempted | extrapolated | impossible
- Action: <what was tried / would be tried>
- Outcome: complete | failed | skipped | not-applicable
- Cost observed: <wall, memory, iterations>  (or "n/a — not run")
- Cost extrapolated: <formula, expected at N>  (or "n/a — measured")
- Reason: <why skipped / why impossible>
- State change: <milestone / PR / artifact transition>
- Reference: <commit, PR, plan §>
```

---

## 2026-11-05 — M1: coverage-guided fuzzing — closed
- Kind: attempted
- Action: Atheris harness for the six parsers; PR-smoke + nightly workflows; seeded-defect canary.
- Outcome: complete
- Cost observed: PR smoke ~30s/target, 0 crashes/0 timeouts; nightly cache round-trip validated.
- Cost extrapolated: n/a — measured
- Reason: n/a
- State change: PR #24 merged to main (`8db7160`); CI 11 → 12 jobs.
- Reference: SEC_M1_FUZZING_PLAN.md §13; nightly dispatches 41907544746 (cold) / 41908000374 (warm).

## 2026-11-05 — M2a: crypto_policy + constant-time helper — awaiting merge
- Kind: attempted
- Action: `keylab/crypto_policy.py` allow-list (zero callers), `keylab/_ct.py` constant_time_equal, two-site refactor, HKDF domain-separation docs/tests.
- Outcome: complete (code); not yet merged.
- Cost observed: full suite 1753 passed/14 skipped; 12/12 CI green on PR #26.
- Cost extrapolated: n/a — measured
- Reason: awaiting user merge decision.
- State change: PR #26 open/green/unmerged.
- Reference: SEC_M2_CRYPTO_POLICY_PLAN.md.

## 2026-11-05 — M2b: CBOM primitive inventory — parked
- Kind: extrapolated
- Action: would add a CycloneDX 1.6 CBOM via pqcheck, incremental `--fail-on-new` gate, baseline + provenance, consistency check, Ruff S-rules.
- Outcome: skipped (not started)
- Cost observed: n/a — not run
- Cost extrapolated: one new CI job (12 → 13), CI-only dep; no runtime cost.
- Reason: blocked on M2a merge + an acked 2b plan doc.
- State change: none.
- Reference: SEC_M2_CRYPTO_POLICY_PLAN.md (2b scope section).

## 2026-11-05 — M3: backward double-and-add — plan acked
- Kind: attempted
- Action: verified most of the module already exists (point_halve delegating to keylab.ec.halving, backward_step, backward_traverse_to_identity, recover_via_backward, cost_table, 11 tests); M3 adds halve_m, docs, demo augmentation, new tests, and an ECDLP measurement harness.
- Outcome: complete (planning)
- Cost observed: n/a — planning
- Cost extrapolated: n/a
- Reason: n/a
- State change: plan acked; implementation in branch `sec/m3-ecdlp`.
- Reference: SEC_M3_BACKWARD_ADD_PLAN.md.

## 2026-11-05 — M3: halve_m(Q, 2**20) naive chained path — not run
- Kind: extrapolated
- Action: literal m-fold chained point-halving at m = 2**20.
- Outcome: skipped (CI); opt-in local only.
- Cost observed: n/a — not run in CI
- Cost extrapolated: ≈ 2**20 × ~2.5ms ≈ 17 minutes for the literal chain. The O(1) shortcut `halve_m(Q, m) = (2^-m mod N)·Q` returns < 100ms.
- Reason: the exponential chain is pointless to run in CI; the shortcut proves the collapse. Equivalence is certifiable at scale via the opt-in `RUN_SLOW_HALVING=1` test (~17 min); small-m equivalence (m=17) runs always.
- State change: n/a.
- Reference: SEC_M3_BACKWARD_ADD_PLAN.md; keylab/research/ecdlp/halving_shortcut.py.

## 2026-11-05 — M3: backward traversal depth > 18 — capped, not run
- Kind: extrapolated
- Action: breadth-first backward traversal at depth ≥ 18.
- Outcome: skipped (guarded)
- Cost observed: n/a — not run
- Cost extrapolated: 2**18 ≈ 262k nodes (~minutes); 2**20 ≈ 1M nodes (~40 min / ~1 GB) — OOM-likely on a GitHub runner. Exponential; the point is already made at depth 12.
- Reason: cost explodes past depth ~18 with no additional pedagogical value.
- State change: demo caps `--max-depth` (≤ 12 CI, ≤ 16 local); the demo guard raises `ValueError` above 18.
- Reference: SEC_M3_BACKWARD_ADD_PLAN.md §3; scripts/demo_backward_wall.py.

## 2026-11-05 — M3: full-strength secp256k1 ECDLP — impossible
- Kind: impossible
- Action: recover a 256-bit private key from its public key.
- Outcome: not-applicable (never attempted)
- Cost observed: n/a — not run
- Cost extrapolated: best generic attack is O(2·√n) ≈ 2^129 group ops ≈ ~10^25+ years at 1e7 ops/sec. Shor's algorithm would need ~10^12 physical qubits at error rates not achievable today.
- Reason: mathematically infeasible with any classical resource; this is the wall KeyLab teaches, not a target.
- State change: none.
- Reference: docs/research/ecdlp_benchmark.md (wall section).

## 2026-11-05 — M3: ECDLP tooling decision — kangaroo is the full-group primitive
- Kind: attempted
- Action: survey the repo for an ECDLP solver to measure the wall against.
- Outcome: complete (decision)
- Cost observed: n/a — survey
- Cost extrapolated: `pollard_kangaroo(Q, 0, N-1)` over the full group is O(2·√n) ≈ 2^129 steps, DP-based memory — the same asymptotics rho would have.
- Reason: the repo's only full-group-usable ECDLP primitive is `pollard_kangaroo`. No ECDLP `pollard_rho` exists (the `pollard_rho` in `keylab/numtheory/rsa.py` is RSA integer factorization — a different algorithm for a different problem). Calling kangaroo over `[0, N-1]` IS the full-group attempt; implementing a new rho or a toy curve was declined (new attack code / out of scope).
- State change: benchmark built on `pollard_kangaroo` only.
- Reference: docs/research/ecdlp_benchmark.md (tooling section); keylab/research/ecdlp/kangaroo.py.

## 2026-11-05 — M3: 20-random-k backward recovery per depth — measured, deep depths gated
- Kind: attempted
- Action: `recover_via_backward` for 20 random k at each depth in {4,6,8,10,12}.
- Outcome: complete (correctness); deep depths moved opt-in for cost.
- Cost observed: with coincurve (~1ms/scalar-mult, 2 halvings per BFS node), 20 recoveries take depth4 ~2s, depth6 ~9s, depth8 ~33s, depth10 ~130s, depth12 ~520s; all of {4..12}×20 ≈ 11.5 min.
- Cost extrapolated: cost per depth ≈ 20 · 2**depth · (2 scalar-mults) — exponential in depth, as expected for the brute-force traversal.
- Reason: 11.5 min always-on would blow the CI test budget; recovery correctness is already proven and the exponential shape is the lesson.
- State change: always-on keeps depths {4,6} (~11s); depths {8,10,12} gated behind `RUN_SLOW_ECDLP=1`. `backward_traverse_to_identity` MAX_DEPTH tightened 64 → 18 (guard cites this journal).
- Reference: tests/test_backward_double_add.py; SEC_M3_BACKWARD_ADD_PLAN.md §5.

## 2026-11-05 — M3: pollard_kangaroo budget bug — fixed
- Kind: attempted
- Action: audit + fix of `max_steps` enforcement in `pollard_kangaroo`.
- Outcome: complete
- Cost observed: regression test `[0,2^30) max_steps=100` returns None in ~0.4s (would hang pre-fix); full-group `[0,N-1] max_steps=200k` returns None in ~13s (~15k hops/s).
- Cost extrapolated: n/a — measured
- Reason: `max_steps` only bounded the outer retry loop; `_run_once` ran its full ~2·√width tame walk before any budget check, so for widths where base_hops > max_steps (full secp256k1: base_hops ≈ 2^129) a budget-bounded call ran unbounded / hung. Docstring claimed max_steps capped total hops; code did not.
- State change: budget now enforced inside the walk; `return_state=True` exposes spent_steps / dps_found (0, single-trap kangaroo) / memory_peak_bytes / attempts_used; `progress_callback` added for SIGTERM flush. Existing callers unchanged (default return path identical); all 10 existing kangaroo tests pass unmodified.
- Reference: commit 32d1faf; tests/test_kangaroo.py::test_kangaroo_max_steps_bounds_inner_walk.

## 2026-11-06 — M3: ECDLP bounded-full attempt — failed as expected (the wall)
- Kind: attempted
- Action: `pollard_kangaroo(Q, 0, N-1, max_steps=2**60, return_state=True)` on a real secp256k1 pubkey, time-bounded to 60s via a progress-callback budget.
- Outcome: failed (expected) — no solution.
- Cost observed: spent_steps = 1,240,000 hops at ~20,554 hops/s; elapsed 60.3s; dps_found 0 (single-trap kangaroo); memory n/a (Windows). fraction_of_work = 2^-109 of the ~2^129 expected. solution_found: false.
- Cost extrapolated: full-group expected ≈ 2·√n ≈ 2^129 hops ≈ ~10^25 years at 1e7 ops/s. Collision probability for 1.24M hops ≈ 10^-33 (birthday on n).
- Reason: this is the ECDLP wall, not a slowdown; no budget changes the exponent.
- State change: measurement recorded; attain anchors 2^20=8,749 / 2^24=39,699 hops give fitted constant ~9.1·√width. walkback (brute force) depth 8 = 229 leaves / 5.6s, depth 12 = 4,005 leaves / 59.9s.
- Reference: state/bounded_full_20261106T035846Z.json; docs/research/ecdlp_benchmark.md (wall section).
