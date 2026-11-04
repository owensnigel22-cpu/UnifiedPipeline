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
