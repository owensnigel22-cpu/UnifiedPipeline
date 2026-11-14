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

## 2026-11-06 — M3: distinguished-point (DP) kangaroo — implemented, density verified
- Kind: attempted
- Action: replace the single moving-trap `pollard_kangaroo` with the two-role distinguished-point variant (`dp_bits` parameter; a point is distinguished when the low `dp_bits` of its x-coordinate are zero, density `1/2**dp_bits`). The tame role records every DP it visits into a table keyed by the point; the wild role walks the same jump function and collides on a recorded DP, yielding `k = tame_scalar - wild_distance` (forward-verified).
- Outcome: complete (correctness + density).
- Cost observed: density check at `dp_bits=8` over `[0, N-1]`, 100k–200k hop budget: `dp_table_size/spent_steps` = 0.004065 (200k) / ~0.0039 (100k), vs the theoretical `1/2**8 = 0.003906`. Within the [1e-3, 1e-2] acceptance band. Recovery of a known `k < 2**20` at `dp_bits=8` succeeds; all 15 prior kangaroo tests pass unmodified; 7 new DP/checkpoint tests added (22 total, ~11s always-on).
- Cost extrapolated: full-group expected still ≈ 2·√n ≈ 2^129 hops. **The DP variant is not faster** — identical asymptotics; what changes is that table memory is bounded by `spent_steps/2**dp_bits` instead of by hop count, and a run is resumable.
- Reason: bounded memory + resumability for long measurement runs; single-process (no multiprocessing) keeps it deterministic and cross-platform.
- State change: `KangarooResult` extended with `dp_table_size`, `last_tame`, `last_wild`, `last_hop`, `elapsed_sec`, `walkers_used` (always 1), `checkpoint_path`; `dps_found` now mirrors `dp_table_size`. Supersedes the "dps_found 0 (single-trap kangaroo)" note in the 2026-11-06 bounded-full entry.
- Reference: src/keylab/research/ecdlp/kangaroo.py; tests/test_kangaroo.py::test_kangaroo_dp_density_matches_dp_bits.

## 2026-11-06 — M3: kangaroo checkpoint serialize/resume — cross-platform, no OS signal
- Kind: attempted
- Action: add `save_checkpoint` (atomic temp-file + `os.replace` + `fsync`) / `load_checkpoint` and `checkpoint_path` / `resume_from` parameters. The full resumable state (phase, tame/wild positions and distances, DP table, spent/offset/attempts) is serialized to JSON with big integers as strings.
- Outcome: complete.
- Cost observed: a 50-hop budget flushes a checkpoint without solving; resuming from it continues the identical deterministic walk and recovers the same `k=7777` that one uninterrupted run finds (spent 1729). Tested via direct serialize/resume calls, not via SIGTERM — so no POSIX-only signal test and no platform skip under the zero-skip CI gate.
- Cost extrapolated: n/a — measured.
- Reason: earlier plan used a SIGTERM handler (POSIX-only → win32 skip → fails the zero-skip gate) and `multiprocessing` (`Manager().dict()` under Windows spawn is nondeterministic/pickling-risky). Both dropped: single-process, signal-free, cross-platform.
- State change: checkpoint round-trip is a first-class, always-on test on every CI cell.
- Reference: src/keylab/research/ecdlp/kangaroo.py (save_checkpoint/load_checkpoint); tests/test_kangaroo.py::test_kangaroo_checkpoint_resume_roundtrip.

## 2026-11-06 — M3: backward-traversal depth cap removed — warns, does not refuse
- Kind: attempted
- Action: replace the hard `MAX_DEPTH` cap (ValueError above 18) in `backward_traverse_to_identity` with a warning. Only `max_depth < 1` raises `ValueError`; non-int raises `TypeError`; `max_depth >= 18` emits `DeepTraversalWarning` and proceeds.
- Outcome: complete.
- Cost observed: the warning fires before the BFS, so a deep `max_depth` with a tiny `k` (e.g. 5, found at depth 3) still returns at once — the test never pays the 2^19 cost. `DeepTraversalWarning` is a `UserWarning` subclass, so the suite's `filterwarnings = error::ResourceWarning` does not escalate it.
- Cost extrapolated: an actual depth-19 traversal of a 19-bit k is ~2^19 = 524k BFS nodes × 2 halvings ≈ minutes; depth-18 of the backward wall is unchanged.
- Reason: earlier plan used `ResourceWarning`, which the test suite escalates to an error (conflict). Switched to a dedicated non-escalated `UserWarning` subclass; deep traversal is *permitted with a warning*, not forbidden. The `scripts/benchmark_ecdlp.py` harness keeps its own `--depth <= 18` budget guard (separate policy from the library).
- State change: `MAX_DEPTH = 18` is now the warn threshold, not a cap. Supersedes the "MAX_DEPTH tightened 64 → 18 (guard cites this journal)" note in the 2026-11-05 20-random-k entry.
- Reference: src/keylab/research/ecdlp/backward_double_add.py (DeepTraversalWarning); tests/test_backward_double_add.py::test_depth_above_cap_warns_not_raises.

## 2026-11-06 — M3: honest framing of the DP variant — recorded
- Kind: extrapolated
- Action: state plainly what the DP work does and does not change.
- Outcome: complete (framing).
- Cost observed: n/a — framing of the measurements above.
- Cost extrapolated: a 60s full-group run reaches ~2^-109 of the ~2^129 work whether single-trap or DP — identical.
- Reason: the DP-table kangaroo is NOT faster than the single trap. Asymptotics are identical, O(2·√width). Removing the depth cap and (future) budget caps does not make deep runs feasible — it makes them *permitted*, with a warning. What the DP variant buys is bounded memory (table size ≈ spent/2**dp_bits) and resumability (checkpoint/resume), nothing more.
- State change: none — documentation of intent, repeated in the kangaroo module docstring and docs/research/ecdlp_benchmark.md.
- Reference: this journal; src/keylab/research/ecdlp/kangaroo.py module docstring.

## 2026-11-08 — SAT encoding of bounded-range secp256k1 ECDLP — the ceiling (dead end)
- Kind: attempted
- Action: encode `k*G == Q` for `k in [L,U]` as CNF over full 256-bit secp256k1 field arithmetic (double-and-add with per-step modular add/mul/inverse, built on keylab.sat.cnf), increasing the number of point-doubling steps, and attempt to solve with kissat.
- Outcome: failed (expected) — intractable at full width; **ceiling ~0 doublings at 256-bit**.
- Cost observed: encoder VERIFIED correct on a toy curve (F_1009, ~65k clauses): solver recovers known k, forward-verified, in seconds. On secp256k1 (width=256): steps=1 → 1,803,251 vars / 8,003,631 clauses / build 32s / solve UNKNOWN (no termination; kissat ran ~145s, killed). steps=2 → 3,607,867 vars / 16,015,924 clauses / build 475s / solve UNKNOWN. (An accidentally-exceptional steps=1 instance returned UNSATISFIABLE fast via a local inv*0==1 contradiction — not a genuine solve.)
- Cost extrapolated: clauses grow ~8M per doubling step; a full-range scalar (hundreds of doublings) would be billions of clauses / terabytes — never buildable, let alone solvable.
- Reason: each doubling touches the full 256-bit modulus, so the field-arithmetic CNF dominates regardless of how narrow [L,U] is. SAT is the wrong tool for 256-bit ECC; this is a memory/clause blow-up, not a slow solve.
- State change: SAT ECDLP work STOPPED by instruction. Encoder + correctness test kept (keylab.research.ecdlp.sat_encoding, tests/test_sat_encoding.py) as a documented dead-end + canary; scripts/benchmark_sat_ecdlp.py made safe-by-default (memory watchdog, hard subprocess timeout, clause cap refusing the gigabyte build unless --i-accept-oom). Negation-map symmetric-WALK attempt (Part B.1) left UNSHIPPED: in testing it did not terminate quickly / showed no verified speedup, same honest call as Phase 2.
- Reference: scripts/benchmark_sat_ecdlp.py; keylab.research.ecdlp.sat_encoding; tests/test_sat_encoding.py.

## 2026-11-08 — M4: ECDSA biased-nonce HNP — correct, but 256-bit LLL is impractical
- Kind: attempted
- Action: recover an ECDSA private key from biased (short) nonces via the Hidden Number Problem, reusing keylab.research.hnp_lattice's LLL/Babai.
- Outcome: attack VERIFIED correct at reduced modulus; full secp256k1 recovery left as a documented performance limitation.
- Cost observed: at order q = 2^31-1, nonce_bits=16, m=6-8 signatures: recovers the planted d in 0.8-3s, forward-verified. At secp256k1 N (256-bit), the exact-Fraction LLL from hnp_lattice (built for toy moduli <= 100k) is impractically slow -- ~18-65s per run for m=6-8 and it did not even return the right key with the naive lattice.
- Cost extrapolated: a correct 256-bit HNP needs an integer-preserving (non-Fraction) LLL; float LLL is unusable because 256-bit basis magnitudes exceed double precision (53-bit mantissa).
- Reason: two issues found and one fixed. (1) CONSTRUCTION BUG: the toy hnp_lattice puts weight 1 on the hidden coordinate, so Babai's distance is dominated by d^2 when d ~ order and it returns the wrong key; FIXED by a scaled CVP lattice (modular coordinates weighted by order/2^nonce_bits) -- now recovers a full-width hidden number. (2) PERFORMANCE: exact-Fraction LLL does not scale to 256-bit; NOT fixed (a fast integer LLL is out of scope this round).
- State change: keylab.research.ecdsa.hnp ships the corrected scaled-lattice recovery with an explicit `order` parameter; tested at q=2^31-1 (fast, always-on). secp256k1-scale recovery is a known limitation, not a correctness gap.
- Reference: keylab.research.ecdsa.hnp (recover_hidden_number, recover_private_key_from_biased_nonces); tests/test_ecdsa_hnp.py.

## 2026-11-08 — SAT ECDLP: resource-safe harness + word-level SMT alternative (ceiling unchanged)
- Kind: attempted
- Action: (1) make the SAT ECDLP experiment fail safely instead of crashing the host; (2) try the one encoding with a real chance of beating naive bit-blasting -- word-level SMT (z3 QF_BV) -- for 1 doubling at 256-bit.
- Outcome: safety achieved; SMT does NOT change the ceiling. Ceiling remains ~0 doublings at 256-bit for both CNF and SMT.
- Cost observed:
  - SAFETY: clauses now STREAM to a DIMACS file (never an 8M-tuple list in RAM); every build/solve runs in a SUBPROCESS under a hard memory cap (Windows Job Object ProcessMemoryLimit / POSIX RLIMIT_AS, scripts/run_capped.py -- self-tested: a 2 GiB alloc under a 400 MiB cap dies with a clean MemoryError) plus a wall-clock timeout. Re-run under a 700 MiB cap (host had ~0.9 GiB free): steps=1 build OK and reproduced the exact counts (1,803,251 vars / 8,003,631 clauses -- caps change only how failure is handled); solve MEM-KILLED cleanly; steps=2 build MEM-KILLED cleanly. No host crash.
  - SMT: z3 QF_BV encoding VERIFIED on the toy curve (status=sat, recovered k=3, 1.8s). secp256k1 1-doubling: status=UNKNOWN in ~8-9s at both 550 and 650 MiB z3 memory caps -- z3 bit-blasts the 256-bit modular multiply, hits the resource limit, and returns no answer. It did not beat the CNF route.
- Cost extrapolated: n/a -- measured both ways.
- Reason: a 256-bit modular-arithmetic circuit (bvmul/URem over 256 bits) is in the same intractability class whether expressed as flat CNF or word-level QF_BV; the solver must still bit-blast the multiplication. SAT/SMT is the wrong tool for 256-bit ECC.
- State change: scripts/benchmark_sat_ecdlp.py rewritten memory-safe (streaming + capped subprocesses); scripts/run_capped.py (reusable cap) and scripts/smt_ecdlp.py (z3 QF_BV, requires `pip install z3-solver`, not a repo dependency) added; sat_encoding.encode_bounded_ecdlp gained an optional injectable `cnf` (for the streaming subclass). FINAL: Part A ceiling stands at ~0 doublings at 256-bit; a correct "it doesn't work past that" is the complete result.
- Reference: scripts/run_capped.py; scripts/benchmark_sat_ecdlp.py; scripts/smt_ecdlp.py.


## 2026-11-08 — M5: truncated SHA-256 pre-image + length extension (reduced/truncated scale)
- Kind: attempted
- Action: implement keylab.research.hash_attacks (truncated-digest pre-image brute force + Merkle-Damgard length-extension demo) with a resource-safe benchmark, under the lifted constraints (deps/skips/network allowed).
- Outcome: complete; the pre-image wall measured and extrapolated, length extension reused and verified.
- Cost observed: truncated pre-image cost tracks 2**bits (hashlib loop, in a capped subprocess): 16-bit 58,096 tries/0.14s, 20-bit 2,491,605/7.43s, 24-bit 16,175,767/48.15s, ~335k hashes/sec. Extrapolation: full 2**256 pre-image at 1e12 guesses/sec ~ 3.7e57 years (~10^60) -- the wall, labelled and never run. Length-extension forge verified by independent recompute hashlib.sha256(secret||forged_message) == forged_digest.
- Cost extrapolated: see the wall above; bits hard-capped at 40 so no infeasible search is ever started.
- Reason: accelerated hash backend evaluated and NOT shipped -- pycryptodome measured ~0.26x (3.8x SLOWER) than hashlib (OpenSSL C) in a tight loop (per-call object overhead), and the Python search loop is ~84% the bottleneck; the only real speedup is a native search kernel (Rust), out of scope for this educational tool. So no new accelerated dependency and no differential test (nothing faster to compare).
- State change: keylab.research.hash_attacks shipped (find_truncated_preimage, demonstrate_length_extension reusing keylab.hashes.length_extension); scripts/benchmark_hash_preimage.py reuses scripts/run_capped.py (hard memory cap + timeout) + a psutil watchdog; heavy 24-bit test marked @pytest.mark.slow (deselected by default); pyproject registers the slow marker and adds `addopts = -m 'not slow'`. docs/hash_attacks.md states the 2**256 wall.
- Reference: keylab.research.hash_attacks; scripts/benchmark_hash_preimage.py; docs/hash_attacks.md; tests/test_hash_attacks.py.

## 2026-11-08 — M6: simulated Bellcore fault attacks (RSA-CRT + ECDSA)
- Kind: attempted
- Action: implement keylab.research.fault_attacks -- a CRT-RSA signer and an ECDSA signer with software fault injection, plus the two key-recovery functions, simulating the mathematical consequence of a physical glitch.
- Outcome: complete; both attacks recover the planted key from one correct + one faulty signature.
- Cost observed: RSA-CRT: a p-branch (or q-branch) fault gives s' = s (mod q), s' != s (mod p), so q = gcd(|s-s'|, n), p = n/q, d = e^-1 mod lcm(p-1,q-1) -- recovered the planted (p,q,d) on a 256-bit-prime keypair; the correct signature independently verifies s^e mod n == m. ECDSA: a scalar-mult glitch (R=(k+delta)G) with the same RFC6979 nonce reused in s gives two linear equations; d = z(s-s_f)*(s_f*r - s*r_f)^-1 mod n recovered the planted d across several keys, forward-verified d*G == pubkey. O(1) maths (one gcd / one 2x2 solve) -- no brute force, no resource guards needed.
- Cost extrapolated: n/a -- exact algebra.
- Reason: unprotected CRT-RSA and ECDSA signers leak the key from a single faulty signature; the mitigation is to verify the signature before output (recompute s^e mod n == m for RSA; re-verify (r,s) for ECDSA). Two correct signatures recover nothing (gcd trivial / denominator zero -> None), never a wrong key/factor.
- State change: keylab.research.fault_attacks shipped (rsa_crt_sign/recover_primes_from_crt_fault, ecdsa_sign_with_fault/recover_private_key_from_ecdsa_fault); docs/research/fault_attacks.md states the physical-vs-mathematical distinction and the verify-before-output mitigation. No new dependency.
- Reference: keylab.research.fault_attacks; docs/research/fault_attacks.md; tests/test_fault_attacks_rsa.py, tests/test_fault_attacks_ecdsa.py.
## 2026-11-09 — M10: ECDH and native ECDSA groundwork (in progress)
- Kind: implemented, validation pending
- Action: add a pure-Python secp256k1 ECDH reference and optional Coincurve path, explicit libsecp256k1 ECDSA sign/verify adapters, and an M7 collection API that independently checks each input concurrently through native verification when available. Add reproducible benchmark tooling.
- Outcome: three local commits on `docs/m10-optimization-ecdh-plan`; implementation is not merged. No ordinary-ECDSA probabilistic equation aggregation was introduced. The collection API keeps exact per-signature acceptance semantics.
- Cost observed: focused Python ECDH/ECDSA/secp256k1 tests: 44 passed, 175 skipped (optional backend/property-test dependencies unavailable). Benchmark smoke on CPython 3.14.7, Windows 10 x64, 2 operations/sample and 3 samples: ECDH pure Python median 63.097 ops/s (58.864–64.456); ECDSA sign pure Python 336.525 ops/s (335.971–371.395); ECDSA verify pure Python 329.159 ops/s (327.150–362.017). Coincurve was unavailable, so no native comparison. Mainnet tests could not collect because required `httpx` is absent. Ruff is available; mypy and several project dependencies are absent. Attempts to install Coincurve failed with OS permission denied while pip wrote wheel metadata to temporary directories.
- Cost extrapolated: none; no performance improvement is claimed without native measurements.
- Security: Python ECDH and signing remain variable-time. Coincurve adapters are explicit and do not silently fall back; the ECDH `auto` API intentionally follows the milestone contract by using Coincurve when installed and a documented variable-time Python fallback otherwise. Callers handling secrets should explicitly require Coincurve. The M7 collection verifies every input exactly; threading overhead may outweigh benefits for small input sets.
- State change: added `[fast]` as an optional extra; added Coincurve to the existing native CI installation set; M10 remains unreviewed/unmerged pending complete validation.
- Reference: `src/keylab/ec/ecdh.py`, `src/keylab/ec/coincurve_backend.py`, `src/keylab/verify/mainnet/verification.py`, `scripts/benchmark_ecc.py`.

## 2026-11-09 — M11: Project Complete
- Kind: attempted
- Action: finalize the M1–M10 documentation and release artifacts; add the M9/M10 modules to the generated API reference; generate the CycloneDX 1.6 CBOM.
- Outcome: complete.
- Cost observed: Ruff passed with 0 errors; Mypy ratchet passed with 0 errors (baseline 0); full pytest suite passed (1956 passed, 14 skipped, 2 deselected); API-doc generation/check passed (50 focused tests passed); CBOM schema validation passed with 189 components.
- Cost extrapolated: n/a — validation and artifact generation completed.
- Reason: n/a.
- State change: M1–M10 delivered; final architecture, math limits, and installation instructions recorded in the README; `docs/api.md` and `cbom-baseline.json` generated. This entry supersedes the provisional M10 status above.
- Reference: `README.md`, `docs/api.md`, `scripts/gen_api_docs.py`, `scripts/gen_cbom.py`, `requirements-cbom.txt`, `cbom-baseline.json`.

## 2026-11-11 — M14: expanded broadcasting architecture (HTTP + P2P + mainnet routing)
- Kind: attempted
- Action: add broadcasters for a pre-signed transaction — HTTP explorer APIs (mempool.space, BlockCypher) in keylab.wallet.broadcast_api, and direct P2P relay (version handshake -> inv -> tx on getdata, the laanwj/bitcoin-submittx methodology) in keylab.wallet.broadcast_p2p — plus network-aware routing in keylab.wallet.broadcast that enables mainnet behind exactly one explicit confirmation and requires the audited coincurve backend for mainnet signing.
- Outcome: complete. 16 new tests (6 HTTP via httpx.MockTransport, 4 P2P via a scripted fake peer, 6 routing incl. the mainnet-confirmation guard and the missing-coincurve guard). Full suite green.
- Cost observed: ruff clean; mypy clean; pytest 2023 passed, 14 skipped, 2 deselected on CPython 3.14 Windows (basetemp outside OneDrive to avoid the symlink teardown PermissionError). Broadcasters touch the network only against injected/mock transports in tests; no live mainnet or testnet send was performed.
- Cost extrapolated: n/a.
- Security: the earlier "no broadcasting, ever" posture was revoked by the owner; mainnet broadcasting is now supported but deliberately bounded. Broadcasters push an already-signed raw_tx_hex and handle NO keys. A Network.MAINNET broadcast raises MainnetConfirmationError unless confirm_mainnet=True — one informed opt-in per transaction, never fired silently. require_coincurve_for_mainnet() refuses to let the non-constant-time pure-Python ECC sign real-value keys (raises ImportError if libsecp256k1/coincurve is absent). HTTP broadcasters enforce TLS 1.2+ with certificate validation and https-only bases. The truthful SECURITY.md warnings ("not constant-time", audited-backend-only for real value) were kept, not deleted; the M12 guarded RPC path in keylab.wallet.tx still rejects mainnet and was left intact as defense in depth.
- State change: keylab.wallet now exports the broadcasters and the router; new deps httpx>=0.27 and python-bitcoinlib>=0.12 added to pyproject; SECURITY.md records mainnet broadcasting + its single confirmation while retaining the real-value warnings; docs/references.md adds the broadcasting references (laanwj/bitcoin-submittx, python-bitcoinlib, mempool.space, BlockCypher).
- Reference: src/keylab/wallet/broadcast_api.py, src/keylab/wallet/broadcast_p2p.py, src/keylab/wallet/broadcast.py; tests/test_broadcast_api.py, tests/test_broadcast_p2p.py, tests/test_broadcast_routing.py; SECURITY.md; docs/references.md.

## 2026-11-14 — M15: feed-forward unwind for the SHA-256 CNF model (opt-in)
- Kind: implemented
- Action: add `unwind_feedforward=True` to `sha256_compression_cnf` / `sha256_hash_preimage_cnf` (threaded through `_build_model` and `_compress_block_cnf`). When the incoming chaining state is a known constant (compression mode, or a single-block hash with `message_length <= 55`), the Davies-Meyer feed-forward is unwound algebraically: the post-feed-forward output is `(initial_i + register_i) mod 2**32`, so the known target forces `register_i = (target_i - initial_i) mod 2**32`. The pre-feed-forward working registers are constrained directly and the 8-word output adder network is omitted.
- Outcome: complete and opt-in; the default path keeps the explicit adder so existing variable/clause-count tests are unchanged. A multi-block message with `unwind_feedforward=True` raises `ValueError` (the final block's incoming state is a variable and cannot be unwound).
- Cost observed: measured reduction per model — compression rounds=8: variables 5767->5287 (-480), clauses 26083->24399 (-1684); single-block hash rounds=4: variables 2564->2085 (-479), clauses 11073->9393 (-1680). SAT-equivalence confirmed with an installed external solver: for compression (r8), single-block hash (r4, r17) the unwound model under the known input is SATISFIABLE and recovers the exact input; a one-bit-corrupted target is UNSATISFIABLE. ruff clean; mypy clean (1 source file); tests/test_sha256_cnf.py 48 passed.
- Cost extrapolated: n/a — exact algebra (subtraction mod 2**32 is a bijection).
- Reason: removing the 256-bit feed-forward adder removes its auxiliary variables and the nonlinear carry chains a solver would otherwise reason through, with no change to the free input bits or the solution set. Scope is bounded to constant-incoming-state instances; nothing here attacks full 64-round SHA-256.
- State change: `src/keylab/hashes/sha256_cnf.py` gains the opt-in unwind and a `SHA256CNFModel.feedforward_unwound` flag; `tests/test_sha256_cnf.py` adds size, SAT-equivalence, UNSAT, multi-block-rejection, and metadata tests. No new dependency; no new CI job.
- Reference: `src/keylab/hashes/sha256_cnf.py`; `tests/test_sha256_cnf.py`.

## 2026-11-14 — M15 Phase D: length-extension expansion (MD5, SHA-1, SHA-256, SHA-512)
- Kind: implemented
- Action: expand `keylab.hashes.length_extension` from SHA-256-only to a unified `length_extend(algorithm, original_digest, original_len, append, *, secret_len=None)` over MD5, SHA-1, SHA-256, SHA-512, with a generic Merkle-Damgard driver (per-hash block size, digest size, length-field size/endianness, and compression). Pure-Python compression functions added for MD5, SHA-1, SHA-512; SHA-256 reuses the existing `_sha_compress`. Per-hash constants are derived from first principles (MD5 K from `sin`; SHA-512 IV/K from exact integer square/cube roots of the first primes via an integer n-th-root helper) so no table is hand-transcribed. `sha256_length_extend` and `SHA256LengthExtension` are retained unchanged as a backward-compatible wrapper.
- Outcome: complete. Reference algorithm is iagox86/hash_extender; correctness is pinned to the `hashlib` oracle (the forged digest equals the real hash of the forged message) rather than a captured hash_extender run — stated honestly in docs/references.md and the module docstring. No fabricated published vectors.
- Cost observed: derivations reproduce the published constants (SHA-512 IV[0]=0x6a09e667f3bcc908, K[0]=0x428a2f98d728ae22, K[79]=0x6c44198c4a475817, MD5 K[0]=0xd76aa478); from-scratch hashes match hashlib for all four algorithms across lengths 0..200; `length_extend` oracle matched hashlib on 28 ad-hoc vectors and on the committed parametrized suite (4 algorithms x 7 secret lengths = 28 vectors). ruff clean; mypy clean (1 source file); tests/test_length_extension.py 45 passed.
- Cost extrapolated: n/a — exact Merkle-Damgard algebra.
- Reason: length extension is a structural consequence of Merkle-Damgard finalization; it forges a digest for an attacker-chosen suffix and recovers no secret and inverts no hash. The lesson recorded in docs is "use HMAC, not H(secret || message)".
- State change: `src/keylab/hashes/length_extension.py` gains `length_extend`, `LengthExtension`, `SUPPORTED_ALGORITHMS`; `tests/test_length_extension.py` adds the multi-algorithm oracle suite, constant-derivation anchors, wrapper-agreement, and validation tests; docs/references.md adds the hash_extender reference. No new dependency; no new CI job.
- Reference: `src/keylab/hashes/length_extension.py`; `tests/test_length_extension.py`; docs/references.md.
