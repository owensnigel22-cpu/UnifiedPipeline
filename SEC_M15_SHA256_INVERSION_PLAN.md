# SEC_M15 — SHA-256 Inversion Expansion (Plan)

**Status:** proposed — awaiting owner ack. **No code written yet.**
**Date:** 2026-11-12 · **Baseline:** `v1.0.0` (M1–M14 merged).
**Branch (on ack):** `sec/m15-sha256-inversion`.

This plan adds five SHA-256 attack families across `keylab.sat`, `keylab.hashes`,
and `keylab.research`, surveyed from the open-source repositories listed in
Phase G. It is written to the M15 directive and the governing constraints in
`AGENTS.md` (DEPENDENCY_POLICY, validation/reporting) and `SECURITY.md`.

---

## 0. Honest positioning (load-bearing — carried into SECURITY.md)

**No full 64-round SHA-256 preimage or collision is claimed. Full-round SHA-256
remains a wall, not a slowdown.** Every M15 attack targets one of:

- **truncated** digests (≤ 40 output bits constrained), or
- **reduced-round** SHA-256 (≤ 24 compression steps; preimage solvers at 19–20
  steps per published results), or
- **constrained input spaces** (bounded prefix/suffix, fixed structure).

Reproduced third-party speedup *claims* (e.g. the Mod-9 "3.2×") are recorded as
**claims to be measured**, never as KeyLab results, until we have our own
numbers with provenance. Measured vs. extrapolated is distinguished everywhere,
per `AGENTS.md`.

---

## 1. Verify-before-acting: what already exists (do NOT regenerate)

A survey of the tree changes the shape of Phase A and D:

| Directive asks for | Already in repo | M15 action |
|---|---|---|
| `keylab.sat.solvers` XOR-native CMS mode | `keylab.sat.cryptominisat.CryptoMiniSatFormula` already emits `x … 0` XOR rows; `keylab.sat.backends.solve_cnf` dispatches PySAT/CMS/PycoSAT | **Extend**, don't duplicate: teach `hashes.sha256_cnf` to emit Σ/σ as XOR via the existing formula; add an `--xor` CMS invocation path in `backends` |
| Cube-and-Conquer driver | `keylab.sat.parallel` already has `generate_cubes`, `dimacs_with_assumptions`, `solve_parallel_cubes` | **Extend** to subprocess dispatch with `scripts/run_capped.py` timeout/memory guards; no new parallel module |
| Length-extension expansion | `keylab.hashes.length_extension` (SHA-256 only) | **Extend** to MD5/SHA-1/SHA-256/SHA-512 + arbitrary secret/append |
| Reduced-round SHA primitives | `keylab.hashes.reduced` (`sha256_reduced`, backward traces, Maj/Ch inversion) | **Reuse** as the oracle for new 19/20-step solvers |

Genuinely new modules: Mod-9 propagator, 19/20-step preimage solvers, belief
propagation, MILP model, differential search, GPU interface stubs.

---

## 2. Dependency plan (DEPENDENCY_POLICY)

`AGENTS.md` classes: *production-support / reference / experimental /
optional-backend / development-only*. Rule: prefer optional extras; never make a
research backend mandatory without owner approval.

| Phase | New runtime dep? | Extra | Class | Justification |
|---|---|---|---|---|
| A — Mod-9 propagator | none (pure Python) | — | experimental | clause-propagation layer in pure Python |
| A — XOR-native CMS | none | `pycryptosat` already core; CLI `cryptominisat5 --xor` optional | optional-backend | graceful fallback if CLI absent |
| A — Cube-and-Conquer | none | — | experimental | pure-Python orchestration + existing `run_capped.py` |
| B — 19/20-step | none (pure Python) | — | experimental | algebraic context-shaping, CPU only |
| C — Belief propagation | none (pure Python) | — | experimental | loopy BP over bit-graph, stdlib only (no numpy) |
| C — MILP | **`pulp>=2.7`** (bundles CBC) | **new `milp` extra** | optional-backend | MILP needs a solver; `pulp`+CBC is pure-Python-installable, MIT/CBC-EPL; **requires owner approval of the new extra** |
| D — length extension | none (pure Python) | — | reference | reimplements padding for 4 hashes |
| E — differential | none (pure Python) | — | experimental | heuristic trail search |
| F — GPU stubs | **none — interface only** | — | reference | abstract class + `--dry-run`; CUDA repos are *reference, not dependencies* |

**Only one new dependency is proposed: `pulp` (Phase C MILP), as an optional
`milp` extra.** If you prefer zero new deps, Phase C MILP ships as a model
*emitter* (writes `.lp`/`.mps` files) with the solver call behind the optional
extra, so the core stays dependency-free. **Flagging for explicit approval.**

---

## 3. Phases

### Phase A — Advanced SAT backends

**New module:** `keylab.sat.mod9` (Mod-9 propagator).
**Extended:** `keylab.sat.backends`, `keylab.hashes.sha256_cnf`, `keylab.sat.parallel`.

**Public API**
- `mod9.Mod9Propagator(cnf: CNF)` with `.propagate(assignment) -> PropagationResult`
  (deduced literals + conflicts); a pure-Python layer run *before/around* an
  existing solver, not a replacement SAT engine.
- `sha256_cnf.sha256_compression_xor_formula(...) -> CryptoMiniSatFormula` — Σ0/Σ1/σ0/σ1
  rotations emitted as XOR rows instead of Tseitin AND/OR fan-out.
- `backends.solve_cnf(..., prefer_xor: bool = False)` — route to `cryptominisat5 --xor`
  when the CLI and XOR formula are present; fall back to the CNF path otherwise.
- `parallel.solve_cubes_subprocess(dimacs, variables, depth, *, timeout_s, mem_mb)` —
  subprocess dispatch guarded by `scripts/run_capped.py`.

**Test strategy**
- `tests/test_sat_mod9.py` — unit: propagator deduces forced literals on small
  hand-built CNFs; agrees with brute force on ≤ 16-var formulas (fast).
- `tests/test_sha256_xor_formula.py` — the XOR formula and the Tseitin CNF are
  **equisatisfiable** on an 8-round compression instance; same model decoded
  (fast); a `@slow` 16-round solve comparing wall-time XOR vs CNF (measured).
- `tests/test_parallel_subprocess.py` — cube split covers the space; timeout and
  memory caps are enforced (one `@slow` guarded run).

**Exit criteria (numbers)**
- Mod-9 propagator: 100% agreement with brute force on all ≤ 16-var test CNFs.
- XOR formula: equisatisfiable with CNF on 8- and 16-round instances (0 mismatches).
- **Measured** XOR-vs-CNF speedup reported on a fixed 16-round instance — whatever
  it is; **the 3.2× claim is cited, not asserted**. Target to *report*, not to beat.
- Subprocess driver: no leaked processes/handles (ResourceWarning = failure).

**Known limitations**
- Mod-9 is a propagation *heuristic*: it prunes, it does not decide; speedup is
  instance-dependent and may be < 1× on some inputs (reported honestly).
- `--xor` path is a no-op without the CMS CLI; CI exercises the fallback.

---

### Phase B — Reduced-round preimage solvers

**New module:** `keylab.research.sha256_reduced` (package).
References: `srw/sha256-19-and-20-step-preimages-with-padding`,
`kamb-code/sha256-r19-preimage`. **CPU only — CUDA variants out of scope.**

**Public API**
- `preimage_19_step(target_digest: bytes, *, budget_s: float) -> PreimageResult | None`
- `preimage_20_step(target_digest: bytes, *, with_padding: bool, budget_s: float) -> PreimageResult | None`
- `PreimageResult(message: bytes, rounds: int, verified: bool)` — every result is
  **forward-verified** against `keylab.hashes.reduced.sha256_reduced` before return.

**Test strategy**
- Fast: API/guard tests, bad-length rejection, verifier wiring (sub-second).
- `@slow`: end-to-end 19-step and 20-step solves on published/self-generated
  targets; each asserts `sha256_reduced(result, 19/20) == target` (measured wall-time recorded).

**Exit criteria**
- 19-step: recover a preimage for ≥ 1 published target **and** 3 self-generated
  targets; forward-verified; median wall-time recorded.
- 20-step (with padding): recover ≥ 1 target; forward-verified.

**Known limitations**
- Expected runtime: **minutes on a 4-core CPU** (to be measured; e.g. "19-step
  ~N min" filled from the actual run). No claim beyond 20 steps.

---

### Phase C — Probabilistic & algebraic solvers

**New modules:** `keylab.research.sha256_prob.belief_propagation`,
`keylab.research.sha256_prob.sha256_milp`.
References: `hirorylabo/preimage-attacks`, `trevphil/cryptosym`.

**Public API**
- `belief_propagation.solve_truncated(target_bits, n_bits, *, max_iters, damping) -> BPResult`
  — loopy BP over the bit factor-graph for a truncated (≤ 40-bit) preimage;
  returns marginals + a decoded candidate, forward-verified.
- `sha256_milp.compression_milp(rounds: int) -> MILPModel` — emits the reduced-round
  compression function as a MILP (variables, constraints) for differential/bound
  analysis; `.write_lp(path)` always available; `.solve()` requires the `milp` extra.

**Test strategy**
- Fast: factor-graph construction, MILP emission to `.lp` (parse-check), guards.
- `@slow`: BP convergence on a 24-bit truncated target (decoded candidate
  verified); MILP solve of a small reduced-round bound (skipped if `pulp` absent).

**Exit criteria**
- BP: converges and verifies a decoded preimage for a ≤ 24-bit truncated target
  in ≥ 3/5 seeded trials (BP is probabilistic — non-convergence is reported, not hidden).
- MILP: `.lp` round-trips; a reduced-round active-Sbox/differential bound matches a
  cited published value for ≥ 1 small case.

**Known limitations**
- Loopy BP has no convergence guarantee; failures are returned as `converged=False`.
- MILP solve time grows fast with rounds; only small instances are tractable.

---

### Phase D — Length-extension expansion

**Extended module:** `keylab.hashes.length_extension`.
References: `iagox86/hash_extender`, `eid3t1c/Hash_Extender`.

**Public API**
- `length_extend(algorithm, original_digest, original_len, append, *, secret_len=None) -> ExtensionResult`
  for `algorithm in {"md5","sha1","sha256","sha512"}`; arbitrary secret & append
  lengths; returns `(new_message_suffix, forged_digest)`.
- Existing `sha256_length_extend` kept as a thin compatibility wrapper (no break).

**Test strategy**
- `tests/test_length_extension_vectors.py` — vectors **verified against
  `iagox86/hash_extender` output** for all four hashes; plus a self-consistency
  oracle: `H(secret || glue || append)` computed independently equals the forged
  digest for random secret lengths. All fast.

**Exit criteria**
- 4 algorithms × ≥ 3 secret-length cases each = **≥ 12 vectors**, all matching the
  reference tool and the independent oracle (0 mismatches).

**Known limitations**
- Educational; demonstrates why raw `H(secret||msg)` MACs are forgeable. Not a MAC.

---

### Phase E — Differential cryptanalysis

**New modules:** `keylab.research.sha256_differential.trail_search`,
`keylab.research.sha256_differential.dobbertin` (scaffold).
References: `ChakshuGupta13/lab`, `nahiyan/cryptanalysis`.

**Public API**
- `trail_search.search(rounds: int, *, budget_s, seed) -> Trail | None` — heuristic
  (greedy/annealing, **not** full automated search) for a high-probability
  differential trail in 22–24-step SHA-256; `Trail` carries per-round differences
  and `log2_probability`.
- `dobbertin.CollisionHarness` — documented scaffold + test harness for reduced-round
  collisions (structure only; no claim of a working full collision).

**Test strategy**
- Fast: trail object invariants; probability accounting; harness wiring.
- `@slow`: a seeded trail search on 22–24 steps returns a trail whose stated
  probability is re-verified by direct sampling to within tolerance.

**Exit criteria**
- Return ≥ 1 valid 22-step trail with `log2_probability` consistent (±1 bit) with
  empirical sampling; harness documents the Dobbertin structure with ≥ 1 reduced
  example.

**Known limitations**
- Heuristic, not exhaustive; "best trail found", never "optimal". Dobbertin module
  is scaffolding, explicitly not a shipped full collision.

---

### Phase F — GPU interface stubs

**New module:** `keylab.research.gpu` + `docs/gpu/README.md`.
**No CUDA/OpenCL/Vulkan in-repo or in deps.** Interface only.

**Public API**
- `GPUBruteForcer` (abstract): `search(bounds) -> Preimage | None` contract; a CLI
  contract (stdin bounds → stdout preimage).
- `dry_run(bounds) -> KernelInvocation` — emits the kernel invocation parameters
  (grid/block/search range) a user feeds to an **external** GPU tool; KeyLab itself
  runs nothing on a GPU.

**Test strategy**
- Fast only: abstract class cannot be instantiated; `dry_run` emits the documented
  parameter schema for sample bounds; README links resolve.

**Exit criteria**
- `--dry-run` produces a valid, documented invocation for 3 sample bound sets; no
  GPU dependency is importable or required.

**Known limitations**
- KeyLab provides the *interface and parameters only*; `shroudy-bit32/CUDA-BruteForce`
  and `floflo777/open-crypto-puzzles` are **reference implementations, not dependencies.**

---

### Phase G — Documentation & references

- `docs/references.md`: add all repos with attribution + license notes —
  `nahiyan/cryptanalysis`, `trevphil/cryptosym`, `hirorylabo/preimage-attacks`,
  `srw/sha256-19-and-20-step-preimages-with-padding`, `kamb-code/sha256-r19-preimage`,
  `ChakshuGupta13/lab`, `iagox86/hash_extender`, `eid3t1c/Hash_Extender`,
  `shroudy-bit32/CUDA-BruteForce` (GPU — reference only), `floflo777/open-crypto-puzzles`
  (GPU — reference only), and the Shelbydon Mod-9 SAT paper/implementation (cited).
- GPU repos **explicitly marked** "reference implementations, not dependencies."
- `SECURITY.md` "Wall" section: add that **all M15 attacks target
  truncated/reduced-round/constrained instances, never full 64-round**, which
  remains infeasible.
- `SEC_STATE_JOURNAL.md`: one M15 entry per the house format (kind/action/outcome/
  cost observed/extrapolated/security/state change/reference).
- `docs/api.md`: regenerate **only if** new public modules are added to the
  `gen_api_docs.MODULES` list (decision deferred to implementation; the api-docs
  `--check` must stay green either way).

---

## 4. Global test & gate strategy

- **No new CI jobs.** New tests land in existing cells. Anything > 30s is
  `@pytest.mark.slow` (deselected by default via `addopts = -m 'not slow and not live'`).
- Every solver **forward-verifies** its own output against the reference oracle
  (`hashes.reduced`, `hashlib`) before returning — no unverified "solutions."
- Gates (all must pass before PR): `ruff` clean · `mypy` 0 errors · `pytest` 0
  failures (default selection) · `@slow` suite run locally at least once with
  numbers recorded · api-docs `--check` green · no `ResourceWarning`.
- Reporting per `AGENTS.md`: exact commands + observed results, measured vs.
  extrapolated kept distinct; failures/skips/env limits disclosed.

## 5. Proposed commit/PR sequence (one branch, phased commits)

1. Phase A — Mod-9 + XOR emit + subprocess cubes (+ tests)
2. Phase B — 19/20-step preimage (+ tests)
3. Phase C — belief propagation + MILP emitter (+ tests; `milp` extra **iff** approved)
4. Phase D — length-extension expansion (+ vectors)
5. Phase E — differential search + Dobbertin scaffold (+ tests)
6. Phase F — GPU interface stubs + `docs/gpu/`
7. Phase G — references, SECURITY.md Wall, journal, (api.md if needed)

Then push `sec/m15-sha256-inversion`, open PR, poll the existing 12-job CI to green.

## 6. Out of scope (restated)

Full 64-round preimage/collision (impossible); in-repo GPU kernels; CUDA/OpenCL/
Vulkan runtime deps; **any** change to `keylab.ec.*`, `keylab.wallet.*`, or M14
broadcasting code.

---

## 7. Decisions needed from owner before coding

1. **Approve the single new dependency** `pulp` (optional `milp` extra) for Phase C
   MILP — **or** direct me to the zero-dep "emit `.lp` only" variant.
2. Confirm **module naming**: new `keylab.sat.mod9` + *extending* existing
   `cryptominisat.py`/`parallel.py`/`backends.py` (rather than a new
   `keylab.sat.solvers`), since the XOR and cube-and-conquer machinery already exists.
3. Confirm the phased **single-branch** sequence above is acceptable (vs. one
   branch/PR per phase).

**Awaiting ack. No code will be written until you approve.**
