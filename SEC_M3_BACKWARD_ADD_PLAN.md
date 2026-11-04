# M3 — Backward double-and-add + chained-halving shortcut — Implementation Plan

**Status:** ACKED (kangaroo-only ECDLP benchmark design). Separate from M2a
(crypto_policy + `_ct.py`, in PR #26) and M2b (CBOM, parked). **`SECURITY.md` is
NOT touched in this PR** (the posture amendment is sequenced *after* M3 lands —
see §8).

**State journal:** milestone/iteration state (incl. the ECDLP tooling decision
and every extrapolated/impossible wall) is recorded in
[SEC_STATE_JOURNAL.md](SEC_STATE_JOURNAL.md).

---

## 0. Verify-before-acting: most of M3 already exists

A repo inspection shows the bulk of what the reference proposes is **already
implemented and tested** in `keylab.research.ecdlp`. This plan therefore scopes
only the genuinely new work and **will not regenerate** correct existing code.

**Already present in `src/keylab/research/ecdlp/backward_double_add.py`** (exported
from `keylab.research.ecdlp.__all__`):

| Function | Status | Notes |
|---|---|---|
| `point_halve(Q)` | ✅ exists | **delegates** to `keylab.ec.halving.halve_point` (HALVING POLICY honored; no duplication). `None → None`. |
| `backward_step(Q)` | ✅ exists | returns `(halve(Q), halve(Q−G))`. |
| `backward_traverse_to_identity(Q, max_depth)` | ✅ exists | BFS deque of `(pt, depth, bits)`; `bits | (1<<depth)` on branch 1; **returns a report dict** (see §5 deviation). |
| `recover_via_backward(Q, max_depth)` | ✅ exists | returns `{k, depth, leaves_explored, time_sec, found, method}`, forward-verified. |
| `cost_table()` | ✅ exists | **already a sorted `list[tuple[int,int,str]]`** for k∈{8,16,20,24,32,64,128,256} — not the reference's set/dict bug. |
| `HALF_SCALAR`, `MAX_DEPTH=64` | ✅ exists | re-exported. |

**Already present elsewhere:**
- `keylab.ec.halving` (authoritative halving): `HALF_SCALAR`, `halve_point`,
  `halving_chain(point, steps) -> list[...]` (returns successive halves Q/2,
  Q/4, …, i.e. O(steps), all intermediates).
- `tests/test_backward_double_add.py` — **11 tests** (half-scalar identity,
  exact halving, identity, two-branches-valid-and-distinct, recovery at
  bit_length, failure below bit_length, leaves bound, max_depth validation,
  cost-table wall, forward verification).
- `scripts/demo_backward_wall.py` — **exists** (halving, branches, recovery at
  depths 6/8/10/12, kangaroo, wall/cost-table).

**Genuinely absent (the real M3 work):** `halve_m`; `docs/research/backward_double_add.md`;
a `halve_m` demo + a `--max-depth` CLI flag/guard + an explicit honest-wall
calc in the demo; and a handful of new tests (§5).

---

## 1. Module additions (signatures)

Only **`halve_m`** is a new function. Proposed placement: a small new module
`src/keylab/research/ecdlp/halving_shortcut.py`, re-exported from
`keylab.research.ecdlp`, to keep the O(1) shortcut *physically separate* from the
O(2^k) branching traversal (structurally reinforcing "do not use `halve_m` to
optimize the traversal").

```python
# keylab/research/ecdlp/halving_shortcut.py
from keylab.ec.halving import HALF_SCALAR          # authoritative 2^-1 mod N
from keylab.ec.secp256k1 import N, Point, scalar_mult

def halve_m(point: Point, m: int) -> Point:
    """Return the point halved m times, as ONE scalar multiplication.

    halve_m(Q, m) == (2^-m mod N) * Q == pow(HALF_SCALAR, m, N) * Q. Chained
    halving of a single point collapses to this O(1) scalar mul, so
    halve_m(Q, 2**20) returns in milliseconds, not the ~17 minutes an actual
    2**20-long chain of point halvings would take.

    This shortcut is valid ONLY for repeatedly halving one point. It does NOT
    apply to keylab.research.ecdlp.backward_double_add: the backward traversal
    branches (halve(Q) vs halve(Q-G)) and the branches diverge, so there is no
    single-scalar collapse. Do not use halve_m to 'optimize' the traversal.
    """
```

- `halve_m` **reuses `HALF_SCALAR`** (the authoritative constant from
  `keylab.ec.halving`); it introduces no new halving arithmetic, consistent with
  the HALVING POLICY. `m` must be a non-negative int (guard + `ValueError`).
- No change to the existing `backward_double_add.py` functions is required; the
  only edit there is **none** unless review wants the docstring to cross-link
  `halve_m`'s "not for traversal" warning (optional, non-behavioral).
- `keylab.research.ecdlp.__init__` gains `halve_m` in its imports and `__all__`.
  Underscore-prefixed helpers remain private (correction #8).

## 2. Docs — `docs/research/backward_double_add.md` (new)

States, in order: (1) what point halving is and why `(N+1)/2` is the exact modular
inverse of 2 on the odd prime-order group; (2) the two-branch structure (bit 0 →
`halve(Q)`, bit 1 → `halve(Q−G)`), both valid points, structurally
indistinguishable; (3) BFS reaches ∞ at exactly one leaf per k, forward-verified;
(4) cost is `2^k` leaves = brute force (the ECDLP, no wall-lowering); (5) **do not
use `halve_m` to optimize the traversal** — chained halving ≠ branching halving;
(6) the kangaroo (`keylab.research.ecdlp.kangaroo`) is `O(2^(k/2))`, the correct
tool for a *bounded* interval; (7) the 2^k vs 2^(k/2) wall table for
8/16/24/32/64/128/256 bits. No wall-lowering claim anywhere.

## 3. Demo — augment existing `scripts/demo_backward_wall.py`

The demo exists; **augment, do not rewrite**. Add:
- `demo_halve_m()` — show `halve_m(Q, m)` equals an actual m-fold halving for
  small m, and that `halve_m(Q, 2**20)` returns in <100 ms (the O(1) collapse).
- A `--max-depth` CLI flag (argparse), **default ≤ 12 (CI), cap ≤ 16 for local**,
  and an explicit guard raising `ValueError` for `max_depth > 18` with a
  memory/time-explosion message (correction #3). Recovery/branch demos respect it.
- `demo_honest_wall()` — print 2^256 at 1e6 leaf-evals/sec as years, labelled
  honestly (no claim the wall is lowered).
- Keep the existing halving/branches/recovery/kangaroo/wall sections.
- **Do not** run a depth-20 backward traversal or `halve_m`+traversal in one
  function (corrections #4, #5). The 2^20 stress belongs to `halve_m` only.

## 4. Corrections applied — and where the reference conflicts with existing code

- **#1 Namespace** → `keylab.research.ecdlp` (already correct; no new top-level
  namespace). `point_halve` already delegates to `keylab.ec.halving`.
- **#2 `cost_table` type** → already a sorted `list[tuple]`; nothing to fix.
- **#3 Demo depth cap / >18 guard** → to be added to the demo (new).
- **#4/#5 Keep `halve_m` and the traversal separate; 2^20 belongs to `halve_m`**
  → enforced by placing `halve_m` in its own module + docstrings + the slow test
  targeting `halve_m` (never a depth-20 traversal).
- **#6 Bit accumulation `| (1<<depth)` LSB-first** → already implemented; a new
  explicit `k=5` bit-walk test is added (§5).
- **#7 `point_halve(None) → None`** → holds (delegates to `halve_point`); a
  comment already notes BFS catches the `None` case upstream.
- **#8 No `_helpers` exports** → underscore helpers stay private.
- **`add_affine` → `_add_affine` bug (reference):** **N/A in-repo.** KeyLab uses
  the real `keylab.ec.secp256k1.point_add_affine`; there is no `add_affine`/
  `_add_affine` symbol. The existing test uses a local `_double` helper built on
  `point_add_affine`. Nothing to rename.

## 5. Test plan — extend `tests/test_backward_double_add.py` (do not create a parallel file)

**Deviation from the reference (flagged):** the reference says tests live in
`tests/research/test_backward_double_add.py`. The repo already has
`tests/test_backward_double_add.py` (11 passing tests). Per "do not regenerate /
consolidate," M3 **extends the existing file** rather than create a parallel one
(`pytest testpaths=['tests']` collects both, so a second file would duplicate).
If you prefer the `tests/research/` path, say so and I will move the file.

New tests to add (existing 11 stay untouched):
- `halve_m` correctness: `2**m * halve_m(Q, m) == Q` (via the existing Jacobian
  double helper `_double`) for several small m and random Q; `halve_m(Q, m)`
  equals m sequential `point_halve` calls; `halve_m(Q, 0) == Q`; `m<0` raises.
- **`halve_m` fast-path:** `halve_m(Q, 2**20)` returns a valid `Point` in
  **< 100 ms**, in a `@pytest.mark.slow` test **opt-in via `RUN_SLOW_HALVING`
  env var** (so CI isn't slowed unless requested). Proves the O(1) collapse
  vs the exponential chain.
- **`k=5` LSB bit-walk** (correction #6): recover `5·G` at `max_depth=3` and
  assert the recovered `bits == 5`, i.e. the branch sequence [1,0,1] (LSB-first)
  accumulates to 5.
- **Recovery breadth:** `recover_via_backward(k·G, depth=bit_length(k))` returns
  `k` for **≥ 20 random k per depth ∈ {4,6,8,10,12}**, deterministic (fixed
  `random.Random` seeds). (`depth<bit_length(k)` → `found=False` already tested.)
- **Demo guard:** importing the demo's traversal entry with `max_depth=19` (or
  the `--max-depth 19` path) raises `ValueError`.

**`backward_traverse_to_identity` return type — deviation (flagged, recommend
keep):** the reference specifies a `(k, depth, leaves, elapsed)` tuple; the repo
function returns a **report dict** that already carries `k`/`depth`/
`leaves_explored`/`time_sec`/`found`/`method`, is consumed by
`recover_via_backward`, and is covered by existing tests. Changing it to a bare
tuple would regress `recover_via_backward` and the 11 existing tests for no
behavioral gain. **Recommendation: keep the dict** (it is a superset of the
tuple). Confirm at ack if you want the tuple instead.

## 6. Exit criteria (numbers)

- `keylab.research.ecdlp` gains `halve_m` (new); `point_halve`, `backward_step`,
  `backward_traverse_to_identity`, `recover_via_backward`, `cost_table` remain
  (already present), each with a docstring stating what it does and cannot do
  (no wall-lowering claim).
- `halve_m(Q, 2**20)` returns a valid `Point` in **< 100 ms** (opt-in
  `RUN_SLOW_HALVING` slow test).
- `recover_via_backward(k·G, depth=bit_length(k)) == k` for **≥ 20 random k per
  depth ∈ {4,6,8,10,12}**, deterministic.
- Two-branch test green (both branches satisfy `2·h0=Q`, `2·h1+G=Q`); `k=5`
  bit-walk asserts `bits==5`.
- Demo runs in **< 30 s total for depth ≤ 12**, prints the cost table, and caps
  at `--max-depth ≤ 16` with a `ValueError` for `> 18`.
- `cost_table()` is a sorted `list[(k_bits, leaves, label)]` (already true;
  regression-guarded).
- Ruff/mypy/pytest green; **12 CI jobs green**; `fuzz-extended` dispatches (if
  any) reported separately; **no regression** in the existing 11
  `test_backward_double_add.py` tests or other `keylab.research.ecdlp` tests.
- `SECURITY.md` **not touched** (§8).

## 7. Risks

- **Regenerating existing code** — avoided by §0; M3 adds `halve_m` + docs +
  demo augmentation + new tests only.
- **HALVING POLICY** — `halve_m` reuses the authoritative `HALF_SCALAR`; it does
  not reintroduce halving arithmetic. `point_halve` already delegates.
- **Demo cost blow-up** — hard `>18` `ValueError` guard + CI depth ≤ 12.
- **Slow test in CI** — the 2^20 `halve_m` timing is opt-in (`RUN_SLOW_HALVING`),
  off by default.

## 8. SECURITY.md and milestone independence (confirmations)

- **`SECURITY.md` is NOT touched in the M3 PR.** Per the agreed sequencing, the
  posture amendment (describing `halve_m`/backward double-and-add, confirming the
  `keylab.research.*` namespace) lands **after** M3 merges, so the text is
  accurate at its commit; the CBOM section still waits for M2b.
- **No conflict with M2a** (`crypto_policy.py`, `_ct.py`, HKDF docs) — disjoint
  files; M3 touches only `keylab.research.ecdlp`, its tests, a research doc, and
  the demo.
- **No conflict with M2b** (CBOM) — M3 adds no dependency and no CI job; the
  12-job CI is unchanged.

---

**Open items for your ack:**
1. Keep `backward_traverse_to_identity` returning the **dict** (recommended) or
   switch to the `(k, depth, leaves, elapsed)` tuple?
2. Put new tests in the **existing `tests/test_backward_double_add.py`**
   (recommended) or create `tests/research/test_backward_double_add.py`?
3. `halve_m` in a **new `halving_shortcut.py`** module (recommended, keeps it
   away from the traversal) or appended to `backward_double_add.py`?

Stop after this plan for ack. No code until then.

READY FOR M3 PLAN REVIEW
