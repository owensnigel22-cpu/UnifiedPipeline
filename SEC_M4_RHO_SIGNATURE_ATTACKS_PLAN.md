# SEC_M4 — Pollard-rho (ECDLP) + signature attacks (PLAN)

Status: **PLAN ONLY — no code.** Per the standing rule (plan doc → ack → code →
gates → merge, do not combine), this scopes the work and waits for ack. Nothing
here changes behaviour.

Sequence position: after M3 (merged) and the SECURITY.md posture amendment
(PR #28, open). M4 lands before M5/M6/M7.

---

## 0. Honest framing (up front)

M4 adds two **measurement/teaching** capabilities, neither of which dents a real
key:

1. **Pollard-rho for the ECDLP** — the canonical full-group discrete-log method.
   It is **not faster** than M3's kangaroo: identical `O(√n) ≈ 2**128`
   asymptotics for the full group. Rho is the natural *full-group* companion to
   kangaroo's *bounded-interval* framing; adding it lets the harness measure the
   same wall two independent ways. A 60-second rho run reaches ~`2**-109` of the
   work and stops — a wall, not a slowdown.
2. **Signature attacks** — key recovery that is only possible when the caller
   **supplies the leaked data the maths requires** (a reused nonce, or enough
   signatures with a specified nonce-bias/leakage model). Given *correct* ECDSA
   with unique uniform nonces, none of this recovers anything. These reproduce
   known results (nonce reuse; the Hidden Number Problem via lattice reduction);
   they are not novel and not a threat to correctly-generated keys.

Every recovered scalar is forward-verified (`d*G == P`) before it is reported.
None of this is selected by `scalar_mult`, signing, or verification.

---

## 1. Verify-before-acting: what already exists (do NOT regenerate)

| Capability | Where | Status |
|---|---|---|
| Bounded-interval ECDLP (kangaroo, DP variant) | `keylab.research.ecdlp.kangaroo` | ✅ M3 |
| Backward double-and-add / `halve_m` | `keylab.research.ecdlp.backward_double_add`, `halving_shortcut` | ✅ M3 |
| ECDLP measurement harness + journal | `scripts/benchmark_ecdlp.py`, `SEC_STATE_JOURNAL.md` | ✅ M3 |
| HNP lattice primitives (LLL, Babai, Gram-Schmidt) over a **toy q** | `keylab.research.hnp_lattice` | ✅ exists (`research/hnp-lattice`) |
| Nonce-reuse **trace** (demo, hard-coded messages) | `advanced_suite.ecdsa_nonce_reuse_attack_trace` | ✅ exists (teaching trace) |
| ECDSA public-key recovery from `(r,s)` | `keylab.ec.ecdsa_recovery.recover_public_keys_from_signature` | ✅ exists |
| `docs/SECURITY_POSITIONING.md` constraints for `keylab.research.ecdsa` | docs | ✅ exists (the governing spec) |

**Genuinely absent (the real M4 work):**
- A **Pollard-rho ECDLP solver** (`keylab.numtheory.rsa` has a rho for *integer
  factorisation* — a different algorithm for a different problem; there is no
  ECDLP rho).
- A **`keylab.research.ecdsa` package** that turns the nonce-reuse trace into a
  reusable, forward-verified recovery function and lifts HNP from the toy modulus
  to secp256k1's `N` with a stated leakage model.

M4 reuses the existing LLL/Babai in `hnp_lattice` and the existing
`recover_public_keys_from_signature`; it does not reimplement lattice reduction
or ECDSA.

---

## 2. Part A — Pollard-rho for the ECDLP

### Module
`src/keylab/research/ecdlp/rho.py`, re-exported from `keylab.research.ecdlp`.

### Signature (proposed)
```python
def pollard_rho(
    point: Point, lo: int, hi: int, *,
    max_steps: int | None = None,
    return_state: bool = False,
    progress_callback: Callable[[int], None] | None = None,
) -> int | None | RhoResult: ...
```
- Distinguished-point rho with the standard 3-partition additive walk
  (`a_i*G + b_i*P`), tracking `(a, b)` so a collision `a1*G+b1*P == a2*G+b2*P`
  yields `k = (a1-a2) / (b2-b1) mod N` (guarding the non-invertible case by
  perturbing the walk — same retry discipline as kangaroo).
- `max_steps` bounds **total** hops exactly (same bounded-measurement contract
  as `pollard_kangaroo`): a full-group call well under `~√n` returns `None` after
  spending exactly `max_steps`. Mirrors the kangaroo budget semantics so the two
  share a harness.
- Full-group attempt = `pollard_rho(P, 0, N-1)`; forward-verified result.
- `RhoResult` dataclass parallel to `KangarooResult`: `solution`,
  `spent_steps`, `distinguished_points`, `collisions`, `elapsed_sec`,
  `memory_peak_bytes`.

### Harness
Add a `rho` mode to `scripts/benchmark_ecdlp.py` reusing the existing record
schema, budget guards, and JSON output, so rho and kangaroo measure the same
wall side by side. Journal entry records the measured rho wall.

### Tests (always-run, zero-skip-safe)
- Recovers small `k` (bounded interval) and at endpoints; forward-verified.
- `max_steps` bounds total hops (no hang on the full group); exact spend.
- Full-group budget run returns `None` at exactly `max_steps`.
- Collision maths validated on a known small instance.
- Non-invertible `(b2-b1)` path handled (does not crash; retries).

---

## 3. Part B — signature attacks: `keylab.research.ecdsa`

Governed by `docs/SECURITY_POSITIONING.md` (prohibited postures enforced: no
key-search, no network, no real-wallet inputs, no "key recovered/exploitable"
claims from heuristics, private scalars never printed by default).

### Module layout
```
src/keylab/research/ecdsa/
  __init__.py
  nonce_reuse.py     recover d from two signatures sharing a nonce k
  hnp.py             biased/partial-nonce recovery via the Hidden Number Problem
  report.py          structured, forward-verified reports (no bare key prints)
```

### B1 — nonce reuse (`nonce_reuse.py`)
Promote the `advanced_suite` trace into a reusable function:
```python
def recover_private_key_from_nonce_reuse(
    r: int, s1: int, z1: int, s2: int, z2: int,
) -> int | None: ...   # k = (z1 - z2)/(s1 - s2); d = (s1*k - z1)/r ; forward-verified
```
- Pure arithmetic on **caller-supplied** signature components; recovers `d` only
  when two signatures genuinely reused `k` (same `r`). Returns `None` (not a
  wrong guess) if the inputs are inconsistent or `d*G` does not verify.
- The existing `ecdsa_nonce_reuse_attack_trace` stays as the teaching trace and
  is refactored to call this function (single source of truth).

### B2 — Hidden Number Problem (`hnp.py`)
Lift HNP from `hnp_lattice`'s toy `q` to secp256k1 `N`, with an **explicit
leakage model** (e.g. known MSBs/LSBs of each nonce), building the CVP/SVP
lattice and solving via the **existing** `_lll_reduce` / `_babai_nearest_plane`:
```python
def recover_private_key_from_biased_nonces(
    signatures: Sequence[Signature], leakage: NonceLeakage,
) -> HNPResult: ...
```
- Requires *sufficient* signatures for the stated bias (documented bound, e.g.
  ~`ceil(N.bit_length() / known_bits) + slack`); below that it reports
  "insufficient" — never a false positive.
- Result is forward-verified; the report states the leakage model and that
  statistical association alone is not proof (per the positioning doc).

### Tests (always-run)
- Nonce reuse: synthetic signer reuses `k`, recovery returns the true `d`
  (forward-verified); inconsistent inputs → `None`.
- HNP: synthetic signer leaks the top `b` bits of each nonce; with enough
  signatures recovery returns the true `d`; with too few → "insufficient", no
  false key.
- Positioning guards: default report never prints the private scalar; a value is
  shown only behind an explicit flag (mirrors the `--show-private` convention).
- Reuse of `hnp_lattice` LLL/Babai verified (no reimplementation).

---

## 4. CLI (optional, if it fits the gate budget)
A `keylab-research` subcommand surface, or extend `scripts/benchmark_ecdlp.py`
(rho) and add a small `scripts/sig_attacks_demo.py` for the nonce-reuse / HNP
demos on **synthetic** keys only. No real-wallet inputs. Decide at code time;
the library is the substance.

## 5. Exit criteria (numbers)
- `pollard_rho` recovers a known `k` in a 2^20 interval and at endpoints;
  forward-verified; full-group `max_steps=50_000` run returns `None` at exactly
  50,000 hops.
- Rho and kangaroo measured side by side in the harness; journal records the rho
  wall (expected ~same `2**-10x` fraction at a 60s budget).
- Nonce-reuse recovery returns the exact `d` on a synthetic reuse; `None` on
  inconsistent inputs.
- HNP recovers the exact `d` on a synthetic known-MSB instance with the
  documented signature count; reports "insufficient" below it (no false key).
- All 12 CI jobs green; zero new skips; no new runtime dependency (stdlib
  `fractions` for lattice rationals, already used by `hnp_lattice`).

## 6. Risks
- **Rho non-invertible step** (`b2 == b1`): handled by perturb-and-retry, like
  kangaroo; bounded by `max_steps`.
- **HNP numerical robustness**: reuse the proven `hnp_lattice` reduction; keep
  exact integer/Fraction arithmetic (no floats).
- **Test runtime**: all recoveries use small/synthetic instances; nothing
  approaches the wall in CI, so no `@slow`/`@skipif` needed (zero-skip gate).
- **Misuse framing**: every entry point and report repeats the positioning-doc
  disclaimers; no interface accepts real wallet/WIF/seed inputs.

## 7. Out of scope
Attacks on correctly-generated signatures; fault/side-channel *collection* (no
timing/EM capture); network or dataset download; any "key recovered/exploitable"
claim not backed by a forward-verified `d*G == P`; production use. Ethereum,
Taproot/Schnorr nonce attacks, and batch/fast-ECC optimisations are later
milestones (M7/M8), not M4.

## 8. Standing rules honored
- Plan doc first; code only after ack. Do not combine milestones.
- No new dependencies; reuse `hnp_lattice` LLL/Babai and `ecdsa_recovery`.
- No `@skipif`, no `@slow`, no CI changes; all tests always-run.
- `keylab.research.*` namespace only; governed by `docs/SECURITY_POSITIONING.md`.
- SECURITY.md: the research-ECDSA posture is already covered by the positioning
  doc; if M4 needs a SECURITY.md line, it is proposed as text for ack first (not
  edited silently), same discipline as PR #28.
