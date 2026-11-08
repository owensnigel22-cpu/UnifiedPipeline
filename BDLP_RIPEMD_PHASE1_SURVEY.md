# Phase 1 survey & verification — bounded-DLP acceleration + reduced-round RIPEMD-160

Written for: the research lead (you), as the project's evidence record. Research
only — **no KeyLab code changed.** Each claim is tagged **VERIFIED** (checked
against a reference or real execution), **PARTIAL**, **UNVERIFIED**, or
**CONTRADICTED**. Stops after the report; awaits approval before Phase 2.

Date: 2026-11-07.

---

## 0. KeyLab baseline (verify-before-acting) — what already exists here

Mapping the external ideas requires knowing the current baseline. **VERIFIED by
repo inspection on `main` @ `7de416d`:**

- **`keylab.research.ecdlp.kangaroo`** is already the **distinguished-point (DP)
  kangaroo** (landed in M3): a DP table keyed by point, powers-of-two jump set
  `{1,2,…,2^k}` (so **`gcd == 1`** holds — it contains 1), tame herd starting at
  `hi (=U) + offset` (**≥ U**), bounded `max_steps`, checkpoint/resume,
  forward-verified results. 22 always-run tests in `tests/test_kangaroo.py`.
  → **Phase 2 item 1 (DP variant) is essentially already built.**
- **No BSGS** anywhere in the repo (gap).
- **No ECDLP Pollard rho** (only an RSA-factoring rho in `numtheory/rsa.py`).
- **Reduced-round RIPEMD-160 CNF** exists: `keylab.hashes.ripemd_cnf`
  (`RIPEMD160PreimageModel`, native XOR clauses via `keylab.sat.cnf`), plus
  `keylab.hashes.reduced` ("no full-hash preimage attack is implemented") and a
  **parallel SAT dispatcher** `keylab.sat.parallel`. It is a reduced-step
  **preimage** CNF, **not** a differential-characteristic **collision** search.
- **No partial-WIF / wildcard / stride** search exists (gap; Phase 2 item 2 is new).

**Discrepancy to flag:** the master prompt's Context describes "`pollard_kangaroo`
… v70 lineage … jump-set `gcd==1` … tame start beyond the interval … the
selftest's fixed parameters … 100+ random `(L,U,secret)` trials." **There is no
`gcd==1` jump-set *check*, no `selftest`, and no "v70" lineage in this repo.** The
*properties* roughly hold for the M3 DP kangaroo (jump set includes 1 → gcd 1;
tame start ≥ U), but the acceptance criterion "the existing `pollard_kangaroo`
selftest … still pass unmodified" has **no matching selftest here** — the
equivalent is the 22 tests in `tests/test_kangaroo.py`. Please confirm whether
the Context refers to an external/earlier codebase; the baseline above is what
this repo actually contains.

**Acceptance grep (VERIFIED, run 2026-11-07):**
`grep -i "recover.*private.*key.*from.*address|crack.*wallet"` over `src/` → the
only hit is a **negative disclaimer** in `advanced_suite.py:1018` ("never claims
to recover a private key from a hash or address"). No address-to-key or
wallet-cracking code exists. ✅

---

## 1. Kangaroo / Rho resources — idea beyond the baseline + license

| Resource | Specific idea beyond KeyLab's DP kangaroo | License | Tag |
|---|---|---|---|
| **RCKangaroo** (RetiredCoder) | "SOTA method" with **negation-map symmetry**, constant factor **K≈1.15** vs classic 3-kangaroo K≈2.1 (~1.8× fewer ops and ~1.8× less DP storage). GPU (CUDA). | **GPLv3** (stated in fork README; upstream to confirm) | PARTIAL (license from fork, not upstream) |
| **Etarkangaroo** | GPU (CUDA) DP kangaroo for secp256k1. | **UNVERIFIED** (repo/license not located via search) | UNVERIFIED |
| **PawelGorny/Kangaroo** | **Stride search over a partially-known WIF**: known chars fixed, search the unknowns; `-stride`/`-checksum`; uses the WIF **checksum to prune** candidates; 125-bit interval cap; built on VanitySearch engine. | Inherits **GPLv3** from VanitySearch; repo LICENSE not confirmed | PARTIAL |
| **Pollard-Rho-kangaroo (CUDA)** / closest MIT analogue **HareInWeed/gec** | CPU+GPU **Pollard rho *and* lambda** on secp256k1; `gec` is a clean reference. | **gec: MIT** (reusable w/ attribution); the CUDA repo itself UNVERIFIED | PARTIAL |
| **discrete-logarithm-computation** (C) | **BSGS** + small-interval kangaroo + **head-to-head method comparison** (BSGS is O(√n) time *and* memory, exact — useful for small stride spaces). | **UNVERIFIED** (repo not located) | UNVERIFIED |
| **mini_ecdsa (qubd)** | **Parallel Pollard rho** for ECDLP (Python, educational). | **UNVERIFIED** (not located) | UNVERIFIED |

**Net new, in-scope ideas worth porting (re-implemented in KeyLab style, not copied):**
1. **Negation-map symmetry** (from RCKangaroo) — a constant-factor (~1.8×) win on the DP kangaroo. **Does not change the 2^128 wall.** CPU-portable.
2. **Partial-WIF stride search + checksum pruning** (from PawelGorny) — maps to Phase 2 item 2; genuinely absent here.
3. **BSGS** (from discrete-logarithm-computation) — absent here; exact, ideal for the small stride keyspace.
4. **ECDLP Pollard rho** (from gec, MIT) — absent here; already in my M4 plan Part A.

GPU paths (RCKangaroo/Etarkangaroo/CUDA rho) are **out of scope** unless a tested CPU reference exists first (per the hard boundary and no-GPU-without-fallback rule).

---

## 2. RIPEMD-160 SAT resources — encoding idea beyond the existing exporter

KeyLab's `ripemd_cnf` is a reduced-step **preimage** CNF. The SAT resources are
about **differential-characteristic collision** search — a different encoding.

| Resource | Specific SAT/SMT technique | Venue / license | Tag |
|---|---|---|---|
| **shal-sat** | CNF encoding of **step-reduced MD5/SHA-1** for inversion/collision; methodology transferable to RIPEMD-160. | academic/code; **license UNVERIFIED** | UNVERIFIED |
| **"Automating Collision Attacks on RIPEMD-160"** (eprint **2024/350**; the "ToSC 2024" item — actually a TOSC 2023 minor-revision) | Re-implements the **MILP signed-differential-characteristic** search as **SAT/SMT (STP)**; yields SFS collisions on **41/42/43 steps**. This is the core encoding idea. | paper (methodology, no code license to reuse) | VERIFIED (claims, from abstract/eprint) |
| **eprint 2025/1531** (follow-on) | Extends the same SAT/SMT (STP) tool to the **first 44-step** SFS collision. | paper | VERIFIED (claim) |
| **PRS** (eprint **2026/1744**) | Automatic search on the **high-performance parallel SAT solver PRS**; **"only two SAT constraints per step"** (compact encoding); **first *practical* 42-step collision** (3 message pairs). | paper | VERIFIED (claim) |

**Net new, in-scope ideas:** (a) the **signed differential-characteristic SAT
encoding** for *collision* search (2024/350) — distinct from the existing
preimage CNF; (b) the **compact "2 constraints per step"** encoding + **parallel
solver dispatch** (2026/1744) — KeyLab already has `keylab.sat.parallel`, so the
missing piece is the encoding, not the parallelism. All strictly **reduced-round
collision** work, matching the existing scope; **no full-80-round inversion.**

---

## 3. "Las Vegas ECDLP solver" — the verification that gated everything

**Sources:** eprint 2018/134 / arXiv 1703.07544 (Mahalanobis & Mallick, INDOCRYPT
2018); follow-ups arXiv 2005.05039 and "Initial minors — a conjecture…"
(researchgate 341310390). Reference implementation: **C++ using NTL + openMPI**,
Bitbucket **"LasVegas-ECDLP"** (Ansari Abdullah), with a **SageMath script for
input generation only** (not the solver).

**What the method is (VERIFIED from the papers):** non-generic; reduces ECDLP to a
linear-algebra "**Problem L**" (a zero-minor / nullspace search); **Las Vegas**
with claimed success ≈0.6 per kernel. Its practical efficiency depends on the
**unproven "initial minors" conjecture**. Authors' own experiments reach only
**28–44 bits**, "solved using one kernel on average."

**My empirical check (item 4):**
- I could **not run the reference solver**: it is C++/NTL/openMPI (not runnable in
  this Windows env), the Bitbucket repo was not confirmed online, and **no
  independent Python/Sage solver exists** (search returned none). → the *direct*
  empirical run is **UNVERIFIED**.
- I **did** build a toy-curve harness
  (`scratchpad/toy_ecdlp_harness.py`) establishing the bar the solver must beat.
  **Actual output (VERIFIED):**
  ```
  toy curve y^2=x^3+2x+3 over F_65537; group order N=65386 (~2^15), counted in 0.168s
  N factors = {2:1, 32693:1}; using prime-order-32693 (~2^14) subgroup
  BSGS baseline: secret k=4403 recovered=4403 forward_verified=True in 0.5ms
  ```
  A generic method recovers the known discrete log on a known-order toy curve,
  forward-verified, in sub-millisecond time. That is the baseline.

**Verdicts:**
- *"Works as a (non-advantageous) solver on toy curves ≤44 bits"*: **PARTIAL /
  plausible** per the authors' own data, but **UNVERIFIED by me** (reference not
  runnable/obtained).
- *"General / polynomial-time ECDLP solver"*: **CONTRADICTED** — rests on an
  unproven conjecture, only toy-scale evidence, non-generic, not independently
  reproduced, and does **not** break deployed ECC (secp256k1 remains secure; the
  master prompt itself states none of these break full-range ECDLP).
- **DECISION: do NOT integrate** — matching the instruction's own rule ("do not
  integrate it on the strength of its description either way"). No basis to build
  on it.

---

## 4. Recommendation for Phase 2 (for your approval — not started)

Port only the **in-scope, CPU-first, wall-respecting** ideas, each attributed:

1. **BSGS** (`keylab.research.ecdlp.bsgs`) — new; exact small-interval solver.
   Source idea: discrete-logarithm-computation. *(No license to reuse — own impl.)*
2. **Partial-WIF stride search** (`keylab.research.recovery` or similar) — own-key
   recovery with partial info; **hard bound** on the wildcard keyspace (raise, not
   silently run); checksum pruning. Source idea: PawelGorny (GPLv3 — **idea only,
   re-implemented**). Reuses existing `keylab.encoding.wif`.
3. **Negation-map symmetry** on the DP kangaroo — optional ~1.8× constant-factor.
   Source idea: RCKangaroo (GPLv3 — **idea only**). Still 2^128 wall.
4. **ECDLP Pollard rho** — already specified in my **M4 plan Part A**; `gec` (MIT)
   is a clean reference with attribution.
5. **Reduced-round RIPEMD-160 differential-collision SAT encoding** — the signed
   differential-characteristic encoding (eprint 2024/350) and compact 2-constraints
   /step idea (2026/1744), reusing `keylab.sat.parallel`. Round count a **loud,
   required parameter**, never defaulting to full. Methodology only (papers).

**Explicitly NOT ported:** the Las Vegas solver (CONTRADICTED/UNVERIFIED); any GPU/
CUDA/Vulkan backend (no tested hardware; CPU-first rule); any full-80-round RIPEMD
inversion; any general address-to-key recovery. Phase 2 item 1 (DP variant) is
**already done** in M3 — only the optional negation-map symmetry remains.

Each Phase-2 function would get: a one-sentence role+scope-boundary docstring,
input validation (reject out-of-bound keyspaces / malformed WIF templates /
non-integer bounds), and a test **against an independent reference** (not self-
consistency). Attribution recorded in `CREDITS.md`.

**Awaiting your review of these findings before any Phase 2 code.**

---

### Sources
- [eprint 2018/134 — A Las Vegas algorithm to solve the ECDLP](https://eprint.iacr.org/2018/134.pdf) · [arXiv 1703.07544](https://arxiv.org/pdf/1703.07544) · [arXiv 2005.05039 — A new method…](https://arxiv.org/html/2005.05039v3) · [Initial minors conjecture](https://www.researchgate.net/publication/341310390)
- [RCKangaroo fork README (GPLv3, SOTA K=1.15)](https://github.com/WanderingPhilosopher/RCKangaroo-Fork) · [RCKangaroo (upstream)](https://relatedrepos.com/gh/RetiredC/RCKangaroo)
- [PawelGorny/Kangaroo (stride, checksum, 125-bit)](https://github.com/PawelGorny/Kangaroo)
- [HareInWeed/gec — MIT, Pollard rho+lambda secp256k1 CUDA](https://github.com/HareInWeed/gec)
- [eprint 2024/350 — Automating Collision Attacks on RIPEMD-160](https://eprint.iacr.org/2024/350) · [eprint 2025/1531 — Improved SFS Collision (44-step, STP)](https://eprint.iacr.org/2025/1531.pdf) · [eprint 2026/1744 — Improved Collision Attack (PRS, practical 42-step)](https://eprint.iacr.org/2026/1744.pdf)
