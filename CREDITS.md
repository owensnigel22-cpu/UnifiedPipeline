# Credits — external ideas re-implemented in KeyLab

KeyLab contains **no copied third-party source**. The items below are *algorithmic
ideas* that were studied and re-implemented in KeyLab's own code and style; each
is attributed to the resource and license it came from. Nothing here is a port of
another project's files.

## Bounded-DLP / ECDLP research (`keylab.research.ecdlp`, `keylab.research.wif_recovery`)

- **Baby-step giant-step (BSGS)** — `keylab.research.ecdlp.bsgs`. Classic
  algorithm (Shanks, 1971); re-implemented from the standard description, not
  from the license-UNVERIFIED `discrete-logarithm-computation` repository.
- **Pollard's rho for the DLP** — `keylab.research.ecdlp.rho`. Classic algorithm
  (Pollard, 1978). The rho+lambda pairing and secp256k1 framing were informed by
  the **MIT-licensed** `gec` library (HareInWeed/gec) — idea only, re-implemented;
  MIT permits reuse with attribution.
- **Negation-map symmetry** — `keylab.research.ecdlp.negation_map`. Idea from
  **RCKangaroo** (RetiredCoder), **GPLv3** — *idea only*, re-implemented in
  KeyLab's style (no GPLv3 source used). Measured to give ~1.0× here (see the
  module docstring for the honest assessment); not the upstream ~1.8×.
- **Partial-WIF stride search** — `keylab.research.wif_recovery`. Idea from
  **PawelGorny's Kangaroo fork / WifSolverCuda**, **GPLv3** — *idea only*,
  re-implemented. Base58Check checksum pruning over a bounded wildcard keyspace.

## Reduced-round RIPEMD-160 collision SAT encoding (`keylab.hashes.ripemd_cnf`)

- **Differential-characteristic collision encoding** — the
  `ripemd160_collision_cnf` model was informed by the methodology in IACR ePrint
  **2024/350** ("Automating Collision Attacks on RIPEMD-160"), **2025/1531**, and
  **2026/1744** ("PRS"): signed differential characteristics and compact
  constraint density. Only the *encoding technique* was studied; no solver binary
  or paper source code was copied. The encoding integrates with KeyLab's existing
  native-XOR CNF exporter (`keylab.sat.cnf`, `keylab.hashes.reduced`). Reduced-round
  only; the round count is always an explicit, required parameter.

## Not integrated (verified non-viable in Phase 1)

- **"Las Vegas Algorithm ECDLP solver"** (eprint 2018/134 and follow-ups) —
  deliberately **not** integrated. No runnable solver exists (C++/NTL/openMPI
  reference with a SageMath input generator only), the method is non-generic and
  depends on the unproven "initial minors" conjecture, and published experiments
  cap at 28–44 bits. See `BDLP_RIPEMD_PHASE1_SURVEY.md`.
