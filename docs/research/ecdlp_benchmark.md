# ECDLP measurement harness (`scripts/benchmark_ecdlp.py`)

Teaching/research only. KeyLab is not production wallet software; see
[SECURITY.md](../../SECURITY.md). This harness *measures the ECDLP wall* on
secp256k1 — it does not and cannot solve a full-strength key.

## Tooling

The repo's only full-group-usable ECDLP primitive is `pollard_kangaroo`. There is
**no** ECDLP Pollard-rho (the `pollard_rho` in `keylab/numtheory/rsa.py` is RSA
integer factorization — a different algorithm for a different problem), and no
toy curve. `pollard_kangaroo(Q, 0, N-1)` over the full group **is** the full-group
attempt: the same kangaroo walk, with the full group as the interval, and
`O(2·√n) ≈ 2^129` expected hops — the same asymptotics rho would have. No new
attack code was written; see `SEC_STATE_JOURNAL.md` (tooling decision) and the
`max_steps` budget fix that made a bounded full-group run possible.

## What "attempt" means

Three attempt modes, all on `pollard_kangaroo`:

- **attain-small / attain-medium** — recover a *known* small `k` over
  `[0, 2^20)` / `[0, 2^24)`. These complete; they calibrate the step rate and the
  kangaroo constant.
- **bounded-full** — run over `[0, N-1]` for `--budget-seconds`. This is a real
  full-group attempt. It will **not** find a solution. It produces a
  *measurement of state reached* (fraction of expected work, as `2^-k`) and stops.
- **walkback** — reverse the double-and-add ladder with
  `backward_traverse_to_identity` for a small `--depth` (≤ 18); `2^depth` leaves,
  i.e. brute force, capped because the cost explodes.

**A bounded attempt produces a measurement, not progress.** A 60s bounded-full
run reaches ~`2^-109` of expected work — a quantified wall, not a slowdown and
not partial progress.

## Measured (local, coincurve backend, 2026-11-06)

| Run | Steps/leaves | Rate | Wall | Result |
|---|---|---|---|---|
| attain `[0,2^20)` | 8,749 hops | ~9.5k hops/s | 0.9 s | found |
| attain `[0,2^24)` | 39,699 hops | — | ~4 s | found |
| walkback depth 8 | 229 leaves | — | 5.6 s | k recovered |
| walkback depth 12 | 4,005 leaves | — | 59.9 s | k recovered |
| **bounded-full 60 s** | **1,240,000 hops** | **~20.5k hops/s** | 60.3 s | **no solution; 2^-109 of expected work** |

Fitted kangaroo constant from the two attain anchors: `steps ≈ 9.1 · √width`
(above the theoretical `2·√width` because of retries and the wild-walk overhead).

## Extrapolation (from the measured constant)

Expected hops `≈ 9.1 · √width`:

| interval width | expected hops |
|---|---|
| 2^32 | ~2^19 |
| 2^40 | ~2^23 |
| 2^48 | ~2^27 |
| 2^64 | ~2^35 |
| 2^128 | ~2^67 |
| **2^256 (full group)** | **~2^131 (≈ 2·√n = 2^129 order)** |

## The wall

The full-group ECDLP needs on the order of `2^129` group operations. At an
optimistic `1e7` ops/sec that is `~2^129 / 1e7 / (3.15e7 s/yr) ≈ 10^25` years —
far longer than the age of the universe. Even Shor's quantum algorithm would
require on the order of `10^12` physical qubits at error rates not achievable
today. **This is a wall, not a slowdown.** No budget, no number of walkers, and
no amount of patience changes the exponent.

## Misuse

Pointing this harness at a public key whose private key you do not own is
**theft** in most jurisdictions — **and it will achieve nothing**: the full-group
attempt reaches `~2^-100` of the work needed and stops. The tool's only purpose
is to *measure and teach the wall*. Do not point it at anyone's wallet.

## Honest framing (canonical)

> `pollard_kangaroo` over `[0, n-1]` IS the full-group ECDLP attempt. The
> algorithm is the same kangaroo walk used for bounded intervals; passing the
> full group as the interval is what makes it a full-group attempt. A 60s
> budget-bounded run reaches approximately `2^-109` of expected work — a wall,
> not a slowdown. This is not partial progress; it is a quantified measurement of
> state reached before stopping.
