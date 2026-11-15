# KeyLab Mathematical Validation Report

**Date:** 2026-11-16
**Curve:** secp256k1, `y² = x³ + 7 (mod p)`.

```
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
```

## Method

Two independent sources of truth were used:

1. **From-scratch reference.** A standalone affine double-and-add
   (`inv = pow(a,-1,p)`; textbook add/double) implemented **without importing any
   of KeyLab's optimized arithmetic**, used as the oracle for differential checks.
2. **KeyLab public API** (`keylab.ec.secp256k1`): `scalar_mult`, `glv_decompose`,
   `wnaf_digits`, and the declared constants `P, N, G, BETA, LAMBDA`.

Randomized trials used a fixed seed (`20261116`) for reproducibility. The harness
is `verify_invariants.py` (run with `python -I`); every row below is an assertion
that must hold, not a printed label.

## Results

| # | Invariant | Method | Trials | Result | Failures |
|---|---|---|---|---|---|
| 1 | `p, n, Gx, Gy` match KeyLab's constants | identity | 4 | **PASS** | 0 |
| 2 | `G` on curve (`y² = x³ + 7 mod p`) | field equality | 1 | **PASS** | 0 |
| 3 | `1·G == G` | double-and-add | 1 | **PASS** | 0 |
| 4 | `2·G == G + G` | double-and-add | 1 | **PASS** | 0 |
| 5 | `n·G == ∞` (both implementations) | double-and-add | 1 | **PASS** | 0 |
| 6 | `scalar_mult(k,G) == reference(k,G)` | differential vs from-scratch | 2,000 | **PASS** | 0 |
| 7 | `(−k mod n)·G == −(k·G)` | differential | 2,000 | **PASS** | 0 |
| 8 | `(k1+k2)·G == k1·G + k2·G` | differential | 2,000 | **PASS** | 0 |
| 9 | `BETA³ ≡ 1 (mod p)` | field | 1 | **PASS** | 0 |
| 10 | `LAMBDA³ ≡ 1 (mod n)` | scalar field | 1 | **PASS** | 0 |
| 11 | `phi(G) = (BETA·x mod p, y) == LAMBDA·G` | endomorphism | 1 | **PASS** | 0 |
| 12 | `k ≡ k1 + LAMBDA·k2 (mod n)` | `glv_decompose` | 10,000 | **PASS** | 0 |
| 13 | GLV components are ~half-width (≤129 bits) | `glv_decompose` | 10,000 | **PASS** | 0 |
| 14 | `Σ wNAF(k)·2ⁱ == k` | `wnaf_digits` | 2,000 | **PASS** | 0 |

**Total: 14/14 invariants pass, 0 failures.** Exit code 0.

## Interpretation

- The GLV endomorphism constants the integration directive warned not to trust
  (`BETA`, `LAMBDA`, and the decomposition basis) are **mathematically correct** on
  this curve: `BETA` is a nontrivial cube root of unity mod `p`, `LAMBDA` is its
  scalar counterpart mod `n`, and `phi(G) = LAMBDA·G` holds. Decomposition is exact
  (`k ≡ k1 + LAMBDA·k2`) with half-width components across 10,000 scalars.
- KeyLab's optimized scalar multiplication (Jacobian + wNAF + GLV + Straus paths,
  exercised through `scalar_mult`) agrees with a fully independent reference over
  2,000 randomized scalars, including negation and additivity — so the classic
  "double but add the original point" scalar-mult bug is **not** present.

## Reproduce

```powershell
# Independent harness (throwaway; lives in the session scratchpad):
python -I verify_invariants.py        # prints the table above; exit 0 on all-pass

# The committed suite that also covers these (and much more):
python -m pytest tests/test_secp256k1*.py tests/test_reference.py -q
```

This report records only what was measured. It makes **no** claim about recovering
a soundly generated private key, inverting SHA-256/RIPEMD-160, or reversing a
HASH160 into a public key — see `SECURITY.md` for the walls.
