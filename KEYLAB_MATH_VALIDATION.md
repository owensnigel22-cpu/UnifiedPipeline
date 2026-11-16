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

1. **Committed from-scratch reference.** [`scripts/verify_invariants.py`](scripts/verify_invariants.py)
   implements affine addition and double-and-add using pinned secp256k1 parameters.
   The oracle does not call KeyLab's point or scalar arithmetic.
2. **KeyLab public API** (`keylab.ec.secp256k1`): `scalar_mult`, `glv_decompose`,
   `wnaf_digits`, `point_add_affine`, and `multi_scalar_mult`.

Randomized trials use the fixed seed `20261116`. The harness uses fixed-base
Miller-Rabin checks as probable-prime screens for the published `P` and `N`;
these checks are not primality certificates. Every other row is asserted against
the pinned constants or independent affine reference.

## Results

| # | Invariant | Method | Trials | Result |
|---|---|---|---:|---|
| 1 | Standard `P` value and probable-prime screen | constant + 16 Miller-Rabin bases | 1 | **PASS** |
| 2 | Standard `N` value and probable-prime screen | constant + 16 Miller-Rabin bases | 1 | **PASS** |
| 3 | Standard `G` and `y² = x³ + 7 (mod P)` | pinned coordinates + field equation | 1 | **PASS** |
| 4 | `G` has order `N` | independent affine `N·G` and API check | 1 | **PASS** |
| 5 | `BETA³ ≡ 1 (mod P)` and `BETA ≠ 1` | field arithmetic | 1 | **PASS** |
| 6 | `LAMBDA³ ≡ 1 (mod N)` and `LAMBDA ≠ 1` | scalar-field arithmetic | 1 | **PASS** |
| 7 | `phi(G) = (BETA·x mod P, y) = LAMBDA·G` | independent affine multiplication | 1 | **PASS** |
| 8 | `k ≡ k1 + LAMBDA·k2 (mod N)` | `glv_decompose` | 10,005 | **PASS** |
| 9 | GLV components are at most 129 bits | `glv_decompose` | 10,005 | **PASS** |
| 10 | Python scalar multiplication equals affine reference | differential | 2,006 | **PASS** |
| 11 | Negative inputs reject; modular inverse points agree | API + affine reference | 2,000 | **PASS** |
| 12 | Scalar addition equals independent point addition | differential | 256 | **PASS** |
| 13 | Width-5 wNAF reconstructs the scalar with valid digits | reconstruction | 2,004 | **PASS** |
| 14 | GLV scalar multiplication equals affine reference | differential | 258 | **PASS** |
| 15 | Affine point addition equals independent reference | differential | 128 | **PASS** |
| 16 | Straus/Shamir MSM equals independent affine sum | differential | 32 | **PASS** |

**Total: 16/16 check groups pass.** Individual trial counts are printed by the
script's labels. The primality checks are probable-prime screens, not proofs.

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
# From a clean source checkout:
python -m pip install -e .
python scripts/verify_invariants.py

# The committed tests that also cover these (and much more):
python -m pytest -q tests/test_secp256k1.py tests/test_ec_reference.py
```

This report records only what was measured. It makes **no** claim about recovering
a soundly generated private key, inverting SHA-256/RIPEMD-160, or reversing a
HASH160 into a public key — see `SECURITY.md` for the walls.
