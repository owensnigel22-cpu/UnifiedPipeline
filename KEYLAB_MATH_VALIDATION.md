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

**Original harness:** 16/16 check groups passed.

**Extended harness (2026-11-16):** 25/25 check groups passed with both optional
native ECC backends installed (`coincurve`/libsecp256k1 and `fastecdsa`). The
additional checks reuse KeyLab's independent differential framework for
Jacobian addition/doubling, SEC1 parsing/serialization, batch normalization,
Straus MSM, and optional native scalar multiplication. They also check direct
batch inverses against Python's `pow`, BIP-340 official vector 0 and even-y
lifting, and RFC 6979 nonce output against the separate `ecdsa` package. With
optional packages absent, native differential checks print `SKIP`; the harness
still runs its pure-Python checks. The fixed-base Miller-Rabin screens remain
probable-prime screens, not proofs.

The accompanying full default pytest run passed **2,420 tests**, with **9
deselected and 0 skipped**, on Windows/Python 3.14.7 with the optional ECC
backends installed. The default configuration excludes tests marked `slow` and
`live`. This local result is distinct from historical counts and from CI.

The test harness is a deterministic finite check, not a proof of every program
path. Algebraic identities below are established by the cited specifications
and mathematics; running tests checks that selected implementations and inputs
conform. Differential agreement is stronger evidence against implementation
errors but does not itself constitute a formal proof.

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

## Mathematical scope and security boundaries

### RSA

For distinct primes `p` and `q`, textbook RSA defines `n = p*q`,
`phi(n) = (p-1)(q-1)`, and chooses `e` coprime to `phi(n)`; a private exponent
`d` satisfies `e*d ≡ 1 (mod phi(n))`. The primitive operation is
`c = m^e mod n`, with recovery `m = c^d mod n`. KeyLab's RSA routines are
small-input demonstrations and bounded diagnostics, not a general factorizer
or a padding implementation. Its `totient` uses trial division and must not be
used to derive private exponents for production-size RSA moduli.

The implemented recovery examples have explicit preconditions: shared-prime
recovery via a nontrivial GCD requires a reused prime; Fermat factoring is
useful when the factors are close; Wiener applies to specially weak, small
private exponents; and Håstad's broadcast example requires repeated unpadded
messages, pairwise-coprime moduli, sufficient recipients, and an exact
small-root condition. These are attacks on weak key/message conditions, not
methods to recover private material from an ordinary correctly generated,
padded RSA public key. Use the encoding and signature schemes in PKCS #1 (RFC
8017), not textbook RSA, in applications.

### secp256k1 and GLV

SEC 2 specifies secp256k1 over `F_p` with `y^2 = x^3 + 7`, generator `G`, and
prime subgroup order `n`. A private scalar is `d ∈ [1,n-1]`, and the public
point is `Q = dG`. Recovering `d` from `Q` is the elliptic-curve discrete
logarithm problem; a generic square-root algorithm still takes on the order of
`sqrt(n)`, about `2^128` group operations for this curve. A known public point
does not make the discrete logarithm practically recoverable.

The efficiently computable endomorphism is
`phi(x,y) = (beta*x mod p, y)`, with `phi(G) = lambda*G`. GLV chooses lattice
components `k1,k2` satisfying
`d ≡ k1 + lambda*k2 (mod n)` and evaluates two roughly half-size
multiplications. This is an arithmetic speedup; it does not lower generic
ECDLP complexity enough to recover a full-size key. The current harness
checks the identities and finite component bounds; it does not prove the
endomorphism or the decomposition implementation for every input.

### SHA-256, RIPEMD-160, and HASH160

SHA-256 expands each 512-bit block into 64 words, with
`W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16] (mod 2^32)`,
then applies 64 compression rounds and feed-forward. RIPEMD-160 uses two
parallel 80-step lines with distinct message schedules/constants and combines
their final states. Both hash constructions use padded blocks and chaining;
HASH160 is `RIPEMD160(SHA256(serialized_public_key))`.

The repository's CNF/SAT and differential experiments are explicitly bounded,
constrained, truncated, or reduced-round research. A reduced-round collision
or preimage, a SAT model, a length-extension construction, and a full-round
preimage are different claims. A collision is not a preimage for a chosen
target; a preimage for HASH160 is not a public-key/private-key recovery; and
none of these experiments reverses full-round SHA-256 or RIPEMD-160. Generic
idealized work factors are roughly `2^160` for a 160-bit preimage and `2^80`
for a collision, not practical attacks on a secret key.

### Evidence types and references

- **Mathematical results:** the curve/group and algorithm equations follow the
  cited standards and papers, conditional on their stated assumptions.
- **Deterministic tests:** pinned constants, fixed vectors, seeded cases, and
  explicit boundary conditions. Passing a finite test set is not a proof.
- **Probabilistic methods:** the harness's fixed-base Miller-Rabin checks are
  probable-prime screens only; they are not primality certificates.
- **Differential tests:** affine reference arithmetic and KeyLab's existing
  validation framework are independent of optimized Jacobian paths. Optional
  `coincurve` calls exercise libsecp256k1; `fastecdsa` is another native
  multiplication implementation. Agreement does not certify constant-time
  behavior or the whole package.
- **Protocol vectors:** BIP-340 vector 0 is read from the repository's pinned
  vector CSV. The complete BIP-340 vector suite remains in `tests/`.

Authoritative and implementation references:

1. [SEC 2, Recommended Elliptic Curve Domain Parameters, v2.0](https://www.secg.org/sec2-v2.pdf), §2.4.1 (secp256k1); [SEC 1, Elliptic Curve Cryptography, v2.0](https://www.secg.org/sec1-v2.pdf) (point encodings).
2. Gallant, Lambert, Vanstone, [“Faster Point Multiplication on Elliptic Curves with Efficient Endomorphisms”](https://doi.org/10.1007/3-540-44647-8_11), CRYPTO 2001.
3. [BIP-340: Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki), including x-only lifting and test vectors.
4. [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) (deterministic DSA/ECDSA nonces); [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) (RSA cryptographic schemes).
5. [NIST FIPS 180-4, Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) (SHA-256); Dobbertin, Bosselaers, Preneel, [“RIPEMD-160: A strengthened version of RIPEMD”](https://doi.org/10.1007/3-540-60865-6_44), FSE 1996.
6. [Bitcoin Core libsecp256k1](https://github.com/bitcoin-core/secp256k1) (independent native differential backend; not a claim that KeyLab itself is audited or constant-time).

## Reproduce

```powershell
# From a clean source checkout:
python -m pip install -e .
python scripts/verify_invariants.py

# Optional native differential checks:
python -m pip install -e ".[fast,ecc-alt]"
python scripts/verify_invariants.py

# The committed tests that also cover these (and much more):
python -m pytest -q tests/test_secp256k1.py tests/test_ec_reference.py
```

This report records only what was measured. It makes **no** claim about recovering
a soundly generated private key, inverting SHA-256/RIPEMD-160, or reversing a
HASH160 into a public key — see `SECURITY.md` for the walls.
