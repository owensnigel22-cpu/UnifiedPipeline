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
batch inverses against Python's `pow`, all 19 BIP-340 official vectors and
even-y lifting, the full 19-vector BIP-340 differential against Coincurve, and
RFC 6979 nonce output against the separate `ecdsa` package. With optional
packages absent, native differential checks print `SKIP`; the harness still
runs its pure-Python checks. The fixed-base Miller-Rabin screens remain
probable-prime screens, not proofs.

The full default pytest run after the cross-module audit passed **2,470 tests**, with **9
deselected and 0 skipped**, on Windows/Python 3.14.7 with the optional ECC
backends installed. The default configuration excludes tests marked `slow` and
`live`. This local result is distinct from historical counts and from CI.

### BIP-340/libsecp256k1 differential validation

BIP-340 verification first requires `0 <= r < p`, `0 <= s < n`, and a public
x-coordinate that lifts to the curve's even-y point `P`. It computes

```
e = tagged_hash("BIP0340/challenge", bytes32(r) || pk || m) mod n
R = sG - eP
```

and accepts only when `R` is not infinity, `R.y` is even, and `R.x == r`.
`tagged_hash(tag, data)` is
`SHA256(SHA256(tag) || SHA256(tag) || data)`. These are specification
requirements; they do not depend on a particular implementation. KeyLab's
pure-Python verifier and Coincurve's `PublicKeyXOnly.verify` are tested against
the expected outcomes in the pinned BIP-340 CSV.

The current deterministic tests and `scripts/verify_invariants.py` examine all
**19 official vectors**: **9 accepted and 10 rejected**, with **19/19 matching
outcomes** between KeyLab, the official expected results, and Bitcoin Core
libsecp256k1 via Coincurve. Coincurve's x-only public-key constructor raises
`ValueError` for malformed public keys in vectors 5 and 14; those parser
rejections are treated as the expected `False` result. The harness reports a
vector index and its official comment for any disagreement. The tests also
compare **6 deterministically generated signatures** byte-for-byte for scalars
1 and `n-1` over three fixed 32-byte messages, exercise 9 single-bit mutations,
and reject malformed signature/public-key lengths, out-of-field x-coordinates,
and invalid signing scalars.

The BIP-340 specification allows messages of arbitrary length. The official
vectors include message lengths 0, 1, 17, and 100 bytes, and those vectors are
verified by both implementations. Coincurve's current `PrivateKey.sign_schnorr`
wrapper requires a 32-byte message, so generated-signature differential tests
are limited to that API's supported length; KeyLab's arbitrary-length signing
and verification is separately tested. Invalid *byte lengths* are not a
protocol error for BIP-340 messages; invalid message types are.

Reproduce the focused suite and the independent seeded harness from the project
root:

```powershell
python -m pytest -q tests/test_bip340_vectors.py tests/test_ecc_differential.py
python scripts/verify_invariants.py
```

Without Coincurve, native-dependent pytest cases are explicitly skipped and
the harness prints its native-backend skip notices; a skip is not a differential
pass. Install the optional backend with `python -m pip install -e ".[fast]"`.
Vector agreement, deterministic mutations, and native differential tests do
not establish constant-time behavior, formal security, or resistance to
side-channel attacks.

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

### Cross-module assurance audit (Milestone 3)

The audit reproduced one scalar-input defect in `scalar_mult`: `True` was
treated as scalar 1, while floats and strings failed later with inconsistent
exceptions. The public function now accepts only exact nonnegative Python
integers, matching the frozen affine reference and MSM input validation.
Regression tests reject `True`, `1.0`, and `"1"`; valid scalar multiplication
and modulo-`n` reduction are unchanged. This check is input-contract validation,
not a constant-time or secret-key safety guarantee.

Deterministic cross-checks also compared affine/Jacobian-backed scalar
multiplication at zero, group-order boundaries, and values above `n` against
the independent affine oracle; reconstructed GLV and wNAF scalars; compared
naive and Straus MSM results; checked batch inverses against modular
exponentiation; and round-tripped compressed and uncompressed SEC1 encodings.
The existing differential tests and invariant harness passed these checks.
Modular inverse implementations agreed with Python's `pow(a, -1, m)` for all
coprime pairs tested with `2 <= m <= 100` and `-100 <= a <= 100`; non-coprime
inputs raised `ValueError`.

For HASH160, KeyLab's custom RIPEMD-160 and HASH160 paths matched the separate
standard-library SHA-256/RIPEMD-160 providers for four deterministic messages
(0, 3, 33, and 1,020 bytes). The custom RIPEMD-160 implementation also matched
the standard-library provider at 13 message lengths around padding and
block-boundary transitions. Existing tests match published RIPEMD-160 vectors,
Bitcoin's genesis public-key HASH160, and the internal SHA-256 compression
feed-forward path against `hashlib`. Full-round `sha256_reduced` delegates to
`hashlib`; no independent full-hash reimplementation claim is made. These are
forward-computation checks only, not evidence of hash inversion.

Two observed behaviors remain bounded by API/specification assumptions rather
than being treated as confirmed defects:

- The direct P2WPKH and P2SH-P2WPKH helpers hash uncompressed SEC1 bytes, while
  WIF address derivation omits those witness forms for uncompressed keys.
  BIP-141 describes compressed witness public keys as a relay/mining policy;
  the audit did not establish a consensus-invalid output. Whether the low-level
  helpers should enforce standardness remains an API-policy decision.
- `wiener_attack(53361, 10445)` returns candidate `d=5`, factors `49` and
  `1089`. The modulus is not a valid RSA semiprime; the candidate factors
  multiply to the modulus but are composite. Wiener's attack assumes an RSA
  modulus formed from two distinct primes. The function verifies the exact
  quadratic/product relationship, not primality for arbitrary caller inputs.
  Treat results as candidates unless the RSA input precondition is met.

The complete default suite ran **2,470 passed, 9 deselected, 0 skipped**.
Focused module tests ran **503 passed, 1 deselected**. Ruff, the mypy ratchet,
the 25-check invariant harness, CLI self-tests, API-doc generation check, and
the 12-fixture vector verifier all passed. The default test configuration
excludes `slow` and `live` tests; no claim is made about those excluded cases.

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
- **Protocol vectors:** all 19 BIP-340 vectors are read from the repository's
  pinned CSV and checked against both implementations when Coincurve is present.

Authoritative and implementation references:

1. [SEC 2, Recommended Elliptic Curve Domain Parameters, v2.0](https://www.secg.org/sec2-v2.pdf), §2.4.1 (secp256k1); [SEC 1, Elliptic Curve Cryptography, v2.0](https://www.secg.org/sec1-v2.pdf) (point encodings).
2. Gallant, Lambert, Vanstone, [“Faster Point Multiplication on Elliptic Curves with Efficient Endomorphisms”](https://doi.org/10.1007/3-540-44647-8_11), CRYPTO 2001.
3. [BIP-340: Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki), including x-only lifting and test vectors.
4. [BIP-141: Segregated Witness](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki), including the compressed-key relay/mining policy for witness spends.
5. [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) (deterministic DSA/ECDSA nonces); [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) (RSA cryptographic schemes).
6. [NIST FIPS 180-4, Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) (SHA-256); Dobbertin, Bosselaers, Preneel, [“RIPEMD-160: A strengthened version of RIPEMD”](https://doi.org/10.1007/3-540-60865-6_44), FSE 1996.
7. [Bitcoin Core libsecp256k1](https://github.com/bitcoin-core/secp256k1) (independent native differential backend; not a claim that KeyLab itself is audited or constant-time).

## Reproduce

```powershell
# From a clean source checkout:
python -m pip install -e .
python scripts/verify_invariants.py

# Optional native differential checks:
python -m pip install -e ".[fast,ecc-alt]"
python scripts/verify_invariants.py

# Full BIP-340 and ECC differential tests:
python -m pytest -q tests/test_bip340_vectors.py tests/test_ecc_differential.py

# Core ECC tests:
python -m pytest -q tests/test_secp256k1.py tests/test_ec_reference.py
```

This report records only what was measured. It makes **no** claim about recovering
a soundly generated private key, inverting SHA-256/RIPEMD-160, or reversing a
HASH160 into a public key — see `SECURITY.md` for the walls.
