# secp256k1 in Keylab

Module: `keylab.ec.secp256k1` (with `sec1`, `schnorr`, `ecdsa_recovery`).

## Curve

`y² = x³ + 7` over F_p, with

- `P = 2²⁵⁶ − 2³² − 977` (field prime, `P ≡ 3 mod 4`)
- `N` = prime group order, so every non-identity point generates the group
  and there is no rational point of small order
- `G` = the standard generator

Points are affine `(x, y)` tuples; `None` is the point at infinity.

## Shared helpers (one implementation each)

| Helper | Purpose |
|---|---|
| `sqrt_mod_p(v)` | Square root via `v^((P+1)/4)`, verified; `None` for non-residues |
| `y_from_x(x, odd=)` | y coordinate with requested parity; raises if x is not on the curve |
| `lift_x(x)` | Even-y point for an x-only key (BIP-340/341) |
| `has_even_y(P)` | Parity test used by BIP-340, BIP-341, and BIP-327 |
| `require_point`, `require_scalar` | Validation with consistent error messages |
| `keylab.hashes.tagged.tagged_hash` | `SHA256(SHA256(tag)‖SHA256(tag)‖msg)` with cached tag digests |

`schnorr`, `taproot`, `ecdsa_recovery`, `decompress_pubkey`, and the advanced
suite all call these helpers rather than keeping private copies.

## Scalar multiplication backends

`scalar_mult(k, P, backend=...)` accepts `auto`, `python`,
`python-affine-window`, `python-glv`, `python-wnaf`, `coincurve`, `fastecdsa`.
`auto` uses libsecp256k1 (coincurve) or fastecdsa when installed and falls
back to a fixed-base window table for `G`. All backends are tested to agree
on edge scalars (1, 2, N−1, N−2, (N±1)/2, 2¹²⁸, 2²⁵⁵ mod N) and on
arbitrary points.

## Signatures

- **ECDSA**: `ecdsa_sign_digest` uses RFC 6979 (HMAC-SHA-256) nonces and
  low-S normalisation; signatures are byte-identical to libsecp256k1 in the
  differential tests. `ecdsa_verify_digest` accepts high-S signatures
  (mathematically valid); Bitcoin relay policy rejects them, so use
  `is_high_s_signature` to check.
- **BIP-340 Schnorr**: see [bip340.md](bip340.md).
- **Public-key recovery**: `recover_public_keys_from_signature` returns every
  verified candidate; it never yields a private key.

## Verification strategy

| Layer | Tests |
|---|---|
| Known answers | `test_secp256k1.py`, BIP vector suites |
| Differential (libsecp256k1, fastecdsa) | `test_ecc_differential.py` |
| Properties: `(k+m)G = kG + mG`, `nG = ∞`, `2P = P + P`, associativity, SEC1 and x-only round trips, `sqrt`/`lift_x` correctness | `test_ecc_properties.py` (Hypothesis) |

## Limitations

- Not constant-time and not side-channel resistant (see `SECURITY.md`).
- Affine `point_add_affine` performs a modular inversion per addition; it is
  written for clarity. Use Jacobian `scalar_mult` paths for throughput.
- No DER (BIP-66) signature encoding/decoding yet; planned for the next release.
