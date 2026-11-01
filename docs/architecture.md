# Architecture

Keylab is a Python research and teaching library for secp256k1 and Bitcoin
key/signature standards, plus SAT/hash-analysis and number-theory tooling.
This page covers the cryptographic core; the SAT and hash modules are
described in the README.

## Layers

```
            CLI: keylab (cli.py)              keylab-advanced (advanced_suite.py)
                    │                                   │ traces/demos
                    ▼                                   ▼
  benchmarks.py ──► protocol layer ◄──────────────── delegates helpers
                    ├─ ec/schnorr.py         BIP-340
                    ├─ ec/musig2.py          BIP-327 KeyAgg
                    ├─ ec/ecdsa_recovery.py  public-key recovery
                    ├─ hd.py                 BIP-32/39/44/49/84/86
                    ├─ encoding/taproot.py   BIP-341 outputs, trees, signing
                    └─ encoding/transaction.py  tx parsing, BIP-341 sighash
                    │
                    ▼
            encoding layer: sec1, address, bech32, base58, wif
                    │
                    ▼
            curve layer: ec/secp256k1.py ── hashes/tagged.py
              field/curve helpers, affine + Jacobian arithmetic,
              scalar_mult backends, ECDSA/RFC 6979
                    │
                    ▼  optional native backends
            coincurve (libsecp256k1), fastecdsa

  research (ec/division_polynomials.py → ec/quartic.py → ec/halving.py) sits
  beside the protocol layer and depends only on the curve layer.
```

The proposed ECDSA analysis package (`keylab.research.ecdsa`) is a separate,
offline research layer. It may depend on the curve and ECDSA verification
helpers but must not be imported by signing, verification, key derivation, or
the curve layer. See
[RESEARCH_SUBSYSTEM_ARCHITECTURE.md](RESEARCH_SUBSYSTEM_ARCHITECTURE.md);
the package is not implemented by this documentation change.

Dependencies point downward only. `hd` lazily imports `taproot` for BIP-86 to
avoid an import cycle; `taproot` lazily imports `schnorr` for signing.

## Single sources of truth

| Concern | Owner | Consumers |
|---|---|---|
| Field square root, `y_from_x`, `lift_x`, `has_even_y` | `ec/secp256k1.py` | schnorr, taproot, sec1, ecdsa_recovery, musig2, advanced_suite |
| Point/scalar validation | `is_on_curve`, `require_point`, `require_scalar` | every public entry point |
| Tagged hashes | `hashes/tagged.py` (cached tag digests) | schnorr, taproot, musig2, transaction, advanced_suite |
| HASH160 and address encodings | `encoding/address.py` | hd, benchmarks, CLI |
| CompactSize / script serialization | `encoding/transaction.py` | taproot sighash |

`advanced_suite.py` keeps its public curve functions (`jacobian_add`,
`scalar_mult_naf`, `batch_inv`, `scalar_mult_g_fast`, ...) as a compatibility
layer over `ec/secp256k1.py`: they translate the suite's `(0, 0)` / `(0, 0, 0)`
point-at-infinity convention and otherwise call the shared code.
`tests/test_advanced_suite_consolidation.py` checks that they reproduce their
earlier outputs exactly and fails if field formulas reappear in the module.
The suite's RSA code is still separate from `numtheory/rsa.py`.

## Cryptographic assumptions

Keylab's protocols rely on the standard assumptions of the BIPs they
implement; Keylab adds none of its own and proves none of them.

- **ECDLP on secp256k1** is hard (≈128-bit security). Nothing in Keylab,
  including the halving, quartic, and division-polynomial research modules,
  weakens it; those modules transform points without revealing discrete logs.
- **SHA-256 behaves as a random oracle** for tagged hashes (BIP-340
  challenges and nonces, BIP-341 tweaks, BIP-327 coefficients) and as a
  collision-resistant hash for Merkle commitments.
- **HMAC-SHA-256 / HMAC-SHA-512** are PRFs: RFC 6979 nonces and BIP-32
  derivation depend on this.
- **PBKDF2-HMAC-SHA512 with 2048 iterations** (BIP-39) offers only modest
  stretching; mnemonic entropy, not the KDF, provides security.
- **Randomness**: BIP-340 `aux_rand` defaults to `secrets.token_bytes`; tests
  pass fixed values only to reproduce vectors.
- **Group structure**: secp256k1 has prime order N and cofactor 1, so there is
  no small-subgroup confinement; invalid-curve inputs are rejected at entry
  points instead.

Out-of-scope assumptions (see [SECURITY.md](../SECURITY.md)): constant-time
execution, side-channel resistance, secure memory, and fault resistance.

## Implementation notes

- **Point representation.** Affine `(x, y)` tuples with `None` for infinity at
  API boundaries; Jacobian `(X, Y, Z)` internally, with `_INFINITY = (0, 1, 0)`.
  `point_add` handles doubling and inverse inputs; `_point_add_mixed` adds an
  affine point to a Jacobian accumulator.
- **Scalar multiplication.** `scalar_mult` reduces the scalar mod N, rejects
  negative scalars, validates the point, and dispatches: native backends for
  `auto` when installed; otherwise a 4-bit fixed-base table for G and
  double-and-add for other points. GLV (`python-glv`), width-5 fixed-base
  wNAF, and an affine-window table are selectable for study and benchmarking.
- **ECDSA.** RFC 6979 with HMAC-SHA-256 and `bits2octets(z mod N)`; retries on
  `r = 0` or `s = 0`; low-S output. Verification accepts high-S (use
  `is_high_s_signature` for Bitcoin policy).
- **BIP-340.** Messages of any length; secret negated for odd-y keys; nonce
  negated for odd-y R; every signature is self-verified before returning.
- **BIP-327.** Public-key operations only (KeySort, KeyAgg, coefficients,
  tweaks). Nonce handling and partial signing are intentionally absent.
- **BIP-32.** `ExtendedKey` is immutable and validated on construction, so a
  parsed key that violates BIP-32 (test vector 5) cannot exist as an object.
  Invalid children (probability ≈ 2⁻¹²⁷) raise rather than skip.
- **BIP-341.** Script trees follow the reference `taproot_tree_helper`
  ordering; control blocks are limited to 128 Merkle nodes and leaf version
  0x50 is rejected (it would be ambiguous with the annex). The sighash
  supports every hash type, the annex, and the BIP-342 extension.
- **Bech32/Bech32m.** v0 programs require Bech32, v1+ require Bech32m, lengths
  follow BIP-141/350, mixed case and non-zero padding are rejected.
- **Research modules.** Polynomials are coefficient lists over F_p (lowest
  degree first). Root-finding is `gcd(f, x^p − x)` plus a deterministic
  Cantor–Zassenhaus split, with exhaustive search for fields below 4096.

## Verification strategy

| Evidence | Where |
|---|---|
| Official vectors: BIP-32 (1–5), BIP-39 (Trezor), BIP-49/84/86, BIP-173, BIP-327, BIP-340 (0–18), BIP-341, BIP-350 | `tests/vectors/` + `tests/test_*_vectors.py`, `test_musig2.py`, `test_taproot_bip341.py` |
| Differential vs libsecp256k1 (and fastecdsa) | `tests/test_ecc_differential.py` (CI installs coincurve) |
| Property-based (Hypothesis) | `tests/test_ecc_properties.py` |
| Regression tests for fixed defects | `test_taproot_limits.py`, `test_advanced_suite.py`, `test_advanced_suite_secrets.py` |
| Research mathematics on secp256k1 and toy curves | `tests/test_ec_research.py` |

## Extending Keylab

- New curve-level code should use the shared helpers rather than re-deriving
  square roots or tagged hashes.
- New protocol code should land with official vectors in `tests/vectors/`
  (add a provenance row to its README) and, where libsecp256k1 implements the
  same operation, a differential test.
- New benchmarks should follow the methodology in
  [benchmarks.md](benchmarks.md): seeded corpus, correctness gate, warm-up
  excluded, shuffled order, median, and no secrets in output.
