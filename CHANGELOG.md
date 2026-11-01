# Changelog

All notable changes to Keylab are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `keylab.ec.schnorr_verify_batch(items)`: BIP-340 batch verification, re-exported
  from `keylab.ec`. It checks many signatures as one multi-scalar multiplication
  with cryptographically random coefficients (first = 1, rest from `secrets`), and
  returns the same verdict as verifying each signature individually. In pure
  Python it is faster than one-by-one verification from ~4 signatures up (~1.8x
  for large batches). Explicit coefficients may be supplied for reproducible
  testing only; production always uses `secrets`.
- `keylab.ec.multi_scalar_mult(pairs, *, method="auto")`: a multi-scalar
  multiplication engine returning `sum(k_i * P_i)`, re-exported from
  `keylab.ec`. The foundation method (`naive`) sums one optimized `k*P` per
  term; Straus/Shamir and Pippenger methods will extend `MSM_METHODS` behind
  the same signature. Validated against a naive reference over empty, singleton,
  duplicate, zero-scalar, infinity, and cancellation cases.
- `keylab --version` and `keylab-advanced --version`. The package version now has
  one source, `keylab.__version__`, which `pyproject.toml` reads.
- `keylab.ec` re-exports the shared curve helpers (`sqrt_mod_p`, `y_from_x`,
  `lift_x`, `has_even_y`, `require_point`, `require_scalar`), `scalar_mult`, `G`,
  `N`, and the BIP-327 MuSig2 API. `ec.secp256k1` and `encoding.{address,
  bech32, base58, wif}` declare `__all__`; `docs/api.md` gains an API-stability
  section.
- `keylab.ec.reference`: a frozen textbook implementation of secp256k1 (affine
  formulas, double-and-add, its own constants) used as the oracle for every
  optimization, and `keylab.ec.validation`: differential checks of scalar
  multiplication, addition, doubling, Jacobian conversion, serialization, and
  infinity handling against it. `scalar_mult` accepts `backend="python-reference"`
  and `backend="python-optimized"` (exactly the pure-Python path `auto` uses
  without a native backend). See `docs/PERFORMANCE_VALIDATION.md`.
- `benchmark-ec` and `benchmark-signatures` check their results against the
  frozen reference before timing.
- `batch_inverse` and `batch_to_affine` in `keylab.ec.secp256k1`: invert many
  field elements, or normalize many Jacobian points, with one modular inversion
  (Montgomery's trick). About 4× faster per point than one-at-a-time
  normalization for 64 points and 6× for 960. The generator table now uses them
  instead of an inline copy; the table is unchanged.

### Changed
- **`ExtendedKey.derive("M/...")` returns the extended public key.** BIP-32
  writes `M/...` for `N(m/...)`; it previously returned the private key, the
  same as `m/...`. Derivation is unchanged (hardened steps still work from a
  private key); only the returned key type differs. `m/...` is unaffected.
- `keylab.advanced_suite`'s curve arithmetic (Jacobian addition, doubling, and
  mixed addition, Jacobian-to-affine conversion, the generator window table,
  NAF digits, batch inversion and conversion, addition geometry, and the
  hash-to-curve square root) now calls `keylab.ec.secp256k1` instead of keeping
  its own copies. Every public name, CLI flag, and output is unchanged.

### Performance
- `multi_scalar_mult` gains a Pippenger bucket method (`method="pippenger"`),
  which overtakes Straus for large batches (measured crossover ~64-128 terms)
  and uses near-constant memory (a fixed bucket array reused across windows)
  versus Straus's linear table growth. `method="auto"` selects naive (<=1 term
  or native backend), Straus (2-127 terms), or Pippenger (>=128 terms); results
  are unchanged.
- `multi_scalar_mult` gains a Straus/Shamir method (`method="straus"`), which
  shares one doubling chain across all terms via interleaved GLV+wNAF. In pure
  Python it beats the naive sum for two or more terms (crossover at n=2, ~2.2x
  by n>=32), at the cost of memory linear in the term count. `method="auto"`
  selects it for n>=2 without a native backend; results are unchanged.
- Arbitrary-point scalar multiplication `k*P` is about 2.1x faster in pure
  Python: the GLV endomorphism splits k into two ~128-bit halves evaluated as
  interleaved width-4 wNAF. This also speeds BIP-340 and ECDSA verification
  (~3x vs 0.2.0), whose slower half is a `k*P`. Results are unchanged, and the
  readable `python` and bitwise `python-glv` paths remain selectable. With a
  native backend, `k*P` still runs on libsecp256k1.
- Fixed-base scalar multiplication `k*G` is about 1.8x faster in pure Python:
  the generator comb's window widened from 4 to 8 bits (32 point additions per
  call instead of 64). The lazily built, cached table is correspondingly larger
  (~1.5 MB, ~0.16 s to build, once per process). Results are unchanged. With a
  native backend installed, `k*G` still runs on libsecp256k1 and is unaffected.
- `scalar_mult(backend="auto")` checks whether coincurve and fastecdsa are
  installed once per process instead of on every call. Without a native backend
  each check searched `sys.path`; removing it makes pure-Python signing,
  verification, BIP-32 derivation, and Taproot tweaks 1.5–3.5× faster. Results
  are unchanged. A backend installed while a process is running is picked up
  after a restart.

### Fixed
- `ecdsa_verify_digest` returns `False` instead of raising `TypeError` for a
  non-bytes digest, a signature that is not a pair of ints, or a public key
  that is not a pair of ints. `bytes`, `bytearray`, and `memoryview` digests
  and list pairs are still accepted.
- `verify_taproot_script_path` returns `False` instead of raising for a
  non-bytes output key, script, or control block.
- `taproot_control_block` rejects an internal key that is not a valid x-only
  public key (x outside the field, or no curve point with that x).

## [0.2.0] - 2026-10-31

### Fixed
- **MuSig2 key aggregation now follows BIP-327.**
  `advanced_suite.musig2_aggregate_keys` previously hashed 32-byte x-only keys
  (a pre-BIP-327 draft) and did not match the official vectors. It now
  defaults to `mode="bip327"`; the old behaviour remains available as
  `mode="legacy-xonly"` and via `keylab-advanced --musig2-mode legacy-xonly`.
- **BIP-340 accepts messages of any length**, per the 2022 revision. Official
  vectors 15-18 (0, 1, 17, and 100-byte messages) now pass. The advanced
  suite's `--schnorr-trace` no longer requires exactly 32 bytes.
- **`advanced_suite.parse_pubkey` parsed `0x03` (odd-y) compressed keys as the
  even-y point.** It now uses the shared SEC1 decoder. This also affects
  `--curve-add` and other suite commands that accept compressed keys.
- **BIP-341 control blocks longer than 128 Merkle nodes are rejected.**
  `verify_taproot_script_path` previously checked only that the length was
  33 + 32m, so a 129-node path with a matching commitment verified.
- **Leaf version 0x50 is rejected** by `tapleaf_hash`, `TapLeaf`, and
  `taproot_control_block`; BIP-341 reserves it to avoid ambiguity with the annex.
- **`keylab-advanced --wif` no longer prints the private scalar by default.**
  Pass the new `--show-private` flag to display it; the library function
  `advanced_suite.decode_wif` is unchanged.

### Added
- `keylab.ec.musig2`: BIP-327 KeySort, KeyAgg, KeyAgg coefficients, and
  plain/x-only ApplyTweak, with `InvalidContributionError`.
- `keylab.hd`: `ExtendedKey` (xprv/xpub and SLIP-132 y/z/u/v families,
  strict parsing, neutering, fingerprints, parent identifiers), CKDpub
  (`derive_child_public`), `derive_account_key`, `derive_bip49_p2sh_p2wpkh`,
  `derive_bip84_p2wpkh`, `format_path`, `key_identifier`, `fingerprint`, and a
  `change=` keyword on the BIP-44/86 helpers.
- `keylab.encoding.taproot`: `taproot_tweak_seckey`, `taproot_sign_key_path`,
  `TapLeaf`, `build_script_tree`, and `taproot_script_tree_output`.
- `keylab.encoding.transaction`: SegWit/legacy transaction parser and BIP-341
  `taproot_signature_message` / `taproot_sighash` for all hash types, annex,
  and the BIP-342 script-path extension.
- Shared curve helpers in `keylab.ec.secp256k1`: `sqrt_mod_p`, `y_from_x`,
  `lift_x`, `has_even_y`, `require_point`, `require_scalar`.
- Research modules `keylab.ec.division_polynomials`, `keylab.ec.quartic`, and
  `keylab.ec.halving`.
- `keylab benchmark-signatures`: BIP-340, ECDSA, BIP-32, Taproot, and MuSig2
  KeyAgg timings against libsecp256k1, with a correctness gate and median
  statistics.
- Official vector fixtures under `tests/vectors/` (BIP-32, 39, 49, 84, 86,
  173, 327, 340, 341, 350) with provenance notes.
- Differential tests against libsecp256k1 (and fastecdsa when installed),
  including ECDSA public-key recovery, and Hypothesis property tests for the
  group law and encodings.
- `SECURITY.md`, this changelog, and `docs/` pages: architecture (with
  cryptographic assumptions and implementation notes), API reference,
  secp256k1, BIP-32, BIP-340, Taproot, benchmarks (with methodology), and
  point halving.
- CI installs the `secp256k1` extra and fails if coincurve is missing, so the
  libsecp256k1 differential tests always run.

### Changed
- Duplicate square-root/`lift_x` code in `schnorr`, `taproot`,
  `ecdsa_recovery`, `secp256k1.decompress_pubkey`, and `advanced_suite` now
  calls the shared helpers. `taproot.lift_x` is re-exported unchanged.
  `advanced_suite.tagged_hash` delegates to `keylab.hashes.tagged`.
- `derive_bip44_accounts` reuses the shared CKDpriv core instead of an inline
  copy of the child-derivation formula (same batching speed-up).
- `hd.py` uses `keylab.encoding.address` for HASH160 and address encoding
  instead of inline copies.
- Feature-audit entries for BIP-49/84 now describe the new derivation APIs.

### Test suite
- 504 → 972 passing tests (12 fastecdsa differential tests skip when it is
  not installed).

## [0.1.0]

Initial research release: secp256k1 reference arithmetic and backends,
RFC 6979 ECDSA, BIP-340 vector 0, BIP-32/39/44/86 basics, Taproot
commitments, WIF/address tooling, SHA-256/RIPEMD-160 CNF and SAT tooling,
RSA and number-theory utilities, benchmarks, and the advanced demonstration
suite.
