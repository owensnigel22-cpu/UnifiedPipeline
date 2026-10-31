# Changelog

All notable changes to Keylab are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `keylab --version` and `keylab-advanced --version`. The package version now has
  one source, `keylab.__version__`, which `pyproject.toml` reads.
- `keylab.ec` re-exports the shared curve helpers (`sqrt_mod_p`, `y_from_x`,
  `lift_x`, `has_even_y`, `require_point`, `require_scalar`), `scalar_mult`, `G`,
  `N`, and the BIP-327 MuSig2 API. `ec.secp256k1` and `encoding.{address,
  bech32, base58, wif}` declare `__all__`; `docs/api.md` gains an API-stability
  section.

### Changed
- **`ExtendedKey.derive("M/...")` returns the extended public key.** BIP-32
  writes `M/...` for `N(m/...)`; it previously returned the private key, the
  same as `m/...`. Derivation is unchanged (hardened steps still work from a
  private key); only the returned key type differs. `m/...` is unaffected.

### Performance
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
