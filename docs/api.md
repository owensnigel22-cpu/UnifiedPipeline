# API reference

Public API of the cryptographic modules, generated from each module's
`__all__`, signatures, and docstrings (regenerate after API changes rather
than editing by hand). Everything here is research/teaching code; read
[SECURITY.md](../SECURITY.md) before handling any real key.

CLI commands are listed by `keylab --help` and `keylab-advanced --help`;
[architecture.md](architecture.md) explains how the modules fit together.

## Contents

- [`keylab.ec.secp256k1`](#keylabecsecp256k1) — secp256k1 arithmetic, backends, ECDSA, shared curve helpers
- [`keylab.ec.sec1`](#keylabecsec1) — SEC1 and x-only public-key encodings
- [`keylab.ec.schnorr`](#keylabecschnorr) — BIP-340 Schnorr signatures
- [`keylab.ec.musig2`](#keylabecmusig2) — BIP-327 MuSig2 key aggregation
- [`keylab.ec.ecdsa_recovery`](#keylabececdsa_recovery) — ECDSA public-key recovery
- [`keylab.ec.reference`](#keylabecreference) — Frozen textbook oracle for validating optimizations
- [`keylab.ec.validation`](#keylabecvalidation) — Differential validation against the reference
- [`keylab.hd`](#keylabhd) — BIP-32/39/44/49/84/86 hierarchical deterministic keys
- [`keylab.encoding.taproot`](#keylabencodingtaproot) — BIP-341 Taproot outputs, script trees, key-path signing
- [`keylab.encoding.transaction`](#keylabencodingtransaction) — Transaction parsing and BIP-341 signature hashing
- [`keylab.encoding.address`](#keylabencodingaddress) — Address encoding and verification
- [`keylab.encoding.bech32`](#keylabencodingbech32) — BIP-173 Bech32 / BIP-350 Bech32m
- [`keylab.encoding.base58`](#keylabencodingbase58) — Base58 and Base58Check
- [`keylab.encoding.wif`](#keylabencodingwif) — Wallet Import Format
- [`keylab.hashes.tagged`](#keylabhashestagged) — BIP-340 tagged hashing
- [`keylab.ec.division_polynomials`](#keylabecdivision_polynomials) — Research: division polynomials over F_p
- [`keylab.ec.quartic`](#keylabecquartic) — Research: doubling-quartic inversion
- [`keylab.ec.halving`](#keylabechalving) — Research: point halving
- [`keylab.benchmarks`](#keylabbenchmarks) — Benchmarks
- [API stability](#api-stability)

## `keylab.ec.secp256k1`

secp256k1 arithmetic, backends, ECDSA, shared curve helpers.

Reference secp256k1 point arithmetic; not constant-time and not a full-key-search facility.

| Name | Signature / value | Summary |
|---|---|---|
| `batch_inverse` | `batch_inverse(values: 'Sequence[int]', modulus: 'int' = 115792089237316195423570985008687907853269984665640564039457584007908834671663) -> 'list[int]'` | Invert every value modulo a prime with a single modular inversion. |
| `batch_to_affine` | `batch_to_affine(points: 'Iterable[object]') -> 'list[Point]'` | Normalize many points to affine coordinates with one modular inversion. |
| `BETA` | `BETA = int` |  |
| `compress_pubkey` | `compress_pubkey(point: 'Point') -> 'bytes'` | Serialize a finite affine point using SEC compressed format. |
| `decompress_pubkey` | `decompress_pubkey(data: 'bytes') -> 'tuple[int, int]'` | Parse a 33-byte compressed SEC public key and validate the resulting curve point. |
| `ecdsa_sign_digest` | `ecdsa_sign_digest(digest: 'bytes', private_scalar: 'int', *, backend: 'str' = 'auto') -> 'tuple[int, int]'` | Create a deterministic, low-S ECDSA signature over one 32-byte digest. |
| `ecdsa_verify_digest` | `ecdsa_verify_digest(digest: 'bytes', signature: 'tuple[int, int]', public_key: 'Point') -> 'bool'` | Verify a raw ``(r, s)`` ECDSA signature over a 32-byte digest. |
| `G` | `G = tuple` |  |
| `glv_decompose` | `glv_decompose(scalar: 'int') -> 'tuple[int, int]'` | Split k into signed components satisfying k = k1 + lambda*k2 (mod N). |
| `has_even_y` | `has_even_y(point: 'Point') -> 'bool'` | Return whether a finite point has an even y coordinate. |
| `is_high_s_signature` | `is_high_s_signature(signature: 'tuple[int, int]') -> 'bool'` | Return whether a valid-range ECDSA signature uses the non-low-S form. |
| `is_on_curve` | `is_on_curve(point: 'Point') -> 'bool'` | Return whether an affine point is infinity or satisfies secp256k1's curve equation. |
| `LAMBDA` | `LAMBDA = int` |  |
| `lift_x` | `lift_x(x: 'int') -> 'tuple[int, int]'` | Lift an x coordinate to the even-y point, as BIP-340 and BIP-341 require. |
| `N` | `N = int` |  |
| `P` | `P = int` |  |
| `point_add` | `point_add(left: 'Jacobian', right: 'Jacobian') -> 'Jacobian'` | Add two Jacobian secp256k1 points. |
| `point_add_affine` | `point_add_affine(left: 'Point', right: 'Point') -> 'Point'` | Add affine secp256k1 points, returning ``None`` for the point at infinity. |
| `point_add_geometry` | `point_add_geometry(left: 'Point', right: 'Point') -> 'dict[str, object]'` | Explain affine secant/tangent addition, including its third intersection. |
| `point_double` | `point_double(point: 'Jacobian') -> 'Jacobian'` | Double a Jacobian secp256k1 point. |
| `point_negate_affine` | `point_negate_affine(point: 'Point') -> 'Point'` | Negate an affine secp256k1 point; infinity is represented by ``None``. |
| `public_key_from_private_scalar` | `public_key_from_private_scalar(private_scalar: 'int', *, backend: 'str' = 'auto') -> 'tuple[int, int]'` | Derive secp256k1 public key ``Q = d*G`` for a valid private scalar ``d``. |
| `recover_private_key_from_reused_nonce` | `recover_private_key_from_reused_nonce(digest1: 'bytes', signature1: 'tuple[int, int]', digest2: 'bytes', signature2: 'tuple[int, int]', public_key: 'Point') -> 'int \| None'` | Recover an ECDSA private scalar from two signatures sharing one nonce. |
| `require_point` | `require_point(point: 'Point', *, name: 'str' = 'point') -> 'tuple[int, int]'` | Validate a finite secp256k1 affine point and return it narrowed for typing. |
| `require_scalar` | `require_scalar(scalar: 'int', *, name: 'str' = 'scalar') -> 'int'` | Validate an integer scalar in ``[1, N-1]``. |
| `rfc6979_nonce_from_digest` | `rfc6979_nonce_from_digest(private_scalar: 'int', digest: 'bytes') -> 'int'` | Return the RFC 6979 HMAC-SHA-256 nonce for a 32-byte digest and valid key. |
| `scalar_mult` | `scalar_mult(scalar: 'int', point: 'Point' = (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424), *, backend: 'str' = 'auto') -> 'Point'` | Multiply a point, preferring installed native backends and retaining Python fallback. |
| `SCALAR_MULT_BACKENDS` | `SCALAR_MULT_BACKENDS = tuple` |  |
| `sqrt_mod_p` | `sqrt_mod_p(value: 'int') -> 'int \| None'` | Return a square root of ``value`` modulo P, or ``None`` for a non-residue. |
| `wnaf_digits` | `wnaf_digits(scalar: 'int', window: 'int' = 5) -> 'tuple[int, ...]'` | Return least-significant-first width-w NAF digits for a nonnegative scalar. |
| `y_from_x` | `y_from_x(x: 'int', *, odd: 'bool' = False) -> 'int'` | Return the curve y coordinate for ``x`` with the requested parity. |

## `keylab.ec.sec1`

SEC1 and x-only public-key encodings.

SEC1 public-key serialization helpers for secp256k1.

| Name | Signature / value | Summary |
|---|---|---|
| `parse_sec1` | `parse_sec1(data: 'bytes') -> 'tuple[int, int]'` | Parse a compressed or uncompressed SEC1 public key and validate the point. |
| `serialize_sec1` | `serialize_sec1(point: 'Point', *, compressed: 'bool' = True) -> 'bytes'` | Serialize a finite secp256k1 point in compressed or uncompressed SEC1 form. |
| `serialize_uncompressed` | `serialize_uncompressed(point: 'Point') -> 'bytes'` | Serialize a finite point using the 65-byte SEC1 uncompressed form. |
| `serialize_xonly` | `serialize_xonly(point: 'Point') -> 'bytes'` | Return the 32-byte x coordinate used by BIP-340/BIP-341. |

## `keylab.ec.schnorr`

BIP-340 Schnorr signatures.

BIP-340 Schnorr signing and verification primitives for secp256k1.

| Name | Signature / value | Summary |
|---|---|---|
| `schnorr_public_key` | `schnorr_public_key(private_scalar: 'int') -> 'bytes'` | Return the 32-byte x-only BIP-340 public key. |
| `schnorr_sign` | `schnorr_sign(message: 'bytes', private_scalar: 'int', aux_rand: 'bytes \| None' = None) -> 'bytes'` | Sign a BIP-340 message of any length; use fresh auxiliary randomness by default. |
| `schnorr_verify` | `schnorr_verify(message: 'bytes', signature: 'bytes', public_key_x: 'bytes') -> 'bool'` | Verify a BIP-340 signature over a message of any length against an x-only key. |
| `tagged_hash` | `tagged_hash(tag: 'str', message: 'bytes') -> 'bytes'` | Return ``SHA256(SHA256(tag) // SHA256(tag) // message)``. |

## `keylab.ec.musig2`

BIP-327 MuSig2 key aggregation.

BIP-327 MuSig2 key aggregation, key sorting, and aggregate-key tweaking.

| Name | Signature / value | Summary |
|---|---|---|
| `apply_tweak` | `apply_tweak(context: 'KeyAggContext', tweak: 'bytes', is_xonly: 'bool') -> 'KeyAggContext'` | Apply a plain or x-only tweak to a KeyAgg context (BIP-327 ``ApplyTweak``). |
| `get_second_key` | `get_second_key(pubkeys: 'Sequence[bytes]') -> 'bytes'` | Return the first key that differs from ``pubkeys[0]``, or 33 zero bytes. |
| `hash_keys` | `hash_keys(pubkeys: 'Sequence[bytes]') -> 'bytes'` | Return ``hash_KeyAgg list(pk_1 // ... // pk_u)``. |
| `InvalidContributionError` | `class InvalidContributionError(signer: 'int', contrib: 'str') -> 'None'` | Raised when one signer's contribution (here, a public key) is invalid. |
| `key_agg` | `key_agg(pubkeys: 'Sequence[bytes]') -> 'KeyAggContext'` | Aggregate plain public keys into a BIP-327 KeyAgg context. |
| `key_agg_and_tweak` | `key_agg_and_tweak(pubkeys: 'Sequence[bytes]', tweaks: 'Sequence[bytes]' = (), is_xonly: 'Sequence[bool]' = ()) -> 'KeyAggContext'` | Aggregate keys, then apply each tweak in order. |
| `key_agg_coeff` | `key_agg_coeff(pubkeys: 'Sequence[bytes]', pubkey: 'bytes') -> 'int'` | Return the KeyAgg coefficient ``a_i`` for ``pubkey`` within ``pubkeys``. |
| `key_sort` | `key_sort(pubkeys: 'Sequence[bytes]') -> 'list[bytes]'` | Sort plain public keys lexicographically (BIP-327 ``KeySort``). |
| `KeyAggContext` | `class KeyAggContext(point: 'tuple[int, int]', gacc: 'int', tacc: 'int') -> None` | BIP-327 KeyAgg context: aggregate point plus tweak accumulators. |

## `keylab.ec.ecdsa_recovery`

ECDSA public-key recovery.

ECDSA public-key recovery from a digest and signature (forensic utility).

| Name | Signature / value | Summary |
|---|---|---|
| `recover_public_keys_from_signature` | `recover_public_keys_from_signature(digest: 'bytes', signature: 'tuple[int, int]') -> 'tuple[Point, ...]'` | Return all valid secp256k1 public-key candidates for an ECDSA signature. |

## `keylab.ec.reference`

Frozen textbook oracle for validating optimizations.

Frozen textbook secp256k1 arithmetic: the oracle for validating optimizations.

| Name | Signature / value | Summary |
|---|---|---|
| `add` | `add(left: 'Point', right: 'Point') -> 'Point'` | Add two affine points with the chord-and-tangent rule. |
| `B` | `B = 7` |  |
| `decode` | `decode(data: 'bytes') -> 'tuple[int, int]'` | Decode a SEC1 compressed or uncompressed public key, validating the point. |
| `double` | `double(point: 'Point') -> 'Point'` | Double an affine point with the tangent rule (a = 0 for secp256k1). |
| `encode_compressed` | `encode_compressed(point: 'Point') -> 'bytes'` | SEC1 compressed encoding: 0x02/0x03 by y parity, then x (33 bytes). |
| `encode_uncompressed` | `encode_uncompressed(point: 'Point') -> 'bytes'` | SEC1 uncompressed encoding: 0x04, x, y (65 bytes). |
| `encode_xonly` | `encode_xonly(point: 'Point') -> 'bytes'` | BIP-340 x-only encoding: the 32-byte x coordinate. |
| `G` | `G = tuple` |  |
| `is_on_curve` | `is_on_curve(point: 'Point') -> 'bool'` | Return whether ``point`` is infinity or a field point with y^2 = x^3 + 7. |
| `N` | `N = int` |  |
| `negate` | `negate(point: 'Point') -> 'Point'` | Return -point: (x, -y), with -infinity = infinity. |
| `P` | `P = int` |  |
| `scalar_mult` | `scalar_mult(scalar: 'int', point: 'Point' = (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424)) -> 'Point'` | Return scalar * point by left-to-right double-and-add. |

## `keylab.ec.validation`

Differential validation against the reference.

Differential validation of secp256k1 implementations against the frozen reference.

| Name | Signature / value | Summary |
|---|---|---|
| `assert_no_mismatches` | `assert_no_mismatches(mismatches: 'Sequence[Mismatch]', *, limit: 'int' = 10) -> 'None'` | Raise ``AssertionError`` listing up to ``limit`` mismatches, if there are any. |
| `available_backends` | `available_backends(*, include_strategies: 'bool' = True) -> 'tuple[str, ...]'` | Return the contract backends usable here (native ones only if installed). |
| `CONTRACT_BACKENDS` | `CONTRACT_BACKENDS = tuple` |  |
| `diff_batch_normalization` | `diff_batch_normalization(points: 'Sequence[Point] \| None' = None) -> 'list[Mismatch]'` | Compare ``batch_to_affine`` with the reference, per point and as one batch. |
| `diff_group_operations` | `diff_group_operations(points: 'Sequence[Point] \| None' = None) -> 'list[Mismatch]'` | Compare addition, doubling, negation, mixed addition, and Jacobian conversion. |
| `diff_infinity` | `diff_infinity(backends: 'Sequence[str] \| None' = None) -> 'list[Mismatch]'` | Check point-at-infinity handling in every operation that can meet it. |
| `diff_scalar_mult` | `diff_scalar_mult(scalars: 'Iterable[int] \| None' = None, points: 'Sequence[tuple[int, int]] \| None' = None, backends: 'Sequence[str] \| None' = None) -> 'list[Mismatch]'` | Compare ``scalar_mult`` for every backend with the reference (defaults: edge inputs). |
| `diff_serialization` | `diff_serialization(points: 'Sequence[tuple[int, int]] \| None' = None) -> 'list[Mismatch]'` | Compare SEC1 and x-only encoding and decoding with the reference. |
| `edge_points` | `edge_points() -> 'tuple[tuple[int, int], ...]'` | Finite points that exercise special cases: G, -G, 2G, lambda*G, and hashed points. |
| `EDGE_SCALARS` | `EDGE_SCALARS = tuple` |  |
| `hashed_point` | `hashed_point(label: 'str') -> 'tuple[int, int]'` | Return a deterministic finite point k*G with k derived from ``label``. |
| `Mismatch` | `class Mismatch(operation: 'str', implementation: 'str', inputs: 'str', expected: 'str', actual: 'str') -> None` | One input on which an implementation disagreed with the reference. |
| `NATIVE_BACKENDS` | `NATIVE_BACKENDS = ('coincurve', 'fastecdsa')` |  |
| `PYTHON_STRATEGIES` | `PYTHON_STRATEGIES = tuple` |  |
| `validate_all` | `validate_all(scalars: 'Iterable[int] \| None' = None) -> 'list[Mismatch]'` | Run every differential check; the gate for any arithmetic change. |

## `keylab.hd`

BIP-32/39/44/49/84/86 hierarchical deterministic keys.

BIP-39 seed and BIP-32 hierarchical deterministic key helpers for secp256k1.

| Name | Signature / value | Summary |
|---|---|---|
| `derive_account_key` | `derive_account_key(seed: 'bytes', purpose: 'int', account: 'int' = 0, *, network: 'str' = 'mainnet') -> 'ExtendedKey'` | Return the account-level extended private key ``m/purpose'/coin'/account'``. |
| `derive_bip44_accounts` | `derive_bip44_accounts(seed: 'bytes', account_count: 'int', addresses_per_account: 'int', *, network: 'str' = 'mainnet') -> 'tuple[DerivedAddress, ...]'` | Derive a deterministic account/address batch while reusing each account node. |
| `derive_bip44_p2pkh` | `derive_bip44_p2pkh(seed: 'bytes', account: 'int', address_index: 'int', *, network: 'str' = 'mainnet', change: 'int' = 0) -> 'DerivedAddress'` | Derive one BIP-44 Bitcoin P2PKH address (m/44'/coin'/account'/change/index). |
| `derive_bip49_p2sh_p2wpkh` | `derive_bip49_p2sh_p2wpkh(seed: 'bytes', account: 'int', address_index: 'int', *, network: 'str' = 'mainnet', change: 'int' = 0) -> 'DerivedAddress'` | Derive one BIP-49 nested-SegWit P2SH-P2WPKH address (m/49'/coin'/account'/change/index). |
| `derive_bip84_p2wpkh` | `derive_bip84_p2wpkh(seed: 'bytes', account: 'int', address_index: 'int', *, network: 'str' = 'mainnet', change: 'int' = 0) -> 'DerivedAddress'` | Derive one BIP-84 native SegWit P2WPKH address (m/84'/coin'/account'/change/index). |
| `derive_bip86_p2tr` | `derive_bip86_p2tr(seed: 'bytes', account: 'int', address_index: 'int', *, network: 'str' = 'mainnet', change: 'int' = 0) -> 'DerivedTaprootAddress'` | Derive a BIP-86 key-path-only P2TR address (empty script-tree root). |
| `derive_child_private` | `derive_child_private(parent_key: 'bytes', chain_code: 'bytes', index: 'int') -> 'tuple[bytes, bytes]'` | Derive one BIP-32 private child. Rare invalid-child cases raise explicitly. |
| `derive_child_public` | `derive_child_public(parent_public_key: 'bytes', chain_code: 'bytes', index: 'int') -> 'tuple[bytes, bytes]'` | BIP-32 CKDpub: derive a non-hardened child public key from a parent public key. |
| `derive_private_path` | `derive_private_path(seed: 'bytes', path: 'str') -> 'tuple[bytes, bytes]'` | Derive a private extended key at a path; returns key and chain code. |
| `DerivedAddress` | `class DerivedAddress(account: 'int', address_index: 'int', path: 'str', public_key: 'bytes', hash160: 'bytes', address: 'str') -> None` | DerivedAddress(account: 'int', address_index: 'int', path: 'str', public_key: 'bytes', hash160: 'bytes', address: 'str') |
| `DerivedTaprootAddress` | `class DerivedTaprootAddress(account: 'int', address_index: 'int', path: 'str', internal_key_x: 'bytes', output_key_x: 'bytes', address: 'str') -> None` | DerivedTaprootAddress(account: 'int', address_index: 'int', path: 'str', internal_key_x: 'bytes', output_key_x: 'bytes', address: 'str') |
| `EXTENDED_KEY_VERSIONS` | `EXTENDED_KEY_VERSIONS = dict` |  |
| `ExtendedKey` | `class ExtendedKey(key: 'bytes', chain_code: 'bytes', is_private: 'bool', depth: 'int' = 0, parent_fingerprint: 'bytes' = b'\x00\x00\x00\x00', child_number: 'int' = 0, family: 'str' = 'x') -> None` | A BIP-32 extended private or public key. |
| `fingerprint` | `fingerprint(public_key: 'bytes') -> 'bytes'` | Return the 4-byte BIP-32 fingerprint (first bytes of the key identifier). |
| `format_path` | `format_path(indices: 'tuple[int, ...] \| list[int]') -> 'str'` | Format child indices as a BIP-32 path using the ``'`` hardened marker. |
| `HARDENED` | `HARDENED = 2147483648` |  |
| `key_identifier` | `key_identifier(public_key: 'bytes') -> 'bytes'` | Return the BIP-32 key identifier, HASH160 of the compressed public key. |
| `master_key` | `master_key(seed: 'bytes') -> 'tuple[bytes, bytes]'` | Return BIP-32 master private key and chain code. |
| `mnemonic_to_seed` | `mnemonic_to_seed(mnemonic: 'str', passphrase: 'str' = '') -> 'bytes'` | Derive the standard 64-byte BIP-39 seed (NFKD, PBKDF2-HMAC-SHA512/2048). |
| `parse_path` | `parse_path(path: 'str') -> 'tuple[int, ...]'` | Parse BIP-32 paths such as ``m/44'/0'/1'/0/5``. |
| `recover_unhardened_parent_private_key` | `recover_unhardened_parent_private_key(child_key: 'bytes', parent_chain_code: 'bytes', parent_public_key: 'bytes', index: 'int') -> 'bytes'` | Recover a BIP-32 parent private scalar from a compromised non-hardened child. |

## `keylab.encoding.taproot`

BIP-341 Taproot outputs, script trees, key-path signing.

BIP-341 Taproot output-key and script-path commitment utilities.

| Name | Signature / value | Summary |
|---|---|---|
| `build_script_tree` | `build_script_tree(tree: 'ScriptTree') -> 'BuiltScriptTree'` | Compute a script tree's Merkle root and each leaf's Merkle path. |
| `BuiltScriptTree` | `class BuiltScriptTree(merkle_root: 'bytes', leaves: 'tuple[ScriptTreeLeaf, ...]') -> None` | Merkle root and per-leaf inclusion data, in depth-first left-to-right order. |
| `lift_x` | `lift_x(x: 'int') -> 'tuple[int, int]'` | Lift an x coordinate to the even-y point, as BIP-340 and BIP-341 require. |
| `ScriptTreeLeaf` | `class ScriptTreeLeaf(leaf: 'TapLeaf', leaf_hash: 'bytes', merkle_path: 'tuple[bytes, ...]') -> None` | A leaf together with its hash and Merkle inclusion path (leaf to root). |
| `tagged_hash` | `tagged_hash(tag: 'str', message: 'bytes') -> 'bytes'` | Return ``SHA256(SHA256(tag) // SHA256(tag) // message)``. |
| `tapbranch_hash` | `tapbranch_hash(left: 'bytes', right: 'bytes') -> 'bytes'` | Combine two 32-byte Taproot nodes in lexicographic order. |
| `TapLeaf` | `class TapLeaf(script: 'bytes', leaf_version: 'int' = 192) -> None` | One script leaf in a Taproot script tree. |
| `tapleaf_hash` | `tapleaf_hash(script: 'bytes', leaf_version: 'int' = 192) -> 'bytes'` | Compute the BIP-341 TapLeaf hash using Bitcoin's CompactSize length. |
| `TAPROOT_ANNEX_TAG` | `TAPROOT_ANNEX_TAG = 80` |  |
| `taproot_control_block` | `taproot_control_block(internal_key_x: 'bytes', output_key_parity: 'int', merkle_path: 'Sequence[bytes]' = (), *, leaf_version: 'int' = 192) -> 'bytes'` | Serialize BIP-341 control block for one leaf and its Merkle path. |
| `TAPROOT_CONTROL_MAX_NODE_COUNT` | `TAPROOT_CONTROL_MAX_NODE_COUNT = 128` |  |
| `TAPROOT_HASH_TYPES` | `TAPROOT_HASH_TYPES = frozenset({0, 1, 2, 3, 129, 130, 131})` |  |
| `taproot_output` | `taproot_output(internal_key_x: 'bytes', merkle_root: 'bytes' = b'', *, network: 'str' = 'mainnet') -> 'TaprootOutput'` | Compute BIP-341 Q=P+tG from an x-only internal key. |
| `taproot_output_from_point` | `taproot_output_from_point(internal_point: 'tuple[int, int]', merkle_root: 'bytes' = b'', *, network: 'str' = 'mainnet') -> 'TaprootOutput'` | Compute Taproot output data from a known point, avoiding a redundant lift_x. |
| `taproot_script_tree_output` | `taproot_script_tree_output(internal_key_x: 'bytes', tree: 'ScriptTree \| None', *, network: 'str' = 'mainnet') -> 'tuple[TaprootOutput, tuple[bytes, ...]]'` | Build an output from an internal key and optional tree, plus control blocks per leaf. |
| `taproot_sign_key_path` | `taproot_sign_key_path(sighash: 'bytes', internal_private_scalar: 'int', merkle_root: 'bytes' = b'', *, hash_type: 'int' = 0, aux_rand: 'bytes \| None' = None) -> 'bytes'` | Produce a BIP-341 key-path witness signature over a 32-byte sighash. |
| `taproot_tweak_seckey` | `taproot_tweak_seckey(private_scalar: 'int', merkle_root: 'bytes' = b'') -> 'int'` | Return the BIP-341 tweaked secret key for a key-path spend. |
| `TaprootOutput` | `class TaprootOutput(internal_key_x: 'bytes', merkle_root: 'bytes', tweak: 'int', output_key_x: 'bytes', output_key_parity: 'int', address: 'str') -> None` | TaprootOutput(internal_key_x: 'bytes', merkle_root: 'bytes', tweak: 'int', output_key_x: 'bytes', output_key_parity: 'int', address: 'str') |
| `verify_taproot_script_path` | `verify_taproot_script_path(output_key_x: 'bytes', script: 'bytes', control_block: 'bytes') -> 'bool'` | Verify control-block commitment to an output key (not script execution). |

## `keylab.encoding.transaction`

Transaction parsing and BIP-341 signature hashing.

Minimal Bitcoin transaction parsing and BIP-341 Taproot signature hashing.

| Name | Signature / value | Summary |
|---|---|---|
| `compact_size` | `compact_size(value: 'int') -> 'bytes'` | Serialize Bitcoin's CompactSize unsigned integer. |
| `parse_transaction` | `parse_transaction(raw: 'bytes') -> 'Transaction'` | Parse a legacy or SegWit (BIP-144) serialized transaction. |
| `ser_string` | `ser_string(data: 'bytes') -> 'bytes'` | Serialize bytes with a CompactSize length prefix. |
| `SIGHASH_ALL` | `SIGHASH_ALL = 1` |  |
| `SIGHASH_ANYONECANPAY` | `SIGHASH_ANYONECANPAY = 128` |  |
| `SIGHASH_DEFAULT` | `SIGHASH_DEFAULT = 0` |  |
| `SIGHASH_NONE` | `SIGHASH_NONE = 2` |  |
| `SIGHASH_SINGLE` | `SIGHASH_SINGLE = 3` |  |
| `taproot_precomputed_hashes` | `taproot_precomputed_hashes(tx: 'Transaction', spent_outputs: 'Sequence[TxOut]') -> 'dict[str, bytes]'` | Return BIP-341's single-SHA256 transaction-wide hashes. |
| `taproot_sighash` | `taproot_sighash(tx: 'Transaction', input_index: 'int', spent_outputs: 'Sequence[TxOut]', hash_type: 'int' = 0, *, annex: 'bytes \| None' = None, leaf_hash: 'bytes \| None' = None, codesep_pos: 'int' = 4294967295) -> 'bytes'` | Return the 32-byte BIP-341 signature hash ``hash_TapSighash(0x00 // SigMsg)``. |
| `taproot_signature_message` | `taproot_signature_message(tx: 'Transaction', input_index: 'int', spent_outputs: 'Sequence[TxOut]', hash_type: 'int' = 0, *, annex: 'bytes \| None' = None, leaf_hash: 'bytes \| None' = None, codesep_pos: 'int' = 4294967295) -> 'bytes'` | Return ``0x00 // SigMsg(hash_type, ext_flag)`` from BIP-341 (and BIP-342 extension). |
| `Transaction` | `class Transaction(version: 'int', inputs: 'tuple[TxIn, ...]', outputs: 'tuple[TxOut, ...]', locktime: 'int') -> None` | Transaction(version: 'int', inputs: 'tuple[TxIn, ...]', outputs: 'tuple[TxOut, ...]', locktime: 'int') |
| `TxIn` | `class TxIn(prev_txid: 'bytes', prev_index: 'int', script_sig: 'bytes', sequence: 'int', witness: 'tuple[bytes, ...]' = ()) -> None` | TxIn(prev_txid: 'bytes', prev_index: 'int', script_sig: 'bytes', sequence: 'int', witness: 'tuple[bytes, ...]' = ()) |
| `TxOut` | `class TxOut(amount: 'int', script_pubkey: 'bytes') -> None` | TxOut(amount: 'int', script_pubkey: 'bytes') |

## `keylab.encoding.address`

Address encoding and verification.

Forward public-key/address conversion and address target-hash decoding only.

| Name | Signature / value | Summary |
|---|---|---|
| `address_belongs_to_wif` | `address_belongs_to_wif(wif: 'str', target_address: 'str') -> 'dict[str, object]'` | Check whether a supported address is one of the addresses derived from a WIF. |
| `address_to_target_hash` | `address_to_target_hash(address: 'str') -> 'bytes'` | Decode P2PKH, P2SH, P2WPKH, or P2TR payload data; never search for a preimage. |
| `derive_addresses_from_wif` | `derive_addresses_from_wif(wif: 'str', *, reveal_private: 'bool' = False) -> 'dict[str, object]'` | Derive addresses from WIF; include private hex only when explicitly requested. |
| `hash160` | `hash160(data: 'bytes') -> 'bytes'` | Return RIPEMD-160(SHA-256(data)); requires a Python/OpenSSL RIPEMD-160 provider. |
| `p2pkh_address` | `p2pkh_address(public_key: 'bytes', network: 'str' = 'mainnet') -> 'str'` | Convert a serialized public key to a Base58Check P2PKH address. |
| `p2sh_p2wpkh_address` | `p2sh_p2wpkh_address(public_key: 'bytes', network: 'str' = 'mainnet') -> 'str'` | Convert a serialized public key to a nested SegWit P2SH-P2WPKH address. |
| `p2tr_address` | `p2tr_address(internal_key_x: 'bytes', merkle_root: 'bytes' = b'', network: 'str' = 'mainnet') -> 'str'` | Build a P2TR address from an x-only internal key and optional Taproot root. |
| `p2wpkh_address` | `p2wpkh_address(public_key: 'bytes', network: 'str' = 'mainnet') -> 'str'` | Convert a serialized public key to a native SegWit P2WPKH address. |
| `verify_pubkey_from_address` | `verify_pubkey_from_address(address: 'str', public_key: 'bytes') -> 'bool'` | Verify a candidate secp256k1 public key against common Bitcoin address forms. |

## `keylab.encoding.bech32`

BIP-173 Bech32 / BIP-350 Bech32m.

Bech32/Bech32m and SegWit address encoding; this does not invert address hashes.

| Name | Signature / value | Summary |
|---|---|---|
| `BECH32` | `BECH32 = 'bech32'` |  |
| `BECH32M` | `BECH32M = 'bech32m'` |  |
| `CHARSET` | `CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'` |  |
| `convertbits` | `convertbits(data: 'bytes \| list[int]', from_bits: 'int', to_bits: 'int', pad: 'bool') -> 'list[int]'` | Convert a sequence between bit widths, rejecting invalid or non-zero padding. |
| `decode` | `decode(text: 'str') -> 'tuple[str, list[int], str]'` | Decode a Bech32 string and return its HRP, data without checksum, and checksum spec. |
| `decode_segwit_address` | `decode_segwit_address(text: 'str') -> 'tuple[str, int, bytes]'` | Decode and validate a SegWit address, including version-specific checksum rules. |
| `encode` | `encode(hrp: 'str', data: 'list[int]', spec: 'str' = 'bech32') -> 'str'` | Encode 5-bit data using the selected checksum variant. |
| `encode_segwit_address` | `encode_segwit_address(hrp: 'str', version: 'int', program: 'bytes') -> 'str'` | Encode a SegWit witness program, selecting Bech32m for witness v1 and later. |

## `keylab.encoding.base58`

Base58 and Base58Check.

Base58 and Base58Check encoding; checksum validation is error detection, not key recovery.

| Name | Signature / value | Summary |
|---|---|---|
| `ALPHABET` | `ALPHABET = str` |  |
| `b58decode` | `b58decode(text: 'str') -> 'bytes'` | Decode Base58, rejecting empty strings and characters outside the alphabet. |
| `b58encode` | `b58encode(data: 'bytes') -> 'str'` | Encode bytes as Base58 while preserving leading zero bytes. |
| `check_decode` | `check_decode(text: 'str') -> 'bytes'` | Decode Base58Check and reject truncated data or a mismatched checksum. |
| `check_encode` | `check_encode(payload: 'bytes') -> 'str'` | Append the four-byte double-SHA-256 checksum and Base58-encode the result. |

## `keylab.encoding.wif`

Wallet Import Format.

Wallet Import Format encoding and checksum validation for candidate own-wallet data.

| Name | Signature / value | Summary |
|---|---|---|
| `decode` | `decode(wif: 'str') -> 'tuple[bytes, bool, str]'` | Validate a WIF checksum and structure; return (32-byte key, compressed, network). |
| `encode` | `encode(private_key: 'bytes \| int', compressed: 'bool' = True, network: 'str' = 'mainnet') -> 'str'` | Encode a valid secp256k1 private scalar as WIF on mainnet or testnet. |

## `keylab.hashes.tagged`

BIP-340 tagged hashing.

Shared tagged SHA-256 hashing used by BIP-340 and Taproot.

| Name | Signature / value | Summary |
|---|---|---|
| `tagged_hash` | `tagged_hash(tag: 'str', message: 'bytes') -> 'bytes'` | Return ``SHA256(SHA256(tag) // SHA256(tag) // message)``. |

## `keylab.ec.division_polynomials`

Research: division polynomials over F_p.

Division polynomials for short-Weierstrass curves ``y^2 = x^3 + ax + b`` over F_p.

| Name | Signature / value | Summary |
|---|---|---|
| `curve_rhs` | `curve_rhs(a: 'int' = 0, b: 'int' = 7, p: 'int' = 115792089237316195423570985008687907853269984665640564039457584007908834671663) -> 'Poly'` | The cubic ``x^3 + ax + b``. |
| `division_polynomials` | `division_polynomials(n_max: 'int', a: 'int' = 0, b: 'int' = 7, p: 'int' = 115792089237316195423570985008687907853269984665640564039457584007908834671663) -> 'list[Poly]'` | Return the reduced division polynomials ``[f_0, f_1, ..., f_{n_max}]``. |
| `multiplication_by_n_x` | `multiplication_by_n_x(n: 'int', a: 'int' = 0, b: 'int' = 7, p: 'int' = 115792089237316195423570985008687907853269984665640564039457584007908834671663) -> 'tuple[Poly, Poly]'` | Return ``(φ_n, ψ_n^2)`` with ``x(nP) = φ_n(x) / ψ_n(x)^2``. |
| `Poly` | `Poly = list[int]` |  |
| `poly_add` | `poly_add(left: 'Sequence[int]', right: 'Sequence[int]', p: 'int') -> 'Poly'` |  |
| `poly_degree` | `poly_degree(poly: 'Sequence[int]') -> 'int'` | Degree of a trimmed polynomial; the zero polynomial has degree -1. |
| `poly_divmod` | `poly_divmod(numerator: 'Sequence[int]', divisor: 'Sequence[int]', p: 'int') -> 'tuple[Poly, Poly]'` | Polynomial long division over the prime field F_p. |
| `poly_eval` | `poly_eval(poly: 'Sequence[int]', x: 'int', p: 'int') -> 'int'` | Horner evaluation at ``x`` modulo p. |
| `poly_gcd` | `poly_gcd(left: 'Sequence[int]', right: 'Sequence[int]', p: 'int') -> 'Poly'` | Monic greatest common divisor. |
| `poly_mod` | `poly_mod(poly: 'Sequence[int]', modulus: 'Sequence[int]', p: 'int') -> 'Poly'` |  |
| `poly_monic` | `poly_monic(poly: 'Sequence[int]', p: 'int') -> 'Poly'` |  |
| `poly_mul` | `poly_mul(left: 'Sequence[int]', right: 'Sequence[int]', p: 'int') -> 'Poly'` |  |
| `poly_pow_mod` | `poly_pow_mod(base: 'Sequence[int]', exponent: 'int', modulus: 'Sequence[int]', p: 'int') -> 'Poly'` | Compute ``base^exponent mod modulus`` by square-and-multiply. |
| `poly_scale` | `poly_scale(poly: 'Sequence[int]', scalar: 'int', p: 'int') -> 'Poly'` |  |
| `poly_sub` | `poly_sub(left: 'Sequence[int]', right: 'Sequence[int]', p: 'int') -> 'Poly'` |  |
| `poly_trim` | `poly_trim(poly: 'Sequence[int]', p: 'int') -> 'Poly'` | Reduce coefficients mod p and drop leading zeros (``[]`` is the zero polynomial). |
| `psi_squared` | `psi_squared(n: 'int', a: 'int' = 0, b: 'int' = 7, p: 'int' = 115792089237316195423570985008687907853269984665640564039457584007908834671663, table: 'Sequence[Poly] \| None' = None) -> 'Poly'` | Return ψ_n^2 as a polynomial in x. |
| `x_of_multiple` | `x_of_multiple(n: 'int', x: 'int', a: 'int' = 0, b: 'int' = 7, p: 'int' = 115792089237316195423570985008687907853269984665640564039457584007908834671663) -> 'int \| None'` | Evaluate ``x(nP)`` from ``x(P)`` alone; ``None`` means nP is the point at infinity. |

## `keylab.ec.quartic`

Research: doubling-quartic inversion.

Quartic inversion of the doubling map on ``y^2 = x^3 + ax + b`` (secp256k1 by default).

| Name | Signature / value | Summary |
|---|---|---|
| `doubling_quartic` | `doubling_quartic(x_q: 'int', a: 'int' = 0, b: 'int' = 7, p: 'int' = 115792089237316195423570985008687907853269984665640564039457584007908834671663) -> 'Poly'` | Coefficients (lowest degree first) of the quartic whose roots satisfy x(2H) = x_q. |
| `invert_doubling_x` | `invert_doubling_x(x_q: 'int', a: 'int' = 0, b: 'int' = 7, p: 'int' = 115792089237316195423570985008687907853269984665640564039457584007908834671663) -> 'list[QuarticRoot]'` | Solve the doubling quartic and classify each F_p root as curve or twist. |
| `QuarticRoot` | `class QuarticRoot(x: 'int', rhs: 'int', on_curve: 'bool', y_values: 'tuple[int, ...]') -> None` | One F_p root of the doubling quartic and where it lives. |
| `roots_mod_p` | `roots_mod_p(poly: 'Sequence[int]', p: 'int' = 115792089237316195423570985008687907853269984665640564039457584007908834671663) -> 'list[int]'` | Return the distinct roots in F_p of a polynomial over F_p, sorted ascending. |

## `keylab.ec.halving`

Research: point halving.

Point halving and doubling-inversion helpers.

| Name | Signature / value | Summary |
|---|---|---|
| `curve_double_affine` | `curve_double_affine(point: 'tuple[int, int] \| None', a: 'int' = 0, p: 'int' = 115792089237316195423570985008687907853269984665640564039457584007908834671663) -> 'tuple[int, int] \| None'` | Tangent-line doubling on ``y^2 = x^3 + ax + b`` (b does not appear in the formula). |
| `double_point` | `double_point(point: 'Point') -> 'Point'` | Double a secp256k1 point. |
| `doubling_preimages` | `doubling_preimages(target: 'tuple[int, int]', a: 'int' = 0, b: 'int' = 7, p: 'int' = 115792089237316195423570985008687907853269984665640564039457584007908834671663) -> 'tuple[tuple[int, int], ...]'` | Return every rational point R with 2R == target on ``y^2 = x^3 + ax + b`` over F_p. |
| `HALF_SCALAR` | `HALF_SCALAR = int` |  |
| `halve_point` | `halve_point(point: 'Point') -> 'Point'` | Return the unique secp256k1 point H with 2H == point (scalar shortcut). |
| `halve_point_via_quartic` | `halve_point_via_quartic(point: 'tuple[int, int]') -> 'tuple[int, int]'` | Halve a secp256k1 point by solving the doubling quartic (research path). |
| `halving_chain` | `halving_chain(point: 'tuple[int, int]', steps: 'int') -> 'list[tuple[int, int]]'` | Return successive halves ``Q/2, Q/4, ...`` (``steps`` entries). |

## `keylab.benchmarks`

Benchmarks.

Small reproducible performance probes for public-key conversion paths.

| Name | Signature / value | Summary |
|---|---|---|
| `available_scalar_backends` | `available_scalar_backends() -> 'tuple[str, ...]'` | List explicit scalar backends currently importable on this machine. |
| `benchmark_ec` | `benchmark_ec(*, count: 'int' = 12, seed: 'int' = 20261020, repetitions: 'int' = 5, backend: 'str' = 'all') -> 'dict[str, object]'` | Compare generator multiplication on one seeded corpus with median timings. |
| `benchmark_hash160_only` | `benchmark_hash160_only(count: 'int' = 10000, *, backend: 'str' = 'auto') -> 'dict[str, object]'` | Measure HASH160 on unique valid compressed public-key fixtures. |
| `benchmark_multiple_wifs` | `benchmark_multiple_wifs(wifs: 'Iterable[str]', *, backend: 'str' = 'auto', derive_addresses: 'bool' = True, address_types: 'Iterable[str] \| None' = None, warmup: 'int' = 3, corpus_source: 'str' = 'provided') -> 'dict[str, object]'` | Profile independent WIFs without printing or returning keys or addresses. |
| `benchmark_repeated_wifs` | `benchmark_repeated_wifs(wifs: 'Iterable[str]', *, repetitions: 'int' = 5, backend: 'str' = 'auto', derive_addresses: 'bool' = True, address_types: 'Iterable[str] \| None' = None, warmup: 'int' = 3, corpus_source: 'str' = 'provided') -> 'dict[str, object]'` | Benchmark one fixed WIF corpus repeatedly and report median timings. |
| `benchmark_signatures` | `benchmark_signatures(*, count: 'int' = 8, seed: 'int' = 20261030, repetitions: 'int' = 5, backend: 'str' = 'all') -> 'dict[str, object]'` | Time BIP-340, ECDSA, BIP-32, Taproot, and MuSig2 operations on a seeded public corpus. |
| `benchmark_synthetic_wifs` | `benchmark_synthetic_wifs(count: 'int' = 1000, *, backend: 'str' = 'auto', derive_addresses: 'bool' = True, address_types: 'Iterable[str] \| None' = None, warmup: 'int' = 3, repetitions: 'int' = 1) -> 'dict[str, object]'` | Create a random synthetic WIF corpus, then benchmark without printing keys. |
| `benchmark_wif_file` | `benchmark_wif_file(path: 'str \| Path', *, backend: 'str' = 'auto', derive_addresses: 'bool' = True, address_types: 'Iterable[str] \| None' = None, warmup: 'int' = 3, repetitions: 'int' = 1) -> 'dict[str, object]'` | Benchmark nonblank, noncomment WIF lines from a local text file. |
| `benchmark_wif_to_pubkey` | `benchmark_wif_to_pubkey(iterations: 'int' = 1000, *, warmup: 'int' = 20, backend: 'str' = 'auto') -> 'dict[str, object]'` | Time WIF decode, scalar parse, secp256k1 multiplication, compression, and hex. |
| `MUSIG2_GROUP_SIZE` | `MUSIG2_GROUP_SIZE = 3` |  |
| `SIGNATURE_OPERATIONS` | `SIGNATURE_OPERATIONS = tuple` |  |

## API stability

- **Public API.** A name is public if it is listed in its module's `__all__`
  (and therefore in this reference). Names starting with `_`, and modules or
  names not listed here, are internal and may change in any release.
- **Package re-exports.** `keylab.ec` re-exports the most used curve,
  signature, and MuSig2 names; `from keylab.ec import ...` and the full module
  path refer to the same objects.
- **Before 1.0.** KeyLab follows semantic versioning with the 0.x convention:
  a minor release (0.2 → 0.3) may change public behaviour, and every such
  change is listed under **Changed** in [CHANGELOG.md](../CHANGELOG.md). Patch
  releases (0.2.x) only fix bugs.
- **Never stable.** Benchmark report fields and teaching-trace output
  (`keylab-advanced`) are for reading, not parsing.
