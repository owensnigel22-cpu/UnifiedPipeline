"""BIP-39 seed and BIP-32 hierarchical deterministic key helpers for secp256k1.

The module accepts already-validated mnemonic text. It intentionally does not
embed a BIP-39 word list or claim to validate mnemonic checksum bits.

Extended keys (xprv/xpub and the SLIP-132 y/z/u/v variants used by BIP-49 and
BIP-84 wallets) are modelled by :class:`ExtendedKey`, which supports private
derivation (CKDpriv), public derivation (CKDpub), fingerprints, parent
identifiers, neutering, and strict Base58Check parsing per BIP-32 test vector 5.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from dataclasses import dataclass

from keylab.ec.sec1 import parse_sec1
from keylab.ec.secp256k1 import (
    G,
    N,
    compress_pubkey,
    decompress_pubkey,
    point_add_affine,
    scalar_mult,
)
from keylab.encoding.address import hash160, p2pkh_address, p2sh_p2wpkh_address, p2wpkh_address
from keylab.encoding.base58 import check_decode, check_encode

HARDENED = 1 << 31

# Extended-key version bytes: BIP-32 (x/t) and SLIP-132 (y/u for BIP-49, z/v for BIP-84).
EXTENDED_KEY_VERSIONS: dict[str, int] = {
    "xprv": 0x0488ADE4, "xpub": 0x0488B21E,
    "tprv": 0x04358394, "tpub": 0x043587CF,
    "yprv": 0x049D7878, "ypub": 0x049D7CB2,
    "uprv": 0x044A4E28, "upub": 0x044A5262,
    "zprv": 0x04B2430C, "zpub": 0x04B24746,
    "vprv": 0x045F18BC, "vpub": 0x045F1CF6,
}
_VERSION_NAMES = {value: name for name, value in EXTENDED_KEY_VERSIONS.items()}
# Purpose -> (mainnet family, testnet family) for account-level key serialization.
_PURPOSE_FAMILIES = {44: ("x", "t"), 49: ("y", "u"), 84: ("z", "v"), 86: ("x", "t")}


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Derive the standard 64-byte BIP-39 seed (NFKD, PBKDF2-HMAC-SHA512/2048)."""
    if not isinstance(mnemonic, str) or not mnemonic.strip():
        raise ValueError("mnemonic must be a non-empty string")
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a string")
    phrase = unicodedata.normalize("NFKD", mnemonic)
    salt = "mnemonic" + unicodedata.normalize("NFKD", passphrase)
    return hashlib.pbkdf2_hmac("sha512", phrase.encode(), salt.encode(), 2048, dklen=64)


def parse_path(path: str) -> tuple[int, ...]:
    """Parse BIP-32 paths such as ``m/44'/0'/1'/0/5``."""
    if not isinstance(path, str):
        raise TypeError("path must be a string")
    parts = path.strip().split("/")
    if parts[0] not in ("m", "M"):
        raise ValueError("path must start with m")
    result: list[int] = []
    for item in parts[1:]:
        if not item:
            raise ValueError("path contains an empty component")
        hardened = item[-1:] in ("'", "h", "H")
        number = item[:-1] if hardened else item
        if not number.isdecimal():
            raise ValueError(f"invalid path component: {item!r}")
        index = int(number)
        if index >= HARDENED:
            raise ValueError("path component must be below 2^31")
        result.append(index | HARDENED if hardened else index)
    return tuple(result)


def format_path(indices: tuple[int, ...] | list[int]) -> str:
    """Format child indices as a BIP-32 path using the ``'`` hardened marker."""
    parts = ["m"]
    for index in indices:
        parts.append(f"{index - HARDENED}'" if index & HARDENED else str(index))
    return "/".join(parts)


def master_key(seed: bytes) -> tuple[bytes, bytes]:
    """Return BIP-32 master private key and chain code."""
    if not isinstance(seed, bytes) or not 16 <= len(seed) <= 64:
        raise ValueError("BIP-32 seed must contain 16 to 64 bytes")
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    scalar = int.from_bytes(digest[:32], "big")
    if not 1 <= scalar < N:
        raise ValueError("BIP-32 master key is invalid for this seed")
    return digest[:32], digest[32:]


def _ckd_priv(parent_scalar: int, parent_public: bytes | None, chain_code: bytes,
              index: int) -> tuple[int, bytes]:
    """Core CKDpriv; ``parent_public`` may be supplied to skip recomputing it."""
    if index & HARDENED:
        data = b"\x00" + parent_scalar.to_bytes(32, "big")
    else:
        if parent_public is None:
            point = scalar_mult(parent_scalar)
            if point is None:
                raise ValueError("parent public key is point at infinity")
            parent_public = compress_pubkey(point)
        data = parent_public
    digest = hmac.new(chain_code, data + index.to_bytes(4, "big"), hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    child = (tweak + parent_scalar) % N
    if tweak >= N or child == 0:
        raise ValueError("invalid BIP-32 child; caller must advance to the next index")
    return child, digest[32:]


def derive_child_private(parent_key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    """Derive one BIP-32 private child. Rare invalid-child cases raise explicitly."""
    if len(parent_key) != 32 or len(chain_code) != 32:
        raise ValueError("parent key and chain code must each be 32 bytes")
    if type(index) is not int or not 0 <= index < 1 << 32:
        raise ValueError("child index must be in [0, 2^32-1]")
    parent_scalar = int.from_bytes(parent_key, "big")
    if not 1 <= parent_scalar < N:
        raise ValueError("parent private key is outside the secp256k1 scalar range")
    child, child_chain = _ckd_priv(parent_scalar, None, chain_code, index)
    return child.to_bytes(32, "big"), child_chain


def derive_child_public(parent_public_key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    """BIP-32 CKDpub: derive a non-hardened child public key from a parent public key.

    Returns the 33-byte compressed child public key and its chain code. Public
    derivation of hardened children is impossible by design and raises.
    """
    if not isinstance(chain_code, bytes) or len(chain_code) != 32:
        raise ValueError("chain code must be 32 bytes")
    if type(index) is not int or not 0 <= index < 1 << 32:
        raise ValueError("child index must be in [0, 2^32-1]")
    if index & HARDENED:
        raise ValueError("cannot derive a hardened child from a public key")
    parent_point = parse_sec1(parent_public_key)
    digest = hmac.new(
        chain_code, compress_pubkey(parent_point) + index.to_bytes(4, "big"), hashlib.sha512
    ).digest()
    tweak = int.from_bytes(digest[:32], "big")
    if tweak >= N:
        raise ValueError("invalid BIP-32 child; caller must advance to the next index")
    child_point = point_add_affine(scalar_mult(tweak, G), parent_point)
    if child_point is None:
        raise ValueError("invalid BIP-32 child; caller must advance to the next index")
    return compress_pubkey(child_point), digest[32:]


def derive_private_path(seed: bytes, path: str) -> tuple[bytes, bytes]:
    """Derive a private extended key at a path; returns key and chain code."""
    key, chain = master_key(seed)
    for index in parse_path(path):
        key, chain = derive_child_private(key, chain, index)
    return key, chain


def key_identifier(public_key: bytes) -> bytes:
    """Return the BIP-32 key identifier, HASH160 of the compressed public key."""
    return hash160(compress_pubkey(parse_sec1(public_key)))


def fingerprint(public_key: bytes) -> bytes:
    """Return the 4-byte BIP-32 fingerprint (first bytes of the key identifier)."""
    return key_identifier(public_key)[:4]


@dataclass(frozen=True)
class ExtendedKey:
    """A BIP-32 extended private or public key.

    ``key`` is the 32-byte private key when ``is_private`` is true, otherwise
    the 33-byte compressed public key. ``family`` selects the serialization
    version: ``x``/``t`` (BIP-32 main/test), ``y``/``u`` (BIP-49), ``z``/``v`` (BIP-84).
    """

    key: bytes
    chain_code: bytes
    is_private: bool
    depth: int = 0
    parent_fingerprint: bytes = b"\x00\x00\x00\x00"
    child_number: int = 0
    family: str = "x"

    def __post_init__(self) -> None:
        if len(self.chain_code) != 32:
            raise ValueError("chain code must be 32 bytes")
        if not 0 <= self.depth <= 255:
            raise ValueError("depth must fit in one byte")
        if len(self.parent_fingerprint) != 4:
            raise ValueError("parent fingerprint must be 4 bytes")
        if not 0 <= self.child_number < 1 << 32:
            raise ValueError("child number must fit in four bytes")
        if f"{self.family}prv" not in EXTENDED_KEY_VERSIONS:
            raise ValueError(f"unknown extended-key family: {self.family!r}")
        if self.is_private:
            if len(self.key) != 32 or not 1 <= int.from_bytes(self.key, "big") < N:
                raise ValueError("private key must be 32 bytes in [1, N-1]")
        else:
            if len(self.key) != 33:
                raise ValueError("public key must be 33-byte compressed SEC1")
            decompress_pubkey(self.key)
        if self.depth == 0 and (self.parent_fingerprint != b"\x00" * 4 or self.child_number):
            raise ValueError("a depth-0 key must have a zero parent fingerprint and index")

    @classmethod
    def from_seed(cls, seed: bytes, *, family: str = "x") -> ExtendedKey:
        """Create the master extended private key for ``seed``."""
        key, chain = master_key(seed)
        return cls(key, chain, True, family=family)

    @property
    def public_key(self) -> bytes:
        """The 33-byte compressed public key."""
        if not self.is_private:
            return self.key
        point = scalar_mult(int.from_bytes(self.key, "big"))
        assert point is not None
        return compress_pubkey(point)

    @property
    def identifier(self) -> bytes:
        """HASH160 of the public key (BIP-32 key identifier)."""
        return hash160(self.public_key)

    @property
    def fingerprint(self) -> bytes:
        """First four bytes of :attr:`identifier`."""
        return self.identifier[:4]

    @property
    def version_name(self) -> str:
        return f"{self.family}{'prv' if self.is_private else 'pub'}"

    def neuter(self) -> ExtendedKey:
        """Return the corresponding extended public key (BIP-32 ``N()``)."""
        return ExtendedKey(self.public_key, self.chain_code, False, self.depth,
                           self.parent_fingerprint, self.child_number, self.family)

    def child(self, index: int) -> ExtendedKey:
        """Derive one child; public keys use CKDpub and cannot derive hardened children."""
        if self.depth == 255:
            raise ValueError("maximum BIP-32 depth reached")
        if type(index) is not int or not 0 <= index < 1 << 32:
            raise ValueError("child index must be in [0, 2^32-1]")
        if self.is_private:
            scalar, chain = _ckd_priv(int.from_bytes(self.key, "big"), self.public_key,
                                      self.chain_code, index)
            key = scalar.to_bytes(32, "big")
        else:
            key, chain = derive_child_public(self.key, self.chain_code, index)
        return ExtendedKey(key, chain, self.is_private, self.depth + 1, self.fingerprint,
                           index, self.family)

    def derive(self, path: str) -> ExtendedKey:
        """Apply each component of ``path`` starting from this key.

        ``m/...`` keeps the key type. ``M/...`` is BIP-32 notation for the
        public key ``N(m/...)``, so it returns the extended public key.
        """
        node = self
        for index in parse_path(path):
            node = node.child(index)
        return node.neuter() if path.strip().startswith("M") else node

    def with_family(self, family: str) -> ExtendedKey:
        """Return the same key re-labelled for another SLIP-132 serialization family."""
        return ExtendedKey(self.key, self.chain_code, self.is_private, self.depth,
                           self.parent_fingerprint, self.child_number, family)

    def serialize(self) -> str:
        """Serialize as Base58Check (78-byte payload)."""
        key_data = b"\x00" + self.key if self.is_private else self.key
        payload = (
            EXTENDED_KEY_VERSIONS[self.version_name].to_bytes(4, "big")
            + bytes([self.depth])
            + self.parent_fingerprint
            + self.child_number.to_bytes(4, "big")
            + self.chain_code
            + key_data
        )
        return check_encode(payload)

    @classmethod
    def parse(cls, text: str) -> ExtendedKey:
        """Parse and fully validate a Base58Check extended key."""
        payload = check_decode(text)
        if len(payload) != 78:
            raise ValueError("extended key payload must be 78 bytes")
        version = int.from_bytes(payload[:4], "big")
        name = _VERSION_NAMES.get(version)
        if name is None:
            raise ValueError("unknown extended key version")
        is_private = name.endswith("prv")
        depth = payload[4]
        parent = payload[5:9]
        child_number = int.from_bytes(payload[9:13], "big")
        chain = payload[13:45]
        key_data = payload[45:]
        if is_private:
            if key_data[0] != 0:
                raise ValueError("private extended key must start with 0x00 key prefix")
            key = key_data[1:]
        else:
            if key_data[0] not in (2, 3):
                raise ValueError("public extended key must hold a compressed public key")
            key = key_data
        try:
            return cls(key, chain, is_private, depth, parent, child_number, name[0])
        except ValueError as exc:
            raise ValueError(f"invalid extended key: {exc}") from exc


def recover_unhardened_parent_private_key(
    child_key: bytes, parent_chain_code: bytes, parent_public_key: bytes, index: int
) -> bytes:
    """Recover a BIP-32 parent private scalar from a compromised non-hardened child.

    This requires the child private key, parent chain code and parent public
    key, and a non-hardened child index. It cannot recover a parent across a
    hardened edge. The function is useful for demonstrating BIP-32's
    non-hardened compromise relationship and is intentionally explicit about
    its required sensitive child-key input.
    """
    if not isinstance(child_key, bytes) or len(child_key) != 32:
        raise ValueError("child private key must be exactly 32 bytes")
    if not isinstance(parent_chain_code, bytes) or len(parent_chain_code) != 32:
        raise ValueError("parent chain code must be exactly 32 bytes")
    if type(index) is not int or not 0 <= index < HARDENED:
        raise ValueError("parent recovery requires a non-hardened index in [0, 2^31-1]")
    child_scalar = int.from_bytes(child_key, "big")
    if not 1 <= child_scalar < N:
        raise ValueError("child private key is outside the secp256k1 scalar range")
    parent_point = parse_sec1(parent_public_key)
    digest = hmac.new(
        parent_chain_code,
        compress_pubkey(parent_point) + index.to_bytes(4, "big"),
        hashlib.sha512,
    ).digest()
    tweak = int.from_bytes(digest[:32], "big")
    if tweak >= N:
        raise ValueError("invalid BIP-32 child tweak")
    parent_scalar = (child_scalar - tweak) % N
    if parent_scalar == 0:
        raise ValueError("recovered parent private key is zero")
    return parent_scalar.to_bytes(32, "big")


@dataclass(frozen=True)
class DerivedAddress:
    account: int
    address_index: int
    path: str
    public_key: bytes
    hash160: bytes
    address: str


@dataclass(frozen=True)
class DerivedTaprootAddress:
    account: int
    address_index: int
    path: str
    internal_key_x: bytes
    output_key_x: bytes
    address: str


def _coin_type(network: str) -> int:
    coin_type = {"mainnet": 0, "testnet": 1}.get(network)
    if coin_type is None:
        raise ValueError("network must be 'mainnet' or 'testnet'")
    return coin_type


def _check_account_args(account: int, address_index: int, change: int) -> None:
    if type(account) is not int or not 0 <= account < HARDENED:
        raise ValueError("account must be in [0, 2^31-1]")
    if type(address_index) is not int or not 0 <= address_index < HARDENED:
        raise ValueError("address index must be in [0, 2^31-1]")
    if change not in (0, 1):
        raise ValueError("change must be 0 (receiving) or 1 (change)")


def _bip43_path(purpose: int, network: str, account: int, change: int, address_index: int) -> str:
    return f"m/{purpose}'/{_coin_type(network)}'/{account}'/{change}/{address_index}"


def _derive_public_key(seed: bytes, path: str) -> bytes:
    key, _ = derive_private_path(seed, path)
    point = scalar_mult(int.from_bytes(key, "big"))
    if point is None:
        raise ValueError("derived public key is point at infinity")
    return compress_pubkey(point)


def derive_account_key(seed: bytes, purpose: int, account: int = 0, *,
                       network: str = "mainnet") -> ExtendedKey:
    """Return the account-level extended private key ``m/purpose'/coin'/account'``.

    The serialization family follows the purpose: BIP-44/86 use xprv/tprv,
    BIP-49 uses yprv/uprv, and BIP-84 uses zprv/vprv (SLIP-132).
    """
    if purpose not in _PURPOSE_FAMILIES:
        raise ValueError("purpose must be 44, 49, 84, or 86")
    if type(account) is not int or not 0 <= account < HARDENED:
        raise ValueError("account must be in [0, 2^31-1]")
    family = _PURPOSE_FAMILIES[purpose][_coin_type(network)]
    root = ExtendedKey.from_seed(seed, family=family)
    return root.derive(f"m/{purpose}'/{_coin_type(network)}'/{account}'")


def derive_bip44_p2pkh(seed: bytes, account: int, address_index: int, *, network: str = "mainnet",
                       change: int = 0) -> DerivedAddress:
    """Derive one BIP-44 Bitcoin P2PKH address (m/44'/coin'/account'/change/index)."""
    _check_account_args(account, address_index, change)
    path = _bip43_path(44, network, account, change, address_index)
    public_key = _derive_public_key(seed, path)
    return DerivedAddress(account, address_index, path, public_key, hash160(public_key),
                          p2pkh_address(public_key, network))


def derive_bip49_p2sh_p2wpkh(seed: bytes, account: int, address_index: int, *,
                             network: str = "mainnet", change: int = 0) -> DerivedAddress:
    """Derive one BIP-49 nested-SegWit P2SH-P2WPKH address (m/49'/coin'/account'/change/index).

    ``hash160`` is the key hash inside the P2WPKH redeem script.
    """
    _check_account_args(account, address_index, change)
    path = _bip43_path(49, network, account, change, address_index)
    public_key = _derive_public_key(seed, path)
    return DerivedAddress(account, address_index, path, public_key, hash160(public_key),
                          p2sh_p2wpkh_address(public_key, network))


def derive_bip84_p2wpkh(seed: bytes, account: int, address_index: int, *,
                        network: str = "mainnet", change: int = 0) -> DerivedAddress:
    """Derive one BIP-84 native SegWit P2WPKH address (m/84'/coin'/account'/change/index)."""
    _check_account_args(account, address_index, change)
    path = _bip43_path(84, network, account, change, address_index)
    public_key = _derive_public_key(seed, path)
    return DerivedAddress(account, address_index, path, public_key, hash160(public_key),
                          p2wpkh_address(public_key, network))


def derive_bip86_p2tr(seed: bytes, account: int, address_index: int,
                       *, network: str = "mainnet", change: int = 0) -> DerivedTaprootAddress:
    """Derive a BIP-86 key-path-only P2TR address (empty script-tree root)."""
    _check_account_args(account, address_index, change)
    path = _bip43_path(86, network, account, change, address_index)
    key, _ = derive_private_path(seed, path)
    point = scalar_mult(int.from_bytes(key, "big"))
    if point is None:
        raise ValueError("derived public key is point at infinity")
    internal_x = point[0].to_bytes(32, "big")
    from keylab.encoding.taproot import taproot_output_from_point

    output = taproot_output_from_point(point, network=network)
    return DerivedTaprootAddress(account, address_index, path, internal_x,
                                 output.output_key_x, output.address)


def derive_bip44_accounts(seed: bytes, account_count: int, addresses_per_account: int,
                          *, network: str = "mainnet") -> tuple[DerivedAddress, ...]:
    """Derive a deterministic account/address batch while reusing each account node.

    This avoids repeating PBKDF2, master-key derivation, and hardened account
    derivation for every address, which is the relevant optimization for
    multi-account benchmarks. It returns public data only; private keys stay
    out of the result.
    """
    if type(account_count) is not int or account_count < 0:
        raise ValueError("account_count must be nonnegative")
    if type(addresses_per_account) is not int or addresses_per_account < 0:
        raise ValueError("addresses_per_account must be nonnegative")
    if account_count >= HARDENED or addresses_per_account >= HARDENED:
        raise ValueError("batch counts must be below 2^31")
    coin_type = _coin_type(network)

    key, chain = master_key(seed)
    key, chain = derive_child_private(key, chain, 44 | HARDENED)
    key, chain = derive_child_private(key, chain, coin_type | HARDENED)
    results: list[DerivedAddress] = []
    for account in range(account_count):
        account_key, account_chain = derive_child_private(key, chain, account | HARDENED)
        external_key, external_chain = derive_child_private(account_key, account_chain, 0)
        external_scalar = int.from_bytes(external_key, "big")
        external_point = scalar_mult(external_scalar)
        if external_point is None:
            raise ValueError("external-chain public key is point at infinity")
        # Reuse the external node's public key for every address child.
        external_pubkey = compress_pubkey(external_point)
        for address_index in range(addresses_per_account):
            child_scalar, _ = _ckd_priv(external_scalar, external_pubkey, external_chain,
                                        address_index)
            child_point = scalar_mult(child_scalar)
            assert child_point is not None
            public_key = compress_pubkey(child_point)
            results.append(DerivedAddress(
                account,
                address_index,
                f"m/44'/{coin_type}'/{account}'/0/{address_index}",
                public_key,
                hash160(public_key),
                p2pkh_address(public_key, network),
            ))
    return tuple(results)


__all__ = [
    "EXTENDED_KEY_VERSIONS",
    "HARDENED",
    "DerivedAddress",
    "DerivedTaprootAddress",
    "ExtendedKey",
    "derive_account_key",
    "derive_bip44_accounts",
    "derive_bip44_p2pkh",
    "derive_bip49_p2sh_p2wpkh",
    "derive_bip84_p2wpkh",
    "derive_bip86_p2tr",
    "derive_child_private",
    "derive_child_public",
    "derive_private_path",
    "fingerprint",
    "format_path",
    "key_identifier",
    "master_key",
    "mnemonic_to_seed",
    "parse_path",
    "recover_unhardened_parent_private_key",
]
