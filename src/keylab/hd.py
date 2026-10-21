"""BIP-39 seed and BIP-32 private derivation helpers for secp256k1 wallets.

The module accepts already-validated mnemonic text. It intentionally does not
embed a BIP-39 word list or claim to validate mnemonic checksum bits.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from dataclasses import dataclass

from keylab.ec.sec1 import parse_sec1
from keylab.ec.secp256k1 import N, compress_pubkey, scalar_mult

HARDENED = 1 << 31


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


def master_key(seed: bytes) -> tuple[bytes, bytes]:
    """Return BIP-32 master private key and chain code."""
    if not isinstance(seed, bytes) or not 16 <= len(seed) <= 64:
        raise ValueError("BIP-32 seed must contain 16 to 64 bytes")
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    scalar = int.from_bytes(digest[:32], "big")
    if not 1 <= scalar < N:
        raise ValueError("BIP-32 master key is invalid for this seed")
    return digest[:32], digest[32:]


def derive_child_private(parent_key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    """Derive one BIP-32 private child. Rare invalid-child cases raise explicitly."""
    if len(parent_key) != 32 or len(chain_code) != 32:
        raise ValueError("parent key and chain code must each be 32 bytes")
    if type(index) is not int or not 0 <= index < 1 << 32:
        raise ValueError("child index must be in [0, 2^32-1]")
    parent_scalar = int.from_bytes(parent_key, "big")
    if not 1 <= parent_scalar < N:
        raise ValueError("parent private key is outside the secp256k1 scalar range")
    if index & HARDENED:
        data = b"\x00" + parent_key
    else:
        point = scalar_mult(parent_scalar)
        if point is None:
            raise ValueError("parent public key is point at infinity")
        data = compress_pubkey(point)
    digest = hmac.new(chain_code, data + index.to_bytes(4, "big"), hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    child = (tweak + parent_scalar) % N
    if tweak >= N or child == 0:
        raise ValueError("invalid BIP-32 child; caller must advance to the next index")
    return child.to_bytes(32, "big"), digest[32:]


def derive_private_path(seed: bytes, path: str) -> tuple[bytes, bytes]:
    """Derive a private extended key at a path; returns key and chain code."""
    key, chain = master_key(seed)
    for index in parse_path(path):
        key, chain = derive_child_private(key, chain, index)
    return key, chain


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


def derive_bip44_p2pkh(seed: bytes, account: int, address_index: int, *, network: str = "mainnet") -> DerivedAddress:
    """Derive one BIP-44 Bitcoin P2PKH address (m/44'/coin'/account'/0/index)."""
    if type(account) is not int or not 0 <= account < HARDENED:
        raise ValueError("account must be in [0, 2^31-1]")
    if type(address_index) is not int or not 0 <= address_index < HARDENED:
        raise ValueError("address index must be in [0, 2^31-1]")
    coin_type = {"mainnet": 0, "testnet": 1}.get(network)
    if coin_type is None:
        raise ValueError("network must be 'mainnet' or 'testnet'")
    path = f"m/44'/{coin_type}'/{account}'/0/{address_index}"
    key, _ = derive_private_path(seed, path)
    public_key = compress_pubkey(scalar_mult(int.from_bytes(key, "big")))
    digest = hashlib.new("ripemd160", hashlib.sha256(public_key).digest()).digest()
    from keylab.encoding.base58 import check_encode

    address = check_encode(bytes([0 if network == "mainnet" else 0x6F]) + digest)
    return DerivedAddress(account, address_index, path, public_key, digest, address)


def derive_bip86_p2tr(seed: bytes, account: int, address_index: int,
                       *, network: str = "mainnet") -> DerivedTaprootAddress:
    """Derive a BIP-86 key-path-only P2TR address (empty script-tree root)."""
    if type(account) is not int or not 0 <= account < HARDENED:
        raise ValueError("account must be in [0, 2^31-1]")
    if type(address_index) is not int or not 0 <= address_index < HARDENED:
        raise ValueError("address index must be in [0, 2^31-1]")
    coin_type = {"mainnet": 0, "testnet": 1}.get(network)
    if coin_type is None:
        raise ValueError("network must be 'mainnet' or 'testnet'")
    path = f"m/86'/{coin_type}'/{account}'/0/{address_index}"
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
    if network not in ("mainnet", "testnet"):
        raise ValueError("network must be 'mainnet' or 'testnet'")

    key, chain = master_key(seed)
    key, chain = derive_child_private(key, chain, 44 | HARDENED)
    key, chain = derive_child_private(key, chain, (0 if network == "mainnet" else 1) | HARDENED)
    results: list[DerivedAddress] = []
    from keylab.encoding.base58 import check_encode

    version = 0 if network == "mainnet" else 0x6F
    for account in range(account_count):
        account_key, account_chain = derive_child_private(key, chain, account | HARDENED)
        external_key, external_chain = derive_child_private(account_key, account_chain, 0)
        external_scalar = int.from_bytes(external_key, "big")
        external_point = scalar_mult(external_scalar)
        if external_point is None:
            raise ValueError("external-chain public key is point at infinity")
        external_pubkey = compress_pubkey(external_point)
        for address_index in range(addresses_per_account):
            child_digest = hmac.new(
                external_chain,
                external_pubkey + address_index.to_bytes(4, "big"),
                hashlib.sha512,
            ).digest()
            child_scalar = (int.from_bytes(child_digest[:32], "big") + external_scalar) % N
            if int.from_bytes(child_digest[:32], "big") >= N or child_scalar == 0:
                raise ValueError("invalid BIP-32 child; caller must advance to the next index")
            child_key = child_scalar.to_bytes(32, "big")
            public_key = compress_pubkey(scalar_mult(int.from_bytes(child_key, "big")))
            digest = hashlib.new("ripemd160", hashlib.sha256(public_key).digest()).digest()
            results.append(DerivedAddress(
                account,
                address_index,
                f"m/44'/{0 if network == 'mainnet' else 1}'/{account}'/0/{address_index}",
                public_key,
                digest,
                check_encode(bytes([version]) + digest),
            ))
    return tuple(results)


__all__ = ["DerivedAddress", "DerivedTaprootAddress", "derive_bip44_accounts", "derive_bip44_p2pkh", "derive_bip86_p2tr", "derive_child_private", "derive_private_path", "master_key", "mnemonic_to_seed", "parse_path", "recover_unhardened_parent_private_key"]
