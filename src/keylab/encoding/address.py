"""Forward public-key/address conversion and address target-hash decoding only."""

from __future__ import annotations

import hashlib

from keylab.encoding import base58, bech32


def hash160(data: bytes) -> bytes:
    """Return RIPEMD-160(SHA-256(data)); requires a Python/OpenSSL RIPEMD-160 provider."""
    sha = hashlib.sha256(data).digest()
    try:
        ripemd = hashlib.new("ripemd160")
    except ValueError as exc:
        raise RuntimeError("this Python build does not provide RIPEMD-160") from exc
    ripemd.update(sha)
    return ripemd.digest()


def p2pkh_address(public_key: bytes, network: str = "mainnet") -> str:
    """Convert a serialized public key to a Base58Check P2PKH address."""
    versions = {"mainnet": 0x00, "testnet": 0x6F}
    try:
        version = versions[network]
    except KeyError as exc:
        raise ValueError("network must be 'mainnet' or 'testnet'") from exc
    return base58.check_encode(bytes([version]) + hash160(public_key))


def p2wpkh_address(public_key: bytes, network: str = "mainnet") -> str:
    """Convert a serialized public key to a native SegWit P2WPKH address."""
    hrps = {"mainnet": "bc", "testnet": "tb"}
    try:
        hrp = hrps[network]
    except KeyError as exc:
        raise ValueError("network must be 'mainnet' or 'testnet'") from exc
    return bech32.encode_segwit_address(hrp, 0, hash160(public_key))


def address_to_target_hash(address: str) -> bytes:
    """Decode a P2PKH or P2WPKH address into its 20-byte hash; never search for a preimage."""
    if "1" in address and address.lower().split("1", 1)[0] in ("bc", "tb", "bcrt"):
        hrp, version, program = bech32.decode_segwit_address(address)
        if hrp not in ("bc", "tb") or version != 0 or len(program) != 20:
            raise ValueError("only mainnet/testnet P2WPKH (witness v0, 20-byte) is supported")
        return program
    payload = base58.check_decode(address)
    if len(payload) != 21 or payload[0] not in (0x00, 0x6F):
        raise ValueError("only mainnet/testnet P2PKH addresses are supported")
    return payload[1:]