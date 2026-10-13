"""Wallet Import Format encoding and checksum validation for candidate own-wallet data."""

from __future__ import annotations

from keylab.encoding.base58 import check_decode, check_encode
from keylab.ec.secp256k1 import N

_VERSIONS = {"mainnet": 0x80, "testnet": 0xEF}
_NETWORKS = {version: network for network, version in _VERSIONS.items()}


def encode(private_key: bytes | int, compressed: bool = True, network: str = "mainnet") -> str:
    """Encode a valid secp256k1 private scalar as WIF on mainnet or testnet."""
    if isinstance(private_key, int):
        if not 1 <= private_key < N:
            raise ValueError("private key integer must be in [1, secp256k1 order)")
        key_bytes = private_key.to_bytes(32, "big")
    else:
        key_bytes = bytes(private_key)
        if len(key_bytes) != 32 or not 1 <= int.from_bytes(key_bytes, "big") < N:
            raise ValueError("private key must be 32 bytes and a valid secp256k1 scalar")
    try:
        version = _VERSIONS[network]
    except KeyError as exc:
        raise ValueError("network must be 'mainnet' or 'testnet'") from exc
    payload = bytes([version]) + key_bytes + (b"\x01" if compressed else b"")
    return check_encode(payload)


def decode(wif: str) -> tuple[bytes, bool, str]:
    """Validate a WIF checksum and structure; return (32-byte key, compressed, network)."""
    try:
        payload = check_decode(wif)
    except ValueError as exc:
        raise ValueError(f"invalid WIF: {exc}") from exc
    if len(payload) not in (33, 34):
        raise ValueError("invalid WIF payload length; expected 33 or 34 bytes")
    network = _NETWORKS.get(payload[0])
    if network is None:
        raise ValueError(f"unsupported WIF version byte: 0x{payload[0]:02x}")
    compressed = len(payload) == 34
    if compressed and payload[-1] != 1:
        raise ValueError("invalid compressed WIF marker; expected 0x01")
    key_bytes = payload[1:33]
    scalar = int.from_bytes(key_bytes, "big")
    if not 1 <= scalar < N:
        raise ValueError("WIF contains an invalid secp256k1 private scalar")
    return key_bytes, compressed, network