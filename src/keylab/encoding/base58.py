"""Base58 and Base58Check encoding; checksum validation is error detection, not key recovery."""

from __future__ import annotations

import hashlib

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {character: index for index, character in enumerate(ALPHABET)}


def _checksum(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def b58encode(data: bytes) -> str:
    """Encode bytes as Base58 while preserving leading zero bytes."""
    zeroes = len(data) - len(data.lstrip(b"\0"))
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = ALPHABET[remainder] + encoded
    return "1" * zeroes + encoded


def b58decode(text: str) -> bytes:
    """Decode Base58, rejecting empty strings and characters outside the alphabet."""
    if not text:
        raise ValueError("Base58 input must not be empty")
    value = 0
    for character in text:
        try:
            digit = _INDEX[character]
        except KeyError as exc:
            raise ValueError(f"invalid Base58 character: {character!r}") from exc
        value = value * 58 + digit
    body = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    zeroes = len(text) - len(text.lstrip("1"))
    return b"\0" * zeroes + body


def check_encode(payload: bytes) -> str:
    """Append the four-byte double-SHA-256 checksum and Base58-encode the result."""
    return b58encode(payload + _checksum(payload))


def check_decode(text: str) -> bytes:
    """Decode Base58Check and reject truncated data or a mismatched checksum."""
    decoded = b58decode(text)
    if len(decoded) < 5:
        raise ValueError("Base58Check data is too short")
    payload, supplied = decoded[:-4], decoded[-4:]
    if supplied != _checksum(payload):
        raise ValueError("Base58Check checksum mismatch")
    return payload

__all__ = [
    "ALPHABET",
    "b58decode",
    "b58encode",
    "check_decode",
    "check_encode",
]
