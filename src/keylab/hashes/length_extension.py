"""Educational SHA-256 length-extension demonstration; not a MAC construction."""

from __future__ import annotations

from dataclasses import dataclass

from .reduced import _sha_compress

_MAX_MESSAGE_BYTES = ((1 << 64) - 1) // 8


@dataclass(frozen=True)
class SHA256LengthExtension:
    """Forged suffix, glue padding, full message, and resulting SHA-256 digest."""

    glue_padding: bytes
    forged_message: bytes
    forged_digest: bytes


def _sha256_padding(message_length: int) -> bytes:
    if not 0 <= message_length <= _MAX_MESSAGE_BYTES:
        raise ValueError("message length must fit the SHA-256 64-bit bit-length field")
    padding = b"\x80"
    padding += b"\0" * ((56 - (message_length + 1) % 64) % 64)
    return padding + (message_length * 8).to_bytes(8, "big")


def sha256_length_extend(
    original_digest: bytes,
    known_message: bytes,
    secret_length: int,
    suffix: bytes,
) -> SHA256LengthExtension:
    """Extend ``SHA256(secret || known_message)`` without knowing the secret.

    The caller supplies the guessed secret length, as a real attack would.
    This helper is for demonstrating the weakness of secret-prefix SHA-256 MACs;
    use HMAC-SHA-256 for authentication instead.
    """
    if len(original_digest) != 32:
        raise ValueError("original_digest must be exactly 32 bytes")
    if secret_length < 0:
        raise ValueError("secret_length must be nonnegative")

    original_length = secret_length + len(known_message)
    glue_padding = _sha256_padding(original_length)
    processed_length = original_length + len(glue_padding)
    extended_length = processed_length + len(suffix)
    final_padding = _sha256_padding(extended_length)
    continuation = suffix + final_padding

    state = tuple(
        int.from_bytes(original_digest[offset : offset + 4], "big")
        for offset in range(0, 32, 4)
    )
    for offset in range(0, len(continuation), 64):
        state = _sha_compress(continuation[offset : offset + 64], state, 64)

    forged_message = known_message + glue_padding + suffix
    forged_digest = b"".join(word.to_bytes(4, "big") for word in state)
    return SHA256LengthExtension(glue_padding, forged_message, forged_digest)


__all__ = ["SHA256LengthExtension", "sha256_length_extend"]
