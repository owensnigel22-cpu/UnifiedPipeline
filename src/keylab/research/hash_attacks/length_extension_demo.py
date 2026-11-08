"""Merkle-Damgard length-extension demonstration (educational), reusing the core.

Mathematical role: given ``H(secret || known_message)`` and the length of the
secret (but NOT the secret), forge ``H(secret || known_message || glue || extension)``
for a chosen ``extension`` -- a structural consequence of Merkle-Damgard, needing
no search and recovering no secret. Delegates to
:func:`keylab.hashes.length_extension.sha256_length_extend`.

Scope boundary: this forges a digest for a controlled suffix; it does not recover
the secret and does not break SHA-256. The lesson is "use HMAC, not
H(secret || message)". See docs/hash_attacks.md and SECURITY.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from keylab.hashes.length_extension import sha256_length_extend

__all__ = ["LengthExtensionReport", "demonstrate_length_extension"]


@dataclass(frozen=True)
class LengthExtensionReport:
    """Result of a forge: the extended message, its forged digest, and what was used."""

    forged_message: bytes   # known_message || glue_padding || extension
    forged_digest: bytes    # H(secret || forged_message), computed without the secret
    glue_padding: bytes
    secret_used: bool       # always False -- the whole point
    note: str


def demonstrate_length_extension(
    original_digest: bytes, known_message: bytes, secret_length: int, extension: bytes
) -> LengthExtensionReport:
    """Forge ``H(secret || known_message || glue || extension)`` from ``original_digest`` alone.

    ``original_digest`` is ``H(secret || known_message)``; ``secret_length`` is the
    byte length of the unknown secret; ``extension`` is the attacker-chosen suffix.
    The secret is never supplied and never used.
    """
    if not isinstance(extension, (bytes, bytearray)):
        raise TypeError("extension must be bytes")
    result = sha256_length_extend(original_digest, bytes(known_message), secret_length, bytes(extension))
    return LengthExtensionReport(
        forged_message=result.forged_message,
        forged_digest=result.forged_digest,
        glue_padding=result.glue_padding,
        secret_used=False,
        note="forged H(secret || known_message || glue || extension) with no knowledge of the secret",
    )
