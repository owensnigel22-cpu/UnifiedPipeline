"""Standard-library HMAC helpers for message authentication."""

from __future__ import annotations

import hashlib
import hmac


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Return the HMAC-SHA-256 tag for a message and shared secret key."""
    return hmac.digest(key, message, hashlib.sha256)


def verify_hmac_sha256(key: bytes, message: bytes, tag: bytes) -> bool:
    """Verify an HMAC-SHA-256 tag using a constant-time comparison."""
    return hmac.compare_digest(hmac_sha256(key, message), tag)


__all__ = ["hmac_sha256", "verify_hmac_sha256"]
