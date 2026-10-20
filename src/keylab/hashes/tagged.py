"""Shared tagged SHA-256 hashing used by BIP-340 and Taproot."""

from __future__ import annotations

import hashlib
from functools import lru_cache


@lru_cache(maxsize=64)
def _tag_digest(tag: str) -> bytes:
    """Cache the fixed SHA-256 digest prefix for frequently reused tags."""
    return hashlib.sha256(tag.encode("ascii")).digest()


def tagged_hash(tag: str, message: bytes) -> bytes:
    """Return ``SHA256(SHA256(tag) || SHA256(tag) || message)``."""
    digest = _tag_digest(tag)
    return hashlib.sha256(digest + digest + message).digest()


__all__ = ["tagged_hash"]
