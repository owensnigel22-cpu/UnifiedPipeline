"""Constant-time byte comparison (leaf utility).

A single shared helper so callers do not reach for ``hmac.compare_digest``
directly. This is a dependency-free leaf module: it must not import any other
``keylab`` module, so hash/MAC code can use it without depending on the crypto
policy module.

Teaching/reference code: it wraps the standard library's constant-time primitive
(:func:`hmac.compare_digest`) and provides no timing guarantee beyond what the
stdlib provides, and no secure erasure. See SECURITY.md.
"""

from __future__ import annotations

import hmac


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Return whether two byte strings are equal, in constant time.

    Rejects non-bytes input with :class:`TypeError`. A length mismatch returns
    ``False`` (it does not raise and does not short-circuit on the first byte),
    because :func:`hmac.compare_digest` compares without leaking which position
    differed.
    """
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        raise TypeError("constant_time_equal requires bytes-like inputs")
    return hmac.compare_digest(bytes(a), bytes(b))


__all__ = ["constant_time_equal"]
