"""Weak-RNG incremental range scan — why low-entropy / sequential keys are unsafe.

If a wallet draws private keys from a small or sequential range (a broken RNG, a
"nonce = counter" bug, a puzzle key), the keys are findable by walking the range
one step at a time. The trick is that consecutive public keys differ by exactly
``G``: ``(k+1)*G = k*G + G``. So a scan does **one** scalar multiplication to seed
``P = start*G`` and then an O(1) point addition per step, instead of a full scalar
multiplication per candidate — orders of magnitude faster.

This module demonstrates that on a **single caller-supplied target public key**
within an explicit ``[start, start+count)`` window. It is offline and bounded: it
matches a public key you already hold, teaches why sequential keys are weak, and
does not look up balances or scan the chain for funds. See ``SECURITY.md``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from keylab.ec.sec1 import parse_sec1, serialize_sec1
from keylab.ec.secp256k1 import G, N, Point, point_add_affine, scalar_mult


@dataclass(frozen=True)
class WeakRNGScanResult:
    """Outcome of an incremental public-key range scan."""

    found: bool
    private_key: int | None
    scanned: int
    start: int
    count: int
    verified: bool


def _coerce_target_point(target_pubkey: bytes | Point) -> Point:
    if isinstance(target_pubkey, (bytes, bytearray)):
        return parse_sec1(bytes(target_pubkey))
    if (
        isinstance(target_pubkey, tuple)
        and len(target_pubkey) == 2
        and all(isinstance(coord, int) for coord in target_pubkey)
    ):
        return target_pubkey
    raise TypeError("target_pubkey must be SEC1 bytes or an (x, y) point")


def incremental_pubkey_scan(
    target_pubkey: bytes | Point,
    start: int,
    count: int,
    *,
    progress: Callable[[int], None] | None = None,
) -> WeakRNGScanResult:
    """Scan ``[start, start + count)`` for the key behind ``target_pubkey``.

    Seeds ``P = start*G`` with one scalar multiplication, then advances by adding
    ``G`` each step (O(1)); on a match it returns and forward-verifies the recovered
    private key. ``progress`` (if given) is called with the running step count every
    100,000 steps. Offline and bounded by ``count``; no network or balance lookups.
    """
    if type(start) is not int or start < 0:
        raise ValueError("start must be a non-negative integer")
    if type(count) is not int or count < 1:
        raise ValueError("count must be a positive integer")
    if start + count > N:
        raise ValueError("scan window exceeds the group order N")

    target = _coerce_target_point(target_pubkey)
    point: Point = scalar_mult(start, G)
    for offset in range(count):
        if progress is not None and offset and offset % 100_000 == 0:
            progress(offset)
        if point == target:
            key = start + offset
            verified = scalar_mult(key, G) == target
            return WeakRNGScanResult(True, key, offset + 1, start, count, verified)
        point = point_add_affine(point, G)
    return WeakRNGScanResult(False, None, count, start, count, verified=False)


def pubkey_sec(private_key: int, *, compressed: bool = True) -> bytes:
    """Helper: the SEC1 public key for a private scalar (for building demo targets)."""
    if not 1 <= private_key < N:
        raise ValueError("private_key must be in [1, N)")
    return serialize_sec1(scalar_mult(private_key, G), compressed=compressed)


__all__ = [
    "WeakRNGScanResult",
    "incremental_pubkey_scan",
    "pubkey_sec",
]
