"""Brute-force pre-image of a *truncated* SHA-256 digest (educational).

Mathematical role: find a message whose SHA-256 (or reduced-round) digest matches
a target in its first ``bits`` bits, by trying ``~2**bits`` candidate messages.
The cost is an explicit, measured ``2**bits``; the full 256-bit pre-image is
``2**256`` (~10^60 years) and is **never** attempted.

Scope boundary: ``bits`` is required and hard-capped at 40 — above that the
function **raises** rather than starting an infeasible search. This resolves only
a short truncated prefix (a teaching measurement of the pre-image wall), never a
full digest and never a real key. See docs/hash_attacks.md and SECURITY.md.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from keylab.hashes.reduced import sha256_reduced

__all__ = ["MAX_BITS", "PreimageResult", "find_truncated_preimage", "truncated_prefix"]

MAX_BITS = 40  # hard cap: 2**40 ~ 10^12 hashes; above this is the wall, refused


@dataclass(frozen=True)
class PreimageResult:
    """A found truncated pre-image: ``message`` whose digest matches ``bits`` of the target."""

    message: bytes
    tries: int
    bits: int
    rounds: int


def _digest(message: bytes, rounds: int) -> bytes:
    return hashlib.sha256(message).digest() if rounds == 64 else sha256_reduced(message, rounds)


def truncated_prefix(digest: bytes, bits: int) -> int:
    """Return the first ``bits`` bits of a 32-byte digest as an int (MSB-first)."""
    return int.from_bytes(digest, "big") >> (len(digest) * 8 - bits)


def _candidate(counter: int) -> bytes:
    return counter.to_bytes(8, "big")


def find_truncated_preimage(
    target: bytes,
    *,
    bits: int,
    rounds: int = 64,
    start: int = 0,
    max_tries: int | None = None,
    workers: int = 1,
) -> PreimageResult | None:
    """Search for a message whose digest matches ``target`` in its first ``bits`` bits.

    ``rounds`` selects full SHA-256 (64) or a reduced-round variant. ``workers > 1``
    splits the counter range across stdlib ``multiprocessing`` processes (stride by
    worker index), first hit wins. Returns a forward-verified :class:`PreimageResult`
    or ``None`` within ``max_tries``.
    """
    if type(bits) is not int or not 1 <= bits <= MAX_BITS:
        raise ValueError(f"bits is required and must be an int in [1, {MAX_BITS}] (the hard cap)")
    if type(rounds) is not int or not 1 <= rounds <= 64:
        raise ValueError("rounds must be an int in [1, 64]")
    if not isinstance(target, (bytes, bytearray)) or len(target) * 8 < bits:
        raise ValueError("target must be bytes with at least `bits` bits")
    if type(start) is not int or start < 0:
        raise ValueError("start must be a non-negative int")
    if type(workers) is not int or workers < 1:
        raise ValueError("workers must be a positive int")
    budget = max_tries if max_tries is not None else (1 << bits) * 64
    if type(budget) is not int or budget < 1:
        raise ValueError("max_tries must be a positive int")

    want = truncated_prefix(bytes(target), bits)
    if workers == 1:
        return _search(want, bits, rounds, start, budget)
    return _search_parallel(want, bits, rounds, start, budget, workers)


def _verify(message: bytes, want: int, bits: int, rounds: int) -> bool:
    return truncated_prefix(_digest(message, rounds), bits) == want  # independent recompute


def _search(want: int, bits: int, rounds: int, start: int, budget: int) -> PreimageResult | None:
    for i in range(budget):
        message = _candidate(start + i)
        if truncated_prefix(_digest(message, rounds), bits) == want:
            assert _verify(message, want, bits, rounds)
            return PreimageResult(message=message, tries=i + 1, bits=bits, rounds=rounds)
    return None


def _worker(args: tuple[int, int, int, int, int, int]) -> tuple[int, bytes] | None:
    want, bits, rounds, start, stride, budget = args
    counter = start
    for _ in range(budget):
        message = _candidate(counter)
        if truncated_prefix(_digest(message, rounds), bits) == want:
            return counter, message
        counter += stride
    return None


def _search_parallel(
    want: int, bits: int, rounds: int, start: int, budget: int, workers: int
) -> PreimageResult | None:
    import multiprocessing as mp

    per = budget // workers + 1
    tasks = [(want, bits, rounds, start + i, workers, per) for i in range(workers)]
    with mp.Pool(workers) as pool:
        hits = [h for h in pool.imap_unordered(_worker, tasks) if h is not None]
    if not hits:
        return None
    counter, message = min(hits)  # smallest counter is the canonical first hit
    tries = (counter - start) // workers + 1
    assert _verify(message, want, bits, rounds)
    return PreimageResult(message=message, tries=tries, bits=bits, rounds=rounds)
