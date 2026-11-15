"""A small, dependency-free Bloom filter for fast membership pre-screening.

Used to pre-screen derived HASH160s against a large target set before the exact
(and more expensive) set-membership confirmation. A Bloom filter has **no false
negatives** -- if an item was added, ``item in filter`` is always ``True`` -- and a
tunable false-positive rate, so it only ever lets extra candidates through to the
exact check, never hides a real match.

Pure Python, standard library only. Hashing uses BLAKE2b with the
Kirsch-Mitzenmacher double-hashing scheme (``h_i = h1 + i*h2``) to derive ``k``
indices from one digest.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable

__all__ = ["BloomFilter"]


class BloomFilter:
    """A classic bit-array Bloom filter keyed on ``bytes`` items."""

    def __init__(self, capacity: int, error_rate: float = 1e-6) -> None:
        if type(capacity) is not int or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        if not 0.0 < error_rate < 1.0:
            raise ValueError("error_rate must be in the open interval (0, 1)")
        self._capacity = capacity
        self._error_rate = error_rate
        self._num_bits = max(8, math.ceil(-capacity * math.log(error_rate) / (math.log(2) ** 2)))
        self._num_hashes = max(1, round(self._num_bits / capacity * math.log(2)))
        self._bits = bytearray((self._num_bits + 7) // 8)
        self._count = 0

    @classmethod
    def from_items(cls, items: Iterable[bytes], *, error_rate: float = 1e-6) -> BloomFilter:
        """Build a filter sized to ``items`` (materialized to count it) and add them."""
        materialized = [bytes(item) for item in items]
        bloom = cls(max(1, len(materialized)), error_rate=error_rate)
        for item in materialized:
            bloom.add(item)
        return bloom

    @property
    def num_bits(self) -> int:
        return self._num_bits

    @property
    def num_hashes(self) -> int:
        return self._num_hashes

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def error_rate(self) -> float:
        return self._error_rate

    def _indexes(self, item: bytes) -> Iterable[int]:
        digest = hashlib.blake2b(bytes(item), digest_size=16).digest()
        h1 = int.from_bytes(digest[:8], "big")
        h2 = int.from_bytes(digest[8:], "big") | 1  # odd stride improves distribution
        for i in range(self._num_hashes):
            yield (h1 + i * h2) % self._num_bits

    def add(self, item: bytes) -> None:
        """Add ``item`` to the filter."""
        for index in self._indexes(item):
            self._bits[index >> 3] |= 1 << (index & 7)
        self._count += 1

    def __contains__(self, item: bytes) -> bool:
        return all(
            self._bits[index >> 3] & (1 << (index & 7)) for index in self._indexes(item)
        )

    def __len__(self) -> int:
        """The number of items added (not the cardinality of the bit set)."""
        return self._count
