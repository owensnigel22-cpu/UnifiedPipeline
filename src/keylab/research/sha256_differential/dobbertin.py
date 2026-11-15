"""Dobbertin-style reduced-round collision harness (documented scaffold only).

Hans Dobbertin's attacks on MD4/MD5 built a *collision* from a differential
characteristic by fixing a sparse input difference, then solving a system of
step equations so the difference vanishes by a chosen step. This module is the
**scaffold and test harness** for that workflow against *reduced-round* SHA-256 --
structure, bookkeeping, and a verifier -- paired with
:mod:`keylab.research.sha256_differential.trail_search`.

It is explicitly **not** a working full SHA-256 collision, and makes no such
claim. What it does provide, honestly and verifiably:

* a way to register a candidate message pair and *verify* whether it collides
  under the reduced-round compression (a real check, not an assertion), and
* a brute-force ``find_reduced_collision`` that searches a tiny, explicitly
  bounded space for a genuine collision in a very small number of rounds -- a
  concrete, reproducible example of the end state Dobbertin's method targets,
  with no claim that it scales.

Full SHA-256 collision resistance is intact; see SECURITY.md and the module
docstring of :mod:`keylab.research.sha256_differential.trail_search`.

References: Dobbertin's MD4/MD5 cryptanalysis; nahiyan/cryptanalysis,
ChakshuGupta13/lab (reduced-round SHA-256 modelling). See docs/references.md.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from keylab.research.sha256_differential.trail_search import Trail, _compress_trace

__all__ = ["CollisionCandidate", "CollisionHarness"]


def _reduced_state(block: bytes, rounds: int) -> tuple[int, ...]:
    if len(block) != 64:
        raise ValueError("block must be exactly 64 bytes")
    words = [int.from_bytes(block[offset : offset + 4], "big") for offset in range(0, 64, 4)]
    _, states = _compress_trace(words, rounds)
    return states[-1]


@dataclass(frozen=True)
class CollisionCandidate:
    """A reduced-round message pair and whether it collides (verified, not assumed)."""

    rounds: int
    first: bytes
    second: bytes
    collides: bool
    first_state: tuple[int, ...]
    second_state: tuple[int, ...]

    @property
    def distinct(self) -> bool:
        """Whether the two messages actually differ."""
        return self.first != self.second


@dataclass
class CollisionHarness:
    """Register and verify reduced-round SHA-256 collision candidates.

    This is a bookkeeping and verification scaffold around the end goal of a
    Dobbertin-style attack; it does not itself solve the step equations, and it
    claims no full-round result. ``rounds`` is the reduced round count of the
    compression (zero incoming chaining difference / IV-zero frame, matching
    :mod:`~keylab.research.sha256_differential.trail_search`).
    """

    rounds: int
    candidates: list[CollisionCandidate] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 1 <= self.rounds <= 64:
            raise ValueError("rounds must be between 1 and 64")

    def check(self, first: bytes, second: bytes) -> CollisionCandidate:
        """Verify whether two 64-byte blocks collide under the reduced compression."""
        first_state = _reduced_state(first, self.rounds)
        second_state = _reduced_state(second, self.rounds)
        candidate = CollisionCandidate(
            rounds=self.rounds,
            first=bytes(first),
            second=bytes(second),
            collides=(first != second and first_state == second_state),
            first_state=first_state,
            second_state=second_state,
        )
        self.candidates.append(candidate)
        return candidate

    def check_difference(self, base: bytes, difference: bytes) -> CollisionCandidate:
        """Verify the pair ``(base, base XOR difference)`` for a reduced collision."""
        if len(base) != 64 or len(difference) != 64:
            raise ValueError("base and difference must each be 64 bytes")
        other = bytes(x ^ y for x, y in zip(base, difference))
        return self.check(base, other)

    def check_trail(self, trail: Trail, base: bytes) -> CollisionCandidate:
        """Verify whether a trail's message difference collides for a given base block.

        A collision requires the trail's output difference to be zero; this method
        just runs the honest check and records the result.
        """
        if trail.rounds != self.rounds:
            raise ValueError("trail.rounds must match the harness rounds")
        return self.check_difference(base, trail.message_difference_bytes)

    def find_reduced_collision(
        self,
        *,
        rounds: int | None = None,
        attempts: int = 200_000,
        seed: int = 0,
    ) -> CollisionCandidate | None:
        """Brute-force a genuine collision in a very small number of rounds.

        This searches ``attempts`` random one-bit-apart message pairs for a real
        reduced-round collision. It succeeds only for tiny ``rounds`` where a
        collision is plentiful (e.g. 1 round, where only one message word is read);
        it is a concrete, reproducible demonstration of the target end state, with
        **no** claim of scaling to more rounds or to full SHA-256.
        """
        active_rounds = self.rounds if rounds is None else rounds
        if not 1 <= active_rounds <= 64:
            raise ValueError("rounds must be between 1 and 64")
        rng = random.Random(seed)
        harness = CollisionHarness(active_rounds)
        for _ in range(attempts):
            base = rng.randbytes(64)
            bit = rng.randrange(512)
            difference = bytearray(64)
            difference[bit // 8] = 1 << (bit % 8)
            candidate = harness.check_difference(base, bytes(difference))
            if candidate.collides:
                self.candidates.append(candidate)
                return candidate
        return None
