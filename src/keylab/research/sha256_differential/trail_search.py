"""Heuristic XOR-differential trail search for reduced-round SHA-256 (educational).

This builds a *carryless* (XOR-linear) differential characteristic for the
reduced-round SHA-256 compression function with a difference injected in the
message block and zero difference in the incoming chaining state, then searches
by seeded random restarts for a low-weight (high-probability) one.

Probability accounting is exact and from first principles:

* **Modular addition** differences use the Lipmaa-Moriai ``xdp+`` weight (the
  characteristic always takes the carryless output ``gamma = alpha ^ beta``; its
  exact weight is counted). Validated by exhaustive enumeration in the tests.
* **Ch / Maj** use the per-bit XOR-differential distribution (bitwise), choosing
  the most probable output bit; their per-bit weights are 0 or 1.
* **Sigma/sigma** rotations and shifts are XOR-linear: differences pass with
  probability 1.

The stated ``log2_probability`` of a trail is the sum of these per-operation
weights negated -- the **characteristic (single-path) weight**. This is an
*upper bound on the true differential cost*: the true probability of the
difference pattern is **at least** ``2**log2_probability`` and is often higher,
because the per-operation events are not fully independent (standard carry/sign
dependencies). :func:`verify_by_sampling` re-measures the probability directly;
across low-weight trails the empirical probability is consistently ``>=`` the
stated one (measured gaps of +1 bit for a tight single-bit trail up to many bits
for a diffuse one). The weight-0 (MSB-only) trails are deterministic and sampling
confirms them exactly.

The search is a **heuristic** -- "best trail found", never "optimal" -- and
nothing here targets full 64-round SHA-256: the weight grows quickly with the
round count, so only low round counts have a sample-measurable probability.
Higher counts (e.g. a 22-step trail) are reported with their characteristic
weight as a **model prediction** well beyond sampling range, never claimed as
empirically sampled.

References: ChakshuGupta13/lab, nahiyan/cryptanalysis (differential modelling of
SHA-256). See docs/references.md.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from math import log2

from keylab.hashes.reduced import _SHA_K

__all__ = [
    "Trail",
    "search",
    "trail_from_message_difference",
    "verify_by_sampling",
]

_MASK = 0xFFFFFFFF
_LOW = _MASK >> 1  # bits 0..30, excluding the most-significant bit


def _ror(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & _MASK


def _small_sigma0(value: int) -> int:
    return _ror(value, 7) ^ _ror(value, 18) ^ (value >> 3)


def _small_sigma1(value: int) -> int:
    return _ror(value, 17) ^ _ror(value, 19) ^ (value >> 10)


def _big_sigma0(value: int) -> int:
    return _ror(value, 2) ^ _ror(value, 13) ^ _ror(value, 22)


def _big_sigma1(value: int) -> int:
    return _ror(value, 6) ^ _ror(value, 11) ^ _ror(value, 25)


def xdp_add_weight(alpha: int, beta: int, gamma: int) -> int | None:
    """Lipmaa-Moriai XOR-differential weight of ``alpha + beta -> gamma`` (mod 2**32).

    Returns the weight ``w`` (the differential holds with probability ``2**-w``),
    or ``None`` if the differential is impossible.
    """
    eq_shift = (~((alpha << 1) ^ (beta << 1))) & (~((alpha << 1) ^ (gamma << 1))) & _MASK
    if (eq_shift & ((alpha ^ beta ^ gamma) ^ (beta << 1)) & _MASK) != 0:
        return None
    return (((alpha ^ beta) | (alpha ^ gamma)) & _LOW).bit_count()


def _add_diff(alpha: int, beta: int) -> tuple[int, int]:
    """Carryless output difference ``alpha ^ beta`` and its exact xdp+ weight."""
    gamma = (alpha ^ beta) & _MASK
    weight = xdp_add_weight(alpha, beta, gamma)
    # The carryless output is always a feasible differential, so weight is defined.
    assert weight is not None
    return gamma, weight


# Per-bit XOR-differential output and weight for Ch and Maj, indexed by the 3
# input-bit differences. Values are (output_bit_difference, weight_bits) and were
# produced by exhaustive enumeration (see the module tests).
_CH_TABLE = {
    (0, 0, 0): (0, 0), (0, 0, 1): (0, 1), (0, 1, 0): (0, 1), (0, 1, 1): (1, 0),
    (1, 0, 0): (0, 1), (1, 0, 1): (0, 1), (1, 1, 0): (0, 1), (1, 1, 1): (0, 1),
}
_MAJ_TABLE = {
    (0, 0, 0): (0, 0), (0, 0, 1): (0, 1), (0, 1, 0): (0, 1), (0, 1, 1): (0, 1),
    (1, 0, 0): (0, 1), (1, 0, 1): (0, 1), (1, 1, 0): (0, 1), (1, 1, 1): (1, 0),
}


def _bitwise_diff(table: dict[tuple[int, int, int], tuple[int, int]], x: int, y: int, z: int) -> tuple[int, int]:
    out = 0
    weight = 0
    for bit in range(32):
        key = ((x >> bit) & 1, (y >> bit) & 1, (z >> bit) & 1)
        out_bit, bit_weight = table[key]
        out |= out_bit << bit
        weight += bit_weight
    return out, weight


@dataclass(frozen=True)
class Trail:
    """A reduced-round SHA-256 XOR-differential characteristic and its probability.

    All differences are XOR masks. ``message_difference`` is the 16-word input
    block difference; ``expanded_w_difference`` adds the schedule-expanded words;
    ``round_state_differences[k]`` is ``(dA..dH)`` before round ``k`` (index 0 is
    the all-zero incoming state), and ``output_difference`` is the 8-word
    post-feed-forward difference. ``log2_probability`` equals ``-weight``.
    """

    rounds: int
    message_difference: tuple[int, ...]
    expanded_w_difference: tuple[int, ...]
    round_state_differences: tuple[tuple[int, ...], ...]
    output_difference: tuple[int, ...]
    weight: int
    method: str
    seed: int

    @property
    def log2_probability(self) -> float:
        """Base-2 log of the characteristic (single-path) probability (``-weight``).

        An upper bound on the true differential cost: the realized difference holds
        with probability at least ``2**log2_probability`` (see the module docstring).
        """
        return float(-self.weight)

    @property
    def message_difference_bytes(self) -> bytes:
        """The 64-byte block difference (big-endian words)."""
        return b"".join(word.to_bytes(4, "big") for word in self.message_difference)

    @property
    def is_trivial(self) -> bool:
        """Whether the message difference is zero (no actual difference injected)."""
        return not any(self.message_difference)


def _expand_schedule_difference(message_difference: tuple[int, ...], rounds: int) -> tuple[tuple[int, ...], int]:
    """Propagate the message difference through the schedule; return (diffs, weight)."""
    words = list(message_difference)
    weight = 0
    for index in range(16, rounds):
        sigma1 = _small_sigma1(words[index - 2])
        sigma0 = _small_sigma0(words[index - 15])
        partial, add_weight = _add_diff(words[index - 16], sigma0)
        weight += add_weight
        partial, add_weight = _add_diff(partial, words[index - 7])
        weight += add_weight
        partial, add_weight = _add_diff(partial, sigma1)
        weight += add_weight
        words.append(partial)
    return tuple(words), weight


def trail_from_message_difference(
    message_difference: tuple[int, ...],
    rounds: int,
    *,
    method: str = "explicit",
    seed: int = 0,
) -> Trail:
    """Build the carryless differential characteristic for a fixed message difference."""
    if len(message_difference) != 16:
        raise ValueError("message_difference must be 16 words (the 512-bit block)")
    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be between 1 and 64")
    message_difference = tuple(word & _MASK for word in message_difference)

    expanded, weight = _expand_schedule_difference(message_difference, rounds)
    # Incoming chaining difference is zero.
    a = b = c = d = e = f = g = h = 0
    states: list[tuple[int, ...]] = [(a, b, c, d, e, f, g, h)]
    for index in range(rounds):
        delta_w = expanded[index]
        upper_sigma1 = _big_sigma1(e)
        choice, choice_weight = _bitwise_diff(_CH_TABLE, e, f, g)
        weight += choice_weight
        temp1, add_weight = _add_diff(h, upper_sigma1)
        weight += add_weight
        temp1, add_weight = _add_diff(temp1, choice)
        weight += add_weight
        # K has no difference; the schedule word does.
        temp1, add_weight = _add_diff(temp1, delta_w)
        weight += add_weight
        upper_sigma0 = _big_sigma0(a)
        majority, majority_weight = _bitwise_diff(_MAJ_TABLE, a, b, c)
        weight += majority_weight
        temp2, add_weight = _add_diff(upper_sigma0, majority)
        weight += add_weight
        new_a, add_weight = _add_diff(temp1, temp2)
        weight += add_weight
        new_e, add_weight = _add_diff(d, temp1)
        weight += add_weight
        a, b, c, d, e, f, g, h = new_a, a, b, c, new_e, e, f, g
        states.append((a, b, c, d, e, f, g, h))

    # Feed-forward adds the (zero-difference) incoming state: output difference is
    # the final register difference, at probability 1.
    output = (a, b, c, d, e, f, g, h)
    return Trail(
        rounds=rounds,
        message_difference=message_difference,
        expanded_w_difference=expanded,
        round_state_differences=tuple(states),
        output_difference=output,
        weight=weight,
        method=method,
        seed=seed,
    )


def _random_sparse_difference(
    rng: random.Random, max_words: int, max_bits: int, word_limit: int
) -> tuple[int, ...]:
    """A sparse difference confined to the ``word_limit`` message words a round
    count actually consumes, so a trail cannot cheat its weight to zero by hiding
    the difference in message words the reduced rounds never read."""
    words = [0] * 16
    active = rng.randint(1, max(1, min(max_words, word_limit)))
    for _ in range(active):
        index = rng.randrange(word_limit)
        bits = rng.randint(1, max_bits)
        value = 0
        for _ in range(bits):
            value |= 1 << rng.randrange(32)
        words[index] ^= value
    if not any(words):
        words[rng.randrange(word_limit)] = 1 << rng.randrange(32)
    return tuple(words)


def search(
    rounds: int,
    *,
    budget_s: float = 2.0,
    seed: int = 0,
    max_active_words: int = 2,
    max_bits_per_word: int = 2,
) -> Trail | None:
    """Search by seeded random restarts for a low-weight reduced-round trail.

    Returns the best (lowest-weight, highest-probability) characteristic found
    within ``budget_s`` seconds, or ``None`` if the budget yielded nothing. This
    is a heuristic, not an exhaustive or optimal search.
    """
    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be between 1 and 64")
    if budget_s <= 0:
        raise ValueError("budget_s must be positive")
    from time import perf_counter

    rng = random.Random(seed)
    deadline = perf_counter() + budget_s
    word_limit = min(rounds, 16)
    best: Trail | None = None
    while perf_counter() < deadline:
        difference = _random_sparse_difference(
            rng, max_active_words, max_bits_per_word, word_limit
        )
        candidate = trail_from_message_difference(
            difference, rounds, method="random-restart", seed=seed
        )
        if best is None or candidate.weight < best.weight:
            best = candidate
    return best


def _compress_trace(words16: list[int], rounds: int) -> tuple[list[int], list[tuple[int, ...]]]:
    """Reduced-round compression from the IV-zero frame, tracking schedule and states."""
    words = list(words16)
    for index in range(16, rounds):
        x, y = words[index - 15], words[index - 2]
        sigma0 = _ror(x, 7) ^ _ror(x, 18) ^ (x >> 3)
        sigma1 = _ror(y, 17) ^ _ror(y, 19) ^ (y >> 10)
        words.append((words[index - 16] + sigma0 + words[index - 7] + sigma1) & _MASK)
    a = b = c = d = e = f = g = h = 0
    states: list[tuple[int, ...]] = [(a, b, c, d, e, f, g, h)]
    for index in range(rounds):
        upper_sigma1 = _big_sigma1(e)
        choice = (e & f) ^ (~e & g)
        temp1 = (h + upper_sigma1 + choice + _SHA_K[index] + words[index]) & _MASK
        upper_sigma0 = _big_sigma0(a)
        majority = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (upper_sigma0 + majority) & _MASK
        a, b, c, d, e, f, g, h = (temp1 + temp2) & _MASK, a, b, c, (d + temp1) & _MASK, e, f, g
        states.append((a, b, c, d, e, f, g, h))
    return words, states


def verify_by_sampling(
    trail: Trail,
    *,
    samples: int = 1 << 20,
    seed: int = 0,
    match: str = "full",
) -> tuple[int, float]:
    """Re-measure a trail's probability by random sampling.

    For ``samples`` random base blocks, apply the trail's message difference and
    count how often the *realized* differences match the characteristic. With
    ``match="full"`` every schedule word and every per-round state difference must
    match (this is the event whose probability is ``2**log2_probability``); with
    ``match="output"`` only the output difference must match (a weaker event, an
    upper bound). Returns ``(match_count, empirical_log2_probability)`` with
    ``-inf`` when nothing matched.
    """
    if samples < 1:
        raise ValueError("samples must be positive")
    if match not in ("full", "output"):
        raise ValueError("match must be 'full' or 'output'")
    rng = random.Random(seed)
    message_difference = trail.message_difference
    matches = 0
    for _ in range(samples):
        base = [rng.getrandbits(32) for _ in range(16)]
        other = [word ^ message_difference[index] for index, word in enumerate(base)]
        base_w, base_states = _compress_trace(base, trail.rounds)
        other_w, other_states = _compress_trace(other, trail.rounds)
        if match == "output":
            if tuple((x ^ y) & _MASK for x, y in zip(base_states[-1], other_states[-1])) == trail.output_difference:
                matches += 1
            continue
        schedule_ok = all(
            ((base_w[index] ^ other_w[index]) & _MASK) == trail.expanded_w_difference[index]
            for index in range(trail.rounds)
        )
        if not schedule_ok:
            continue
        states_ok = all(
            tuple((x ^ y) & _MASK for x, y in zip(base_states[step], other_states[step]))
            == trail.round_state_differences[step]
            for step in range(trail.rounds + 1)
        )
        if states_ok:
            matches += 1
    empirical = log2(matches / samples) if matches else float("-inf")
    return matches, empirical
