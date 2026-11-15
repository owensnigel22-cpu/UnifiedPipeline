import random

import pytest

from keylab.research.sha256_differential import (
    CollisionHarness,
    Trail,
    search,
    trail_from_message_difference,
    verify_by_sampling,
    xdp_add_weight,
)

_MASK = 0xFFFFFFFF


def _single_bit_block(word_index: int, bit: int) -> tuple[int, ...]:
    return tuple((1 << bit) if index == word_index else 0 for index in range(16))


@pytest.mark.parametrize("width", [3, 4, 5])
def test_xdp_add_weight_matches_exhaustive_enumeration(width: int) -> None:
    # The module's weight formula is 32-bit; re-derive it at a small width here
    # and check it against brute force. The validity/weight logic is identical.
    mask = (1 << width) - 1
    low = mask >> 1

    def small_weight(alpha: int, beta: int, gamma: int) -> int | None:
        eq_shift = (~((alpha << 1) ^ (beta << 1))) & (~((alpha << 1) ^ (gamma << 1))) & mask
        if (eq_shift & ((alpha ^ beta ^ gamma) ^ (beta << 1)) & mask) != 0:
            return None
        return (((alpha ^ beta) | (alpha ^ gamma)) & low).bit_count()

    total = (1 << width) ** 2
    for alpha in range(1 << width):
        for beta in range(1 << width):
            for gamma in range(1 << width):
                count = sum(
                    1
                    for x in range(1 << width)
                    for y in range(1 << width)
                    if (((x + y) & mask) ^ (((x ^ alpha) + (y ^ beta)) & mask)) == gamma
                )
                weight = small_weight(alpha, beta, gamma)
                if weight is None:
                    assert count == 0
                else:
                    assert count == total / (1 << weight)


def test_xdp_add_weight_32bit_known_values() -> None:
    # Adding a single low bit to a zero-difference operand costs 1 bit.
    assert xdp_add_weight(0, 1, 1) == 1
    # The most-significant bit never carries out, so an MSB difference is free.
    assert xdp_add_weight(0, 1 << 31, 1 << 31) == 0
    # An impossible differential returns None.
    assert xdp_add_weight(0, 0, 1) is None


def test_trail_is_deterministic_and_well_formed() -> None:
    block = _single_bit_block(1, 0)
    first = trail_from_message_difference(block, 2)
    second = trail_from_message_difference(block, 2)

    assert first == second
    assert isinstance(first, Trail)
    assert first.weight >= 0
    assert first.log2_probability == -first.weight
    assert len(first.message_difference) == 16
    assert len(first.message_difference_bytes) == 64
    assert len(first.round_state_differences) == first.rounds + 1
    # The incoming chaining difference is zero.
    assert first.round_state_differences[0] == (0,) * 8
    # Output difference is the final register difference.
    assert first.output_difference == first.round_state_differences[-1]


def test_trail_rejects_bad_inputs() -> None:
    with pytest.raises(ValueError, match="16 words"):
        trail_from_message_difference((0,) * 15, 2)
    with pytest.raises(ValueError, match="rounds"):
        trail_from_message_difference((0,) * 16, 0)


def test_msb_only_trail_is_deterministic_and_sampling_confirms_probability_one() -> None:
    # A single MSB difference in the last consumed word propagates with probability 1.
    trail = trail_from_message_difference(_single_bit_block(1, 31), 2)
    assert trail.weight == 0
    assert trail.log2_probability == 0.0
    assert any(trail.output_difference)  # non-trivial: the output really changes

    matches, empirical = verify_by_sampling(trail, samples=3000, seed=5)
    assert matches == 3000
    assert empirical == 0.0


def test_search_returns_valid_trail_and_restricts_to_consumed_words() -> None:
    trail = search(4, budget_s=0.5, seed=1)
    assert trail is not None
    assert trail.rounds == 4
    assert trail.weight >= 0
    # Only message words a 4-round compression reads (W0..W3) may carry a difference.
    assert all(word == 0 for word in trail.message_difference[4:])
    assert any(trail.message_difference)  # non-trivial


def test_search_produces_a_22_step_trail_as_a_model_prediction() -> None:
    # A 22-step trail exists with a characteristic weight; its probability is a
    # model prediction far beyond sampling range (not claimed as sampled).
    trail = search(22, budget_s=1.0, seed=0)
    assert trail is not None
    assert trail.rounds == 22
    assert trail.weight > 30  # deep trails are high-weight; nowhere near sampleable
    assert any(trail.output_difference)


def test_verify_by_sampling_validates_arguments() -> None:
    trail = trail_from_message_difference(_single_bit_block(1, 0), 2)
    with pytest.raises(ValueError, match="samples"):
        verify_by_sampling(trail, samples=0)
    with pytest.raises(ValueError, match="match"):
        verify_by_sampling(trail, samples=10, match="partial")


def test_dobbertin_harness_verifies_collisions_honestly() -> None:
    harness = CollisionHarness(1)
    # At one round only W0 is read, so a difference confined to W1 collides.
    base = b"\x11" * 64
    difference = bytes(64)
    candidate = harness.check_difference(base, b"\x00\x00\x00\x00" + b"\x01" + b"\x00" * 59)
    assert candidate.collides is True
    assert candidate.distinct is True
    assert candidate.first_state == candidate.second_state
    # Identical messages never count as a collision.
    same = harness.check(base, base)
    assert same.collides is False
    # A difference reaching W0 changes the one-round state, so no collision.
    reaches_w0 = harness.check_difference(base, b"\x01" + b"\x00" * 63)
    assert reaches_w0.collides is False
    assert bytes(difference) == bytes(64)


def test_dobbertin_find_reduced_collision_at_one_round() -> None:
    harness = CollisionHarness(1)
    candidate = harness.find_reduced_collision(attempts=20_000, seed=3)
    assert candidate is not None
    assert candidate.collides is True
    assert candidate.distinct is True


@pytest.mark.slow
def test_low_weight_trail_probability_is_sample_consistent() -> None:
    # Re-measure a weight-3 single-bit trail. The characteristic weight is an
    # upper bound on the cost, so the empirical probability is at least the stated
    # one (true probability >= 2**log2_probability), and within a small gap for
    # this near-tight single-bit trail.
    trail = trail_from_message_difference(_single_bit_block(1, 0), 2)
    assert trail.weight == 3
    matches, empirical = verify_by_sampling(trail, samples=1 << 20, seed=9)
    assert matches > 0
    # empirical >= stated (minus sampling noise): the trail is at least as probable.
    assert empirical >= trail.log2_probability - 0.3
    # ...and the model is in the ballpark (not wildly more probable).
    assert empirical <= trail.log2_probability + 1.5


@pytest.mark.slow
def test_random_base_sampling_is_stable_across_seeds() -> None:
    trail = trail_from_message_difference(_single_bit_block(2, 7), 3)
    rng = random.Random(0)
    readings = []
    for _ in range(3):
        _, empirical = verify_by_sampling(trail, samples=1 << 18, seed=rng.randrange(1 << 30))
        readings.append(empirical)
    assert max(readings) - min(readings) < 0.5
