"""Faithfulness tests for the ported 19-step context-shaping solver.

The full search is impractical in pure Python (see the module note), so these
tests validate the *ported machinery* — the compression, the a-register window,
the context shaping that forces e9 = e10 = 0xffffffff, the padding algebra, the
Q-table, and the RNG — against independent references. A returned preimage is
always forward-verified by the solver itself, so correctness of the parts is what
needs pinning.
"""

from __future__ import annotations

import hashlib
import random
import time

import pytest

from keylab.hashes.reduced import sha256_reduced
from keylab.research.sha256_reduced import (
    build_q_table,
    reduced_compress,
    search_17_step_preimage,
    search_19_step_preimage,
)
from keylab.research.sha256_reduced import context_shaping as cs


def _seed_solver(target_digest: bytes) -> cs._NineteenStepSolver:
    """Replicate the IV/target a-sequence setup that the search performs."""
    solver = cs._NineteenStepSolver()
    for i, value in enumerate(cs.window_from_state(cs._IV)):
        solver.a[i] = value
    digest = tuple(int.from_bytes(target_digest[i : i + 4], "big") for i in range(0, 32, 4))
    state = tuple((digest[i] - cs._IV[i]) & 0xFFFFFFFF for i in range(8))
    for i, value in enumerate(cs.window_from_state(state)):
        solver.a[(19 - 7 + i) + cs._OFF] = value
    return solver


def _block_bytes(words: list[int]) -> bytes:
    return b"".join(w.to_bytes(4, "big") for w in words)


@pytest.mark.parametrize("rounds", [17, 18, 19, 20])
@pytest.mark.parametrize("seed", range(3))
def test_ported_compress_matches_reference(rounds: int, seed: int) -> None:
    rng = random.Random(f"{rounds}-{seed}")
    words = [rng.getrandbits(32) for _ in range(16)]
    from keylab.research.sha256_reduced import reduced_compress

    expected = reduced_compress(_block_bytes(words), rounds)
    got = cs._compress(words, rounds)
    assert _block_bytes(got) == expected


def test_splitmix64_is_deterministic() -> None:
    a = cs._SplitMix64(12345)
    b = cs._SplitMix64(12345)
    assert [a.next32() for _ in range(8)] == [b.next32() for _ in range(8)]
    assert cs._SplitMix64(1).next32() != cs._SplitMix64(2).next32()


@pytest.mark.parametrize("table_bits", [8, 12, 14])
def test_q_table_entries_are_valid_inverses(table_bits: int) -> None:
    table = build_q_table(table_bits)
    assert table
    for value, inverses in table.items():
        assert 1 <= len(inverses) <= 8
        for u in inverses:
            assert cs._q(u) == value


def test_q_table_range_validated() -> None:
    with pytest.raises(ValueError, match="table_bits"):
        build_q_table(0)
    with pytest.raises(ValueError, match="table_bits"):
        build_q_table(32)


def test_window_from_state_requires_eight_words() -> None:
    with pytest.raises(ValueError, match="8 words"):
        cs.window_from_state((1, 2, 3))


@pytest.mark.parametrize("seed", range(4))
def test_comp_context_forces_e9_e10_all_ones(seed: int) -> None:
    solver = _seed_solver(hashlib.sha256(f"comp{seed}".encode()).digest())
    rng = cs._SplitMix64(seed)
    difference = cs._setup_context(solver, rng, padded=False, kmax=8, start=time.monotonic(), time_budget=5.0)
    assert difference == 0
    assert solver.e(9) == 0xFFFFFFFF
    assert solver.e(10) == 0xFFFFFFFF


@pytest.mark.parametrize("seed", range(4))
def test_padded_context_forces_shaping_and_padding(seed: int) -> None:
    # Padded setup rejects ~255/256 draws on the 0x80 marker gate before the
    # popcount gate, so kmax is kept loose and the budget wide to keep this
    # probabilistic loop from flaking; the invariants asserted are the point.
    kmax = 14
    solver = _seed_solver(hashlib.sha256(f"pad{seed}".encode()).digest())
    rng = cs._SplitMix64(seed)
    difference = cs._setup_context(
        solver, rng, padded=True, kmax=kmax, start=time.monotonic(), time_budget=30.0
    )
    assert difference is not None
    # context shaping
    assert solver.e(9) == 0xFFFFFFFF
    assert solver.e(10) == 0xFFFFFFFF
    # padding algebra: W14 = 0, W15 = 440 (55 bytes), W13 ends in the 0x80 marker
    assert solver.w(14) == 0
    assert solver.w(15) == 440
    assert solver.w(13) & 0xFF == 0x80
    assert difference.bit_count() <= kmax


def test_search_returns_clean_result_on_small_budget() -> None:
    # A tiny budget will not find a full 19-step preimage; the result must be a
    # clean found=False, not an error or a false claim.
    target = hashlib.sha256(b"unreachable-in-budget").digest()
    result = search_19_step_preimage(
        target, mode="comp", table_bits=10, seed=1, max_contexts=1,
        chains_per_context=256, time_budget=2.0,
    )
    assert result.found is False
    assert result.verified is False
    assert result.block is None
    assert result.chains >= 0


def test_search_validates_arguments() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        search_19_step_preimage(b"\x00" * 10)
    with pytest.raises(ValueError, match="mode"):
        search_19_step_preimage(b"\x00" * 32, mode="bogus")


@pytest.mark.parametrize("label", ["kl17-live-a", "kl17-live-b"])
def test_search_17_finds_verified_compression_preimage(label: str) -> None:
    # The 17-step search is feasible in pure Python (single schedule constraint): it
    # must actually FIND a forward-verified compression preimage, live, in seconds.
    target = hashlib.sha256(label.encode()).digest()
    result = search_17_step_preimage(target, seed=1)

    assert result.found is True
    assert result.verified is True
    assert result.mode == "comp17"
    assert result.block is not None
    assert result.message is None  # a compression preimage, not a padded message
    assert len(result.block) == 64  # one 512-bit block
    # Independent forward verification: the block's 17-round compression hits target.
    assert reduced_compress(result.block, 17) == target
    # And internally consistent with the solver's own compressor.
    words = [int.from_bytes(result.block[i : i + 4], "big") for i in range(0, 64, 4)]
    out = cs._compress(words, 17)
    assert out == [int.from_bytes(target[i : i + 4], "big") for i in range(0, 32, 4)]


def test_search_17_wrong_round_count_misses_target() -> None:
    # A 17-step compression preimage is specific to 17 rounds.
    target = hashlib.sha256(b"kl17-round-specificity").digest()
    result = search_17_step_preimage(target, seed=1)
    assert result.found and result.block is not None
    assert reduced_compress(result.block, 17) == target
    assert reduced_compress(result.block, 16) != target
    assert reduced_compress(result.block, 18) != target


def test_search_17_clean_miss_on_zero_budget() -> None:
    # A zero time budget must return a clean found=False, not an error or false claim.
    target = hashlib.sha256(b"kl17-no-budget").digest()
    result = search_17_step_preimage(target, seed=1, time_budget=0.0)
    assert result.found is False
    assert result.verified is False
    assert result.block is None
    assert result.contexts == 0


def test_search_17_validates_arguments() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        search_17_step_preimage(b"\x00" * 10)
    with pytest.raises(ValueError, match="table_bits"):
        search_17_step_preimage(b"\x00" * 32, table_bits=4)
    with pytest.raises(ValueError, match="table_bits"):
        search_17_step_preimage(b"\x00" * 32, table_bits=30)
    with pytest.raises(ValueError, match="max_attempts"):
        search_17_step_preimage(b"\x00" * 32, max_attempts=0)
    with pytest.raises(ValueError, match="draws"):
        search_17_step_preimage(b"\x00" * 32, draws=0)


def test_search_found_result_would_be_verified() -> None:
    # Construct a fake solver scenario is complex; instead confirm the invariant
    # that the published 19-step block, fed through the solver's own compressor,
    # reproduces the target (the exact check the search gates every hit on).
    from keylab.research.sha256_reduced import SRW_ABC_19_STEP

    msg = SRW_ABC_19_STEP.message
    words = [int.from_bytes(msg[i : i + 4], "big") for i in range(0, 52, 4)]
    words.append(int.from_bytes(msg[52:55] + b"\x80", "big"))
    words += [0, 440]
    out = cs._compress(words, 19)
    target = [int.from_bytes(SRW_ABC_19_STEP.target[i : i + 4], "big") for i in range(0, 32, 4)]
    assert out == target
    assert sha256_reduced(msg, 19) == SRW_ABC_19_STEP.target
