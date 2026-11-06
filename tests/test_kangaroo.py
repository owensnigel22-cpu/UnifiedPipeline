"""Pollard's kangaroo for the bounded-interval ECDLP (educational recovery)."""

from __future__ import annotations

import random
import time

import pytest

from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.research.ecdlp.kangaroo import (
    KangarooResult,
    load_checkpoint,
    pollard_kangaroo,
    recover_via_kangaroo,
    save_checkpoint,
)


def test_kangaroo_recovers_k_in_small_intervals() -> None:
    rng = random.Random(7)
    for _ in range(8):
        lo = rng.randrange(1, 10_000)
        hi = lo + rng.randrange(1, 4096)
        k = rng.randrange(lo, hi + 1)
        got = pollard_kangaroo(scalar_mult(k, G), lo, hi)
        assert got == k, f"k={k} interval=[{lo},{hi}] got={got}"


def test_kangaroo_recovers_at_interval_endpoints() -> None:
    lo, hi = 1000, 1000 + 2048
    for k in (lo, hi, (lo + hi) // 2):
        assert pollard_kangaroo(scalar_mult(k, G), lo, hi) == k


def test_kangaroo_width_zero_interval() -> None:
    k = 12345
    assert pollard_kangaroo(scalar_mult(k, G), k, k) == k
    assert pollard_kangaroo(scalar_mult(k + 1, G), k, k) is None  # Q not in the singleton interval


def test_kangaroo_result_is_forward_verified() -> None:
    k = 0xC0FFEE
    lo, hi = k - 2000, k + 2000
    got = pollard_kangaroo(scalar_mult(k, G), lo, hi)
    assert got is not None and scalar_mult(got, G) == scalar_mult(k, G)


def test_kangaroo_returns_none_when_out_of_interval() -> None:
    # k is outside [lo, hi]; no collision should validate.
    k = 50_000
    assert pollard_kangaroo(scalar_mult(k, G), 1, 2048, max_steps=5000) is None


@pytest.mark.parametrize("lo,hi", [(-1, 10), (10, 5), (0, N)])
def test_kangaroo_rejects_bad_intervals(lo, hi) -> None:
    with pytest.raises((ValueError, TypeError)):
        pollard_kangaroo(scalar_mult(7, G), lo, hi)


def test_kangaroo_rejects_non_integer_bounds() -> None:
    with pytest.raises(TypeError):
        pollard_kangaroo(scalar_mult(7, G), 1.0, 10)  # type: ignore[arg-type]


def test_recover_via_kangaroo_report() -> None:
    k = 77_777
    report = recover_via_kangaroo(scalar_mult(k, G), k - 3000, k + 3000)
    assert report["found"] and report["k"] == k
    assert report["method"] == "pollard-kangaroo"
    assert report["width"] == 6000


# --- max_steps budget enforcement (regression for the inner-walk bound) --------------------------

def test_kangaroo_max_steps_bounds_inner_walk() -> None:
    # [0, 2**30) -> base_hops ~2**16; max_steps=100 must stop almost immediately.
    # WITHOUT the fix this hangs (the first tame walk runs ~2**16 hops unbounded).
    start = time.perf_counter()
    result = pollard_kangaroo(scalar_mult(5, G), 0, 2**30, max_steps=100)
    assert result is None
    assert time.perf_counter() - start < 1.0


def test_kangaroo_max_steps_preserves_success() -> None:
    # Budget comfortably above 2*sqrt(width): the happy path is unchanged.
    k = 0xABCDE  # < 2**20
    assert pollard_kangaroo(scalar_mult(k, G), 0, 2**20, max_steps=10**6) == k


def test_kangaroo_return_state_optional() -> None:
    # return_state=True -> KangarooResult; default -> bare int | None (unchanged).
    state = pollard_kangaroo(scalar_mult(5, G), 0, 2**30, max_steps=100, return_state=True)
    assert isinstance(state, KangarooResult)
    assert state.spent_steps > 0 and state.dps_found >= 0 and state.attempts_used >= 1
    assert state.solution is None
    bare = pollard_kangaroo(scalar_mult(5, G), 0, 2**30, max_steps=100)
    assert bare is None and not isinstance(bare, KangarooResult)


def test_kangaroo_progress_callback() -> None:
    seen: list[int] = []
    pollard_kangaroo(
        scalar_mult(0xBEEF, G), 0, 2**20, max_steps=10**6,
        progress_callback=lambda spent, dps: seen.append(spent), progress_every=1000,
    )
    assert seen and all(s > 0 for s in seen)


def test_kangaroo_full_group_budget() -> None:
    # The full-group ECDLP attempt, budget-bounded: spends exactly max_steps and
    # returns None (no hang). Always-on at a modest 50k-hop budget (~3-5s) so it
    # exercises the full-group bound without a skip (zero-skip CI gate).
    state = pollard_kangaroo(scalar_mult(123456, G), 0, N - 1, max_steps=50_000, return_state=True)
    assert isinstance(state, KangarooResult)
    assert state.solution is None
    assert state.spent_steps == 50_000


# --- distinguished-point (DP) table variant --------------------------------------------------

def test_kangaroo_dp_density_matches_dp_bits() -> None:
    # The density check: dp_table_size / spent_steps must track 1/2**dp_bits.
    # At dp_bits=8 that is ~0.0039; assert it lands in [1e-3, 1e-2]. Budget-bounded
    # full-group walk (tame lays DPs, wild never reached), always-on (~2-4s).
    state = pollard_kangaroo(
        scalar_mult(123456, G), 0, N - 1, dp_bits=8, max_steps=100_000, return_state=True
    )
    assert isinstance(state, KangarooResult)
    density = state.dp_table_size / state.spent_steps
    assert 1e-3 <= density <= 1e-2, f"density {density} outside [1e-3, 1e-2]"
    assert state.dps_found == state.dp_table_size  # dps_found mirrors the table
    assert state.walkers_used == 1  # single process


def test_kangaroo_dp_recovers_with_explicit_dp_bits() -> None:
    # The DP table is the actual collision mechanism: recover a known k at an
    # explicit DP density.
    k = 0xABCDE  # < 2**20
    assert pollard_kangaroo(scalar_mult(k, G), 0, 2**20, dp_bits=8) == k


def test_kangaroo_rejects_bad_dp_bits() -> None:
    for bad in (0, 257, 2.0, "8"):
        with pytest.raises((ValueError, TypeError)):
            pollard_kangaroo(scalar_mult(7, G), 1, 10, dp_bits=bad)  # type: ignore[arg-type]


def test_kangaroo_result_exposes_dp_and_state_fields() -> None:
    state = pollard_kangaroo(
        scalar_mult(0xBEEF, G), 0, 2**20, dp_bits=8, max_steps=10**6, return_state=True
    )
    assert isinstance(state, KangarooResult)
    assert state.solution == 0xBEEF
    assert state.dp_table_size >= 1
    assert state.last_hop == state.spent_steps
    assert state.elapsed_sec >= 0.0
    assert state.walkers_used == 1
    assert state.checkpoint_path is None  # none requested


# --- checkpointing (cross-platform; direct serialize/resume, no OS signal) -------------------

def test_kangaroo_checkpoint_resume_roundtrip(tmp_path) -> None:
    # A tiny budget flushes a resumable checkpoint without solving; resuming from
    # it continues the identical deterministic walk and recovers the same k a
    # single uninterrupted run finds. Cross-platform: no SIGTERM, no subprocess.
    k = 7777
    q = scalar_mult(k, G)
    lo, hi = 0, 2**16
    cp = tmp_path / "state.json"

    partial = pollard_kangaroo(q, lo, hi, dp_bits=6, max_steps=50, return_state=True, checkpoint_path=cp)
    assert isinstance(partial, KangarooResult)
    assert partial.solution is None  # budget too small to collide
    assert cp.is_file()
    assert partial.checkpoint_path == str(cp)

    resumed = pollard_kangaroo(q, lo, hi, dp_bits=6, max_steps=10**6, return_state=True, resume_from=cp)
    assert isinstance(resumed, KangarooResult)
    assert resumed.solution == k

    direct = pollard_kangaroo(q, lo, hi, dp_bits=6, max_steps=10**6)
    assert direct == k  # resume reaches the same answer as one uninterrupted run


def test_save_load_checkpoint_roundtrip(tmp_path) -> None:
    cp = tmp_path / "cp.json"
    state = {"version": 1, "phase": "wild", "spent": 42, "dp_table": [[1, 2, "3"]]}
    save_checkpoint(cp, state)
    assert load_checkpoint(cp) == state


def test_load_checkpoint_rejects_unknown_version(tmp_path) -> None:
    cp = tmp_path / "bad.json"
    save_checkpoint(cp, {"version": 999})
    with pytest.raises(ValueError, match="checkpoint version"):
        load_checkpoint(cp)
