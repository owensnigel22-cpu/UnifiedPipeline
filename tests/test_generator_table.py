"""The fixed-base comb for k*G: table-construction invariants and k*G correctness.

Covers the M2.4 generator-table optimization. The comb is the path
``scalar_mult(backend="auto")`` runs with no native backend, also selectable as
``python-optimized`` and ``python-affine-window``. Every result is checked
against the frozen reference (keylab.ec.reference), independent of this code.
"""

from __future__ import annotations

import random

import pytest

from keylab.ec import reference as ref
from keylab.ec import secp256k1 as curve
from keylab.ec.secp256k1 import (
    _AFFINE_WINDOW_BITS,
    _AFFINE_WINDOW_COUNT,
    G,
    N,
    _generator_affine_window_table,
    _scalar_mult_generator_affine_window,
)

WINDOW = 1 << _AFFINE_WINDOW_BITS
AFFINE = "python-affine-window"


@pytest.fixture(scope="module")
def table():
    return _generator_affine_window_table()


# --- table-generation invariants -----------------------------------------------------------------

def test_window_geometry_matches_the_configured_width(table) -> None:
    assert _AFFINE_WINDOW_COUNT == -(-256 // _AFFINE_WINDOW_BITS)  # ceil(256 / bits)
    assert len(table) == _AFFINE_WINDOW_COUNT
    for window in table:
        assert len(window) == WINDOW            # entries 0 .. WINDOW-1
        assert window[0] is None                # digit 0 is the point at infinity


def test_every_table_entry_is_the_exact_fixed_base_multiple(table) -> None:
    # Window w, digit d must be exactly d * (2**bits)**w * G.
    for w, window in enumerate(table):
        unit = (1 << (_AFFINE_WINDOW_BITS * w))
        for d in (1, 2, WINDOW // 2, WINDOW - 1):
            assert window[d] == ref.scalar_mult(d * unit), (w, d)


def test_all_table_points_are_distinct_and_on_curve(table) -> None:
    seen = set()
    for window in table:
        for point in window[1:]:
            assert ref.is_on_curve(point)
            assert point not in seen            # no repeated multiples
            seen.add(point)
    assert len(seen) == _AFFINE_WINDOW_COUNT * (WINDOW - 1)


def test_table_is_cached_as_one_object() -> None:
    assert _generator_affine_window_table() is _generator_affine_window_table()


def test_table_builds_with_a_single_modular_inversion(monkeypatch) -> None:
    calls: list[int] = []
    real = curve.mod_inverse_builtin
    monkeypatch.setattr(curve, "mod_inverse_builtin", lambda v, m: calls.append(m) or real(v, m))
    _generator_affine_window_table.cache_clear()
    try:
        _generator_affine_window_table()
        assert calls == [curve.P]               # batch normalization: one inversion
    finally:
        _generator_affine_window_table.cache_clear()


# --- window boundaries ----------------------------------------------------------------------------

@pytest.mark.parametrize("window_index", [0, 1, _AFFINE_WINDOW_COUNT // 2, _AFFINE_WINDOW_COUNT - 1])
def test_scalars_on_window_boundaries(window_index: int) -> None:
    base = 1 << (_AFFINE_WINDOW_BITS * window_index)
    for delta in (-1, 0, 1, WINDOW - 1, WINDOW):
        scalar = base + delta
        if scalar < 0:
            continue
        assert _scalar_mult_generator_affine_window(scalar) == ref.scalar_mult(scalar)


def test_single_digit_set_in_each_window() -> None:
    for window_index in range(_AFFINE_WINDOW_COUNT):
        for digit in (1, WINDOW - 1):
            scalar = digit << (_AFFINE_WINDOW_BITS * window_index)
            assert _scalar_mult_generator_affine_window(scalar) == ref.scalar_mult(scalar)


def test_top_window_is_exercised() -> None:
    # A scalar whose highest bits fall in the last window (close to N).
    for scalar in (N - 1, N - 2, 2**255, 2**255 + 1, (1 << 252) | 1):
        assert _scalar_mult_generator_affine_window(scalar) == ref.scalar_mult(scalar)


# --- edge scalars ---------------------------------------------------------------------------------

# scalar_mult reduces mod N before the comb runs, so it accepts any non-negative
# scalar; the low-level comb assumes an already-reduced scalar (< N), exactly as
# before M2.4. Unreduced values are checked through the public backends.
@pytest.mark.parametrize("scalar", [0, 1, 2, WINDOW - 1, WINDOW, WINDOW + 1,
                                    N - 1, N, N + 1, 2 * N, 2 * N + 5,
                                    curve.LAMBDA, N - curve.LAMBDA, 2**256 - 1, 2**300 + 7])
def test_edge_scalars_against_reference(scalar: int) -> None:
    expected = ref.scalar_mult(scalar % N) if scalar % N else None
    assert curve.scalar_mult(scalar, G, backend=AFFINE) == expected
    assert curve.scalar_mult(scalar, G, backend="python-optimized") == expected
    if scalar < N:  # the comb's own contract: caller supplies a reduced scalar
        assert _scalar_mult_generator_affine_window(scalar) == expected


def test_reduction_modulo_group_order() -> None:
    # scalar_mult reduces, so k, k + N and k + 2N give the same point.
    for k in (1, 12345, 2**200):
        point = curve.scalar_mult(k, G, backend=AFFINE)
        assert point == curve.scalar_mult(k + N, G, backend=AFFINE)
        assert point == curve.scalar_mult(k + 2 * N, G, backend=AFFINE)
    assert curve.scalar_mult(N, G, backend=AFFINE) is None
    assert _scalar_mult_generator_affine_window(0) is None


# --- random scalars -------------------------------------------------------------------------------

def test_many_random_scalars_match_reference() -> None:
    rng = random.Random(0x9E_17_C0_FFEE)
    for _ in range(600):
        scalar = rng.randrange(0, N)
        assert _scalar_mult_generator_affine_window(scalar) == ref.scalar_mult(scalar)


def test_random_scalars_match_native_backends() -> None:
    rng = random.Random(0x5EED)
    for backend in ("coincurve", "fastecdsa"):
        pytest.importorskip(backend)
        for _ in range(60):
            scalar = rng.randrange(1, N)
            assert (curve.scalar_mult(scalar, G, backend=AFFINE)
                    == curve.scalar_mult(scalar, G, backend=backend))


def test_additive_structure_on_random_scalars() -> None:
    rng = random.Random(0xA11CE)
    mult = _scalar_mult_generator_affine_window
    for _ in range(100):
        a, b = rng.randrange(1, N), rng.randrange(1, N)
        assert curve.point_add_affine(mult(a), mult(b)) == mult((a + b) % N)
