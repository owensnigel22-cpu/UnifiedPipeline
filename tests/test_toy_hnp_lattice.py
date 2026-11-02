"""Toy Hidden Number Problem lattice demonstration (research, toy modulus only).

Exact-arithmetic (Fraction) tests: determinism, bounded errors, equation
verification, and rejection of production-sized moduli and malformed matrices.
No secp256k1 signatures, WIF, HD-wallet, network, or filesystem access.
"""

from __future__ import annotations

import pytest

from keylab.research import hnp_lattice as h

# secp256k1 group order -- a production-sized modulus this toy must reject.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def test_determinism_same_seed_same_output() -> None:
    first = h.run_demo()
    second = h.run_demo()
    assert first == second
    assert first["recovered_x"] == h.TOY_X


def test_bounded_errors() -> None:
    result = h.run_demo()
    residuals = result["residuals"]
    assert isinstance(residuals, list)
    assert all(abs(e) <= h.ERROR_BOUND for e in residuals)


def test_lattice_equations_verified() -> None:
    result = h.run_demo()
    x = result["recovered_x"]
    residuals = result["residuals"]
    q, multipliers, observations, _ = h.make_instance()
    assert q == h.TOY_Q
    for a, t, e in zip(multipliers, observations, residuals, strict=True):
        assert (a * x - t - e) % q == 0


def test_make_instance_matches_known_errors() -> None:
    # The synthetic instance is t_i = a_i*x + e_i (mod q) with the declared |e_i| <= bound.
    q, multipliers, observations, errors = h.make_instance()
    assert all(abs(e) <= h.ERROR_BOUND for e in errors)
    for a, t, e in zip(multipliers, observations, errors, strict=True):
        assert (a * h.TOY_X + e) % q == t


@pytest.mark.parametrize("q", [SECP256K1_N, h.MAX_MODULUS + 1, 1, 0])
def test_rejects_production_and_degenerate_moduli(q: int) -> None:
    with pytest.raises(ValueError):
        h.run_demo(q)
    with pytest.raises(ValueError):
        h.make_instance(q)


def test_rejects_non_integer_modulus() -> None:
    for bad in (3.0, "1009", None):
        with pytest.raises(TypeError):
            h.make_instance(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad",
    [
        [[1, 2], [3]],       # ragged
        [[1, 2, 3], [4, 5]],  # ragged (different widths)
        [],                  # empty
        [[]],                # empty row
    ],
)
def test_rejects_malformed_basis(bad) -> None:
    with pytest.raises(ValueError):
        h._gram_schmidt(bad)
    with pytest.raises(ValueError):
        h._lll_reduce(bad)


def test_rejects_non_integer_matrix_entries() -> None:
    with pytest.raises(TypeError):
        h._gram_schmidt([[1, 2], [3, 4.0]])
    with pytest.raises(TypeError):
        h._lll_reduce([[1, "x"], [3, 4]])


def test_babai_rejects_wrong_width_target() -> None:
    basis = [[1, 0], [0, 1]]
    with pytest.raises(ValueError):
        h._babai_nearest_plane(basis, [1, 2, 3])
    with pytest.raises(TypeError):
        h._babai_nearest_plane(basis, [1, 2.0])


def test_demo_prints_and_returns_toy_x(capsys) -> None:
    recovered = h.demo()
    assert recovered == h.TOY_X
    out = capsys.readouterr().out
    assert "toy modulus only" in out
    assert "not an ECDSA or wallet-key recovery tool" in out
