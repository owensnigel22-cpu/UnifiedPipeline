"""SAT encoding of the bounded-range ECDLP (educational).

Correctness is verified on a small curve against the KNOWN discrete log used to
build each instance (and re-checked with independent curve arithmetic): the
solver's recovered k must satisfy k*G == Q. The required bounded range is
validated. Full-width (secp256k1) behaviour is a measurement, not a test -- see
scripts/benchmark_sat_ecdlp.py.
"""

from __future__ import annotations

import pytest

from keylab.research.ecdlp.sat_encoding import encode_bounded_ecdlp
from keylab.sat.solver import find_solver, run_solver

# --- a tiny curve, independent reference arithmetic ----------------------------------------------

_P, _A, _B = 1009, 2, 3


def _add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    m = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P if P == Q else (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    return (x3, (m * (x1 - x3) - y1) % _P)


def _mul(k, P):
    R = None
    while k > 0:
        if k & 1:
            R = _add(R, P)
        P = _add(P, P)
        k >>= 1
    return R


def _generator():
    for x in range(_P):
        for y in range(_P):
            if (y * y - (x * x * x + _A * x + _B)) % _P == 0:
                return (x, y)
    raise AssertionError


_G = _generator()
_WIDTH = _P.bit_length()


def _build(k: int, lower: int, upper: int):
    steps = max(1, (upper - lower).bit_length())
    return encode_bounded_ecdlp(
        p=_P, width=_WIDTH,
        base_point=_mul(lower, _G),
        doubling_points=[_mul(pow(2, i), _G) for i in range(steps)],
        target=_mul(k, _G), lower=lower, upper=upper,
    )


def test_range_is_required_and_validated() -> None:
    dpts = [_mul(1, _G)]
    with pytest.raises(ValueError, match="bounded range"):
        encode_bounded_ecdlp(p=_P, width=_WIDTH, base_point=_G, doubling_points=dpts,
                             target=_G, lower=5, upper=1)  # upper < lower
    with pytest.raises(ValueError, match="cover the range"):
        encode_bounded_ecdlp(p=_P, width=_WIDTH, base_point=_G, doubling_points=dpts,
                             target=_G, lower=0, upper=99)  # 1 doubling cannot cover span 99
    with pytest.raises(TypeError):
        encode_bounded_ecdlp(p=_P, width=_WIDTH, base_point=_G, doubling_points=dpts,
                             target=_G, lower=1.0, upper=5)  # type: ignore[arg-type]


def test_stats_available_without_a_solver() -> None:
    inst = _build(3, 1, 7)
    assert inst.stats.steps == 3
    assert inst.stats.variable_count > 0 and inst.stats.clause_count > 0
    assert "p cnf" in inst.to_dimacs()


@pytest.mark.parametrize("k", [1, 3, 5, 7])
def test_solver_recovers_known_k_verified(k) -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")
    inst = _build(k, 1, k + 4)
    result = run_solver(solver, inst.to_dimacs(), timeout=60)
    assert result.status == "SATISFIABLE"
    recovered = inst.recover_k(result.assignments)
    assert recovered == k
    assert _mul(recovered, _G) == _mul(k, _G)  # independent forward verification


def test_regression_canary_smallest_working_case() -> None:
    # Pins the smallest terminating instance; a shift in the encoder that breaks
    # this is the early warning the task asked for.
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")
    inst = _build(3, 1, 7)
    result = run_solver(solver, inst.to_dimacs(), timeout=60)
    assert result.status == "SATISFIABLE"
    assert inst.recover_k(result.assignments) == 3
