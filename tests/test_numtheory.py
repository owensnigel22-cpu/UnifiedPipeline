"""Small-number checks for exact arithmetic helpers."""

import pytest

from keylab.numtheory.core import euler_check, extended_gcd, fermat_check, totient


@pytest.mark.parametrize("a,b", [(240, 46), (-21, 6), (0, 0), (17, 0)])
def test_extended_gcd_bezout_identity(a: int, b: int) -> None:
    gcd, x, y = extended_gcd(a, b)
    assert gcd >= 0
    assert a * x + b * y == gcd


@pytest.mark.parametrize("n,expected", [(1, 1), (2, 1), (9, 6), (36, 12), (97, 96)])
def test_totient(n: int, expected: int) -> None:
    assert totient(n) == expected


def test_congruence_checks_and_invalid_inputs() -> None:
    assert fermat_check(2, 7)
    assert euler_check(2, 9)
    assert not fermat_check(2, 9)
    with pytest.raises(ValueError):
        totient(0)