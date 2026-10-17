"""Small-number checks for exact arithmetic helpers."""

import pytest

from keylab.advanced_suite import modular_inverse_report
from keylab.ec.secp256k1 import P as SECP256K1_P
from keylab.numtheory.core import (
    euler_check,
    extended_gcd,
    fermat_check,
    mod_inverse_builtin,
    mod_inverse_egcd,
    mod_inverse_fermat,
    totient,
)


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


@pytest.mark.parametrize("value", [3, -17, 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798])
def test_modular_inverse_methods_agree_for_large_prime(value: int) -> None:
    inverses = (
        mod_inverse_builtin(value, SECP256K1_P),
        mod_inverse_egcd(value, SECP256K1_P),
        mod_inverse_fermat(value, SECP256K1_P),
    )
    assert inverses[0] == inverses[1] == inverses[2]
    assert value * inverses[0] % SECP256K1_P == 1


def test_builtin_and_egcd_inverse_support_composite_rsa_modulus() -> None:
    assert mod_inverse_builtin(3, 40) == 27
    assert mod_inverse_egcd(3, 40) == 27


def test_builtin_and_egcd_inverse_handle_thousands_of_bits_iteratively() -> None:
    modulus = 1 << 4096
    builtin = mod_inverse_builtin(17, modulus)
    iterative = mod_inverse_egcd(17, modulus)
    assert builtin == iterative
    assert 17 * iterative % modulus == 1


def test_advanced_inverse_report_selects_each_algorithm() -> None:
    assert modular_inverse_report(3, 40, "builtin")["inverse"] == 27
    assert modular_inverse_report(3, 40, "egcd")["inverse"] == 27
    assert modular_inverse_report(3, 7, "fermat")["inverse"] == 5


@pytest.mark.parametrize("inverse", [mod_inverse_builtin, mod_inverse_egcd, mod_inverse_fermat])
def test_modular_inverse_rejects_noninvertible_values(inverse) -> None:
    with pytest.raises(ValueError):
        inverse(6, 15)


def test_fermat_inverse_detects_composite_modulus_that_breaks_its_result() -> None:
    with pytest.raises(ValueError, match="must be prime"):
        mod_inverse_fermat(2, 15)


@pytest.mark.parametrize("inverse", [mod_inverse_builtin, mod_inverse_egcd, mod_inverse_fermat])
def test_modular_inverse_rejects_invalid_modulus(inverse) -> None:
    with pytest.raises(ValueError, match="greater than 1"):
        inverse(3, 1)
