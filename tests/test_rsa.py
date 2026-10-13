import json

import pytest

from keylab.cli import main
from keylab.numtheory.rsa import (
    RSAExponentiationResult,
    SharedFactorFinding,
    WienerRecovery,
    batch_gcd,
    fermat_factor,
    hastad_broadcast,
    recover_rsa_private_key,
    rsa_exponentiation_roundtrip,
    wiener_attack,
)


def test_rsa_modular_exponentiation_roundtrip_succeeds() -> None:
    p, q = 1009, 1013
    modulus = p * q
    totient = (p - 1) * (q - 1)
    public_exponent = pow(13, -1, totient)

    result = rsa_exponentiation_roundtrip(42, modulus, public_exponent, 13)

    assert result == RSAExponentiationResult(
        message=42,
        ciphertext=pow(42, public_exponent, modulus),
        recovered_message=42,
    )
    assert result.success is True


def test_rsa_modular_exponentiation_reports_failed_roundtrip() -> None:
    result = rsa_exponentiation_roundtrip(42, 55, 3, 1)

    assert result.recovered_message != result.message
    assert result.success is False


@pytest.mark.parametrize(
    ("message", "modulus", "public_exponent", "private_exponent", "error"),
    [
        (0, 1, 3, 7, "modulus"),
        (1, 55, 0, 7, "exponents"),
        (55, 55, 3, 7, "message"),
    ],
)
def test_rsa_modular_exponentiation_validates_arguments(
    message: int,
    modulus: int,
    public_exponent: int,
    private_exponent: int,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        rsa_exponentiation_roundtrip(message, modulus, public_exponent, private_exponent)


def test_rsa_roundtrip_cli_reports_exponentiation_success(capsys) -> None:
    p, q = 1009, 1013
    modulus = p * q
    public_exponent = pow(13, -1, (p - 1) * (q - 1))

    assert main(
        [
            "rsa-roundtrip",
            "--modulus",
            str(modulus),
            "--public-exponent",
            str(public_exponent),
            "--private-exponent",
            "13",
            "--message",
            "42",
        ]
    ) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["success"] is True
    assert output["message"] == 42
    assert output["recovered_message"] == 42
    assert "not secure" in output["warning"]


def test_rsa_roundtrip_cli_returns_failure_for_bad_private_exponent(capsys) -> None:
    assert main(
        [
            "rsa-roundtrip",
            "--modulus",
            "55",
            "--public-exponent",
            "3",
            "--private-exponent",
            "1",
            "--message",
            "42",
        ]
    ) == 1
    assert '"success": false' in capsys.readouterr().out


def test_fermat_factor_finds_close_factors_within_bound() -> None:
    p_true, q_true = 1009, 1013

    p, q, iterations = fermat_factor(p_true * q_true, max_iterations=10)

    assert (p, q) == (p_true, q_true)
    assert 0 < iterations <= 10


def test_fermat_factor_is_bounded_and_rejects_invalid_inputs() -> None:
    assert fermat_factor(17, max_iterations=0) == (None, None, 0)
    assert fermat_factor(2) == (None, None, 0)
    assert fermat_factor(84) == (2, 42, 1)
    with pytest.raises(ValueError, match="modulus"):
        fermat_factor(1)
    with pytest.raises(ValueError, match="max_iterations"):
        fermat_factor(15, max_iterations=-1)


def test_fermat_rsa_recovery_verifies_factors_and_private_exponent() -> None:
    p_true, q_true = 1009, 1013
    modulus = p_true * q_true
    totient = (p_true - 1) * (q_true - 1)
    public_exponent = pow(13, -1, totient)

    p, q, private_exponent = recover_rsa_private_key(modulus, public_exponent, 10)

    assert (p, q) == (p_true, q_true)
    assert (public_exponent * private_exponent) % totient == 1


def test_fermat_rsa_recovery_rejects_nonprime_factors_and_invalid_exponent() -> None:
    with pytest.raises(ValueError, match="distinct primes"):
        recover_rsa_private_key(45, 7)
    with pytest.raises(ValueError, match="coprime"):
        recover_rsa_private_key(1009 * 1013, 3, 10)


def test_wiener_attack_recovers_small_private_exponent() -> None:
    p, q, private_exponent = 1009, 1013, 13
    modulus = p * q
    phi = (p - 1) * (q - 1)
    public_exponent = pow(private_exponent, -1, phi)

    assert wiener_attack(modulus, public_exponent) == WienerRecovery(private_exponent, p, q)


def test_wiener_attack_returns_none_for_ordinary_key_parameters() -> None:
    assert wiener_attack(61 * 53, 17) is None


def test_hastad_broadcast_recovers_repeated_unpadded_toy_message() -> None:
    message = 42
    exponent = 3
    moduli = (101, 103, 107)
    ciphertexts = tuple(pow(message, exponent, modulus) for modulus in moduli)

    assert hastad_broadcast(ciphertexts, moduli, exponent) == message


def test_hastad_broadcast_rejects_non_exact_crt_root() -> None:
    with pytest.raises(ValueError, match="exact"):
        hastad_broadcast((2, 2, 2), (101, 103, 107), 3)


@pytest.mark.parametrize(
    ("ciphertexts", "moduli", "exponent", "error"),
    [
        ((1, 1), (101,), 2, "same length"),
        ((1, 1), (101, 103), 3, "at least"),
        ((1, 1), (101, 101), 2, "pairwise coprime"),
        ((101, 1), (101, 103), 2, "between"),
        ((1, 1), (1, 103), 2, "greater than 1"),
        ((1, 1), (101, 103), 1, "at least 2"),
    ],
)
def test_hastad_broadcast_rejects_invalid_inputs(
    ciphertexts: tuple[int, ...],
    moduli: tuple[int, ...],
    exponent: int,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        hastad_broadcast(ciphertexts, moduli, exponent)


def test_batch_gcd_reports_shared_divisors_by_modulus_pair() -> None:
    moduli = (101 * 103, 101 * 107, 109 * 113, 101 * 103)

    assert batch_gcd(moduli) == (
        SharedFactorFinding(0, 1, 101),
        SharedFactorFinding(0, 3, 101 * 103),
        SharedFactorFinding(1, 3, 101),
    )


def test_batch_gcd_returns_empty_without_shared_divisors_and_validates() -> None:
    assert batch_gcd((101 * 103, 107 * 109)) == ()
    with pytest.raises(ValueError, match="greater than 1"):
        batch_gcd((101, 1))
    with pytest.raises(ValueError, match="integer"):
        batch_gcd((101, True))


def test_rsa_broadcast_cli_recovers_and_reports_toy_warning(capsys) -> None:
    moduli = (101, 103, 107)
    args = ["rsa-hastad-broadcast", "--public-exponent", "3"]
    for modulus in moduli:
        args.extend(("--modulus", str(modulus)))
        args.extend(("--ciphertext", str(pow(42, 3, modulus))))

    assert main(args) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["message"] == 42
    assert "unpadded" in output["warning"]


def test_rsa_batch_gcd_cli_reports_shared_factor(capsys) -> None:
    assert main(
        [
            "rsa-batch-gcd",
            "--modulus",
            str(101 * 103),
            "--modulus",
            str(101 * 107),
        ]
    ) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["findings"] == [
        {"first_index": 0, "second_index": 1, "common_divisor": 101}
    ]


@pytest.mark.parametrize(
    "modulus,public_exponent",
    [(1, 3), (100, 1), (100, 100)],
)
def test_wiener_attack_rejects_invalid_parameters(modulus: int, public_exponent: int) -> None:
    with pytest.raises(ValueError):
        wiener_attack(modulus, public_exponent)
