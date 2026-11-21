"""Verify secp256k1 invariants against an independent affine reference."""

from __future__ import annotations

import csv
import hashlib
import random
from importlib.util import find_spec
from pathlib import Path

from keylab.ec.rfc6979 import generate_nonce
from keylab.ec.schnorr import schnorr_verify
from keylab.ec.secp256k1 import (
    BETA,
    LAMBDA,
    G,
    N,
    P,
    batch_inverse,
    ecdsa_sign_digest,
    ecdsa_verify_digest,
    glv_decompose,
    is_on_curve,
    lift_x,
    multi_scalar_mult,
    point_add_affine,
    rfc6979_nonce_from_digest,
    scalar_mult,
    wnaf_digits,
)
from keylab.ec.validation import (
    assert_no_mismatches,
    available_backends,
    diff_batch_normalization,
    diff_group_operations,
    diff_msm,
    diff_scalar_mult,
    diff_serialization,
    edge_points,
)

REFERENCE_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
REFERENCE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
REFERENCE_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
REFERENCE_BETA = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
REFERENCE_LAMBDA = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72
_MILLER_RABIN_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53)
_Point = tuple[int, int] | None


def _is_probable_prime(value: int) -> bool:
    """Run a fixed-base Miller-Rabin screen; this is not a primality certificate."""
    for prime in _MILLER_RABIN_BASES:
        if value == prime:
            return True
        if value % prime == 0:
            return False

    odd_part = value - 1
    powers_of_two = 0
    while odd_part % 2 == 0:
        odd_part //= 2
        powers_of_two += 1

    for base in _MILLER_RABIN_BASES:
        residue = pow(base, odd_part, value)
        if residue in (1, value - 1):
            continue
        for _ in range(powers_of_two - 1):
            residue = pow(residue, 2, value)
            if residue == value - 1:
                break
        else:
            return False
    return True


def _reference_add(left: _Point, right: _Point) -> _Point:
    """Textbook affine addition using only the pinned field modulus."""
    if left is None:
        return right
    if right is None:
        return left

    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % REFERENCE_P == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, REFERENCE_P) % REFERENCE_P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, REFERENCE_P) % REFERENCE_P
    x3 = (slope * slope - x1 - x2) % REFERENCE_P
    y3 = (slope * (x1 - x3) - y1) % REFERENCE_P
    return x3, y3


def _reference_scalar_mult(scalar: int, point: _Point = REFERENCE_G) -> _Point:
    """Independent affine double-and-add; does not call KeyLab arithmetic."""
    result: _Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _reference_add(result, addend)
        addend = _reference_add(addend, addend)
        scalar >>= 1
    return result


def _check(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError(f"{label} failed" + (f": {detail}" if detail else ""))
    print(f"PASS {label}")


def main() -> int:
    rng = random.Random(20261116)
    checks = 0

    _check(
        "P matches the secp256k1 field-prime parameter and passes fixed-base Miller-Rabin",
        P == REFERENCE_P and _is_probable_prime(P),
        f"P={P:#x}",
    )
    checks += 1
    _check(
        "N matches the secp256k1 group-order parameter and passes fixed-base Miller-Rabin",
        N == REFERENCE_N and _is_probable_prime(N),
        f"N={N:#x}",
    )
    checks += 1
    _check(
        "G matches the standard generator and is on the curve",
        G == REFERENCE_G
        and (G[1] * G[1] - G[0] * G[0] * G[0] - 7) % REFERENCE_P == 0
        and is_on_curve(G),
    )
    checks += 1
    _check(
        "G has order N",
        _reference_scalar_mult(REFERENCE_N) is None
        and scalar_mult(N, G, backend="python") is None
        and G is not None,
    )
    checks += 1
    _check(
        "BETA is the standard nontrivial cube root of unity modulo P",
        BETA == REFERENCE_BETA and pow(BETA, 3, P) == 1 and BETA != 1,
        f"BETA^3 mod P={pow(BETA, 3, P)}",
    )
    checks += 1
    _check(
        "LAMBDA is the standard nontrivial cube root of unity modulo N",
        LAMBDA == REFERENCE_LAMBDA and pow(LAMBDA, 3, N) == 1 and LAMBDA != 1,
        f"LAMBDA^3 mod N={pow(LAMBDA, 3, N)}",
    )
    checks += 1
    _check(
        "endomorphism phi(G) equals the independent LAMBDA*G result",
        (BETA * REFERENCE_G[0] % REFERENCE_P, REFERENCE_G[1])
        == _reference_scalar_mult(REFERENCE_LAMBDA),
    )
    checks += 1

    glv_scalars = [0, 1, N - 1, N, N + 1]
    glv_scalars.extend(rng.randrange(N) for _ in range(10_000))
    decompositions = [glv_decompose(scalar) for scalar in glv_scalars]
    for scalar, (k1, k2) in zip(glv_scalars, decompositions):
        if (k1 + LAMBDA * k2 - scalar) % N:
            raise AssertionError(f"GLV identity failed for scalar {scalar:#x}")
    _check("GLV scalar decomposition identity (10,005 cases)", True)
    checks += 1
    if any(max(abs(k1).bit_length(), abs(k2).bit_length()) > 129 for k1, k2 in decompositions):
        raise AssertionError("GLV component bound exceeded 129 bits")
    _check("GLV components are at most 129 bits", True)
    checks += 1

    scalars = [0, 1, 2, N - 1, N, N + 1]
    scalars.extend(rng.randrange(N) for _ in range(2_000))
    reference_points: dict[int, _Point] = {}
    for scalar in scalars:
        expected = _reference_scalar_mult(scalar)
        actual = scalar_mult(scalar, G, backend="python")
        if actual != expected:
            raise AssertionError(f"Python scalar multiplication differs for {scalar:#x}")
        reference_points[scalar] = expected
    _check("Python scalar multiplication matches affine reference (2,006 cases)", True)
    checks += 1

    for scalar in (-1, -2, -N):
        try:
            scalar_mult(scalar, G, backend="python")
        except ValueError:
            continue
        raise AssertionError(f"negative scalar {scalar} was accepted")
    for scalar in scalars[6:]:
        point = reference_points[scalar]
        negative = None if point is None else (point[0], (-point[1]) % REFERENCE_P)
        if scalar_mult(N - scalar, G, backend="python") != negative:
            raise AssertionError(f"modular group inverse identity failed for {scalar:#x}")
    _check("negative inputs are rejected; inverse group elements agree (2,000 cases)", True)
    checks += 1

    for _ in range(256):
        left_scalar, right_scalar = rng.randrange(N), rng.randrange(N)
        expected = _reference_add(
            _reference_scalar_mult(left_scalar),
            _reference_scalar_mult(right_scalar),
        )
        actual = scalar_mult((left_scalar + right_scalar) % N, G, backend="python")
        if actual != expected:
            raise AssertionError(
                f"scalar-addition identity failed for {left_scalar:#x}, {right_scalar:#x}"
            )
    _check("scalar addition agrees with independent point addition (256 cases)", True)
    checks += 1

    wnaf_scalars = [0, 1, 2, N - 1]
    wnaf_scalars.extend(rng.randrange(N) for _ in range(2_000))
    for scalar in wnaf_scalars:
        digits = wnaf_digits(scalar)
        if sum(digit << bit for bit, digit in enumerate(digits)) != scalar:
            raise AssertionError(f"wNAF reconstruction failed for {scalar:#x}")
        if any(digit and (digit % 2 == 0 or abs(digit) >= 1 << 4) for digit in digits):
            raise AssertionError(f"wNAF digit constraint failed for {scalar:#x}")
    _check("width-5 wNAF reconstruction and digit constraints (2,004 cases)", True)
    checks += 1

    for scalar in [1, N - 1, *(rng.randrange(N) for _ in range(256))]:
        if scalar_mult(scalar, G, backend="python-glv") != _reference_scalar_mult(scalar):
            raise AssertionError(f"GLV scalar multiplication differs for {scalar:#x}")
    _check("GLV scalar multiplication matches affine reference (258 cases)", True)
    checks += 1

    for _ in range(128):
        left = _reference_scalar_mult(rng.randrange(N))
        right = _reference_scalar_mult(rng.randrange(N))
        if point_add_affine(left, right) != _reference_add(left, right):
            raise AssertionError("affine point addition differs from independent reference")
    _check("affine point addition matches independent reference (128 pairs)", True)
    checks += 1

    for trial in range(32):
        pairs = [
            (rng.randrange(N), _reference_scalar_mult(rng.randrange(1, N)))
            for _ in range(2 + trial % 3)
        ]
        expected: _Point = None
        for scalar, point in pairs:
            expected = _reference_add(expected, _reference_scalar_mult(scalar, point))
        if multi_scalar_mult(pairs, method="straus") != expected:
            raise AssertionError(f"Straus/Shamir result differs from reference in case {trial}")
    _check("Straus/Shamir multiplication matches affine reference (32 cases)", True)
    checks += 1

    differential_checks = (
        ("affine/Jacobian addition and doubling", diff_group_operations()),
        ("SEC1 public-key parsing and serialization", diff_serialization()),
        ("batch Jacobian normalization", diff_batch_normalization()),
        ("Straus multi-scalar multiplication", diff_msm()),
    )
    for label, mismatches in differential_checks:
        assert_no_mismatches(mismatches)
        _check(f"independent differential: {label}", True)
        checks += 1

    inverse_inputs = (1, 2, P - 1, P + 1, -5)
    if batch_inverse(inverse_inputs, P) != [pow(value, -1, P) for value in inverse_inputs]:
        raise AssertionError("batch modular inverses differ from Python's independent pow oracle")
    try:
        batch_inverse((1, 0, 3), P)
    except ValueError:
        pass
    else:
        raise AssertionError("batch inversion accepted a zero residue")
    _check("batch modular inversion matches pow and rejects zero", True)
    checks += 1

    vector_path = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "bip340_test_vectors.csv"
    with vector_path.open(encoding="utf-8", newline="") as vector_file:
        bip340_vectors = list(csv.DictReader(vector_file))
    valid_count = sum(row["verification result"] == "TRUE" for row in bip340_vectors)
    invalid_count = sum(row["verification result"] == "FALSE" for row in bip340_vectors)
    if len(bip340_vectors) != 19 or (valid_count, invalid_count) != (9, 10):
        raise AssertionError(
            "BIP-340 fixture shape changed: expected 19 vectors (9 valid, 10 invalid), "
            f"got {len(bip340_vectors)} ({valid_count} valid, {invalid_count} invalid)"
        )
    for vector in bip340_vectors:
        public_key = bytes.fromhex(vector["public key"])
        message = bytes.fromhex(vector["message"])
        signature = bytes.fromhex(vector["signature"])
        expected_verification = vector["verification result"] == "TRUE"
        if schnorr_verify(message, signature, public_key) is not expected_verification:
            raise AssertionError(
                f"KeyLab disagrees with BIP-340 official vector {vector['index']}: "
                f"{vector['comment']}"
            )
    vector = bip340_vectors[0]
    public_key = bytes.fromhex(vector["public key"])
    message = bytes.fromhex(vector["message"])
    signature = bytes.fromhex(vector["signature"])
    lifted = lift_x(int.from_bytes(public_key, "big"))
    if lifted[0].to_bytes(32, "big") != public_key or lifted[1] & 1:
        raise AssertionError("BIP-340 x-only public key did not lift to its even-y point")
    _check(
        "BIP-340 official vectors (19: 9 valid, 10 invalid) and even-y public-key lifting",
        True,
    )
    checks += 1

    digest = hashlib.sha256(b"KeyLab deterministic RFC 6979 validation").digest()
    private_scalar = 0x123456789ABCDEF
    nonce = rfc6979_nonce_from_digest(private_scalar, digest)
    if nonce != generate_nonce(N, private_scalar, hashlib.sha256, digest):
        raise AssertionError("KeyLab RFC 6979 nonce differs from the independent ecdsa implementation")
    if not 1 <= nonce < N:
        raise AssertionError("RFC 6979 nonce is outside the valid scalar range")
    python_signature = ecdsa_sign_digest(digest, private_scalar, backend="python")
    public_point = scalar_mult(private_scalar, G, backend="python")
    if (
        ecdsa_sign_digest(digest, private_scalar, backend="python") != python_signature
        or not ecdsa_verify_digest(digest, python_signature, public_point)
    ):
        raise AssertionError("RFC 6979 ECDSA signature is not deterministic or does not verify")
    _check("RFC 6979 nonce matches independent ecdsa implementation", True)
    checks += 1

    native_backends = tuple(
        backend for backend in available_backends()
        if backend in ("coincurve", "fastecdsa")
    )
    if native_backends:
        assert_no_mismatches(
            diff_scalar_mult(
                scalars=(0, 1, 2, N - 1, N, N + 1),
                points=edge_points(),
                backends=native_backends,
            )
        )
        _check(f"optional native scalar-multiplication differential: {native_backends}", True)
        checks += 1
    else:
        print("SKIP optional native scalar-multiplication differential: no native backend installed")

    if find_spec("coincurve") is not None:
        from coincurve import PublicKeyXOnly

        for vector in bip340_vectors:
            public_key = bytes.fromhex(vector["public key"])
            message = bytes.fromhex(vector["message"])
            signature = bytes.fromhex(vector["signature"])
            expected_verification = vector["verification result"] == "TRUE"
            keylab_result = schnorr_verify(message, signature, public_key)
            try:
                native_result = PublicKeyXOnly(public_key).verify(signature, message)
            except (TypeError, ValueError):
                native_result = False
            if native_result != keylab_result or native_result != expected_verification:
                raise AssertionError(
                    f"BIP-340 vector {vector['index']} ({vector['comment']}): "
                    f"KeyLab={keylab_result}, libsecp256k1={native_result}, "
                    f"expected={expected_verification}"
                )
        from keylab.ec.coincurve_backend import ecdsa_sign_digest_coincurve

        if ecdsa_sign_digest_coincurve(digest, private_scalar) != python_signature:
            raise AssertionError("libsecp256k1 ECDSA signature differs from the Python implementation")
        _check(
            "libsecp256k1 BIP-340 differential (19: 9 valid, 10 invalid) "
            "and deterministic ECDSA",
            True,
        )
        checks += 1
    else:
        print("SKIP libsecp256k1 signature differentials: coincurve is not installed")

    print(f"Result: {checks}/{checks} checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
