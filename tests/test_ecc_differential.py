"""Differential tests against libsecp256k1 (via coincurve) and optionally fastecdsa.

Each test is skipped when its reference library is not installed, so the
suite still runs on a minimal install. Inputs are deterministic so failures
are reproducible.
"""

from __future__ import annotations

import hashlib
import random

import pytest

from keylab.ec import reference
from keylab.ec.ecdsa_recovery import recover_public_keys_from_signature
from keylab.ec.schnorr import schnorr_public_key, schnorr_sign, schnorr_verify
from keylab.ec.sec1 import parse_sec1, serialize_sec1, serialize_xonly
from keylab.ec.secp256k1 import (
    G,
    N,
    ecdsa_sign_digest,
    ecdsa_verify_digest,
    point_add_affine,
    scalar_mult,
)

RNG = random.Random(0x5EC9256)
EDGE_SCALARS = [1, 2, 3, N - 1, N - 2, (N - 1) // 2, (N + 1) // 2, 1 << 128, (1 << 255) % N]
SCALARS = EDGE_SCALARS + [RNG.randrange(1, N) for _ in range(24)]
PYTHON_BACKENDS = ("python", "python-glv", "python-wnaf", "python-affine-window")


def _point(scalar: int) -> tuple[int, int]:
    point = scalar_mult(scalar, G, backend="python")
    assert point is not None
    return point


def _coincurve():
    return pytest.importorskip("coincurve")


@pytest.mark.parametrize("scalar", SCALARS)
def test_generator_multiplication_matches_libsecp256k1(scalar: int) -> None:
    cc = _coincurve()
    expected = cc.PrivateKey(scalar.to_bytes(32, "big")).public_key.format(compressed=False)
    for backend in PYTHON_BACKENDS:
        assert serialize_sec1(scalar_mult(scalar, G, backend=backend), compressed=False) == expected


@pytest.mark.parametrize("scalar", SCALARS[:16])
def test_arbitrary_point_multiplication_matches_libsecp256k1(scalar: int) -> None:
    cc = _coincurve()
    base_scalar = random.Random(scalar).randrange(1, N)  # order-independent, reproducible
    base = _point(base_scalar)
    expected = cc.PublicKey(serialize_sec1(base)).multiply(scalar.to_bytes(32, "big")).format()
    for backend in PYTHON_BACKENDS:
        assert serialize_sec1(scalar_mult(scalar, base, backend=backend)) == expected


@pytest.mark.parametrize("pair", [(SCALARS[i], SCALARS[-i - 1]) for i in range(12)])
def test_point_addition_matches_libsecp256k1(pair: tuple[int, int]) -> None:
    cc = _coincurve()
    left, right = map(_point, pair)
    if (pair[0] + pair[1]) % N == 0:
        assert point_add_affine(left, right) is None
        return
    combined = cc.PublicKey.combine_keys([cc.PublicKey(serialize_sec1(left)),
                                          cc.PublicKey(serialize_sec1(right))])
    assert serialize_sec1(point_add_affine(left, right)) == combined.format()


@pytest.mark.parametrize("scalar", SCALARS[:12])
def test_point_doubling_matches_libsecp256k1(scalar: int) -> None:
    cc = _coincurve()
    point = _point(scalar)
    key = cc.PublicKey(serialize_sec1(point))
    doubled = cc.PublicKey.combine_keys([key, key]).format()
    assert serialize_sec1(point_add_affine(point, point)) == doubled
    assert serialize_sec1(scalar_mult(2, point, backend="python")) == doubled


@pytest.mark.parametrize("scalar", SCALARS[:16])
def test_sec1_and_xonly_serialization_match_libsecp256k1(scalar: int) -> None:
    cc = _coincurve()
    public = cc.PrivateKey(scalar.to_bytes(32, "big")).public_key
    point = _point(scalar)
    assert serialize_sec1(point) == public.format(compressed=True)
    assert serialize_sec1(point, compressed=False) == public.format(compressed=False)
    assert parse_sec1(public.format(compressed=True)) == point
    assert parse_sec1(public.format(compressed=False)) == point
    xonly = cc.keys.PublicKeyXOnly.from_secret(scalar.to_bytes(32, "big"))
    assert serialize_xonly(point) == xonly.format() == schnorr_public_key(scalar)


@pytest.mark.parametrize("index", range(16))
def test_schnorr_signatures_cross_verify_with_libsecp256k1(index: int) -> None:
    cc = _coincurve()
    scalar = SCALARS[index]
    message = hashlib.sha256(f"differential schnorr {index}".encode()).digest()
    aux = hashlib.sha256(f"aux {index}".encode()).digest()
    key = cc.PrivateKey(scalar.to_bytes(32, "big"))
    xonly = cc.keys.PublicKeyXOnly.from_secret(scalar.to_bytes(32, "big"))

    ours = schnorr_sign(message, scalar, aux)
    theirs = key.sign_schnorr(message, aux)
    assert ours == theirs  # BIP-340 signing is deterministic given aux_rand
    assert xonly.verify(ours, message)
    assert schnorr_verify(message, theirs, xonly.format())
    tampered = theirs[:-1] + bytes([theirs[-1] ^ 1])
    assert not schnorr_verify(message, tampered, xonly.format())
    assert not xonly.verify(tampered, message)


@pytest.mark.parametrize("index", range(16))
def test_ecdsa_rfc6979_signatures_match_libsecp256k1(index: int) -> None:
    cc = _coincurve()
    scalar = SCALARS[index]
    digest = hashlib.sha256(f"differential ecdsa {index}".encode()).digest()
    key = cc.PrivateKey(scalar.to_bytes(32, "big"))
    r, s = ecdsa_sign_digest(digest, scalar, backend="python")
    der = key.sign(digest, hasher=None)
    assert cc.PublicKey(key.public_key.format()).verify(der, digest, hasher=None)
    assert _der_to_rs(der) == (r, s)
    assert ecdsa_verify_digest(digest, (r, s), _point(scalar))


def _der_to_rs(der: bytes) -> tuple[int, int]:
    assert der[0] == 0x30 and der[1] == len(der) - 2
    offset = 2
    values = []
    for _ in range(2):
        assert der[offset] == 0x02
        length = der[offset + 1]
        values.append(int.from_bytes(der[offset + 2:offset + 2 + length], "big"))
        offset += 2 + length
    return values[0], values[1]


@pytest.mark.parametrize("index", range(24))
def test_public_key_recovery_matches_libsecp256k1_recoverable_signatures(index: int) -> None:
    cc = _coincurve()
    scalar = SCALARS[index]
    digest = hashlib.sha256(f"differential recovery {index}".encode()).digest()
    key = cc.PrivateKey(scalar.to_bytes(32, "big"))
    compact = key.sign_recoverable(digest, hasher=None)  # r || s || recovery id
    r, s = int.from_bytes(compact[:32], "big"), int.from_bytes(compact[32:64], "big")
    candidates = recover_public_keys_from_signature(digest, (r, s))
    expected = parse_sec1(key.public_key.format())
    assert expected in candidates
    # libsecp256k1's own recovery with the given id must land on the same key.
    recovered = cc.PublicKey.from_signature_and_message(compact, digest, hasher=None)
    assert parse_sec1(recovered.format()) == expected
    # Every candidate we return must itself verify under libsecp256k1.
    der = key.sign(digest, hasher=None)
    for candidate in candidates:
        assert cc.PublicKey(serialize_sec1(candidate)).verify(der, digest, hasher=None)


@pytest.mark.parametrize("scalar", SCALARS[:12])
def test_multiplication_matches_fastecdsa_when_installed(scalar: int) -> None:
    pytest.importorskip("fastecdsa")
    base = _point(random.Random(scalar).randrange(1, N))
    assert scalar_mult(scalar, base, backend="fastecdsa") == scalar_mult(scalar, base, backend="python")
    assert scalar_mult(scalar, G, backend="fastecdsa") == scalar_mult(scalar, G, backend="python")


@pytest.mark.parametrize("backend", ["coincurve", "fastecdsa"])
def test_native_libraries_match_the_frozen_reference(backend: str) -> None:
    # libsecp256k1 / fastecdsa against keylab.ec.reference directly, independent of KeyLab's
    # optimized Python paths: each side is checked by something that shares no code with it.
    pytest.importorskip(backend)
    points = [G, *(_point(s) for s in SCALARS[-3:])]
    for scalar in SCALARS[:12] + [0, N, N + 5]:
        for base in points:
            assert scalar_mult(scalar, base, backend=backend) == reference.scalar_mult(scalar, base)
