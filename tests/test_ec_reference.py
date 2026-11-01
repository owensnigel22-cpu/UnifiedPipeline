"""The frozen oracle (keylab.ec.reference) is checked against external evidence, not KeyLab."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from keylab.ec import reference as ref
from keylab.ec import secp256k1

# Published secp256k1 multiples of G (SEC 2 generator; 2G and 3G are standard test values).
TWO_G = (0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
         0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A)
THREE_G = (0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,
           0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672)

with (Path(__file__).parent / "vectors" / "bip340_test_vectors.csv").open(encoding="utf-8") as _csv:
    BIP340_KEYS = [(int(row["secret key"], 16), bytes.fromhex(row["public key"]))
                   for row in csv.DictReader(_csv) if row["secret key"]]


def test_constants_match_sec2_and_keylab() -> None:
    assert ref.P == 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    assert (ref.P, ref.N, ref.G) == (secp256k1.P, secp256k1.N, secp256k1.G)
    assert ref.is_on_curve(ref.G)


def test_published_small_multiples() -> None:
    assert ref.scalar_mult(1) == ref.G
    assert ref.scalar_mult(2) == ref.double(ref.G) == TWO_G
    assert ref.scalar_mult(3) == ref.add(TWO_G, ref.G) == THREE_G


@pytest.mark.parametrize("secret,xonly", BIP340_KEYS, ids=[f"bip340-{i}" for i in range(len(BIP340_KEYS))])
def test_public_keys_match_the_official_bip340_vectors(secret: int, xonly: bytes) -> None:
    assert ref.encode_xonly(ref.scalar_mult(secret)) == xonly


def test_group_order_and_identity() -> None:
    assert ref.scalar_mult(ref.N) is None
    assert ref.scalar_mult(ref.N - 1) == ref.negate(ref.G)
    assert ref.scalar_mult(ref.N + 1) == ref.G
    assert ref.scalar_mult(0) is None
    assert ref.add(ref.G, ref.negate(ref.G)) is None
    assert ref.add(None, ref.G) == ref.add(ref.G, None) == ref.G
    assert ref.double(None) is None


def test_addition_is_associative_and_commutative_on_small_multiples() -> None:
    a, b, c = ref.scalar_mult(5), ref.scalar_mult(11), ref.scalar_mult(1000003)
    assert ref.add(a, b) == ref.add(b, a)
    assert ref.add(ref.add(a, b), c) == ref.add(a, ref.add(b, c)) == ref.scalar_mult(5 + 11 + 1000003)


def test_encodings_round_trip_and_reject_invalid_input() -> None:
    point = THREE_G
    assert ref.encode_compressed(point).hex().startswith("02")  # 3G has even y
    assert ref.decode(ref.encode_compressed(point)) == point
    assert ref.decode(ref.encode_uncompressed(point)) == point
    assert ref.decode(ref.encode_compressed(ref.negate(point))) == ref.negate(point)
    for invalid in (b"\x02" + bytes(32), b"\x04" + bytes(64), b"\x06" + bytes(32), b""):
        with pytest.raises(ValueError):
            ref.decode(invalid)
    with pytest.raises(ValueError):
        ref.encode_compressed(None)
    with pytest.raises(ValueError):
        ref.scalar_mult(-1)
    with pytest.raises(ValueError):
        ref.scalar_mult(1, (1, 1))
