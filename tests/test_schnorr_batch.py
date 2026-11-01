"""BIP-340 batch verification: equals the AND of individual verifications (M3.0).

`schnorr_verify_batch` checks many signatures as one multi-scalar multiplication
with random coefficients (first = 1). Its result must equal
`all(schnorr_verify(...))` on every input, under both production (secrets) and
deterministic (explicit-coefficient) modes.
"""

from __future__ import annotations

import csv
import random
import secrets
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from keylab.ec import schnorr
from keylab.ec.schnorr import (
    schnorr_public_key,
    schnorr_sign,
    schnorr_verify,
    schnorr_verify_batch,
)
from keylab.ec.secp256k1 import N

FAST = settings(max_examples=25, deadline=None)
DET = {"coefficients": None}  # placeholder; most tests pass explicit coefficients


def _key(seed: int) -> int:
    return random.Random(seed).randrange(1, N)


def _item(seed: int, message: bytes):
    k = _key(seed)
    return (message, schnorr_sign(message, k, bytes(32)), schnorr_public_key(k))


def _valid_items(n: int, start: int = 0):
    rng = random.Random(1000 + start)
    return [_item(start + i + 1, bytes([start + i]) + rng.randbytes(8 + i)) for i in range(n)]


def _corrupt_sig(item):
    message, signature, pub = item
    b = bytearray(signature)
    b[40] ^= 0x01
    return (message, bytes(b), pub)


def _det(n: int):
    """Deterministic coefficients of length n, first = 1, rest fixed and in range."""
    return [1, *[(37 * i + 11) % (N - 1) + 1 for i in range(1, n)]]


def _matches_individual(items, **kw) -> bool:
    batch = schnorr_verify_batch(items, **kw)
    individual = all(schnorr_verify(*it) for it in items)
    assert batch == individual, (batch, individual)
    return batch


# --- required cases ---------------------------------------------------------------------------

def test_empty_batch_is_true() -> None:
    assert schnorr_verify_batch([]) is True


def test_singleton_equals_individual() -> None:
    for item in _valid_items(3):
        assert _matches_individual([item]) is True
        assert _matches_individual([_corrupt_sig(item)]) is False


def test_mixed_valid_signatures() -> None:
    items = _valid_items(8)
    assert _matches_individual(items) is True
    assert _matches_individual(items, coefficients=_det(8)) is True


@pytest.mark.parametrize("position", [0, 3, 7])
def test_one_invalid_among_many(position: int) -> None:
    items = _valid_items(8)
    items[position] = _corrupt_sig(items[position])
    assert _matches_individual(items) is False
    assert _matches_individual(items, coefficients=_det(8)) is False


def test_multiple_invalid_signatures() -> None:
    items = _valid_items(10)
    for position in (1, 4, 9):
        items[position] = _corrupt_sig(items[position])
    assert _matches_individual(items) is False


def test_malformed_signatures() -> None:
    good = _valid_items(3)
    base = good[1]
    for bad_sig in (b"\x00" * 63, b"\x00" * 65, b"", bytearray(64), 12345):
        assert schnorr_verify_batch([*good[:1], (base[0], bad_sig, base[2])]) is False


def test_malformed_public_keys() -> None:
    good = _valid_items(2)
    base = good[0]
    for bad_key in (b"\x00" * 31, b"\x00" * 33, 777, b""):
        assert schnorr_verify_batch([(base[0], base[1], bad_key), good[1]]) is False


def test_invalid_x_coordinate_does_not_lift() -> None:
    # An x-only key whose x has no even-y point on the curve fails the batch.
    item = _valid_items(1)[0]
    non_liftable = (0).to_bytes(32, "big")  # x=0: 7 is not a QR, no point
    assert schnorr_verify_batch([(item[0], item[1], non_liftable)]) is False


def test_invalid_r_value() -> None:
    item = _valid_items(1)[0]
    p_hex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
    r_ge_p = bytes.fromhex(p_hex) + item[1][32:]          # r = P (>= field prime)
    r_no_lift = (0).to_bytes(32, "big") + item[1][32:]    # r that does not lift
    assert schnorr_verify_batch([(item[0], r_ge_p, item[2])]) is False
    assert schnorr_verify_batch([(item[0], r_no_lift, item[2])]) is False


def test_invalid_s_value() -> None:
    item = _valid_items(1)[0]
    s_ge_n = item[1][:32] + N.to_bytes(32, "big")          # s = N (out of range)
    assert schnorr_verify_batch([(item[0], s_ge_n, item[2])]) is False


def test_duplicate_signatures() -> None:
    item = _valid_items(1)[0]
    assert _matches_individual([item, item, item]) is True
    bad = _corrupt_sig(item)
    assert _matches_individual([bad, bad]) is False


def test_duplicate_public_keys_distinct_messages() -> None:
    k = _key(42)
    pub = schnorr_public_key(k)
    items = [(m, schnorr_sign(m, k, bytes(32)), pub) for m in (b"a", b"bb", b"ccc")]
    assert _matches_individual(items) is True


def test_duplicate_messages_distinct_keys() -> None:
    message = b"one message, many signers"
    items = [_item(s, message) for s in (1, 2, 3)]
    assert _matches_individual(items) is True


# --- official BIP-340 vectors -----------------------------------------------------------------

_VEC = Path(__file__).parent / "vectors" / "bip340_test_vectors.csv"
with _VEC.open(encoding="utf-8") as _f:
    _ROWS = list(csv.DictReader(_f))


def _vector_items():
    valid, expected = [], []
    for row in _ROWS:
        pub = bytes.fromhex(row["public key"])
        msg = bytes.fromhex(row["message"])
        sig = bytes.fromhex(row["signature"])
        result = row["verification result"].strip().upper() == "TRUE"
        valid.append((msg, sig, pub))
        expected.append(result)
    return valid, expected


def test_official_vectors_batch_equals_individual() -> None:
    items, expected = _vector_items()
    for item, want in zip(items, expected, strict=True):
        assert schnorr_verify_batch([item]) is (want and schnorr_verify(*item))


def test_official_valid_vectors_batch_verify_together() -> None:
    items, expected = _vector_items()
    valid = [it for it, ok in zip(items, expected, strict=True) if ok and schnorr_verify(*it)]
    assert len(valid) >= 4
    assert schnorr_verify_batch(valid) is True
    assert schnorr_verify_batch(valid, coefficients=_det(len(valid))) is True


# --- deterministic / production modes + first-coefficient rule --------------------------------

def test_first_coefficient_must_be_one() -> None:
    items = _valid_items(3)
    with pytest.raises(ValueError, match="first equal to 1"):
        schnorr_verify_batch(items, coefficients=[2, 3, 4])
    with pytest.raises(ValueError, match="len\\(items\\)"):
        schnorr_verify_batch(items, coefficients=[1, 2])
    with pytest.raises(ValueError):
        schnorr_verify_batch(items, coefficients=[1, 0, 5])     # 0 out of [1, N-1]
    assert schnorr.N == N
    assert schnorr_verify_batch(items, coefficients=[1, 2, 3]) == all(schnorr_verify(*it) for it in items)


def test_batch_coefficients_helper_shape() -> None:
    coeffs = schnorr._batch_coefficients(5)
    assert len(coeffs) == 5 and coeffs[0] == 1
    assert all(1 <= a < N for a in coeffs)


def test_deterministic_and_production_agree_on_result() -> None:
    items = _valid_items(6)
    assert schnorr_verify_batch(items) is True                   # production (secrets)
    assert schnorr_verify_batch(items, coefficients=_det(6)) is True
    bad = list(items)
    bad[2] = _corrupt_sig(bad[2])
    assert schnorr_verify_batch(bad) is False
    assert schnorr_verify_batch(bad, coefficients=_det(6)) is False


# --- security: coefficients come from secrets, never random.Random ----------------------------

def test_production_coefficients_come_from_secrets(monkeypatch) -> None:
    calls = {"n": 0}
    real = secrets.randbelow

    def counting(n):
        calls["n"] += 1
        return real(n)

    monkeypatch.setattr(schnorr.secrets, "randbelow", counting)
    items = _valid_items(5)
    assert schnorr_verify_batch(items) is True
    assert calls["n"] == 4   # count-1 secure draws (first coefficient is the fixed 1)


def test_coefficient_generation_never_uses_random_module(monkeypatch) -> None:
    items = _valid_items(5)  # build inputs before forbidding random (the helper uses it)

    # If the batch coefficient path ever reached random.Random, this would raise.
    import random as random_module

    def forbidden(*args, **kwargs):
        raise AssertionError("batch verification must not use random.Random")

    monkeypatch.setattr(random_module, "Random", forbidden)
    monkeypatch.setattr(random_module, "randrange", forbidden)
    monkeypatch.setattr(random_module, "randint", forbidden)
    assert schnorr_verify_batch(items) is True


def test_explicit_coefficients_do_not_persist_into_production(monkeypatch) -> None:
    items = _valid_items(4)
    # A deterministic call must not change the source of a later production call.
    assert schnorr_verify_batch(items, coefficients=_det(4)) is True
    seen = {"secrets": False}
    real = secrets.randbelow
    monkeypatch.setattr(schnorr.secrets, "randbelow", lambda n: seen.__setitem__("secrets", True) or real(n))
    assert schnorr_verify_batch(items) is True
    assert seen["secrets"] is True


# --- Hypothesis -------------------------------------------------------------------------------

@given(st.lists(st.integers(1, 2**248), min_size=0, max_size=8),
       st.lists(st.booleans(), min_size=0, max_size=8))
@FAST
def test_random_batches_match_individual(seeds: list[int], flip: list[bool]) -> None:
    items = []
    for i, seed in enumerate(seeds):
        message = seed.to_bytes(32, "big")
        item = _item(seed, message)
        if i < len(flip) and flip[i]:
            item = _corrupt_sig(item)
        items.append(item)
    assert schnorr_verify_batch(items) == all(schnorr_verify(*it) for it in items)
