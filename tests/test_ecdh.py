"""ECDH reference, backend-fallback, and libsecp256k1 differential tests."""

from __future__ import annotations

import importlib

import pytest

from keylab.ec import reference
from keylab.ec.ecdh import ecdh, ecdh_coincurve, ecdh_reference
from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import G, N

_TWO_G_X = bytes.fromhex("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")


def test_known_shared_x_vector_and_party_symmetry() -> None:
    public_2g = reference.scalar_mult(2, G)
    assert public_2g is not None
    assert ecdh_reference(1, public_2g) == _TWO_G_X
    assert ecdh_reference(2, G) == _TWO_G_X
    assert ecdh_reference(1, serialize_sec1(public_2g)) == _TWO_G_X
    assert ecdh_reference(1, serialize_sec1(public_2g, compressed=False)) == _TWO_G_X


@pytest.mark.parametrize("privkey", [1, 2, 3, N - 1, N - 2, (1 << 255) + 12345])
def test_coincurve_matches_reference_for_deterministic_keys(privkey: int) -> None:
    pytest.importorskip("coincurve")
    peer_scalar = (privkey * 17 + 23) % N or 1
    peer_public = reference.scalar_mult(peer_scalar, G)
    assert peer_public is not None
    expected = ecdh_reference(privkey, peer_public)
    assert ecdh_coincurve(privkey, peer_public) == expected
    assert ecdh_coincurve(privkey, serialize_sec1(peer_public)) == expected


def test_auto_backend_falls_back_when_coincurve_is_unavailable(monkeypatch) -> None:
    ecdh_module = importlib.import_module("keylab.ec.ecdh")
    monkeypatch.setattr(ecdh_module, "find_spec", lambda name: None)
    assert ecdh(1, G) == ecdh_reference(1, G)


@pytest.mark.parametrize("privkey", [0, -1, N, N + 1, True])
def test_invalid_private_scalar_is_rejected(privkey: int) -> None:
    with pytest.raises(ValueError, match="private scalar"):
        ecdh_reference(privkey, G)


def test_invalid_public_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="infinity"):
        ecdh_reference(1, None)
    with pytest.raises(ValueError, match="SEC1"):
        ecdh_reference(1, b"invalid")
    with pytest.raises(ValueError, match="public key"):
        ecdh_reference(1, (1, 1))


def test_explicit_coincurve_backend_does_not_fall_back(monkeypatch) -> None:
    ecdh_module = importlib.import_module("keylab.ec.ecdh")

    def unavailable(privkey: int, pubkey: object) -> bytes:
        raise ImportError("coincurve unavailable")

    monkeypatch.setattr(ecdh_module, "ecdh_coincurve", unavailable)
    with pytest.raises(ImportError, match="coincurve unavailable"):
        ecdh(1, G, backend="coincurve")


def test_unknown_backend_is_rejected() -> None:
    with pytest.raises(ValueError, match="backend must be one of"):
        ecdh(1, G, backend="native")
