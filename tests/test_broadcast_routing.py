"""Broadcast routing: the mainnet confirmation guard and the coincurve guard."""

from __future__ import annotations

import pytest

from keylab.verify.node import Network
from keylab.wallet.broadcast import (
    MainnetConfirmationError,
    broadcast,
    require_coincurve_for_mainnet,
)

_TXID = "cd" * 32


class _FakeBroadcaster:
    def __init__(self) -> None:
        self.called_with: str | None = None

    def broadcast(self, raw_tx_hex: str) -> str:
        self.called_with = raw_tx_hex
        return _TXID


def test_mainnet_requires_explicit_confirmation() -> None:
    caster = _FakeBroadcaster()
    with pytest.raises(MainnetConfirmationError, match="explicit confirmation"):
        broadcast("00" * 20, Network.MAINNET, broadcaster=caster)
    assert caster.called_with is None  # nothing was sent


def test_mainnet_broadcasts_with_confirmation() -> None:
    caster = _FakeBroadcaster()
    txid = broadcast("ab" * 20, Network.MAINNET, confirm_mainnet=True, broadcaster=caster)
    assert txid == _TXID
    assert caster.called_with == "ab" * 20


def test_testnet_needs_no_confirmation() -> None:
    caster = _FakeBroadcaster()
    assert broadcast("ef" * 20, Network.TESTNET, broadcaster=caster) == _TXID
    assert caster.called_with == "ef" * 20


def test_rejects_bad_network() -> None:
    with pytest.raises(TypeError, match="Network"):
        broadcast("ab" * 20, "mainnet")  # type: ignore[arg-type]


def test_require_coincurve_for_mainnet() -> None:
    # coincurve is installed in CI, so the mainnet guard passes and testnet is a no-op.
    require_coincurve_for_mainnet(Network.MAINNET)
    require_coincurve_for_mainnet(Network.TESTNET)


def test_require_coincurve_raises_when_backend_missing(monkeypatch) -> None:
    import keylab.ec.coincurve_backend as backend

    def _raise() -> None:
        raise ImportError("coincurve not installed")

    monkeypatch.setattr(backend, "_coincurve", _raise)
    with pytest.raises(ImportError, match="coincurve"):
        require_coincurve_for_mainnet(Network.MAINNET)
