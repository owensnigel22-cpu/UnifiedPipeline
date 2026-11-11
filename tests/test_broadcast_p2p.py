"""P2P broadcaster (scripted fake peer — no real socket).

A fake Peer scripts the server side (version, verack, getdata) and records what we
send; the broadcaster must complete the handshake, announce via inv, send the tx
on getdata, and return the correct txid.
"""

from __future__ import annotations

import bitcoin
import pytest
from bitcoin.core import (
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    COutPoint,
    Hash,
    b2lx,
    b2x,
    lx,
    x,
)
from bitcoin.messages import msg_getdata, msg_verack, msg_version
from bitcoin.net import CInv

from keylab.verify.node import Network
from keylab.wallet.broadcast_p2p import P2PBroadcaster, P2PBroadcastError


def _sample_tx_hex() -> str:
    bitcoin.SelectParams("mainnet")
    txin = CMutableTxIn(COutPoint(lx("00" * 32), 0))
    txout = CMutableTxOut(1000, x("76a914" + "11" * 20 + "88ac"))
    return b2x(CMutableTransaction([txin], [txout]).serialize())


class _FakePeer:
    def __init__(self, inbound: list) -> None:
        self.inbound = list(inbound)
        self.sent: list = []
        self.closed = False

    def send(self, message) -> None:
        self.sent.append(message)

    def recv(self):
        if not self.inbound:
            raise AssertionError("broadcaster read past the scripted messages")
        return self.inbound.pop(0)

    def close(self) -> None:
        self.closed = True


def _getdata_for(tx_hash: bytes) -> msg_getdata:
    getdata = msg_getdata()
    item = CInv()
    item.type = 1
    item.hash = tx_hash
    getdata.inv = [item]
    return getdata


def test_p2p_broadcast_completes_and_returns_txid() -> None:
    raw = _sample_tx_hex()
    tx_hash = Hash(x(raw))
    peer = _FakePeer([msg_version(), msg_verack(), _getdata_for(tx_hash)])

    caster = P2PBroadcaster(Network.MAINNET, peer_factory=lambda h, p, t: peer)
    txid = caster.broadcast(raw)

    assert txid == b2lx(tx_hash)
    sent = [m.command for m in peer.sent]
    assert sent == [b"version", b"verack", b"inv", b"tx"]
    assert peer.closed is True


def test_p2p_default_port_by_network() -> None:
    assert P2PBroadcaster(Network.MAINNET)._port == 8333
    assert P2PBroadcaster(Network.TESTNET)._port == 18333
    assert P2PBroadcaster(Network.REGTEST)._port == 18444


def test_p2p_no_getdata_raises() -> None:
    raw = _sample_tx_hex()
    # handshake completes but the peer never requests the tx
    peer = _FakePeer([msg_version(), msg_verack()] + [msg_verack() for _ in range(40)])
    caster = P2PBroadcaster(peer_factory=lambda h, p, t: peer)
    with pytest.raises(P2PBroadcastError, match="getdata"):
        caster.broadcast(raw)


def test_p2p_rejects_bad_tx_hex() -> None:
    caster = P2PBroadcaster(peer_factory=lambda h, p, t: _FakePeer([]))
    with pytest.raises(ValueError, match="valid transaction|hex"):
        caster.broadcast("00")
