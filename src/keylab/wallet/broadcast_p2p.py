"""Broadcast a pre-signed Bitcoin transaction directly over the P2P protocol.

Connects to a Bitcoin node's P2P port (8333 mainnet / 18333 testnet / 18444
regtest), performs the version handshake, announces the transaction with an
``inv``, and sends the ``tx`` when the peer requests it with ``getdata`` -- the
methodology of ``laanwj/bitcoin-submittx``. It pushes an **already-signed**
transaction and handles **no private keys**. See docs/references.md and SECURITY.md.
"""

from __future__ import annotations

import random
import socket
from collections.abc import Callable
from typing import Protocol

import bitcoin
from bitcoin.core import CTransaction, Hash, b2lx, x
from bitcoin.messages import (
    PROTO_VERSION,
    MsgSerializable,
    msg_inv,
    msg_pong,
    msg_tx,
    msg_verack,
    msg_version,
)
from bitcoin.net import CInv

from keylab.verify.node import Network

__all__ = ["P2PBroadcastError", "P2PBroadcaster", "Peer"]

_PORTS = {Network.MAINNET: 8333, Network.TESTNET: 18333, Network.REGTEST: 18444}
_PARAMS = {Network.MAINNET: "mainnet", Network.TESTNET: "testnet", Network.REGTEST: "regtest"}
_MSG_TX = 1
_MAX_MESSAGES = 32  # bound every receive loop so a misbehaving peer cannot hang us


class P2PBroadcastError(RuntimeError):
    """The P2P handshake or transaction relay did not complete."""


class Peer(Protocol):
    """A framed message channel to one node (send/recv python-bitcoinlib messages)."""

    def send(self, message: MsgSerializable) -> None: ...
    def recv(self) -> MsgSerializable: ...
    def close(self) -> None: ...


class _SocketPeer:
    def __init__(self, sock: socket.socket, protover: int) -> None:
        self._sock = sock
        self._reader = sock.makefile("rb")
        self._protover = protover

    def send(self, message: MsgSerializable) -> None:
        self._sock.sendall(message.to_bytes())

    def recv(self) -> MsgSerializable:
        return MsgSerializable.stream_deserialize(self._reader, self._protover)

    def close(self) -> None:
        try:
            self._reader.close()
        finally:
            self._sock.close()


def _default_peer_factory(host: str, port: int, timeout: float) -> Peer:
    return _SocketPeer(socket.create_connection((host, port), timeout=timeout), PROTO_VERSION)


def _pong_for(message: MsgSerializable) -> msg_pong:
    pong = msg_pong()
    pong.nonce = getattr(message, "nonce", 0)
    return pong


class P2PBroadcaster:
    """Push a signed tx to a node over P2P (handshake -> inv -> tx on getdata)."""

    def __init__(
        self, network: Network = Network.MAINNET, host: str = "127.0.0.1", *,
        port: int | None = None, timeout: float = 15.0,
        peer_factory: Callable[[str, int, float], Peer] | None = None,
    ) -> None:
        if network not in _PARAMS:
            raise ValueError(f"unsupported network: {network}")
        self._network = network
        self._host = host
        self._port = port if port is not None else _PORTS[network]
        self._timeout = timeout
        self._peer_factory = peer_factory or _default_peer_factory

    def broadcast(self, raw_tx_hex: str) -> str:
        if not isinstance(raw_tx_hex, str) or not raw_tx_hex:
            raise ValueError("raw_tx_hex must be a non-empty hex string")
        bitcoin.SelectParams(_PARAMS[self._network])
        try:
            tx = CTransaction.deserialize(x(raw_tx_hex))
        except Exception as exc:
            raise ValueError("raw_tx_hex is not a valid transaction") from exc
        tx_hash = Hash(tx.serialize())

        peer = self._peer_factory(self._host, self._port, self._timeout)
        try:
            self._handshake(peer)
            self._announce_and_send(peer, tx, tx_hash)
            return b2lx(tx_hash)
        finally:
            peer.close()

    def _handshake(self, peer: Peer) -> None:
        version = msg_version()
        version.nVersion = PROTO_VERSION
        version.nNonce = random.getrandbits(64)
        version.strSubVer = b"/keylab-submittx:0.1/"
        version.nStartingHeight = 0
        peer.send(version)
        got_version = got_verack = False
        for _ in range(_MAX_MESSAGES):
            if got_version and got_verack:
                return
            message = peer.recv()
            command = message.command
            if command == b"version":
                got_version = True
                peer.send(msg_verack())
            elif command == b"verack":
                got_verack = True
            elif command == b"ping":
                peer.send(_pong_for(message))
        if not (got_version and got_verack):
            raise P2PBroadcastError("P2P version handshake did not complete")

    def _announce_and_send(self, peer: Peer, tx: CTransaction, tx_hash: bytes) -> None:
        inv = msg_inv()
        item = CInv()
        item.type = _MSG_TX
        item.hash = tx_hash
        inv.inv = [item]
        peer.send(inv)
        for _ in range(_MAX_MESSAGES):
            message = peer.recv()
            command = message.command
            if command == b"ping":
                peer.send(_pong_for(message))
                continue
            if command == b"getdata" and any(getattr(i, "hash", None) == tx_hash for i in message.inv):
                relay = msg_tx()
                relay.tx = tx
                peer.send(relay)
                return
            if command == b"reject":
                reason = getattr(message, "reason", b"")
                raise P2PBroadcastError(f"peer rejected the transaction: {reason!r}")
        raise P2PBroadcastError("peer did not request the transaction (no getdata)")
