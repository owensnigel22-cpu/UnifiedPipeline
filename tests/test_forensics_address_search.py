"""Phase D forensics: resolve an address's pubkey on-chain, then bounded search.

The fixtures build a real BIP-143 P2WPKH spend signed by a known small key, hand
it to a fake read-only client, and assert that the pubkey is resolved and the key
is recovered over a *bounded* interval -- or that resolution fails loudly when the
address never spent. No network access occurs.
"""

from __future__ import annotations

import pytest

from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.encoding.address import hash160, p2wpkh_address
from keylab.encoding.transaction import (
    SIGHASH_ALL,
    Transaction,
    TxIn,
    TxOut,
    bip143_sighash,
    serialize_transaction,
)
from keylab.research.forensics.address_search import (
    PubkeyNotRevealed,
    recover_key_for_address,
    resolve_pubkey_for_address,
)

# A deliberately tiny private key so the kangaroo interval below is searchable.
_PRIVATE_KEY = 0xC0FFEE
_NONCE = 0x00DEAD0000BEEF0000CAFE0000F00D0000BA5E0000D00D0000ABCDEF0012345678
_AMOUNT = 100_000

assert 0 < _PRIVATE_KEY < N
assert 0 < _NONCE < N


def _der(r: int, s: int) -> bytes:
    def _element(value: int) -> bytes:
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw

    body = _element(r) + _element(s)
    return b"\x30" + bytes([len(body)]) + body


def _pubkey() -> bytes:
    return serialize_sec1(scalar_mult(_PRIVATE_KEY, G), compressed=True)


def _sign(z: int) -> tuple[int, int]:
    point = scalar_mult(_NONCE, G)
    assert point is not None
    r = point[0] % N
    s = pow(_NONCE, -1, N) * (z + r * _PRIVATE_KEY) % N
    return r, s


def _spending_transaction() -> tuple[str, bytes, list[dict]]:
    """A 1-input P2WPKH spend signed by ``_PRIVATE_KEY`` (reveals its pubkey)."""
    pubkey = _pubkey()
    pubkey_hash = hash160(pubkey)
    script_pubkey = b"\x00\x14" + pubkey_hash
    script_code = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"

    unsigned = Transaction(
        version=2,
        inputs=(TxIn(prev_txid=b"\x11" * 32, prev_index=0, script_sig=b"", sequence=0xFFFFFFFF),),
        outputs=(TxOut(amount=_AMOUNT - 1_000, script_pubkey=script_pubkey),),
        locktime=0,
    )
    z = int.from_bytes(bip143_sighash(unsigned, 0, script_code, _AMOUNT, SIGHASH_ALL), "big")
    r, s = _sign(z)
    witness = (_der(r, s) + bytes([SIGHASH_ALL]), pubkey)
    signed = Transaction(
        version=2,
        inputs=(TxIn(b"\x11" * 32, 0, b"", 0xFFFFFFFF, witness),),
        outputs=unsigned.outputs,
        locktime=0,
    )
    txid = "a" * 64
    entry = {
        "txid": txid,
        "vin": [
            {"prevout": {"value": _AMOUNT, "scriptpubkey": script_pubkey.hex()}}
        ],
    }
    return txid, serialize_transaction(signed), [entry]


class _FakeClient:
    """Duck-typed read-only client returning a canned address history and tx hex."""

    def __init__(self, txid: str, raw: bytes, entries: list[dict]) -> None:
        self._txid = txid
        self._raw = raw
        self._entries = entries

    def get_address_transactions(self, address: str) -> list[dict]:
        return self._entries

    def get_transaction_hex(self, txid: str) -> bytes:
        assert txid == self._txid
        return self._raw


def _client_with_spend() -> tuple[_FakeClient, str]:
    txid, raw, entries = _spending_transaction()
    return _FakeClient(txid, raw, entries), p2wpkh_address(_pubkey())


def test_resolve_pubkey_from_spending_input() -> None:
    client, address = _client_with_spend()
    resolved = resolve_pubkey_for_address(address, client=client)
    assert resolved.pubkey == _pubkey()
    assert resolved.public_point == scalar_mult(_PRIVATE_KEY, G)
    assert resolved.txid == "a" * 64
    assert resolved.input_index == 0


def test_resolve_pubkey_raises_when_never_spent() -> None:
    # The address history contains a spend, but by a *different* key, so the
    # queried address never revealed its own public key.
    client, _ = _client_with_spend()
    other_address = p2wpkh_address(serialize_sec1(scalar_mult(0xDEADBEEF, G), compressed=True))
    with pytest.raises(PubkeyNotRevealed, match="not revealed"):
        resolve_pubkey_for_address(other_address, client=client)


def test_resolve_pubkey_validates_max_txs() -> None:
    client, address = _client_with_spend()
    with pytest.raises(ValueError, match="max_txs"):
        resolve_pubkey_for_address(address, client=client, max_txs=0)


def test_recover_key_for_address_over_bounded_interval() -> None:
    client, address = _client_with_spend()
    lo, hi = _PRIVATE_KEY - 2000, _PRIVATE_KEY + 2000
    report = recover_key_for_address(address, lo, hi, client=client)
    assert report["found"] is True
    assert report["address"] == address
    assert report["pubkey"] == _pubkey().hex()
    assert report["revealed_by"] == {"txid": "a" * 64, "input_index": 0}
    # Masked by default.
    assert report["private_key_revealed"] is False
    assert report["private_key_hex"] is None


def test_recover_key_for_address_reveals_only_when_asked() -> None:
    client, address = _client_with_spend()
    lo, hi = _PRIVATE_KEY - 2000, _PRIVATE_KEY + 2000
    report = recover_key_for_address(address, lo, hi, client=client, reveal_private=True)
    assert report["found"] is True
    assert report["private_key_revealed"] is True
    assert report["private_key_hex"] == f"{_PRIVATE_KEY:064x}"


def test_recover_key_for_address_misses_outside_interval() -> None:
    client, address = _client_with_spend()
    # The true key is below this interval, so a bounded search must not find it.
    report = recover_key_for_address(
        address, _PRIVATE_KEY + 10_000, _PRIVATE_KEY + 12_000, client=client, max_steps=5000
    )
    assert report["found"] is False
    assert report["private_key_hex"] is None
