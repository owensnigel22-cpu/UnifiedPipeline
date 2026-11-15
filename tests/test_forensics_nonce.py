"""Phase A forensics: synthetic nonce-reuse recovery and the address-tx fetch.

The fixtures build a real BIP-143 P2WPKH transaction whose two inputs reuse one
ECDSA nonce, sign them by hand with a known key, and assert the scanner recovers
exactly that key. No network access occurs; the client test uses an in-memory
httpx transport.
"""

from __future__ import annotations

import httpx
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
)
from keylab.research.forensics import (
    NonceReuseScanner,
    extract_input_signatures,
    script_type_of,
)
from keylab.verify.mainnet.client import ReadOnlyExplorerClient

_PRIVATE_KEY = 0xC0FFEE1234567890ABCDEF00FACEB00C0DED00D1E5A1AD5BADC0DE5EEDF00D12
_NONCE = 0x00DEAD0000BEEF0000CAFE0000F00D0000BA5E0000D00D0000ABCDEF0012345678
_AMOUNT = 100_000

# Guard against a malformed test constant: both must be valid secp256k1 scalars.
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


def _sign(z: int, *, nonce: int) -> tuple[int, int]:
    point = scalar_mult(nonce, G)
    assert point is not None
    r = point[0] % N
    s = pow(nonce, -1, N) * (z + r * _PRIVATE_KEY) % N
    return r, s


def _reused_nonce_transaction(*, second_nonce: int = _NONCE) -> tuple[str, Transaction, list[TxOut]]:
    """A 2-input P2WPKH tx signed with one key; both inputs share ``second_nonce``'s r."""
    pubkey = _pubkey()
    pubkey_hash = hash160(pubkey)
    script_pubkey = b"\x00\x14" + pubkey_hash
    script_code = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"

    inputs_unsigned = (
        TxIn(prev_txid=b"\x11" * 32, prev_index=0, script_sig=b"", sequence=0xFFFFFFFF),
        TxIn(prev_txid=b"\x22" * 32, prev_index=1, script_sig=b"", sequence=0xFFFFFFFF),
    )
    outputs = (TxOut(amount=_AMOUNT - 1_000, script_pubkey=script_pubkey),)
    unsigned = Transaction(version=2, inputs=inputs_unsigned, outputs=outputs, locktime=0)

    z0 = int.from_bytes(bip143_sighash(unsigned, 0, script_code, _AMOUNT, SIGHASH_ALL), "big")
    z1 = int.from_bytes(bip143_sighash(unsigned, 1, script_code, _AMOUNT, SIGHASH_ALL), "big")
    r0, s0 = _sign(z0, nonce=_NONCE)
    r1, s1 = _sign(z1, nonce=second_nonce)

    witness0 = (_der(r0, s0) + bytes([SIGHASH_ALL]), pubkey)
    witness1 = (_der(r1, s1) + bytes([SIGHASH_ALL]), pubkey)
    signed = Transaction(
        version=2,
        inputs=(
            TxIn(b"\x11" * 32, 0, b"", 0xFFFFFFFF, witness0),
            TxIn(b"\x22" * 32, 1, b"", 0xFFFFFFFF, witness1),
        ),
        outputs=outputs,
        locktime=0,
    )
    spent = [TxOut(_AMOUNT, script_pubkey), TxOut(_AMOUNT, script_pubkey)]
    return "a" * 64, signed, spent


def test_script_type_classification() -> None:
    assert script_type_of(b"\x00\x14" + b"\x00" * 20) == "p2wpkh"
    assert script_type_of(b"\xa9\x14" + b"\x00" * 20 + b"\x87") == "p2sh-p2wpkh"
    # Legacy P2PKH is out of scope and must not be mistaken for an in-scope type.
    assert script_type_of(b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac") is None


def test_extract_input_signatures_exposes_shared_r() -> None:
    txid, tx, spent = _reused_nonce_transaction()
    signatures = extract_input_signatures(tx, spent, txid=txid)
    assert len(signatures) == 2
    assert signatures[0].r == signatures[1].r  # reused nonce -> identical r
    assert signatures[0].z != signatures[1].z  # different inputs -> different digest
    assert all(sig.script_type == "p2wpkh" for sig in signatures)
    assert all(len(sig.pubkey) == 33 for sig in signatures)


def test_scanner_recovers_the_exact_private_key() -> None:
    txid, tx, spent = _reused_nonce_transaction()
    report = NonceReuseScanner().scan_transactions([(txid, tx, spent)], address="test")

    assert report.vulnerable is True
    assert report.signatures_examined == 2
    assert report.reused_r_groups == 1
    assert len(report.recovered) == 1

    recovered = report.recovered[0]
    assert recovered.private_key == _PRIVATE_KEY
    assert recovered.verified is True
    assert recovered.addresses["p2wpkh"] == p2wpkh_address(_pubkey())
    # Evidence points at the two colluding inputs.
    assert {item.input_index for item in recovered.evidence} == {0, 1}


def test_report_json_masks_private_key_by_default() -> None:
    txid, tx, spent = _reused_nonce_transaction()
    report = NonceReuseScanner().scan_transactions([(txid, tx, spent)], address="test")

    masked = report.to_dict()
    assert masked["vulnerable"] is True
    entry = masked["recovered"][0]
    assert entry["private_key_revealed"] is False
    assert entry["private_key_hex"] is None

    revealed = report.to_dict(reveal_private=True)["recovered"][0]
    assert revealed["private_key_revealed"] is True
    assert revealed["private_key_hex"] == f"{_PRIVATE_KEY:064x}"


def test_distinct_nonces_do_not_recover_a_key() -> None:
    # Same key, but the second input uses a different nonce: no shared r, no reuse.
    txid, tx, spent = _reused_nonce_transaction(second_nonce=_NONCE ^ 0x1)
    report = NonceReuseScanner().scan_transactions([(txid, tx, spent)], address="test")
    assert report.vulnerable is False
    assert report.reused_r_groups == 0
    assert report.recovered == ()


def test_identical_signature_seen_twice_is_not_reuse() -> None:
    # The same transaction fetched twice must not look like a nonce-reuse pair
    # (identical z and s -> s1 == s2 -> unsolvable, correctly not reported).
    _txid, tx, spent = _reused_nonce_transaction()
    single_input_tx = Transaction(
        version=tx.version,
        inputs=(tx.inputs[0],),
        outputs=tx.outputs,
        locktime=tx.locktime,
    )
    one_spent = [spent[0]]
    report = NonceReuseScanner().scan_transactions(
        [("tx1" + "0" * 61, single_input_tx, one_spent), ("tx2" + "0" * 61, single_input_tx, one_spent)]
    )
    assert report.signatures_examined == 2
    assert report.vulnerable is False


def test_get_address_transactions_uses_readonly_get() -> None:
    address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        return httpx.Response(200, json=[{"txid": "a" * 64, "vin": []}])

    client = ReadOnlyExplorerClient(transport=httpx.MockTransport(handler))
    try:
        result = client.get_address_transactions(address)
    finally:
        client.close()

    assert captured["method"] == "GET"
    assert captured["path"] == f"/api/address/{address}/txs"
    assert result == [{"txid": "a" * 64, "vin": []}]


def test_get_address_transactions_rejects_unsafe_address() -> None:
    client = ReadOnlyExplorerClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    try:
        with pytest.raises(ValueError, match="Base58/Bech32 address"):
            client.get_address_transactions("../../evil/path")
    finally:
        client.close()
