"""Phase E: the unified `keylab forensics` CLI (offline, mock-transport only).

The online subcommands are exercised against an httpx.MockTransport-backed client
injected through the `_make_explorer_client` seam, so no network access occurs.
"""

from __future__ import annotations

import json

import httpx
import pytest

from keylab import cli
from keylab.cli import main
from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.encoding.address import hash160, p2pkh_address, p2wpkh_address
from keylab.encoding.transaction import (
    SIGHASH_ALL,
    Transaction,
    TxIn,
    TxOut,
    bip143_sighash,
    serialize_transaction,
)
from keylab.research.brainwallet import passphrase_to_privkey
from keylab.research.weak_rng_milksad import milksad_hash160, milksad_key_from_timestamp

_AMOUNT = 100_000
_NONCE = 0x00DEAD0000BEEF0000CAFE0000F00D0000BA5E0000D00D0000ABCDEF0012345678


def _json_out(capsys) -> dict:
    return json.loads(capsys.readouterr().out.strip().splitlines()[-1])


def _der(r: int, s: int) -> bytes:
    def _element(value: int) -> bytes:
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw

    body = _element(r) + _element(s)
    return b"\x30" + bytes([len(body)]) + body


def _sign(z: int, key: int, nonce: int) -> tuple[int, int]:
    point = scalar_mult(nonce, G)
    assert point is not None
    r = point[0] % N
    s = pow(nonce, -1, N) * (z + r * key) % N
    return r, s


def _pubkey(key: int) -> bytes:
    return serialize_sec1(scalar_mult(key, G), compressed=True)


def _patch_client(monkeypatch, entries: list[dict], raw_by_txid: dict[str, str]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/address/" in path and path.endswith("/txs"):
            return httpx.Response(200, json=entries)
        if "/tx/" in path and path.endswith("/hex"):
            txid = path.rsplit("/tx/", 1)[1].split("/hex")[0]
            if txid in raw_by_txid:
                return httpx.Response(200, text=raw_by_txid[txid])
        return httpx.Response(404, text="not found")

    from keylab.verify.mainnet.client import ReadOnlyExplorerClient

    client = ReadOnlyExplorerClient(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(cli, "_make_explorer_client", lambda args: client)


def _spend_fixture(key: int, txid: str) -> tuple[str, list[dict], dict[str, str]]:
    """A 1-input P2WPKH spend by ``key`` (reveals its pubkey). Returns (address, entries, raw)."""
    pubkey = _pubkey(key)
    pubkey_hash = hash160(pubkey)
    script_pubkey = b"\x00\x14" + pubkey_hash
    script_code = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
    unsigned = Transaction(
        version=2,
        inputs=(TxIn(b"\x11" * 32, 0, b"", 0xFFFFFFFF),),
        outputs=(TxOut(_AMOUNT - 1_000, script_pubkey),),
        locktime=0,
    )
    z = int.from_bytes(bip143_sighash(unsigned, 0, script_code, _AMOUNT, SIGHASH_ALL), "big")
    r, s = _sign(z, key, _NONCE)
    signed = Transaction(
        version=2,
        inputs=(TxIn(b"\x11" * 32, 0, b"", 0xFFFFFFFF, (_der(r, s) + bytes([SIGHASH_ALL]), pubkey)),),
        outputs=unsigned.outputs,
        locktime=0,
    )
    entries = [{"txid": txid, "vin": [{"prevout": {"value": _AMOUNT, "scriptpubkey": script_pubkey.hex()}}]}]
    return p2wpkh_address(pubkey), entries, {txid: serialize_transaction(signed).hex()}


def _reused_nonce_fixture(key: int, txid: str) -> tuple[str, list[dict], dict[str, str]]:
    """A 2-input P2WPKH tx by ``key`` reusing one nonce (recoverable). Returns (address, entries, raw)."""
    pubkey = _pubkey(key)
    pubkey_hash = hash160(pubkey)
    script_pubkey = b"\x00\x14" + pubkey_hash
    script_code = b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
    inputs = (TxIn(b"\x11" * 32, 0, b"", 0xFFFFFFFF), TxIn(b"\x22" * 32, 1, b"", 0xFFFFFFFF))
    outputs = (TxOut(_AMOUNT - 1_000, script_pubkey),)
    unsigned = Transaction(version=2, inputs=inputs, outputs=outputs, locktime=0)
    z0 = int.from_bytes(bip143_sighash(unsigned, 0, script_code, _AMOUNT, SIGHASH_ALL), "big")
    z1 = int.from_bytes(bip143_sighash(unsigned, 1, script_code, _AMOUNT, SIGHASH_ALL), "big")
    r0, s0 = _sign(z0, key, _NONCE)
    r1, s1 = _sign(z1, key, _NONCE)  # same nonce -> same r, recoverable
    signed = Transaction(
        version=2,
        inputs=(
            TxIn(b"\x11" * 32, 0, b"", 0xFFFFFFFF, (_der(r0, s0) + bytes([SIGHASH_ALL]), pubkey)),
            TxIn(b"\x22" * 32, 1, b"", 0xFFFFFFFF, (_der(r1, s1) + bytes([SIGHASH_ALL]), pubkey)),
        ),
        outputs=outputs,
        locktime=0,
    )
    entries = [{
        "txid": txid,
        "vin": [
            {"prevout": {"value": _AMOUNT, "scriptpubkey": script_pubkey.hex()}},
            {"prevout": {"value": _AMOUNT, "scriptpubkey": script_pubkey.hex()}},
        ],
    }]
    return p2wpkh_address(pubkey), entries, {txid: serialize_transaction(signed).hex()}


# --- offline commands -------------------------------------------------------------------------

def test_cli_forensics_milksad_recovers_seed(capsys) -> None:
    seed = 1_690_000_123
    target = milksad_hash160(seed).hex()
    code = main([
        "forensics", "milksad", "--start-ts", str(seed - 5), "--end-ts", str(seed + 5),
        "--target-hash160", target,
    ])
    payload = _json_out(capsys)
    assert code == 0
    assert payload["mode"] == "forensics-milksad"
    assert payload["found"] is True
    assert payload["hits"][0]["timestamp"] == seed
    assert payload["hits"][0]["private_key"] == "<redacted>"  # masked by default


def test_cli_forensics_milksad_reveal(capsys) -> None:
    seed = 1_690_000_200
    target = milksad_hash160(seed).hex()
    code = main([
        "forensics", "milksad", "--start-ts", str(seed), "--end-ts", str(seed + 1),
        "--target-hash160", target, "--reveal",
    ])
    payload = _json_out(capsys)
    assert code == 0
    assert payload["hits"][0]["private_key"] == f"{milksad_key_from_timestamp(seed):064x}"


def test_cli_forensics_milksad_no_match_returns_1(capsys) -> None:
    code = main([
        "forensics", "milksad", "--start-ts", "1000", "--end-ts", "1010",
        "--target-hash160", (b"\x00" * 20).hex(),
    ])
    payload = _json_out(capsys)
    assert code == 1
    assert payload["found"] is False


def test_cli_forensics_milksad_bad_hex_errors() -> None:
    with pytest.raises(SystemExit):
        main([
            "forensics", "milksad", "--start-ts", "1", "--end-ts", "2",
            "--target-hash160", "nothex",
        ])


def test_cli_forensics_brainwallet_multi(tmp_path, capsys) -> None:
    passphrase = b"satoshi nakamoto"
    address = p2pkh_address(_pubkey(passphrase_to_privkey(passphrase)))
    wordlist = tmp_path / "wl.txt"
    wordlist.write_bytes(b"alpha\nsatoshi nakamoto\nbeta\n")
    code = main([
        "forensics", "brainwallet-multi", "--wordlist", str(wordlist),
        "--address", address, "--executor", "serial",
    ])
    payload = _json_out(capsys)
    assert code == 0
    assert payload["mode"] == "forensics-brainwallet-multi"
    assert payload["found"] is True
    assert payload["hits"][0]["passphrase"] == "satoshi nakamoto"
    assert payload["hits"][0]["private_key_hex"] is None  # masked by default


# --- online commands (mock transport) ---------------------------------------------------------

def test_cli_forensics_nonce_scan(monkeypatch, capsys) -> None:
    key = 0xC0FFEE1234567890ABCDEF00FACEB00C0DED00D1E5A1AD5BADC0DE5EEDF00D12
    address, entries, raw = _reused_nonce_fixture(key, "a" * 64)
    _patch_client(monkeypatch, entries, raw)
    code = main(["forensics", "nonce-scan", "--address", address])
    payload = _json_out(capsys)
    assert code == 0
    assert payload["mode"] == "forensics-nonce-scan"
    assert payload["vulnerable"] is True
    assert len(payload["recovered"]) == 1
    assert payload["recovered"][0]["private_key_hex"] is None  # masked


def test_cli_forensics_nonce_scan_reveal(monkeypatch, capsys) -> None:
    key = 0xC0FFEE1234567890ABCDEF00FACEB00C0DED00D1E5A1AD5BADC0DE5EEDF00D12
    address, entries, raw = _reused_nonce_fixture(key, "a" * 64)
    _patch_client(monkeypatch, entries, raw)
    code = main(["forensics", "nonce-scan", "--address", address, "--reveal"])
    payload = _json_out(capsys)
    assert code == 0
    assert payload["recovered"][0]["private_key_hex"] == f"{key:064x}"


def test_cli_forensics_address_pubkey_revealed(monkeypatch, capsys) -> None:
    address, entries, raw = _spend_fixture(0xC0FFEE, "b" * 64)
    _patch_client(monkeypatch, entries, raw)
    code = main(["forensics", "address-pubkey", "--address", address])
    payload = _json_out(capsys)
    assert code == 0
    assert payload["pubkey_revealed"] is True
    assert payload["pubkey"] == _pubkey(0xC0FFEE).hex()
    assert payload["revealed_by"] == {"txid": "b" * 64, "input_index": 0}


def test_cli_forensics_address_pubkey_not_revealed(monkeypatch, capsys) -> None:
    _, entries, raw = _spend_fixture(0xC0FFEE, "b" * 64)
    _patch_client(monkeypatch, entries, raw)
    other = p2wpkh_address(_pubkey(0xDEADBEEF))  # not the spender -> key never exposed
    code = main(["forensics", "address-pubkey", "--address", other])
    payload = _json_out(capsys)
    assert code == 1
    assert payload["pubkey_revealed"] is False
    assert "not revealed" in payload["message"]


def test_cli_forensics_address_search_recovers_bounded_key(monkeypatch, capsys) -> None:
    key = 0xC0FFEE
    address, entries, raw = _spend_fixture(key, "b" * 64)
    _patch_client(monkeypatch, entries, raw)
    code = main([
        "forensics", "address-search", "--address", address,
        "--lo", str(key - 2000), "--hi", str(key + 2000),
    ])
    payload = _json_out(capsys)
    assert code == 0
    assert payload["mode"] == "forensics-address-search"
    assert payload["found"] is True
    assert payload["private_key_hex"] is None  # masked by default


def test_cli_forensics_address_search_reveal(monkeypatch, capsys) -> None:
    key = 0xC0FFEE
    address, entries, raw = _spend_fixture(key, "b" * 64)
    _patch_client(monkeypatch, entries, raw)
    code = main([
        "forensics", "address-search", "--address", address,
        "--lo", str(key - 2000), "--hi", str(key + 2000), "--reveal",
    ])
    payload = _json_out(capsys)
    assert code == 0
    assert payload["private_key_hex"] == f"{key:064x}"


def test_cli_forensics_triage_reports_without_keys(monkeypatch, capsys) -> None:
    key = 0xC0FFEE1234567890ABCDEF00FACEB00C0DED00D1E5A1AD5BADC0DE5EEDF00D12
    address, entries, raw = _reused_nonce_fixture(key, "a" * 64)
    _patch_client(monkeypatch, entries, raw)
    code = main(["forensics", "triage", "--address", address])
    captured = capsys.readouterr().out.strip().splitlines()[-1]
    payload = json.loads(captured)
    assert code == 0
    assert payload["mode"] == "forensics-triage"
    assert payload["nonce_reuse"]["vulnerable"] is True
    assert payload["nonce_reuse"]["recovered_count"] == 1
    assert payload["pubkey"]["revealed"] is True
    # Triage must not print any private key material.
    assert f"{key:064x}" not in captured
    assert "private_key" not in captured
