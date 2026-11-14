"""Brainwallet dictionary-attack demo: offline, correct, and safely scoped."""

from __future__ import annotations

import pytest

from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import G, scalar_mult
from keylab.encoding.address import p2pkh_address, p2wpkh_address
from keylab.research.brainwallet import (
    crack_brainwallet,
    iter_wordlist,
    passphrase_hash160s,
    passphrase_to_privkey,
    passphrase_to_pubkeys,
)

_PASS = b"correct horse battery staple"


def _address(passphrase: bytes, *, compressed: bool, kind: str = "p2pkh") -> str:
    sec = serialize_sec1(scalar_mult(passphrase_to_privkey(passphrase), G), compressed=compressed)
    return p2pkh_address(sec, "mainnet") if kind == "p2pkh" else p2wpkh_address(sec, "mainnet")


def _wordlist(tmp_path, lines: list[bytes]):
    path = tmp_path / "words.txt"
    path.write_bytes(b"\n".join(lines) + b"\n")
    return path


def test_passphrase_to_privkey_is_deterministic_sha256() -> None:
    import hashlib

    expected = int.from_bytes(hashlib.sha256(_PASS).digest(), "big")
    assert passphrase_to_privkey(_PASS) == expected


def test_passphrase_to_privkey_rejects_non_bytes() -> None:
    with pytest.raises(TypeError):
        passphrase_to_privkey("not-bytes")  # type: ignore[arg-type]


def test_hash160s_match_derived_addresses() -> None:
    hashes = passphrase_hash160s(_PASS)
    pubkeys = passphrase_to_pubkeys(_PASS)
    assert set(hashes) == {"compressed", "uncompressed"}
    assert len(pubkeys["compressed"]) == 33
    assert len(pubkeys["uncompressed"]) == 65


def test_iter_wordlist_streams_binary_and_strips(tmp_path) -> None:
    path = tmp_path / "wl.txt"
    path.write_bytes(b"alpha\r\n\nbeta\n\xff\xfe\n")  # blank line + non-UTF8 bytes
    assert list(iter_wordlist(path)) == [b"alpha", b"beta", b"\xff\xfe"]


@pytest.mark.parametrize("compressed", [True, False])
def test_crack_finds_planted_passphrase(tmp_path, compressed: bool) -> None:
    target = _address(_PASS, compressed=compressed)
    wordlist = _wordlist(tmp_path, [b"password", b"123456", _PASS, b"letmein"])
    result = crack_brainwallet(target, wordlist, reveal_private_key=True)
    assert result.found is True
    assert result.passphrase == _PASS
    assert result.matched_form == ("compressed" if compressed else "uncompressed")
    assert result.tried == 3
    assert result.private_key_hex == f"{passphrase_to_privkey(_PASS):064x}"


def test_crack_matches_p2wpkh_target_too(tmp_path) -> None:
    # P2WPKH shares HASH160 with P2PKH for the compressed key, so it matches.
    target = _address(_PASS, compressed=True, kind="p2wpkh")
    wordlist = _wordlist(tmp_path, [_PASS])
    assert crack_brainwallet(target, wordlist).found is True


def test_crack_reports_clean_miss(tmp_path) -> None:
    target = _address(_PASS, compressed=True)
    wordlist = _wordlist(tmp_path, [b"nope", b"wrong"])
    result = crack_brainwallet(target, wordlist)
    assert result.found is False
    assert result.passphrase is None
    assert result.private_key_hex is None
    assert result.tried == 2


def test_private_key_hidden_unless_revealed(tmp_path) -> None:
    target = _address(_PASS, compressed=True)
    wordlist = _wordlist(tmp_path, [_PASS])
    assert crack_brainwallet(target, wordlist).private_key_hex is None


def test_limit_caps_attempts(tmp_path) -> None:
    target = _address(_PASS, compressed=True)
    wordlist = _wordlist(tmp_path, [b"a", b"b", _PASS])
    result = crack_brainwallet(target, wordlist, limit=2)
    assert result.found is False
    assert result.tried == 2
