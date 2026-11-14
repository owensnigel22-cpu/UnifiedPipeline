"""CLI wiring for the educational key-weakness demos (JSON summaries)."""

from __future__ import annotations

import json

from keylab.cli import main
from keylab.ec.sec1 import serialize_sec1
from keylab.ec.secp256k1 import G, scalar_mult
from keylab.encoding.address import p2pkh_address
from keylab.research.brainwallet import passphrase_to_privkey
from keylab.research.weak_rng import pubkey_sec


def _json_out(capsys) -> dict:
    return json.loads(capsys.readouterr().out.strip().splitlines()[-1])


def test_cli_halving_lsb_demo(capsys) -> None:
    code = main(["halving-lsb", "--secret", "0xBEEF", "--leaks", "8"])
    payload = _json_out(capsys)
    assert code == 0
    assert payload["mode"] == "halving-lsb-demo"
    assert payload["verified"] is True
    assert payload["recovered"] == 0xBEEF


def test_cli_weak_rng_scan(capsys) -> None:
    target = pubkey_sec(1_000_077).hex()
    code = main(["weak-rng-scan", "--target-pubkey", target, "--start", "1000000", "--count", "200"])
    payload = _json_out(capsys)
    assert code == 0
    assert payload["found"] is True
    assert payload["private_key"] == 1_000_077
    assert payload["verified"] is True


def test_cli_weak_rng_scan_miss_returns_1(capsys) -> None:
    target = pubkey_sec(9_000_000).hex()
    code = main(["weak-rng-scan", "--target-pubkey", target, "--start", "1000000", "--count", "50"])
    payload = _json_out(capsys)
    assert code == 1
    assert payload["found"] is False


def test_cli_brainwallet(tmp_path, capsys) -> None:
    passphrase = b"satoshi nakamoto"
    address = p2pkh_address(
        serialize_sec1(scalar_mult(passphrase_to_privkey(passphrase), G), compressed=True), "mainnet"
    )
    wordlist = tmp_path / "wl.txt"
    wordlist.write_bytes(b"alpha\nsatoshi nakamoto\nbeta\n")
    code = main(["brainwallet", "--address", address, "--wordlist", str(wordlist)])
    payload = _json_out(capsys)
    assert code == 0
    assert payload["found"] is True
    assert payload["passphrase"] == "satoshi nakamoto"
    assert payload["private_key_hex"] is None  # not revealed by default
    assert "Educational" in payload["warning"]
