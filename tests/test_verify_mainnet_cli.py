"""Offline tests for the mainnet verification CLI input and reporting paths."""

from __future__ import annotations

import io
from typing import Self

import scripts.verify_mainnet as verify_cli
from keylab.encoding.transaction import TxOut


def test_load_prevouts_from_stdin(monkeypatch) -> None:
    monkeypatch.setattr(
        verify_cli.sys,
        "stdin",
        io.StringIO('{"prevouts":[{"amount_sat":1234,"script_pubkey":"0014"}]}'),
    )
    assert verify_cli._load_prevouts("-") == (TxOut(1234, bytes.fromhex("0014")),)


def test_cli_reports_pass_without_network(monkeypatch, capsys) -> None:
    class FakeClient:
        def __init__(self, *, allowlist: tuple[str, ...]) -> None:
            assert allowlist == ("https://mempool.space",)

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def get_transaction_hex(self, txid: str) -> bytes:
            assert txid == "ab" * 32
            return b"raw-transaction"

    monkeypatch.setattr(verify_cli, "ReadOnlyExplorerClient", FakeClient)
    monkeypatch.setattr(verify_cli, "_load_prevouts", lambda _: (TxOut(1, b"\x00\x14"),))
    monkeypatch.setattr(verify_cli, "verify_transaction_signatures", lambda raw, prevouts: True)

    assert verify_cli.main(["--txid", "ab" * 32, "--prevout-data", "-"]) == 0
    assert "PASS:" in capsys.readouterr().out


def test_cli_reports_invalid_signature(monkeypatch, capsys) -> None:
    class FakeClient:
        def __init__(self, *, allowlist: tuple[str, ...]) -> None:
            pass

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def get_transaction_hex(self, txid: str) -> bytes:
            return b"raw-transaction"

    monkeypatch.setattr(verify_cli, "ReadOnlyExplorerClient", FakeClient)
    monkeypatch.setattr(verify_cli, "_load_prevouts", lambda _: (TxOut(1, b"\x00\x14"),))
    monkeypatch.setattr(verify_cli, "verify_transaction_signatures", lambda raw, prevouts: False)

    assert verify_cli.main(["--txid", "ab" * 32, "--prevout-data", "-"]) == 1
    assert "FAIL:" in capsys.readouterr().out