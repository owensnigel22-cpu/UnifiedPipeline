"""The advanced suite must not reveal user-supplied private keys without --show-private."""

from __future__ import annotations

import sys

import pytest

from keylab import advanced_suite

# Canonical public test WIF for private scalar 1 (never use for funds).
SCALAR_ONE_WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
SCALAR_ONE_HEX = "0x" + "00" * 31 + "01"


def _run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], *args: str) -> str:
    monkeypatch.setattr(sys, "argv", ["keylab-advanced", *args])
    advanced_suite.main()
    return capsys.readouterr().out


def test_wif_private_scalar_is_redacted_by_default(monkeypatch, capsys) -> None:
    output = _run(monkeypatch, capsys, "--wif", SCALAR_ONE_WIF)
    assert SCALAR_ONE_HEX not in output
    assert "pass --show-private to reveal" in output
    # Public outputs are unchanged.
    assert "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" in output


def test_show_private_reveals_the_scalar_on_request(monkeypatch, capsys) -> None:
    output = _run(monkeypatch, capsys, "--wif", SCALAR_ONE_WIF, "--show-private")
    assert f"Private Scalar        : {SCALAR_ONE_HEX}" in output


def test_demo_wif_stays_redacted_even_with_show_private(monkeypatch, capsys) -> None:
    output = _run(monkeypatch, capsys, "--all", "--show-private")
    assert "[redacted demo key]" in output


def test_decode_wif_library_function_still_returns_the_scalar() -> None:
    # Library behaviour is preserved; only CLI display is gated.
    assert advanced_suite.decode_wif(SCALAR_ONE_WIF)["private_key_hex"] == SCALAR_ONE_HEX
