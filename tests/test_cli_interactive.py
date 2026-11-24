"""Interactive numbered-menu CLI (`keylab interactive`), driven via injected IO."""

from __future__ import annotations

from collections.abc import Callable

from keylab.cli import interactive_menu, main


def _scripted(lines: list[str]) -> Callable[[], str]:
    """An input_fn that yields each line in turn, then raises EOFError."""
    iterator = iter(lines)

    def _input() -> str:
        try:
            return next(iterator)
        except StopIteration as exc:  # mimic end-of-stdin
            raise EOFError from exc

    return _input


def _run(lines: list[str]) -> list[str]:
    out: list[str] = []
    code = interactive_menu(input_fn=_scripted(lines), output_fn=out.append)
    assert code == 0
    return out


def test_menu_banner_and_clean_exit() -> None:
    out = _run(["0"])
    assert any("KEYLAB" in line for line in out)
    assert any("Goodbye" in line for line in out)


def test_menu_invalid_choice_is_reported() -> None:
    out = _run(["abc", "0"])
    assert any("Invalid selection." in line for line in out)


def test_menu_eof_exits_cleanly() -> None:
    # Empty input stream -> _menu_read returns "0" -> clean exit, no hang/traceback.
    out = _run([])
    assert any("Goodbye" in line for line in out)


def test_menu_status_screen() -> None:
    out = _run(["10", "0"])
    assert any("KeyLab" in line for line in out)
    assert any("Subsystems" in line for line in out)


def test_menu_category_back_navigation() -> None:
    out = _run(["1", "0", "0"])  # into Public Key Tools, back, exit
    assert any("Public Key Tools" in line for line in out)


def test_menu_runs_selftest(capsys) -> None:
    _run(["8", "0"])
    assert "PASS extended gcd" in capsys.readouterr().out


def test_menu_dispatches_a_command(capsys) -> None:
    # Category 1 -> option 1 (address-hash, positional) -> a valid address.
    out = _run(["1", "1", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "0", "0"])
    assert any("[exit code 0]" in line for line in out)
    # address-hash prints the 20-byte HASH160 as a 40-char hex line.
    printed = capsys.readouterr().out.strip().splitlines()[-1]
    assert len(printed) == 40 and all(ch in "0123456789abcdef" for ch in printed)


def test_menu_bad_command_args_no_traceback() -> None:
    # A bogus address must not raise through the menu; it is reported cleanly.
    out = _run(["1", "1", "not a valid address", "0", "0"])
    assert any(("[command exited:" in line) or ("[exit code 1]" in line) for line in out)


def test_interactive_command_eof_exits(monkeypatch) -> None:
    def _raise_eof(*_args: object) -> str:
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise_eof)
    assert main(["interactive"]) == 0
