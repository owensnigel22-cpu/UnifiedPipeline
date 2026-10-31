"""keylab.__version__ is the single version source and both CLIs report it."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import pytest

import keylab
from keylab import advanced_suite, cli


def test_pyproject_reads_the_version_from_the_package() -> None:
    project = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text("utf-8"))
    assert "version" not in project["project"]
    assert "version" in project["project"]["dynamic"]
    dynamic = project["tool"]["setuptools"]["dynamic"]["version"]
    assert dynamic == {"attr": "keylab.__version__"}


def test_keylab_version_flag(capsys) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"keylab {keylab.__version__}"


def test_keylab_advanced_version_flag(capsys, monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["keylab-advanced", "--version"])
    with pytest.raises(SystemExit) as exit_info:
        advanced_suite.main()
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"keylab-advanced {keylab.__version__}"
