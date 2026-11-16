"""Convenience launcher: ``python run-keylab.py ...`` runs the KeyLab CLI.

The canonical entry points are the installed ``keylab`` / ``keylab-advanced``
console scripts (see ``pyproject.toml``). This thin shim just forwards to
``keylab.cli:main`` for running from a source checkout without installing.

It is deliberately **not** named ``keylab.py``: a module named ``keylab`` at the
repository root would shadow the ``keylab`` package (``import keylab`` would load
this file instead), breaking every import and the whole test suite. The hyphen in
``run-keylab`` makes this file non-importable as a module, so no collision occurs.
"""

from __future__ import annotations

import sys
from pathlib import Path


def _main() -> int:
    src = Path(__file__).resolve().parent / "src"
    if src.is_dir():
        sys.path.insert(0, str(src))
    from keylab.cli import main

    return main()


if __name__ == "__main__":
    raise SystemExit(_main())
