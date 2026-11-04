"""Atheris availability shim shared by the ``fuzz/fuzz_*.py`` entry points.

Importing this module never fails on a platform without Atheris (e.g. Windows or
local dev): it sets ``HAVE_ATHERIS`` accordingly. The Atheris-instrumented
imports and the libFuzzer loop live in the individual ``fuzz_*.py`` entry points
so that only running a campaign (Linux CI) requires Atheris.
"""

from __future__ import annotations

try:  # pragma: no cover - exercised only where Atheris is installed (Linux CI)
    import atheris  # type: ignore
    HAVE_ATHERIS = True
except ImportError:  # pragma: no cover - the common case off-Linux
    atheris = None  # type: ignore
    HAVE_ATHERIS = False
