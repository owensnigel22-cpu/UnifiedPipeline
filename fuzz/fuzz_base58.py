"""Atheris entry point for the base58 parser. Run on Linux CI only.

Usage: ``python fuzz/fuzz_base58.py <libfuzzer-flags> [corpus_dir]``
"""

import os
import sys

# Allow `python fuzz/fuzz_base58.py` to resolve the top-level `fuzz` package
# regardless of the launcher's cwd (sys.path[0] is the fuzz/ dir otherwise).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import atheris  # type: ignore

with atheris.instrument_imports():
    from fuzz.targets import run_base58


def TestOneInput(data: bytes) -> None:
    run_base58(data)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
