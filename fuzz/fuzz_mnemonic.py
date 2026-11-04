"""Atheris entry point for the mnemonic parser. Run on Linux CI only.

Usage: ``python fuzz/fuzz_mnemonic.py <libfuzzer-flags> [corpus_dir]``
"""

import os
import sys

# Allow `python fuzz/fuzz_mnemonic.py` to resolve the top-level `fuzz` package
# regardless of the launcher's cwd (sys.path[0] is the fuzz/ dir otherwise).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import atheris  # type: ignore

with atheris.instrument_imports():
    from fuzz.targets import run_mnemonic


def TestOneInput(data: bytes) -> None:
    run_mnemonic(data)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
