"""Require the reference ECC backends that CI installs, before any test runs.

Usage: ``python scripts/check_backends.py coincurve [fastecdsa]``

Each named backend must import and compute 1·G equal to KeyLab's generator.
Failing here, instead of letting the differential tests skip, makes a missing
or broken backend the visible cause of a red build.
"""

from __future__ import annotations

import sys

from keylab.ec.secp256k1 import G


def coincurve_generator() -> tuple[int, int]:
    from coincurve import PrivateKey

    encoded = PrivateKey((1).to_bytes(32, "big")).public_key.format(compressed=False)
    return int.from_bytes(encoded[1:33], "big"), int.from_bytes(encoded[33:], "big")


def fastecdsa_generator() -> tuple[int, int]:
    from fastecdsa.curve import secp256k1

    return secp256k1.G.x, secp256k1.G.y


CHECKS = {"coincurve": coincurve_generator, "fastecdsa": fastecdsa_generator}


def main(argv: list[str] | None = None) -> int:
    names = sys.argv[1:] if argv is None else argv
    unknown = [name for name in names if name not in CHECKS]
    if not names or unknown:
        print(f"usage: check_backends.py {{{','.join(CHECKS)}}} ...; unknown: {unknown}")
        return 2
    failed = False
    for name in names:
        try:
            point = CHECKS[name]()
        except ImportError as exc:
            print(f"FAIL: {name} is not importable: {exc}")
            failed = True
            continue
        if point != G:
            print(f"FAIL: {name} computes a different 1*G than KeyLab")
            failed = True
        else:
            print(f"{name}: 1*G matches KeyLab ({point[0]:#x})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
