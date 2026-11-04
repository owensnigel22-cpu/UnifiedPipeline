"""Build seed corpora for the fuzz targets from the pinned official vectors.

Seeds are *derived at runtime* from ``tests/vectors/*`` (no new committed vector
copies, so the ``SOURCES.json`` provenance gate is untouched), plus a few
near-valid literal seeds so every target starts near an interesting boundary.
Used by CI (``write_corpus``) and by ``tests/test_corpus_smoke.py``
(``seeds_for``).
"""

from __future__ import annotations

import json
from pathlib import Path

_VECTORS = Path(__file__).resolve().parent.parent / "tests" / "vectors"


def _load(name: str) -> dict | list | None:
    try:
        return json.loads((_VECTORS / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _hexes(obj: object) -> list[bytes]:
    """Collect every hex-looking leaf string from a nested structure as bytes."""
    out: list[bytes] = []

    def walk(x: object) -> None:
        if isinstance(x, str):
            s = x.strip()
            if len(s) >= 8 and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
                try:
                    out.append(bytes.fromhex(s))
                except ValueError:
                    pass
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(obj)
    return out


def _strings(obj: object, *, predicate) -> list[bytes]:
    out: list[bytes] = []

    def walk(x: object) -> None:
        if isinstance(x, str):
            if predicate(x):
                out.append(x.encode("utf-8"))
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(obj)
    return out


_ABANDON = ("abandon " * 11 + "about").encode()


def seeds_for(target: str) -> list[bytes]:
    """Return a de-duplicated list of seed inputs (bytes) for ``target``."""
    seeds: list[bytes] = []
    if target == "psbt":
        v = _load("bip174_psbt_vectors.json")
        if isinstance(v, dict):
            for key in ("valid", "invalid"):
                for case in v.get(key, []):
                    if isinstance(case, dict) and "hex" in case:
                        try:
                            seeds.append(bytes.fromhex(case["hex"]))
                        except ValueError:
                            pass
        seeds.append(b"psbt\xff")
    elif target == "transaction":
        for name in ("bip143_signing_vectors.json", "bip143_sighash_vectors.json"):
            seeds += _hexes(_load(name) or {})
    elif target == "bech32":
        seeds += _strings(_load("bech32_vectors.json"), predicate=lambda s: "1" in s and 2 <= len(s) <= 120)
        seeds += [b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", b"tb1q0000"]
    elif target == "base58":
        v = _load("bip32_test_vectors.json")
        seeds += _strings(v, predicate=lambda s: s[:4] in ("xprv", "xpub", "tprv", "tpub"))
        seeds += [b"1BoatSLRHtKNngkdXEeobR76b53LETtpyT", b"3P14159f73E4gFr7JterCCQh9QjiTjiZrG"]
    elif target == "wif":
        seeds += [
            b"5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
            b"KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
            b"L5oLkpV3aqBjhki6LmvChTCV6odsp4SXM6FfU2Gppt5kFLaHLuZ9",
        ]
    elif target == "mnemonic":
        v = _load("bip39_trezor_vectors.json")
        if isinstance(v, dict):
            seeds += _strings(v.get("english", []), predicate=lambda s: " " in s and s.split(" ", 1)[0].isalpha())
        seeds.append(_ABANDON)
    # de-duplicate, keep order
    seen: set[bytes] = set()
    unique: list[bytes] = []
    for s in seeds:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique


def write_corpus(root: Path) -> dict[str, int]:
    """Write seed files under ``root/<target>/`` and return a {target: count} map."""
    import hashlib

    counts: dict[str, int] = {}
    for target in ("psbt", "transaction", "bech32", "base58", "wif", "mnemonic"):
        target_dir = root / target
        target_dir.mkdir(parents=True, exist_ok=True)
        seeds = seeds_for(target)
        for seed in seeds:
            (target_dir / hashlib.sha256(seed).hexdigest()[:16]).write_bytes(seed)
        counts[target] = len(seeds)
    return counts


if __name__ == "__main__":
    import sys

    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("fuzz/corpus")
    result = write_corpus(out)
    print(f"seeded corpus at {out}: " + ", ".join(f"{k}={v}" for k, v in result.items()))
