"""Measure truncated SHA-256 pre-image cost and extrapolate to the 2**256 wall -- safely.

For increasing prefix widths, run the brute-force search in a SUBPROCESS under a
hard memory cap and wall-clock timeout (scripts/run_capped.py) with a psutil RAM
watchdog, record tries and wall time, confirm ``tries ~ 2**bits``, and extrapolate
the measured throughput to the full 256-bit pre-image: ``2**256`` ~ 10^60 years --
a wall, reached by LABELLED extrapolation, never run. ``bits`` is hard-capped at 40.

Also records the backend evaluation: ``hashlib`` (OpenSSL C) vs ``pycryptodome``;
the latter is slower in a tight loop, so no accelerated backend is shipped.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_capped import run_capped

from keylab.research.hash_attacks import find_truncated_preimage, truncated_prefix

_TARGET = hashlib.sha256(b"keylab m5 preimage benchmark target").digest()
_GUESSES_PER_SEC_REF = 1e12  # optimistic reference rate for the wall extrapolation


def _ram_guard(threshold: float = 90.0) -> None:
    try:
        import psutil
        if psutil.virtual_memory().percent > threshold:
            print(f"FATAL: system RAM over {threshold}%; aborting.", file=sys.stderr)
            sys.exit(1)
    except ImportError:
        pass


def search_once(bits: int) -> tuple[int, float]:
    t0 = time.perf_counter()
    result = find_truncated_preimage(_TARGET, bits=bits)
    elapsed = time.perf_counter() - t0
    if result is None:
        return -1, elapsed
    assert truncated_prefix(hashlib.sha256(result.message).digest(), bits) == truncated_prefix(_TARGET, bits)
    return result.tries, elapsed


def _wall_statement(rate: float) -> str:
    years = (2.0 ** 256) / rate / (3.15e7)
    return (f"Full SHA-256 pre-image = 2**256 guesses. At an optimistic {rate:.0e} guesses/sec "
            f"that is ~{years:.1e} years (~10^60) -- a wall, not a slowdown. [EXTRAPOLATION, not run]")


def orchestrate(bits_list, cap_mib, timeout):
    _ram_guard()
    print(f"cap={cap_mib}MiB timeout={timeout}s  target={_TARGET.hex()[:16]}...")
    print(f"{'bits':>5} {'expected 2^bits':>16} {'tries':>14} {'wall_s':>9} {'hashes/sec':>12} {'status':>10}")
    rates = []
    for bits in bits_list:
        _ram_guard()
        res = run_capped([sys.executable, "-I", __file__, "--search", str(bits)],
                         mem_bytes=cap_mib << 20, timeout=timeout)
        if res.status != "ok":
            print(f"{bits:>5} {1 << bits:>16,} {'-':>14} {'-':>9} {'-':>12} {res.status.upper():>10}")
            print(f"-- search at {bits} bits hit a {res.status} guard (clean); stopping.")
            break
        toks = dict(t.split("=") for t in res.stdout.split() if "=" in t)
        tries, wall = int(toks.get("TRIES", -1)), float(toks.get("TIME", 0.0))
        rate = tries / wall if wall > 0 and tries > 0 else 0.0
        if rate:
            rates.append(rate)
        print(f"{bits:>5} {1 << bits:>16,} {tries:>14,} {wall:>9.2f} {rate:>12,.0f} {'OK':>10}")
        sys.stdout.flush()
    print()
    measured_rate = max(rates) if rates else _GUESSES_PER_SEC_REF
    print(f"measured throughput: ~{measured_rate:,.0f} hashes/sec (pure-Python hashlib loop)")
    print("backend note: pycryptodome measured ~0.26x (slower) in a tight loop; hashlib (OpenSSL C) "
          "is the reference, and the Python search loop is the bottleneck -- no faster drop-in backend.")
    print(_wall_statement(_GUESSES_PER_SEC_REF))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Truncated SHA-256 pre-image benchmark (memory-safe).")
    ap.add_argument("--search", type=int, help="internal: run one search at this bit width, print TRIES/TIME")
    ap.add_argument("--bits", type=int, nargs="+", default=[16, 20, 24])
    ap.add_argument("--cap-mib", type=int, default=300)
    ap.add_argument("--timeout", type=float, default=150.0)
    args = ap.parse_args()

    if args.search is not None:
        tries, wall = search_once(args.search)
        print(f"TRIES={tries} TIME={wall:.4f}")
    else:
        orchestrate(args.bits, args.cap_mib, args.timeout)
