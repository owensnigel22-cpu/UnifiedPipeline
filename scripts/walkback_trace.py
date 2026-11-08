"""Walkback-trace CLI: reverse the double-and-add ladder from a public key to recover k.

Runs ``backward_traverse_to_identity`` (BFS to the identity via point halving) on a
SEC1 public key, then prints the step-by-step path -- branch (0 = halve(Q),
1 = halve(Q - G)), the current x-coordinate, and the LSB-first bits accumulated --
and the recovered scalar k. This is KeyLab's *mathematical* walkback (reversing the
group operation); it is NOT a side-channel execution trace (which would monitor
branch timing/power). Teaching aid only; cost is 2**depth, so it only resolves
small, bounded scalars. See docs/math_mechanics.md and SECURITY.md.

Resource safety (mandatory): a daemon watchdog aborts cleanly on a wall-clock
timeout or when system RAM crosses a threshold, so a deep run never crashes the
host; depth >= 18 also emits a warning.
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import warnings

from keylab.ec.sec1 import parse_sec1
from keylab.ec.secp256k1 import G, point_add_affine, point_negate_affine, scalar_mult
from keylab.research.ecdlp.backward_double_add import (
    MAX_DEPTH,
    backward_traverse_to_identity,
    point_halve,
)


def _ram_percent() -> float:
    try:
        import psutil
        return float(psutil.virtual_memory().percent)
    except Exception:  # noqa: BLE001 - best-effort guard; never fail the run on the watchdog
        return 0.0


def _start_watchdog(timeout: float, ram_threshold: float) -> threading.Event:
    done = threading.Event()

    def _watch() -> None:
        deadline = time.monotonic() + timeout
        while not done.wait(0.5):
            if time.monotonic() > deadline:
                print(f"\nFATAL: wall-clock timeout ({timeout}s) exceeded; aborting cleanly.", file=sys.stderr)
                os._exit(124)
            if _ram_percent() > ram_threshold:
                print(f"\nFATAL: system RAM over {ram_threshold}%; aborting to protect the host.", file=sys.stderr)
                os._exit(137)

    threading.Thread(target=_watch, daemon=True).start()
    return done


def trace(point: tuple[int, int] | None, depth: int) -> dict[str, object]:
    """Recover k and reconstruct the walkback path. Returns a structured result."""
    report = backward_traverse_to_identity(point, depth)
    k = report["k"]
    steps: list[dict[str, object]] = []
    if isinstance(k, int):
        current = point
        bits = 0
        minus_g = point_negate_affine(G)
        for i in range(k.bit_length()):
            branch = (k >> i) & 1
            current = point_halve(current) if branch == 0 else point_halve(point_add_affine(current, minus_g))
            if branch:
                bits |= 1 << i
            steps.append({"step": i, "branch": branch,
                          "x": None if current is None else current[0], "bits": bits})
    return {"k": k, "found": report["found"], "depth": report["depth"],
            "leaves_explored": report["leaves_explored"], "steps": steps}


def _print(result: dict[str, object]) -> None:
    if not result["found"]:
        print(f"No path to the identity within depth {result['depth']} "
              f"({result['leaves_explored']} leaves explored); k not in range.")
        return
    print(f"Walkback trace (depth {result['depth']}, {result['leaves_explored']} leaves explored):")
    print(f"{'step':>4} {'branch':>6} {'bits':>12}  x-coord")
    for s in result["steps"]:  # type: ignore[union-attr]
        x = "identity" if s["x"] is None else f"0x{s['x']:064x}"
        print(f"{s['step']:>4} {s['branch']:>6} {s['bits']:>12}  {x}")
    k = result["k"]
    print(f"\nRecovered k = {k}  (0x{k:x})")
    print(f"Total leaves explored: {result['leaves_explored']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reverse double-and-add from a SEC1 public key.")
    parser.add_argument("public_key", help="SEC1 public key hex (compressed 02/03 or uncompressed 04)")
    parser.add_argument("--depth", type=int, default=8, help="max BFS depth (bit length to search)")
    parser.add_argument("--timeout", type=float, default=60.0, help="hard wall-clock timeout (seconds)")
    parser.add_argument("--ram-threshold", type=float, default=90.0, help="abort if system RAM exceeds this %%")
    args = parser.parse_args(argv)

    if args.depth >= MAX_DEPTH:
        print(f"WARNING: depth {args.depth} explores up to 2**{args.depth} nodes; this may be slow.",
              file=sys.stderr)
    try:
        point = parse_sec1(bytes.fromhex(args.public_key.removeprefix("0x")))
    except (ValueError, TypeError) as exc:
        print(f"error: invalid SEC1 public key: {exc}", file=sys.stderr)
        return 2

    done = _start_watchdog(args.timeout, args.ram_threshold)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("default")  # surface DeepTraversalWarning on the console
            result = trace(point, args.depth)
    finally:
        done.set()
    _print(result)
    return 0 if result["found"] else 1


if __name__ == "__main__":
    # convenience: no args -> demonstrate on k=5 so the script is runnable standalone
    if len(sys.argv) == 1:
        from keylab.ec.sec1 import serialize_sec1
        demo = serialize_sec1(scalar_mult(5, G), compressed=True).hex()
        print(f"(no public key given; demonstrating on k=5, pubkey {demo})\n")
        sys.argv.append(demo)
    raise SystemExit(main())
