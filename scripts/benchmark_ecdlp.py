"""ECDLP attempt / measurement harness (educational).

Modes, all built on the existing primitives (no new attack code):

- ``attain-small`` / ``attain-medium`` -- recover a known small k with
  ``pollard_kangaroo`` over ``[0, 2**interval_bits)`` (default 20 / 24). Completes.
- ``bounded-full`` -- the full-group ECDLP attempt: ``pollard_kangaroo`` over
  ``[0, N-1]`` for ``--budget-seconds``. Will NOT find a solution (~2**129
  expected hops); records the fraction of expected work reached, as 2**-k.
- ``walkback`` -- ``backward_traverse_to_identity`` for ``--depth`` (<= 18).
- ``extrapolate`` -- fit the kangaroo constant from the attain anchors and
  project expected work to 2**32..2**128.
- ``all`` -- attain-small, attain-medium (opt-in), bounded-full (short), extrapolate.

Honest framing: ``pollard_kangaroo`` over ``[0, n-1]`` IS the full-group ECDLP
attempt -- the same kangaroo walk, with the full group as the interval. A
budget-bounded run reaches ~2**-100 of expected work: a quantified wall, not
partial progress. See docs/research/ecdlp_benchmark.md. Single-process; no new
dependencies (stdlib argparse/json/math/os/signal/time).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import signal
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from keylab.ec.secp256k1 import G, N, scalar_mult
from keylab.research.ecdlp.backward_double_add import (
    MAX_DEPTH,
    backward_traverse_to_identity,
)
from keylab.research.ecdlp.kangaroo import pollard_kangaroo

_BUDGET_HARD_CAP = 86_400       # 24h: refused unconditionally
_BUDGET_CONFIRM = 3_600         # >1h: requires --i-know-this-wont-work
_EXTRAPOLATE_BITS = (32, 40, 48, 64, 128)


class _BudgetReached(Exception):
    """Raised from the progress callback to stop a timed run cleanly."""


def _expected_steps(width: int) -> float:
    """Kangaroo expected hops over an interval of ``width`` (~2*sqrt(width))."""
    return 2.0 * math.sqrt(width)


def _fraction(steps: int, expected: float) -> tuple[float, float]:
    """Return (fraction_of_work, k) where fraction == 2**-k."""
    frac = steps / expected if expected else 0.0
    k = -math.log2(frac) if frac > 0 else float("inf")
    return frac, k


def _write_json(path: Path | None, record: dict) -> None:
    if path is not None:
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")


# --- modes -------------------------------------------------------------------------------------

def run_attain(interval_bits: int, seed: int, output: Path | None) -> dict:
    rng = __import__("random").Random(seed)
    k = rng.randrange(1, 1 << interval_bits)
    width = 1 << interval_bits
    start = time.perf_counter()
    state = pollard_kangaroo(scalar_mult(k, G), 0, width, max_steps=10**7, return_state=True)
    elapsed = time.perf_counter() - start
    expected = _expected_steps(width)
    frac, kbits = _fraction(state.spent_steps, expected)
    record = {
        "mode": f"attain ({interval_bits}-bit interval)",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_description": f"known k in [0, 2**{interval_bits})",
        "bits_or_interval": interval_bits,
        "steps_taken": state.spent_steps,
        "expected_steps": expected,
        "fraction_of_work": frac,
        "fraction_as_2_neg_k": kbits,
        "dps_found": state.dps_found,
        "memory_peak_bytes": state.memory_peak_bytes,
        "solution_found": state.solution == k,
        "elapsed_sec": elapsed,
        "step_rate_ops_per_sec": state.spent_steps / elapsed if elapsed else 0.0,
    }
    _write_json(output, record)
    return record


def run_bounded_full(budget_seconds: float, seed: int, output: Path | None,
                     progress_every: int = 20_000) -> dict:
    k_target = scalar_mult(0x1234_5678_9ABC_DEF0, G)  # a real secp256k1 point; k not searched for
    est_rate = 15_000  # rough hops/sec prior for the wall-warning estimate
    est_k = -math.log2((budget_seconds * est_rate) / _expected_steps(N - 1))
    print(
        f"BOUNDED-FULL runs kangaroo over the full secp256k1 group [0, n-1]. "
        f"Expected work is ~2^129 ops; a {budget_seconds:g}s run will reach "
        f"~2^-{est_k:.0f} of that work and will not find a solution. This is a "
        f"measurement, not partial progress. See docs/research/ecdlp_benchmark.md.",
        flush=True,
    )
    live = {"spent": 0, "dps": 0}
    start = time.perf_counter()

    def _cb(spent: int, dps: int) -> None:
        live["spent"] = spent
        live["dps"] = dps
        if time.perf_counter() - start > budget_seconds:
            raise _BudgetReached

    def _emit(solution_found: bool) -> dict:
        elapsed = time.perf_counter() - start
        expected = _expected_steps(N - 1)
        frac, kbits = _fraction(live["spent"], expected)
        return {
            "mode": "bounded-full",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_description": "real secp256k1 pubkey, full group [0, n-1]",
            "bits_or_interval": (N - 1).bit_length(),
            "steps_taken": live["spent"],
            "expected_steps": expected,
            "fraction_of_work": frac,
            "fraction_as_2_neg_k": kbits,
            "dps_found": live["dps"],
            "memory_peak_bytes": None,
            "solution_found": solution_found,
            "elapsed_sec": elapsed,
            "step_rate_ops_per_sec": live["spent"] / elapsed if elapsed else 0.0,
        }

    # On SIGTERM, flush the latest state and exit 130 (within one callback window).
    def _on_sigterm(signum, frame):  # pragma: no cover - exercised via subprocess in tests
        _write_json(output, _emit(False))
        sys.exit(130)
    had_handler = hasattr(signal, "SIGTERM")
    if had_handler:
        signal.signal(signal.SIGTERM, _on_sigterm)

    try:
        state = pollard_kangaroo(
            k_target, 0, N - 1, max_steps=1 << 60, return_state=True,
            progress_callback=_cb, progress_every=progress_every,
        )
        live["spent"] = state.spent_steps
        live["dps"] = state.dps_found
        record = _emit(state.solution is not None)
    except _BudgetReached:
        record = _emit(False)
    _write_json(output, record)
    return record


def run_walkback(depth: int, seed: int, output: Path | None) -> dict:
    if type(depth) is not int or not 0 <= depth <= MAX_DEPTH:
        raise ValueError(
            f"--depth must be an int in [0, {MAX_DEPTH}]; above {MAX_DEPTH} the tree "
            "explodes (see SEC_STATE_JOURNAL.md depth-cap)"
        )
    rng = __import__("random").Random(seed)
    k = rng.randrange(1, 1 << depth) if depth else 0
    start = time.perf_counter()
    report = backward_traverse_to_identity(scalar_mult(k, G), depth)
    elapsed = time.perf_counter() - start
    record = {
        "mode": "walkback",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_description": f"known k={k} at depth {depth}",
        "bits_or_interval": depth,
        "steps_taken": report["leaves_explored"],
        "expected_steps": float(1 << depth),
        "fraction_of_work": report["leaves_explored"] / (1 << depth) if depth else 1.0,
        "fraction_as_2_neg_k": 0.0,
        "dps_found": 0,
        "memory_peak_bytes": None,
        "solution_found": report["found"] and report["k"] == k,
        "recovered_k": report["k"],
        "elapsed_sec": elapsed,
        "step_rate_ops_per_sec": report["leaves_explored"] / elapsed if elapsed else 0.0,
    }
    _write_json(output, record)
    return record


def run_extrapolate(seed: int, output: Path | None) -> dict:
    anchors = [run_attain(20, seed, None), run_attain(24, seed, None)]
    # Fit constant C in steps ~= C * sqrt(width) from the attain anchors.
    consts = [a["steps_taken"] / math.sqrt(1 << a["bits_or_interval"]) for a in anchors]
    c = sum(consts) / len(consts)
    table = []
    for bits in _EXTRAPOLATE_BITS:
        projected = c * math.sqrt(float(1 << bits))
        table.append((bits, projected, math.log2(projected) if projected > 0 else 0.0))
    record = {
        "mode": "extrapolate",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "fitted_constant": c,
        "anchors": [(a["bits_or_interval"], a["steps_taken"]) for a in anchors],
        "extrapolation_table": [
            {"bits": b, "expected_steps": s, "log2_steps": lg} for b, s, lg in table
        ],
    }
    _write_json(output, record)
    return record


# --- CLI ---------------------------------------------------------------------------------------

def _check_budget(budget: float, i_know: bool) -> None:
    if budget > _BUDGET_HARD_CAP:
        raise ValueError(
            f"--budget-seconds > {_BUDGET_HARD_CAP} (24h) is refused unconditionally; "
            "beyond a day the marginal evidence is negligible and extrapolation covers it"
        )
    if budget > _BUDGET_CONFIRM and not i_know:
        raise ValueError(
            f"--budget-seconds > {_BUDGET_CONFIRM} requires --i-know-this-wont-work"
        )
    if budget < 10:
        print(
            f"WARNING: a {budget:g}s bounded-full run reaches a fraction so close to zero "
            "(~2^-120+) that the measurement is degenerate; 10s minimum is suggested.",
            flush=True,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", required=True,
                        choices=("attain-small", "attain-medium", "bounded-full", "walkback", "extrapolate", "all"))
    parser.add_argument("--budget-seconds", type=float, default=60.0)
    parser.add_argument("--depth", type=int, default=8)
    parser.add_argument("--interval-bits", type=int, default=None)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--i-know-this-wont-work", action="store_true")
    args = parser.parse_args(argv)

    if args.mode == "attain-small":
        print(json.dumps(run_attain(args.interval_bits or 20, args.seed, args.output), indent=2))
    elif args.mode == "attain-medium":
        print(json.dumps(run_attain(args.interval_bits or 24, args.seed, args.output), indent=2))
    elif args.mode == "bounded-full":
        _check_budget(args.budget_seconds, args.i_know_this_wont_work)
        print(json.dumps(run_bounded_full(args.budget_seconds, args.seed, args.output), indent=2))
    elif args.mode == "walkback":
        print(json.dumps(run_walkback(args.depth, args.seed, args.output), indent=2))
    elif args.mode == "extrapolate":
        print(json.dumps(run_extrapolate(args.seed, args.output), indent=2))
    elif args.mode == "all":
        out = {
            "attain_small": run_attain(20, args.seed, None),
            "attain_medium": run_attain(24, args.seed, None) if os.environ.get("RUN_SLOW_ECDLP") == "1" else "skipped (set RUN_SLOW_ECDLP=1)",
            "bounded_full": run_bounded_full(min(args.budget_seconds, 60.0), args.seed, None),
            "extrapolate": run_extrapolate(args.seed, None),
        }
        print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
