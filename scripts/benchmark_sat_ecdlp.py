"""Measure the ceiling of the SAT bounded-range ECDLP encoder on secp256k1.

RESULT (already recorded in SEC_STATE_JOURNAL.md): the full 256-bit field
encoding produces ~8 million clauses per point-doubling step and the SAT solver
does **not** terminate even at 1 doubling step within a 90s budget. This is a
memory/clause blow-up and a dead end; the encoder is correct (validated on a
small toy curve) but the 256-bit instance is intractable.

This script is kept for reproducibility but is **safe by default**: it refuses to
build instances past a conservative clause cap unless ``--i-accept-oom`` is
passed, aborts if system RAM crosses a threshold, and kills the solver with a
hard subprocess timeout. Building the 256-bit instance needs gigabytes of RAM --
do not run it with ``--i-accept-oom`` on a memory-constrained host.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import subprocess
import sys
import time
from pathlib import Path

from keylab.ec.secp256k1 import G, P, scalar_mult
from keylab.research.ecdlp.sat_encoding import encode_bounded_ecdlp
from keylab.sat.solver import find_solver, parse_solver_output

_WIDTH = 256
_SAFE_CLAUSE_CAP = 1_000_000  # refuse to build past this unless explicitly overridden


def _ram_percent() -> float:
    """Best-effort system RAM usage percent (psutil if present, else OS-native)."""
    try:
        import psutil  # optional; not a hard dependency
        return float(psutil.virtual_memory().percent)
    except (ImportError, OSError, AttributeError):
        pass
    if sys.platform == "win32":
        class _M(ctypes.Structure):
            _fields_ = [("l", ctypes.c_ulong), ("p", ctypes.c_uint)] + [
                (n, ctypes.c_ulonglong) for n in ("tp", "ap", "tpg", "apg", "tv", "av", "ae")
            ]
        m = _M()
        m.l = ctypes.sizeof(_M)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))  # type: ignore[attr-defined]
        return float(m.p)
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            info = {k: int(v.split()[0]) for k, v in (ln.split(":", 1) for ln in fh)}
        return 100.0 * (1 - info["MemAvailable"] / info["MemTotal"])
    except (OSError, KeyError, ValueError, ZeroDivisionError):
        return 0.0


def _guard_memory(threshold: float = 85.0) -> None:
    pct = _ram_percent()
    if pct > threshold:
        print(f"FATAL: system RAM at {pct:.1f}% (> {threshold}%). Aborting to protect the host.")
        sys.exit(1)


def _solve_hard(solver: str, dimacs: str, timeout: float):
    """Run the solver with a HARD subprocess timeout that actually kills the child."""
    try:
        proc = subprocess.run([solver], check=False, input=dimacs, capture_output=True, text=True, timeout=timeout)
        return parse_solver_output(proc.stdout, proc.stderr, proc.returncode), None
    except subprocess.TimeoutExpired:
        return None, "timeout"


def run(steps_list, solve_budget, clause_cap, mem_threshold, out):
    solver = find_solver()
    print(f"solver={solver} solve_budget={solve_budget}s clause_cap={clause_cap:,} mem_threshold={mem_threshold}%")
    print(f"{'steps':>5} {'variables':>13} {'clauses':>13} {'build_s':>9} {'solve_s':>9} {'status':>14} {'correct':>8}")
    rows = []
    for steps in steps_list:
        _guard_memory(mem_threshold)
        d = 1 << (steps - 1)
        lower, upper, k = 1000, 1000 + d, 1000 + d
        base = scalar_mult(lower, G)
        dpts = [scalar_mult(1 << i, G) for i in range(steps)]
        top = scalar_mult(1 << (steps - 1), G)
        assert base is not None and top is not None and base[0] != top[0], "exceptional; bump lower"

        t0 = time.perf_counter()
        inst = encode_bounded_ecdlp(p=P, width=_WIDTH, base_point=base, doubling_points=dpts,
                                    target=scalar_mult(k, G), lower=lower, upper=upper)
        clauses = len(inst.formula.clauses)
        if clauses > clause_cap:
            print(f"{steps:>5} {inst.formula.variable_count:>13,} {clauses:>13,} "
                  f"{time.perf_counter()-t0:>9.2f} {'-':>9} {'skip>cap':>14} {'-':>8}")
            print(f"-- refusing to solve/continue: {clauses:,} clauses > cap {clause_cap:,} (pass --i-accept-oom to raise)")
            break
        dimacs = inst.to_dimacs()
        build_s = time.perf_counter() - t0
        _guard_memory(mem_threshold)

        status, correct, solve_s = "not-attempted", None, None
        if solver is not None:
            t1 = time.perf_counter()
            result, err = _solve_hard(solver, dimacs, solve_budget)
            solve_s = time.perf_counter() - t1
            status = "timeout" if err else result.status
            if result is not None and result.status == "SATISFIABLE":
                rec = inst.recover_k(result.assignments)
                correct = rec == k and scalar_mult(rec, G) == scalar_mult(k, G)
        rows.append({"steps": steps, "variables": inst.formula.variable_count, "clauses": clauses,
                     "build_sec": round(build_s, 2), "solve_sec": None if solve_s is None else round(solve_s, 2),
                     "status": status, "correct": correct})
        print(f"{steps:>5} {inst.formula.variable_count:>13,} {clauses:>13,} {build_s:>9.2f} "
              f"{(solve_s or 0):>9.2f} {status:>14} {correct!s:>8}")
        sys.stdout.flush()
    if out is not None:
        Path(out).write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return rows


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Measure the SAT ECDLP ceiling (safe by default).")
    ap.add_argument("--out", type=str, default=None)
    ap.add_argument("--steps", type=int, nargs="+", default=[1, 2, 3])
    ap.add_argument("--solve-budget", type=float, default=90.0)
    ap.add_argument("--mem-threshold", type=float, default=85.0)
    ap.add_argument("--i-accept-oom", action="store_true",
                    help="raise the clause cap to allow the gigabyte-scale 256-bit build (host may OOM)")
    args = ap.parse_args()
    cap = 50_000_000 if args.i_accept_oom else _SAFE_CLAUSE_CAP
    run(args.steps, args.solve_budget, cap, args.mem_threshold, args.out)
