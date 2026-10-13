"""Benchmark cube-and-conquer solving throughput across worker process counts."""

from __future__ import annotations

import argparse
import csv
import time
from collections.abc import Sequence
from pathlib import Path

from keylab.hashes.reduced import ripemd160_reduced, sha256_reduced
from keylab.hashes.ripemd_cnf import ripemd160_preimage_cnf
from keylab.hashes.sha256_cnf import sha256_hash_preimage_cnf
from keylab.sat.parallel import solve_parallel_cubes
from keylab.sat.solver import SOLVER_CANDIDATES, find_solver

_BENCHMARK_MESSAGE = b"keylab benchmark"
_DEFAULT_WORKERS = (1, 2, 4, 8)
_MAX_CUBE_DEPTH = 16

def _default_csv_path() -> Path:
    """
    Resolve the default CSV path the dashboard reads.

    Dashboard authority: dashboard/app.py._CSV_CANDIDATES[0] is
        _ROOT / "benchmark_reports" / "scaling_results.csv"
    where _ROOT is the keylab project root.

    Editable installs expose the source tree via __file__; non-editable
    installs fall back to CWD-relative resolution.
    """
    here = Path(__file__).resolve()
    # keylab/src/keylab/sat/benchmark_throughput.py  ->  parents[3] = keylab/
    project_root = here.parents[3]
    if (project_root / "pyproject.toml").is_file():
        return project_root / "benchmark_reports" / "scaling_results.csv"
    return Path.cwd() / "benchmark_reports" / "scaling_results.csv"

def benchmark_solving_throughput(
    hash_name: str = "sha256",
    rounds: int = 15,
    cube_depth: int = 4,
    worker_counts: Sequence[int] | None = None,
    timeout_per_cube: float = 30.0,
    solver: str | None = None,
    csv_output: str | None = None,
) -> None:
    """Measure free-input reduced-hash inversion with input-bit cube partitions.

    The benchmark message is only used to generate a target digest. Its message
    bits are not fixed in the CNF sent to the solver.
    """
    workers_to_test = tuple(_DEFAULT_WORKERS if worker_counts is None else worker_counts)
    if not workers_to_test or any(
        type(workers) is not int or workers < 1 for workers in workers_to_test
    ):
        raise ValueError("worker counts must be positive integers")
    if len(set(workers_to_test)) != len(workers_to_test):
        raise ValueError("worker counts must be unique")
    if 1 not in workers_to_test:
        raise ValueError("worker counts must include 1 to calculate speedup")
    if timeout_per_cube <= 0:
        raise ValueError("timeout per cube must be positive")
    selected_solver = solver or find_solver()
    if selected_solver is None:
        raise ValueError(
            f"no supported SAT solver found on PATH ({', '.join(SOLVER_CANDIDATES)})"
        )

    if hash_name == "sha256":
        target = sha256_reduced(_BENCHMARK_MESSAGE, rounds=rounds)
        model = sha256_hash_preimage_cnf(
            target,
            message_length=len(_BENCHMARK_MESSAGE),
            rounds=rounds,
        )
    elif hash_name == "ripemd160":
        target = ripemd160_reduced(_BENCHMARK_MESSAGE, steps=rounds)
        model = ripemd160_preimage_cnf(
            target,
            message_length=len(_BENCHMARK_MESSAGE),
            steps=rounds,
        )
    else:
        raise ValueError("hash name must be 'sha256' or 'ripemd160'")

    if model.fixed_bits:
        raise RuntimeError("benchmark preimage model unexpectedly has fixed input bits")
    if not 1 <= cube_depth <= min(len(model.input_bits), _MAX_CUBE_DEPTH):
        raise ValueError(
            f"cube depth must be between 1 and {min(len(model.input_bits), _MAX_CUBE_DEPTH)}"
        )

    dimacs = model.to_dimacs()
    print("=" * 88)
    print("BENCHMARK: Single-Process vs. Multi-Process Solving Throughput")
    print(
        f"Hash Target: {hash_name.upper()} ({rounds} rounds/steps) | "
        f"Cube Depth: {cube_depth} ({1 << cube_depth} sub-problems)"
    )
    print(
        f"Free input bits: {len(model.input_bits)} "
        "(benchmark message used only to generate the target)"
    )
    print(f"Solver: {selected_solver}")
    print(f"Base Formula Metrics: {model.variable_count} variables, {model.clause_count} clauses")
    print()

    results: list[tuple[int, float, int, int, str, bool | None, str | None]] = []
    for workers in workers_to_test:
        started = time.perf_counter()
        result = solve_parallel_cubes(
            selected_solver,
            dimacs,
            model.input_bits,
            depth=cube_depth,
            workers=workers,
            timeout=timeout_per_cube,
        )
        elapsed = time.perf_counter() - started
        candidate_validated: bool | None = None
        candidate_hex: str | None = None
        if result.status == "SATISFIABLE":
            candidate = model.recover_input(result.assignments)
            candidate_hex = candidate.hex()
            candidate_digest = (
                sha256_reduced(candidate, rounds)
                if hash_name == "sha256"
                else ripemd160_reduced(candidate, steps=rounds)
            )
            candidate_validated = candidate_digest == target
            if not candidate_validated:
                raise RuntimeError(
                    f"SAT solver candidate for {hash_name} does not match the target digest"
                )
        results.append(
            (
                workers,
                elapsed,
                result.completed_cubes,
                result.total_cubes,
                result.status,
                candidate_validated,
                candidate_hex,
            )
        )

    baseline_time = next(
        elapsed for workers, elapsed, _, _, _, _, _ in results if workers == 1
    )
    print(
        f"{'Workers':<10} | {'Wall Time (s)':<15} | {'Cubes/Sec':<15} | "
        f"{'Speedup Factor':<15} | Status | Candidate Valid"
    )
    print("-" * 88)
    csv_rows: list[dict[str, int | float | str | bool | None]] = []
    for (
        workers,
        elapsed,
        completed_cubes,
        total_cubes,
        status,
        candidate_validated,
        candidate_hex,
    ) in results:
        throughput = completed_cubes / elapsed if elapsed > 0 else 0.0
        speedup = baseline_time / elapsed if elapsed > 0 else 0.0
        print(
            f"{workers:<10} | {elapsed:<15.4f} | {throughput:<15.2f} | "
            f"{speedup:<14.2f}x | {status} | {candidate_validated}"
        )
        csv_rows.append(
            {
                "hash": hash_name,
                "rounds": rounds,
                "cube_depth": cube_depth,
                "workers": workers,
                "elapsed_seconds": elapsed,
                "completed_cubes": completed_cubes,
                "total_cubes": total_cubes,
                "cubes_per_second": throughput,
                "speedup": speedup,
                "status": status,
                "candidate_validated": candidate_validated,
                "candidate_hex": candidate_hex,
                "target_hex": target.hex(),
                "fixed_input_bits": len(model.fixed_bits),
                "solver": selected_solver,
                "variables": model.variable_count,
                "clauses": model.clause_count,
            }
        )
    if csv_output is not None:
        fields = list(csv_rows[0])
        try:
            output_path = Path(csv_output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8", newline="") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=fields)
                writer.writeheader()
                writer.writerows(csv_rows)
        except OSError as exc:
            raise OSError(f"could not write benchmark CSV {csv_output!r}: {exc}") from exc
    print("=" * 88)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Multi-process SAT solver scaling benchmark")
    parser.add_argument("--hash", choices=("sha256", "ripemd160"), default="sha256")
    parser.add_argument("--rounds", type=int, default=15)
    parser.add_argument("--cube-depth", type=int, default=4)
    parser.add_argument("--workers", type=int, nargs="+", default=list(_DEFAULT_WORKERS))
    parser.add_argument("--timeout-per-cube", type=float, default=30.0)
    parser.add_argument(
        "--solver",
        help="SAT solver executable (defaults to the first supported solver on PATH)",
    )
    parser.add_argument(
        "--csv-output",
        default=None,
        help=(
            "write measured worker results to this CSV file "
            "(default: benchmark_reports/scaling_results.csv)"
        ),
    )
    args = parser.parse_args(argv)

    try:

        benchmark_solving_throughput(
            hash_name=args.hash,
            rounds=args.rounds,
            cube_depth=args.cube_depth,
            worker_counts=args.workers,
            timeout_per_cube=args.timeout_per_cube,
            solver=args.solver,
            csv_output=args.csv_output,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
