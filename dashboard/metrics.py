"""CSV normalization and aggregation for recorded solver benchmark runs."""

from __future__ import annotations

import csv
import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from io import StringIO

MetricValue = str | int | float | bool | None
BenchmarkRow = dict[str, MetricValue]


class BenchmarkDataError(ValueError):
    """Raised when a benchmark CSV is malformed or lacks required fields."""


def _first_value(row: Mapping[str, str | None], *names: str) -> str | None:
    for name in names:
        value = row.get(name)
        if value is not None and value.strip():
            return value.strip()
    return None


def _parse_number(value: str | None, column: str, row_number: int) -> float | None:
    if value is None:
        return None
    try:
        number = float(value)
    except ValueError as exc:
        raise BenchmarkDataError(
            f"row {row_number}: {column} must be numeric, got {value!r}"
        ) from exc
    if not math.isfinite(number):
        raise BenchmarkDataError(f"row {row_number}: {column} must be finite")
    if number < 0:
        raise BenchmarkDataError(f"row {row_number}: {column} must not be negative")
    return number


def _numeric_values(
    rows: Sequence[Mapping[str, MetricValue]],
    column: str,
) -> list[float]:
    values: list[float] = []
    for row in rows:
        value = row.get(column)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            values.append(float(value))
    return values


def parse_benchmark_csv(content: str) -> list[BenchmarkRow]:
    """Parse supported benchmark CSV columns into a stable dashboard schema."""
    reader = csv.DictReader(StringIO(content))
    if reader.fieldnames is None:
        raise BenchmarkDataError("CSV must include a header row")
    normalized: list[BenchmarkRow] = []
    for row_number, raw_row in enumerate(reader, start=2):
        if not any(value and value.strip() for value in raw_row.values()):
            continue
        raw: dict[str, str | None] = raw_row
        workers_text = _first_value(raw, "workers", "worker_count")
        runtime_text = _first_value(
            raw,
            "elapsed_seconds",
            "runtime",
            "wall_time_seconds",
            "solver_seconds",
        )
        if runtime_text is None:
            raise BenchmarkDataError(
                f"row {row_number}: missing elapsed_seconds/runtime column"
            )
        workers = _parse_number(workers_text, "workers", row_number)
        runtime = _parse_number(runtime_text, "runtime", row_number)
        if workers is not None and (not workers.is_integer() or workers < 1):
            raise BenchmarkDataError(f"row {row_number}: workers must be a positive integer")

        completed = _parse_number(
            _first_value(raw, "completed_cubes", "cubes_completed"),
            "completed_cubes",
            row_number,
        )
        total = _parse_number(
            _first_value(raw, "total_cubes", "cube_total"),
            "total_cubes",
            row_number,
        )
        throughput = _parse_number(
            _first_value(raw, "cubes_per_second", "throughput"),
            "throughput",
            row_number,
        )
        if throughput is None and completed is not None and runtime and runtime > 0:
            throughput = completed / runtime
        rounds = _parse_number(_first_value(raw, "rounds", "steps"), "rounds", row_number)
        cube_depth = _parse_number(_first_value(raw, "cube_depth"), "cube_depth", row_number)
        variables = _parse_number(_first_value(raw, "variables", "num_vars"), "variables", row_number)
        clauses = _parse_number(_first_value(raw, "clauses"), "clauses", row_number)
        unit_clauses = _parse_number(
            _first_value(raw, "unit_clauses"), "unit_clauses", row_number
        )
        avg_clause_width = _parse_number(
            _first_value(raw, "avg_clause_width"),
            "avg_clause_width",
            row_number,
        )
        candidate_value = _first_value(raw, "candidate_validated")
        candidate_validated: bool | None = None
        if candidate_value is not None:
            if candidate_value.lower() not in ("true", "false", "1", "0"):
                raise BenchmarkDataError(
                    f"row {row_number}: candidate_validated must be boolean"
                )
            candidate_validated = candidate_value.lower() in ("true", "1")

        normalized.append(
            {
                "hash": _first_value(raw, "hash") or "unknown",
                "rounds": int(rounds) if rounds is not None else None,
                "workers": int(workers) if workers is not None else None,
                "runtime": runtime,
                "throughput": throughput,
                "completed_cubes": int(completed) if completed is not None else None,
                "total_cubes": int(total) if total is not None else None,
                "cube_depth": int(cube_depth) if cube_depth is not None else None,
                "variables": int(variables) if variables is not None else None,
                "clauses": int(clauses) if clauses is not None else None,
                "unit_clauses": int(unit_clauses) if unit_clauses is not None else None,
                "avg_clause_width": avg_clause_width,
                "status": (_first_value(raw, "status", "solver_status") or "UNKNOWN").upper(),
                "candidate_validated": candidate_validated,
                "solver": _first_value(raw, "solver") or "unknown",
            }
        )
    if not normalized:
        raise BenchmarkDataError("CSV contains no benchmark rows")
    return normalized


def solver_summary(rows: Sequence[Mapping[str, MetricValue]]) -> dict[str, int | float]:
    """Summarize solver outcomes and runtime without guessing timeout counts."""
    runtimes = _numeric_values(rows, "runtime")
    if not runtimes:
        raise BenchmarkDataError("no numeric runtime measurements are available")
    statuses = [str(row.get("status", "UNKNOWN")).upper() for row in rows]
    unknown_count = sum(status == "UNKNOWN" for status in statuses)
    return {
        "runs": len(rows),
        "sat_solves": sum(status == "SATISFIABLE" for status in statuses),
        "unsat_solves": sum(status == "UNSATISFIABLE" for status in statuses),
        "unknown_solves": unknown_count,
        "unknown_rate_percent": 100.0 * unknown_count / len(rows),
        "average_runtime": sum(runtimes) / len(runtimes),
        "median_runtime": sorted(runtimes)[len(runtimes) // 2]
        if len(runtimes) % 2
        else (sorted(runtimes)[len(runtimes) // 2 - 1] + sorted(runtimes)[len(runtimes) // 2]) / 2,
    }


def worker_scaling(rows: Sequence[Mapping[str, MetricValue]]) -> list[dict[str, float | int]]:
    """Aggregate throughput by worker count and estimate ideal-linear efficiency."""
    by_workers: defaultdict[int, list[float]] = defaultdict(list)
    for row in rows:
        workers = row.get("workers")
        throughput = row.get("throughput")
        if (
            isinstance(workers, int)
            and not isinstance(workers, bool)
            and isinstance(throughput, (int, float))
            and not isinstance(throughput, bool)
        ):
            by_workers[workers].append(float(throughput))
    means = {workers: sum(values) / len(values) for workers, values in by_workers.items()}
    baseline = means.get(1)
    return [
        {
            "workers": workers,
            "throughput": means[workers],
            "efficiency_percent": (
                means[workers] / (baseline * workers) * 100.0
                if baseline is not None and baseline > 0
                else 0.0
            ),
        }
        for workers in sorted(means)
    ]


def grouped_analysis(
    rows: Sequence[Mapping[str, MetricValue]],
    group_column: str,
) -> list[dict[str, int | float]]:
    """Summarize runtime, run count, and SAT outcome by rounds or cube depth."""
    groups: defaultdict[int, list[Mapping[str, MetricValue]]] = defaultdict(list)
    for row in rows:
        group_value = row.get(group_column)
        if isinstance(group_value, int):
            groups[group_value].append(row)
    result: list[dict[str, int | float]] = []
    for value, group_rows in sorted(groups.items()):
        runtimes = _numeric_values(group_rows, "runtime")
        sat_rate = (
            100.0
            * sum(str(row.get("status", "")).upper() == "SATISFIABLE" for row in group_rows)
            / len(group_rows)
        )
        result.append(
            {
                group_column: value,
                "runs": len(group_rows),
                "average_runtime": sum(runtimes) / len(runtimes) if runtimes else 0.0,
                "sat_rate_percent": sat_rate,
            }
        )
    return result


def cnf_analysis(rows: Sequence[Mapping[str, MetricValue]]) -> dict[str, object]:
    """Report CNF measurements only when the input data contains them."""
    totals: dict[str, float] = {
        "variables": 0.0,
        "clauses": 0.0,
        "unit_clauses": 0.0,
        "avg_clause_width": 0.0,
    }
    counts: dict[str, int] = {
        "variables": 0,
        "clauses": 0,
        "unit_clauses": 0,
        "avg_clause_width": 0,
    }

    for row in rows:
        for column in totals:
            value = row.get(column)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                totals[column] += float(value)
                counts[column] += 1

    return {
        "mean_variables": totals["variables"] / counts["variables"] if counts["variables"] else None,
        "mean_clauses": totals["clauses"] / counts["clauses"] if counts["clauses"] else None,
        "mean_unit_clauses": (
            totals["unit_clauses"] / counts["unit_clauses"]
            if counts["unit_clauses"]
            else None
        ),
        "mean_clause_width": (
            totals["avg_clause_width"] / counts["avg_clause_width"]
            if counts["avg_clause_width"]
            else None
        ),
        "propagation_strength": "not measured by available CSV fields",
    }
