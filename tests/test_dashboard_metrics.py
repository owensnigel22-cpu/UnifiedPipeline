from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

from dashboard.exporters import report_json
from dashboard.metrics import (
    BenchmarkDataError,
    cnf_analysis,
    grouped_analysis,
    parse_benchmark_csv,
    solver_summary,
    worker_scaling,
)
from dashboard.storage import history_count, import_csv_history, load_history


def test_parse_throughput_csv_and_summarize() -> None:
    rows = parse_benchmark_csv(
        "hash,rounds,cube_depth,workers,elapsed_seconds,completed_cubes,"
        "total_cubes,cubes_per_second,status,candidate_validated,variables,clauses\n"
        "ripemd160,1,1,1,2,2,2,1,SATISFIABLE,true,317,877\n"
        "ripemd160,1,1,2,4,4,4,1,UNKNOWN,,317,877\n"
    )

    assert rows[0]["candidate_validated"] is True
    assert solver_summary(rows) == {
        "runs": 2,
        "sat_solves": 1,
        "unsat_solves": 0,
        "unknown_solves": 1,
        "unknown_rate_percent": 50.0,
        "average_runtime": 3.0,
        "median_runtime": 3.0,
    }
    assert worker_scaling(rows) == [
        {"workers": 1, "throughput": 1.0, "efficiency_percent": 100.0},
        {"workers": 2, "throughput": 1.0, "efficiency_percent": 50.0},
    ]
    assert grouped_analysis(rows, "cube_depth")[0]["runs"] == 2
    assert cnf_analysis(rows)["mean_clause_width"] is None


def test_parse_supports_existing_sha_benchmark_csv_fields() -> None:
    rows = parse_benchmark_csv(
        "rounds,solver_seconds,solver_status,variables,clauses\n"
        "16,0.25,SATISFIABLE,105,361\n"
    )

    assert rows[0]["runtime"] == 0.25
    assert rows[0]["status"] == "SATISFIABLE"
    assert rows[0]["throughput"] is None
    assert rows[0]["workers"] is None


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("", "header row"),
        ("workers,runtime\n", "no benchmark rows"),
        ("workers,runtime\none,1\n", "workers must be numeric"),
        ("workers,runtime\n1,-1\n", "must not be negative"),
    ],
)
def test_parse_rejects_invalid_benchmark_csv(content: str, message: str) -> None:
    with pytest.raises(BenchmarkDataError, match=message):
        parse_benchmark_csv(content)


def test_history_import_is_idempotent(tmp_path) -> None:
    csv_bytes = b"workers,runtime,throughput,status\n1,1,8,SATISFIABLE\n"
    rows = parse_benchmark_csv(csv_bytes.decode())
    database = tmp_path / "benchmark_history.db"

    assert import_csv_history(database, "run.csv", csv_bytes, rows) == 1
    assert import_csv_history(database, "run.csv", csv_bytes, rows) == 0
    assert load_history(database) == rows
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM benchmark_runs").fetchone() == (1,)


def test_history_count_tracks_total_rows(tmp_path) -> None:
    csv_bytes = b"workers,runtime,throughput,status\n1,1,8,SATISFIABLE\n"
    rows = parse_benchmark_csv(csv_bytes.decode())
    database = tmp_path / "benchmark_history.db"

    assert import_csv_history(database, "run.csv", csv_bytes, rows) == 1
    assert history_count(database) == 1


def test_report_json_accepts_precomputed_metrics() -> None:
    rows = parse_benchmark_csv("workers,runtime,status\n1,1,SATISFIABLE\n")
    summary = solver_summary(rows)
    scaling = worker_scaling(rows)
    round_analysis = grouped_analysis(rows, "rounds")
    cube_analysis = grouped_analysis(rows, "cube_depth")
    details = cnf_analysis(rows)

    report = report_json(
        rows,
        solver_summary_data=summary,
        worker_scaling_data=scaling,
        round_analysis=round_analysis,
        cube_analysis=cube_analysis,
        cnf_analysis_data=details,
    )

    assert '"propagation_strength": "not measured by available CSV fields"' in report
    assert '"runs": 1' in report


def test_report_json_identifies_unmeasured_propagation() -> None:
    rows = parse_benchmark_csv("workers,runtime,status\n1,1,SATISFIABLE\n")

    report = report_json(rows)

    assert '"propagation_strength": "not measured by available CSV fields"' in report
