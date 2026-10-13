from __future__ import annotations

import csv

import pytest

from keylab import cli
from keylab.hashes.reduced import ripemd160_reduced
from keylab.sat import benchmark_throughput
from keylab.sat.parallel import ParallelCubeResult
from keylab.sat.solver import find_solver


def test_benchmark_reports_throughput_and_speedup(monkeypatch, capsys) -> None:
    completed = iter(
        (
            ParallelCubeResult("SATISFIABLE", 2, 2, 1, {}, (1,)),
            ParallelCubeResult("SATISFIABLE", 2, 1, 1, {}, (1,)),
        )
    )
    solver_calls: list[tuple[str, tuple[int, ...], int]] = []
    timestamps = iter((0.0, 2.0, 2.0, 3.0))

    def fake_solve(
        solver: str,
        dimacs: str,
        variables: tuple[int, ...],
        *,
        depth: int,
        workers: int,
        timeout: float,
    ) -> ParallelCubeResult:
        assert solver == "test-solver"
        assert dimacs.startswith("p cnf ")
        assert len(variables) == 128
        assert depth == 1
        assert timeout == 30
        solver_calls.append((solver, variables, workers))
        result = next(completed)
        if result.status == "SATISFIABLE":
            result = ParallelCubeResult(
                result.status,
                result.total_cubes,
                result.completed_cubes,
                result.cube_depth,
                {
                    variable: bool(
                        (
                            benchmark_throughput._BENCHMARK_MESSAGE[index // 8]
                            >> (7 - index % 8)
                        )
                        & 1
                    )
                    for index, variable in enumerate(variables)
                },
                result.satisfying_cube,
            )
        return result

    monkeypatch.setattr(benchmark_throughput, "solve_parallel_cubes", fake_solve)
    monkeypatch.setattr(benchmark_throughput.time, "perf_counter", lambda: next(timestamps))

    benchmark_throughput.benchmark_solving_throughput(
        rounds=1,
        cube_depth=1,
        worker_counts=(1, 2),
        solver="test-solver",
    )

    output = capsys.readouterr().out
    result_rows = [
        [column.strip() for column in line.split("|")]
        for line in output.splitlines()
        if line.startswith(("1", "2")) and "|" in line
    ]
    assert [row[0] for row in result_rows] == ["1", "2"]
    assert [row[2] for row in result_rows] == ["1.00", "1.00"]
    assert [row[3].replace(" ", "") for row in result_rows] == ["1.00x", "2.00x"]
    assert [row[4] for row in result_rows] == ["SATISFIABLE", "SATISFIABLE"]
    assert [row[5] for row in result_rows] == ["True", "True"]
    assert [call[2] for call in solver_calls] == [1, 2]


def test_benchmark_rejects_sat_candidate_that_does_not_match_target(monkeypatch) -> None:
    def fake_solve(
        solver: str,
        dimacs: str,
        variables: tuple[int, ...],
        *,
        depth: int,
        workers: int,
        timeout: float,
    ) -> ParallelCubeResult:
        return ParallelCubeResult(
            "SATISFIABLE",
            2,
            1,
            depth,
            {variable: False for variable in variables},
            (),
        )

    monkeypatch.setattr(benchmark_throughput, "solve_parallel_cubes", fake_solve)
    with pytest.raises(RuntimeError, match="does not match the target digest"):
        benchmark_throughput.benchmark_solving_throughput(
            rounds=1,
            cube_depth=1,
            worker_counts=(1,),
            solver="test-solver",
        )


@pytest.mark.parametrize(
    ("worker_counts", "error"),
    [
        ((2,), "include 1"),
        ((1, 1), "unique"),
        ((0, 1), "positive integers"),
    ],
)
def test_benchmark_validates_worker_counts(worker_counts, error) -> None:
    with pytest.raises(ValueError, match=error):
        benchmark_throughput.benchmark_solving_throughput(
            rounds=1,
            worker_counts=worker_counts,
            solver="test-solver",
        )


def test_benchmark_builds_ripemd160_model(monkeypatch) -> None:
    recorded: list[tuple[str, tuple[int, ...], int]] = []

    def fake_solve(
        solver: str,
        dimacs: str,
        variables: tuple[int, ...],
        *,
        depth: int,
        workers: int,
        timeout: float,
    ) -> ParallelCubeResult:
        recorded.append((solver, variables, workers))
        return ParallelCubeResult("UNKNOWN", 2, 2, depth, {}, None)

    monkeypatch.setattr(benchmark_throughput, "solve_parallel_cubes", fake_solve)
    monkeypatch.setattr(benchmark_throughput.time, "perf_counter", iter((0.0, 1.0)).__next__)

    benchmark_throughput.benchmark_solving_throughput(
        hash_name="ripemd160",
        rounds=1,
        cube_depth=1,
        worker_counts=(1,),
        solver="test-solver",
    )

    assert len(recorded[0][1]) == 128


def test_cli_benchmark_writes_measured_csv(monkeypatch, tmp_path) -> None:
    def fake_solve(
        solver: str,
        dimacs: str,
        variables: tuple[int, ...],
        *,
        depth: int,
        workers: int,
        timeout: float,
    ) -> ParallelCubeResult:
        return ParallelCubeResult("UNSATISFIABLE", 2, 2, depth, {}, None)

    monkeypatch.setattr(benchmark_throughput, "solve_parallel_cubes", fake_solve)
    monkeypatch.setattr(benchmark_throughput.time, "perf_counter", iter((4.0, 6.0)).__next__)
    csv_path = tmp_path / "scaling_results.csv"

    assert cli.main(
        [
            "sat-throughput-benchmark",
            "--rounds",
            "1",
            "--cube-depth",
            "1",
            "--workers",
            "1",
            "--solver",
            "test-solver",
            "--csv-output",
            str(csv_path),
        ]
    ) == 0

    with csv_path.open(encoding="utf-8", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))
    assert len(rows) == 1
    assert rows[0]["workers"] == "1"
    assert rows[0]["elapsed_seconds"] == "2.0"
    assert rows[0]["completed_cubes"] == "2"
    assert rows[0]["total_cubes"] == "2"
    assert rows[0]["cubes_per_second"] == "1.0"
    assert rows[0]["speedup"] == "1.0"
    assert rows[0]["status"] == "UNSATISFIABLE"
    assert rows[0]["candidate_validated"] == ""
    assert rows[0]["candidate_hex"] == ""
    assert rows[0]["fixed_input_bits"] == "0"
    assert rows[0]["solver"] == "test-solver"


def test_benchmark_solves_a_free_input_preimage_with_external_solver(
    capsys, tmp_path
) -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")
    csv_path = tmp_path / "preimage-result.csv"

    benchmark_throughput.benchmark_solving_throughput(
        hash_name="ripemd160",
        rounds=1,
        cube_depth=1,
        worker_counts=(1,),
        timeout_per_cube=3,
        solver=solver,
        csv_output=str(csv_path),
    )

    output = capsys.readouterr().out
    assert "Free input bits: 128" in output
    assert "SATISFIABLE | True" in output
    with csv_path.open(encoding="utf-8", newline="") as csv_file:
        row = next(csv.DictReader(csv_file))
    assert row["fixed_input_bits"] == "0"
    assert row["candidate_validated"] == "True"
    assert bytes.fromhex(row["candidate_hex"])
    assert (
        ripemd160_reduced(bytes.fromhex(row["candidate_hex"]), steps=1).hex()
        == row["target_hex"]
    )
