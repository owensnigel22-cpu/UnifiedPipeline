from threading import Barrier, Event

import pytest

from keylab.sat.parallel import (
    dimacs_with_assumptions,
    generate_cubes,
    solve_parallel_cubes,
)
from keylab.sat.solver import find_solver


def test_generate_cubes_partitions_bits_in_stable_order() -> None:
    assert generate_cubes((3, 8, 11), 2) == (
        (-3, -8),
        (-3, 8),
        (3, -8),
        (3, 8),
    )


@pytest.mark.parametrize(
    ("variables", "depth", "error"),
    [
        ((1, 2), 0, "cube depth"),
        ((1,), 2, "cube depth"),
        ((1,) * 17, 17, "cannot exceed"),
        ((1, 1), 1, "unique"),
        ((0, 1), 1, "positive"),
    ],
)
def test_generate_cubes_validates_variables(
    variables: tuple[int, ...],
    depth: int,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        generate_cubes(variables, depth)


def test_parallel_cubes_run_solver_and_aggregate_sat_and_unsat() -> None:
    solver = find_solver()
    if solver is None:
        pytest.skip("no supported external SAT solver is installed")

    sat_result = solve_parallel_cubes(
        solver,
        "p cnf 1 1\n1 0\n",
        (1,),
        depth=1,
        workers=2,
        timeout=10,
    )
    assert sat_result.status == "SATISFIABLE"
    assert sat_result.satisfying_cube == (1,)
    assert sat_result.total_cubes == 2

    unsat_result = solve_parallel_cubes(
        solver,
        "p cnf 1 2\n1 0\n-1 0\n",
        (1,),
        depth=1,
        workers=2,
        timeout=10,
    )
    assert unsat_result.status == "UNSATISFIABLE"
    assert unsat_result.completed_cubes == 2


def test_sat_cube_cancels_other_running_solver_jobs(monkeypatch) -> None:
    from keylab.sat import parallel

    both_started = Barrier(2)
    cancelled_job_observed = Event()

    def fake_solver(executable, dimacs, timeout, *, cancel_event):
        both_started.wait(timeout=2)
        cube_literal = dimacs.splitlines()[-1]
        if cube_literal == "-1 0":
            return parallel.SolverResult("SATISFIABLE", {1: False}, "", "", 10)
        if cancel_event.wait(timeout=2):
            cancelled_job_observed.set()
        return parallel.SolverResult("UNKNOWN", {}, "", "cancelled", -1)

    monkeypatch.setattr(parallel, "run_solver", fake_solver)
    result = solve_parallel_cubes(
        "unused",
        "p cnf 1 1\n1 0\n",
        (1,),
        depth=1,
        workers=2,
        timeout=10,
    )
    assert result.status == "SATISFIABLE"
    assert result.completed_cubes == 1
    assert cancelled_job_observed.is_set()


def test_dimacs_with_assumptions_updates_header_and_adds_unit_clauses() -> None:
    dimacs = "c tiny formula\np cnf 2 2\n1 -2 0\n2 0\n"

    assert dimacs_with_assumptions(dimacs, (-1, 2)) == (
        "c tiny formula\np cnf 2 4\n1 -2 0\n2 0\n-1 0\n2 0\n"
    )


@pytest.mark.parametrize(
    ("dimacs", "assumptions", "error"),
    [
        ("1 0\n", (), "problem header"),
        ("p cnf 1 1\n1 0\n", (2,), "allocated"),
        ("p cnf 1 2\n1 0\n", (), "clause count"),
        ("p cnf 1 1\n2 0\n", (), "unallocated"),
    ],
)
def test_dimacs_with_assumptions_rejects_malformed_inputs(
    dimacs: str,
    assumptions: tuple[int, ...],
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        dimacs_with_assumptions(dimacs, assumptions)
