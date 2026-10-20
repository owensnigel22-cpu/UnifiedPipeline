"""Parallel cube-and-conquer dispatch for existing DIMACS CNF formulas."""

from __future__ import annotations

import math
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from itertools import product
from threading import Event

from keylab.sat.solver import SolverResult, run_solver

_MAX_CUBE_DEPTH = 16


@dataclass(frozen=True)
class ParallelCubeResult:
    """Aggregate result from solving a formula under input-bit cubes."""

    status: str
    total_cubes: int
    completed_cubes: int
    cube_depth: int
    assignments: dict[int, bool]
    satisfying_cube: tuple[int, ...] | None


@dataclass(frozen=True)
class _PreparedDIMACS:
    variable_count: int
    clause_count: int
    preamble: str
    body: str

    def with_assumptions(self, assumptions: tuple[int, ...]) -> str:
        if any(literal == 0 or abs(literal) > self.variable_count for literal in assumptions):
            raise ValueError("assumptions must refer to allocated DIMACS variables")
        header = f"p cnf {self.variable_count} {self.clause_count + len(assumptions)}\n"
        assumption_clauses = "".join(f"{literal} 0\n" for literal in assumptions)
        return self.preamble + header + self.body + assumption_clauses


def _validate_cube_inputs(variables: tuple[int, ...], depth: int) -> None:
    if type(depth) is not int or not 1 <= depth <= len(variables):
        raise ValueError("cube depth must be between 1 and the number of variables")
    if depth > _MAX_CUBE_DEPTH:
        raise ValueError(f"cube depth cannot exceed {_MAX_CUBE_DEPTH}")
    if any(type(variable) is not int or variable <= 0 for variable in variables):
        raise ValueError("cube variables must be positive DIMACS variable identifiers")
    if len(set(variables)) != len(variables):
        raise ValueError("cube variables must be unique")


def _iter_cubes(variables: tuple[int, ...], depth: int) -> Iterator[tuple[int, ...]]:
    """Yield signed assignments to the first ``depth`` variables."""
    _validate_cube_inputs(variables, depth)
    yield from (
        tuple(variable if value else -variable for variable, value in zip(variables[:depth], values))
        for values in product((False, True), repeat=depth)
    )


def generate_cubes(variables: tuple[int, ...], depth: int) -> tuple[tuple[int, ...], ...]:
    """Generate every signed assignment to the first ``depth`` variables."""
    return tuple(_iter_cubes(variables, depth))


def _prepare_dimacs(dimacs: str) -> _PreparedDIMACS:
    """Validate a DIMACS formula and retain its reusable clause body."""
    from io import StringIO

    preamble_lines: list[str] = []
    body_lines: list[str] = []
    variable_count: int | None = None
    clause_count: int | None = None
    clause_terminators = 0
    last_literal: int | None = None
    for raw_line in StringIO(dimacs):
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()
        if variable_count is None:
            if stripped.startswith("p "):
                header = stripped.split()
                if len(header) != 4 or header[1] != "cnf":
                    raise ValueError("DIMACS header must have the form 'p cnf VARIABLES CLAUSES'")
                try:
                    variable_count, clause_count = int(header[2]), int(header[3])
                except ValueError as exc:
                    raise ValueError("DIMACS header variable and clause counts must be integers") from exc
                if variable_count < 0 or clause_count < 0:
                    raise ValueError("DIMACS header counts must be nonnegative")
                continue
            preamble_lines.append(line)
            continue

        body_lines.append(line)
        if not stripped or stripped.startswith("c"):
            continue
        for token in stripped.split():
            try:
                literal = int(token)
            except ValueError as exc:
                raise ValueError("DIMACS clauses must contain integer literals") from exc
            last_literal = literal
            if literal == 0:
                clause_terminators += 1
            elif abs(literal) > variable_count:
                raise ValueError("DIMACS clause references an unallocated variable")

    if variable_count is None or clause_count is None:
        raise ValueError("DIMACS input must contain a problem header")
    if clause_count != clause_terminators or (last_literal is not None and last_literal != 0):
        raise ValueError("DIMACS clause data does not match the declared clause count")

    preamble = "\n".join(preamble_lines)
    if preamble:
        preamble += "\n"
    body = "\n".join(body_lines)
    if body:
        body += "\n"
    return _PreparedDIMACS(variable_count, clause_count, preamble, body)


def dimacs_with_assumptions(dimacs: str, assumptions: tuple[int, ...]) -> str:
    """Add unit clauses to DIMACS and update its declared clause count."""
    return _prepare_dimacs(dimacs).with_assumptions(assumptions)


def _solve_one_cube(
    dimacs: _PreparedDIMACS,
    executable: str,
    cube: tuple[int, ...],
    timeout: float,
    cancel_event: Event,
) -> tuple[tuple[int, ...], SolverResult]:
    return cube, run_solver(
        executable,
        dimacs.with_assumptions(cube),
        timeout=timeout,
        cancel_event=cancel_event,
    )


def solve_parallel_cubes(
    executable: str,
    dimacs: str,
    variables: tuple[int, ...],
    *,
    depth: int,
    workers: int,
    timeout: float,
) -> ParallelCubeResult:
    """Solve a CNF under all selected cubes using independent solver processes.

    Worker threads supervise independent external SAT solver processes. This
    avoids Python process-pool startup and named-pipe overhead while retaining
    concurrent solver execution. A SAT cube ends the search early; otherwise
    the aggregate is UNKNOWN if any cube timed out or returned UNKNOWN, and
    UNSAT only if every cube proved UNSAT.
    """
    if type(workers) is not int or workers < 1:
        raise ValueError("workers must be positive")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be positive")
    _validate_cube_inputs(variables, depth)
    cube_iterator = iter(_iter_cubes(variables, depth))
    total_cubes = 1 << depth
    # Parse and validate once; worker processes receive the formula only at startup.
    base_dimacs = _prepare_dimacs(dimacs)
    worker_count = min(workers, total_cubes)
    cancel_event = Event()

    completed = 0
    saw_unknown = False
    with ThreadPoolExecutor(
        max_workers=worker_count,
    ) as executor:
        pending = {}
        for _ in range(worker_count):
            cube = next(cube_iterator, None)
            if cube is None:
                break
            future = executor.submit(
                _solve_one_cube, base_dimacs, executable, cube, timeout, cancel_event
            )
            pending[future] = cube

        while pending:
            future = next(as_completed(tuple(pending)))
            pending.pop(future)
            cube, result = future.result()
            completed += 1
            if result.status == "SATISFIABLE":
                cancel_event.set()
                for outstanding in pending:
                    outstanding.cancel()
                return ParallelCubeResult(
                    "SATISFIABLE",
                    total_cubes,
                    completed,
                    depth,
                    result.assignments,
                    cube,
                )
            if result.status != "UNSATISFIABLE":
                saw_unknown = True
            next_cube = next(cube_iterator, None)
            if next_cube is not None:
                next_future = executor.submit(
                    _solve_one_cube,
                    base_dimacs,
                    executable,
                    next_cube,
                    timeout,
                    cancel_event,
                )
                pending[next_future] = next_cube

    return ParallelCubeResult(
        "UNKNOWN" if saw_unknown else "UNSATISFIABLE",
        total_cubes,
        completed,
        depth,
        {},
        None,
    )


__all__ = [
    "ParallelCubeResult",
    "dimacs_with_assumptions",
    "generate_cubes",
    "solve_parallel_cubes",
]
