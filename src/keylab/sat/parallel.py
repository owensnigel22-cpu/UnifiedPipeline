"""Parallel cube-and-conquer dispatch for existing DIMACS CNF formulas."""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from itertools import product

from keylab.sat.solver import SolverResult, run_solver

_MAX_CUBE_DEPTH = 16
_WORKER_DIMACS: _PreparedDIMACS | None = None


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
    lines = dimacs.splitlines()
    header_index = next(
        (index for index, line in enumerate(lines) if line.strip().startswith("p ")),
        None,
    )
    if header_index is None:
        raise ValueError("DIMACS input must contain a problem header")

    header = lines[header_index].split()
    if len(header) != 4 or header[1] != "cnf":
        raise ValueError("DIMACS header must have the form 'p cnf VARIABLES CLAUSES'")
    try:
        variable_count, clause_count = int(header[2]), int(header[3])
    except ValueError as exc:
        raise ValueError("DIMACS header variable and clause counts must be integers") from exc
    if variable_count < 0 or clause_count < 0:
        raise ValueError("DIMACS header counts must be nonnegative")

    tokens: list[int] = []
    body_lines = []
    for line in lines[header_index + 1 :]:
        stripped = line.strip()
        body_lines.append(line)
        if not stripped or stripped.startswith("c"):
            continue
        try:
            tokens.extend(int(token) for token in stripped.split())
        except ValueError as exc:
            raise ValueError("DIMACS clauses must contain integer literals") from exc
    if clause_count != tokens.count(0) or (tokens and tokens[-1] != 0):
        raise ValueError("DIMACS clause data does not match the declared clause count")
    if any(literal != 0 and abs(literal) > variable_count for literal in tokens):
        raise ValueError("DIMACS clause references an unallocated variable")

    preamble = "\n".join(lines[:header_index])
    if preamble:
        preamble += "\n"
    body = "\n".join(body_lines)
    if body:
        body += "\n"
    return _PreparedDIMACS(variable_count, clause_count, preamble, body)


def dimacs_with_assumptions(dimacs: str, assumptions: tuple[int, ...]) -> str:
    """Add unit clauses to DIMACS and update its declared clause count."""
    return _prepare_dimacs(dimacs).with_assumptions(assumptions)


def _initialize_cube_worker(dimacs: _PreparedDIMACS) -> None:
    global _WORKER_DIMACS
    _WORKER_DIMACS = dimacs


def _solve_one_cube(
    executable: str,
    cube: tuple[int, ...],
    timeout: float,
) -> tuple[tuple[int, ...], SolverResult]:
    if _WORKER_DIMACS is None:
        raise RuntimeError("cube worker was not initialized with a DIMACS formula")
    return cube, run_solver(
        executable,
        _WORKER_DIMACS.with_assumptions(cube),
        timeout=timeout,
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

    Each worker runs an external SAT solver in a process pool. A SAT cube ends
    the search early; otherwise the aggregate is UNKNOWN if any cube timed out
    or returned UNKNOWN, and UNSAT only if every cube proved UNSAT.
    """
    if workers < 1:
        raise ValueError("workers must be positive")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    _validate_cube_inputs(variables, depth)
    cube_iterator = iter(_iter_cubes(variables, depth))
    total_cubes = 1 << depth
    # Parse and validate once; worker processes receive the formula only at startup.
    base_dimacs = _prepare_dimacs(dimacs)

    completed = 0
    saw_unknown = False
    with ProcessPoolExecutor(
        max_workers=workers,
        initializer=_initialize_cube_worker,
        initargs=(base_dimacs,),
    ) as executor:
        pending = {}
        for _ in range(workers):
            cube = next(cube_iterator, None)
            if cube is None:
                break
            future = executor.submit(_solve_one_cube, executable, cube, timeout)
            pending[future] = cube

        while pending:
            future = next(as_completed(tuple(pending)))
            pending.pop(future)
            cube, result = future.result()
            completed += 1
            if result.status == "SATISFIABLE":
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
                    executable,
                    next_cube,
                    timeout,
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
