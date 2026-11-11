"""In-process SAT backends backed by PySAT, CryptoMiniSat, or PycoSAT."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.util import find_spec
from time import perf_counter
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from keylab.sat.cryptominisat import CryptoMiniSatFormula

SATStatus = Literal["SATISFIABLE", "UNSATISFIABLE", "UNKNOWN"]


@dataclass(frozen=True)
class CNFSolveResult:
    """Normalized in-process SAT result with backend and elapsed-time metadata."""

    status: SATStatus
    assignments: dict[int, bool]
    backend: str
    elapsed_seconds: float


def available_backends() -> tuple[str, ...]:
    """Return installed in-process SAT backends in preferred dispatch order."""
    backends = []
    if find_spec("pysat") is not None:
        backends.append("pysat")
    if find_spec("pycryptosat") is not None:
        backends.append("cryptosat")
    if find_spec("pycosat") is not None:
        backends.append("pycosat")
    return tuple(backends)


def _validate_clauses(clauses: list[list[int]] | tuple[tuple[int, ...], ...]) -> list[list[int]]:
    normalized = []
    for clause in clauses:
        row = list(clause)
        if any(type(literal) is not int or literal == 0 for literal in row):
            raise ValueError("clauses must contain nonzero integer literals")
        normalized.append(row)
    return normalized


def solve_cnf(
    clauses: list[list[int]] | tuple[tuple[int, ...], ...],
    *,
    backend: str = "auto",
    solver_name: str = "cadical195",
) -> CNFSolveResult:
    """Solve clauses with a native backend; PySAT is preferred when installed.

    ``backend`` accepts ``auto``, ``pysat``, ``cryptosat``, or ``pycosat``.
    PySAT supports selecting a bundled solver by ``solver_name``. This API
    complements the existing DIMACS/external-solver and bounded reference paths.
    """
    if backend not in {"auto", "pysat", "cryptosat", "pycosat"}:
        raise ValueError("backend must be auto, pysat, cryptosat, or pycosat")
    formula = _validate_clauses(clauses)
    selected = backend
    if selected == "auto":
        selected = next(iter(available_backends()), "")
        if not selected:
            raise RuntimeError("no native SAT backend installed; install keylab[sat-native]")

    started = perf_counter()
    if selected == "pysat":
        if find_spec("pysat") is None:
            raise RuntimeError("PySAT is not installed; run pip install 'keylab[sat-native]'")
        from pysat.solvers import Solver

        with Solver(name=solver_name, bootstrap_with=formula) as solver:
            satisfiable = solver.solve()
            model = solver.get_model() if satisfiable else None
        assignments = {abs(literal): literal > 0 for literal in model or []}
        status: SATStatus = (
            "UNKNOWN" if satisfiable is None else "SATISFIABLE" if satisfiable else "UNSATISFIABLE"
        )
    elif selected == "cryptosat":
        if find_spec("pycryptosat") is None:
            raise RuntimeError("pycryptosat is not installed")
        from pycryptosat import Solver

        solver = Solver()
        for clause in formula:
            solver.add_clause(clause)
        satisfiable, model = solver.solve()
        assignments = (
            {variable: bool(value) for variable, value in enumerate(model[1:], 1) if value is not None}
            if satisfiable and model is not None
            else {}
        )
        status = (
            "UNKNOWN" if satisfiable is None else "SATISFIABLE" if satisfiable else "UNSATISFIABLE"
        )
    else:
        if find_spec("pycosat") is None:
            raise RuntimeError("pycosat is not installed; run pip install 'keylab[sat-native]'")
        import pycosat

        model = pycosat.solve(formula)
        if model == "UNSAT":
            status = "UNSATISFIABLE"
            assignments = {}
        elif model == "UNKNOWN":
            status = "UNKNOWN"
            assignments = {}
        else:
            status = "SATISFIABLE"
            assignments = {abs(literal): literal > 0 for literal in model}

    return CNFSolveResult(status, assignments, selected, perf_counter() - started)


def solve_xor_formula(formula: CryptoMiniSatFormula) -> CNFSolveResult:
    """Solve a mixed CNF + native-XOR formula with CryptoMiniSat's XOR engine.

    CryptoMiniSat handles XOR constraints natively (``add_xor_clause``) rather
    than through the Tseitin clause expansion a CNF-only solver needs, which is
    the point of emitting the SHA-256 Sigma/sigma rotations as XOR rows (see
    :mod:`keylab.hashes.sha256_xor`). This is the in-process equivalent of the
    ``cryptominisat5 --xor`` command-line path and needs no external binary.

    Requires the ``pycryptosat`` backend (a core dependency). An ``XOR()=true``
    row with no variables is an immediate contradiction and returns UNSAT
    without invoking the solver.
    """
    if find_spec("pycryptosat") is None:
        raise RuntimeError("pycryptosat is not installed; the XOR engine is unavailable")
    from pycryptosat import Solver

    started = perf_counter()
    solver = Solver()
    for clause in formula.clauses:
        solver.add_clause(list(clause))
    for variables, rhs in formula.xors:
        if not variables:
            if rhs:
                return CNFSolveResult("UNSATISFIABLE", {}, "cryptosat-xor", perf_counter() - started)
            continue
        solver.add_xor_clause(list(variables), rhs)
    satisfiable, model = solver.solve()
    assignments = (
        {variable: bool(value) for variable, value in enumerate(model[1:], 1) if value is not None}
        if satisfiable and model is not None
        else {}
    )
    status: SATStatus = (
        "UNKNOWN" if satisfiable is None else "SATISFIABLE" if satisfiable else "UNSATISFIABLE"
    )
    return CNFSolveResult(status, assignments, "cryptosat-xor", perf_counter() - started)


__all__ = ["CNFSolveResult", "available_backends", "solve_cnf", "solve_xor_formula"]
