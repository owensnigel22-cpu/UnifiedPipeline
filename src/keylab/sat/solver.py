"""Explicit external SAT-solver subprocess integration for bounded research models."""

from __future__ import annotations

import math
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event

SOLVER_CANDIDATES = ("kissat", "cadical", "cryptominisat5", "minisat")


@dataclass(frozen=True)
class SolverResult:
    """Parsed SAT status and any signed literal assignments returned by a solver."""

    status: str
    assignments: dict[int, bool]
    stdout: str
    stderr: str
    returncode: int


def find_solver(
    candidates: tuple[str, ...] = SOLVER_CANDIDATES,
) -> str | None:
    """Return the path of an installed supported solver, without installing or running it."""
    for candidate in candidates:
        executable = shutil.which(candidate)
        if executable:
            return executable
    return None


def parse_solver_output(stdout: str, stderr: str = "", returncode: int = 0) -> SolverResult:
    """Parse common SAT competition output lines (s SATISFIABLE, v literals)."""
    status = "UNKNOWN"
    assignments: dict[int, bool] = {}
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("s "):
            candidate = stripped[2:].strip().upper()
            if candidate in ("SATISFIABLE", "UNSATISFIABLE", "UNKNOWN"):
                status = candidate
        elif stripped.startswith("v "):
            for token in stripped[2:].split():
                literal = int(token)
                if literal:
                    assignments[abs(literal)] = literal > 0
    return SolverResult(status, assignments, stdout, stderr, returncode)


def run_solver(
    executable: str,
    dimacs: str,
    timeout: float = 60.0,
    *,
    cancel_event: Event | None = None,
) -> SolverResult:
    """Run the explicitly selected solver with DIMACS on stdin; no solver is fetched implicitly."""
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be positive")
    if cancel_event is not None and cancel_event.is_set():
        return SolverResult("UNKNOWN", {}, "", "solver cancelled before launch", -1)
    temporary_path: str | None = None
    if Path(executable).name.lower().startswith("cryptominisat"):
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".cnf",
                encoding="ascii",
                newline="\n",
                delete=False,
            ) as input_file:
                input_file.write(dimacs)
                temporary_path = input_file.name
            command = [executable, temporary_path]
            input_data = None
        except OSError:
            if temporary_path is not None:
                Path(temporary_path).unlink(missing_ok=True)
            raise
    else:
        command = [executable]
        input_data = dimacs

    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_data is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + timeout
        first_input = input_data
        while True:
            if cancel_event is not None and cancel_event.is_set():
                process.kill()
                stdout, stderr = process.communicate()
                return SolverResult("UNKNOWN", {}, stdout, stderr + "\nsolver cancelled", -1)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                stdout, stderr = process.communicate()
                return SolverResult("UNKNOWN", {}, stdout, stderr + "\nsolver timed out", -1)
            try:
                stdout, stderr = process.communicate(
                    input=first_input,
                    timeout=min(0.05, remaining),
                )
                return parse_solver_output(stdout, stderr, process.returncode or 0)
            except subprocess.TimeoutExpired:
                first_input = None
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.communicate()
        if temporary_path is not None:
            Path(temporary_path).unlink(missing_ok=True)


__all__ = [
    "SOLVER_CANDIDATES",
    "SolverResult",
    "find_solver",
    "parse_solver_output",
    "run_solver",
]
