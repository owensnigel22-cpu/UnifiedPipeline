"""Explicit external SAT-solver subprocess integration for bounded research models."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

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


def run_solver(executable: str, dimacs: str, timeout: float = 60.0) -> SolverResult:
    """Run the explicitly selected solver with DIMACS on stdin; no solver is fetched implicitly."""
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if Path(executable).name.lower().startswith("cryptominisat"):
        temporary_path: str | None = None
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
            completed = subprocess.run(
                [executable, temporary_path],
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout_value = exc.stdout
            stderr_value = exc.stderr
            stdout = stdout_value.decode(errors="replace") if isinstance(stdout_value, bytes) else stdout_value or ""
            stderr = stderr_value.decode(errors="replace") if isinstance(stderr_value, bytes) else stderr_value or ""
            return SolverResult("UNKNOWN", {}, stdout, stderr + "\nsolver timed out", -1)
        finally:
            if temporary_path is not None:
                Path(temporary_path).unlink(missing_ok=True)
        return parse_solver_output(completed.stdout, completed.stderr, completed.returncode)
    try:
        completed = subprocess.run(
            [executable], input=dimacs, text=True, capture_output=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        stdout_value = exc.stdout
        stderr_value = exc.stderr
        stdout = stdout_value.decode(errors="replace") if isinstance(stdout_value, bytes) else stdout_value or ""
        stderr = stderr_value.decode(errors="replace") if isinstance(stderr_value, bytes) else stderr_value or ""
        return SolverResult("UNKNOWN", {}, stdout, stderr + "\nsolver timed out", -1)
    return parse_solver_output(completed.stdout, completed.stderr, completed.returncode)


__all__ = [
    "SOLVER_CANDIDATES",
    "SolverResult",
    "find_solver",
    "parse_solver_output",
    "run_solver",
]