"""Memory- and time-capped cube-and-conquer dispatch (injected fake runner).

No real SAT solver or subprocess runs here: a fake ``run_capped`` scripts the
per-cube outcome so the aggregation logic — early exit on SAT, UNKNOWN on a
memory/timeout cap, UNSAT only when every cube proves UNSAT — is tested
deterministically. The fake also asserts each cube's DIMACS file was written.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from keylab.sat.parallel import solve_cubes_capped

# A trivial satisfiable formula over two variables.
_DIMACS = "p cnf 2 1\n1 2 0\n"
_VARIABLES = (1, 2)


@dataclass
class _FakeRun:
    status: str
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = 0


def _make_runner(statuses, *, calls=None):
    """Return a fake run_capped yielding ``statuses`` per call, newest last."""
    pending = list(statuses)

    def runner(argv, *, mem_bytes, timeout, input_text=None):
        assert isinstance(argv, list) and len(argv) == 2
        with open(argv[1], encoding="ascii") as handle:
            assert handle.read().startswith("p cnf")  # the cube file was written
        if calls is not None:
            calls.append({"mem_bytes": mem_bytes, "timeout": timeout})
        return pending.pop(0)

    return runner


def test_all_unsat_aggregates_unsat() -> None:
    runner = _make_runner([_FakeRun("ok", "s UNSATISFIABLE\n")] * 2)
    result = solve_cubes_capped(
        "solver", _DIMACS, _VARIABLES, depth=1, workers=1, timeout=1.0, mem_bytes=1 << 20, runner=runner
    )
    assert result.status == "UNSATISFIABLE"
    assert result.total_cubes == 2
    assert result.completed_cubes == 2
    assert (result.memory_breaches, result.timeouts, result.errors) == (0, 0, 0)


def test_satisfiable_cube_ends_search() -> None:
    runner = _make_runner([_FakeRun("ok", "s SATISFIABLE\nv 1 -2 0\n"), _FakeRun("ok", "s UNSATISFIABLE\n")])
    result = solve_cubes_capped(
        "solver", _DIMACS, _VARIABLES, depth=1, workers=1, timeout=1.0, mem_bytes=1 << 20, runner=runner
    )
    assert result.status == "SATISFIABLE"
    assert result.assignments == {1: True, 2: False}
    assert result.satisfying_cube is not None


def test_memory_breach_makes_unknown() -> None:
    runner = _make_runner([_FakeRun("ok", "s UNSATISFIABLE\n"), _FakeRun("memory")])
    result = solve_cubes_capped(
        "solver", _DIMACS, _VARIABLES, depth=1, workers=1, timeout=1.0, mem_bytes=1 << 20, runner=runner
    )
    assert result.status == "UNKNOWN"
    assert result.memory_breaches == 1


def test_timeout_makes_unknown() -> None:
    runner = _make_runner([_FakeRun("timeout"), _FakeRun("ok", "s UNSATISFIABLE\n")])
    result = solve_cubes_capped(
        "solver", _DIMACS, _VARIABLES, depth=1, workers=1, timeout=1.0, mem_bytes=1 << 20, runner=runner
    )
    assert result.status == "UNKNOWN"
    assert result.timeouts == 1


def test_runner_receives_caps() -> None:
    calls: list[dict] = []
    runner = _make_runner([_FakeRun("ok", "s UNSATISFIABLE\n")] * 2, calls=calls)
    solve_cubes_capped(
        "solver", _DIMACS, _VARIABLES, depth=1, workers=2, timeout=2.5, mem_bytes=777, runner=runner
    )
    assert calls and all(c == {"mem_bytes": 777, "timeout": 2.5} for c in calls)


def test_rejects_bad_mem_bytes() -> None:
    with pytest.raises(ValueError, match="mem_bytes"):
        solve_cubes_capped(
            "solver", _DIMACS, _VARIABLES, depth=1, workers=1, timeout=1.0, mem_bytes=0, runner=_make_runner([])
        )
