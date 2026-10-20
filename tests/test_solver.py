import subprocess
from threading import Event

import pytest

from keylab.sat.solver import run_solver


def test_run_solver_stops_a_running_child_after_cancellation(monkeypatch) -> None:
    cancel_event = Event()

    class FakeProcess:
        returncode = None
        killed = False

        def __init__(self, *args, **kwargs):
            pass

        def communicate(self, input=None, timeout=None):
            if self.killed:
                return "", ""
            cancel_event.set()
            raise subprocess.TimeoutExpired("fake solver", timeout)

        def kill(self):
            self.killed = True
            self.returncode = -9

        def poll(self):
            return self.returncode

    monkeypatch.setattr("keylab.sat.solver.subprocess.Popen", FakeProcess)
    result = run_solver(
        "fake-solver",
        "p cnf 0 0\n",
        timeout=10,
        cancel_event=cancel_event,
    )

    assert result.status == "UNKNOWN"
    assert "cancelled" in result.stderr


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), True])
def test_run_solver_rejects_invalid_timeout(timeout) -> None:
    with pytest.raises(ValueError, match="timeout"):
        run_solver("unused", "", timeout=timeout)
