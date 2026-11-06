"""Tests for scripts/benchmark_ecdlp.py (ECDLP measurement harness)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

import scripts.benchmark_ecdlp as bench

_ROOT = Path(bench.__file__).resolve().parent.parent
_RUN_SLOW_ECDLP = os.environ.get("RUN_SLOW_ECDLP") == "1"
_REQUIRED_FIELDS = {
    "mode", "timestamp", "target_description", "bits_or_interval", "steps_taken",
    "expected_steps", "fraction_of_work", "fraction_as_2_neg_k", "dps_found",
    "solution_found", "elapsed_sec", "step_rate_ops_per_sec",
}


# --- attain ------------------------------------------------------------------------------------

def test_attain_small_finds_known_k() -> None:
    start = time.perf_counter()
    record = bench.run_attain(20, seed=1, output=None)
    assert record["solution_found"] is True
    assert record["steps_taken"] > 0
    assert _REQUIRED_FIELDS <= set(record)
    assert time.perf_counter() - start < 10.0


@pytest.mark.skipif(not _RUN_SLOW_ECDLP, reason="set RUN_SLOW_ECDLP=1 to run the 2**24 attain anchor")
def test_attain_medium_finds_known_k() -> None:
    record = bench.run_attain(24, seed=1, output=None)
    assert record["solution_found"] is True


# --- bounded-full ------------------------------------------------------------------------------

def test_bounded_full_5s_reaches_a_wall(capsys) -> None:
    record = bench.run_bounded_full(5.0, seed=1, output=None)
    assert record["solution_found"] is False
    assert _REQUIRED_FIELDS <= set(record)
    assert record["steps_taken"] > 0
    assert 0.0 < record["fraction_of_work"] < 1.0
    assert record["fraction_as_2_neg_k"] >= 80  # ~2^-112 in 5s; far from any collision
    out = capsys.readouterr().out
    assert "measurement, not partial progress" in out  # the wall warning printed


def test_bounded_refuses_long_budget() -> None:
    with pytest.raises(ValueError, match="refused unconditionally"):
        bench._check_budget(86_401, i_know=False)


def test_bounded_refuses_extreme_budget_even_with_flag() -> None:
    # the 24h cap is unconditional
    with pytest.raises(ValueError, match="refused unconditionally"):
        bench._check_budget(86_401, i_know=True)


def test_bounded_requires_flag_above_one_hour() -> None:
    with pytest.raises(ValueError, match="i-know-this-wont-work"):
        bench._check_budget(3_601, i_know=False)
    bench._check_budget(3_601, i_know=True)  # allowed with the flag


def test_bounded_warns_short_budget(capsys) -> None:
    bench._check_budget(5, i_know=False)
    assert "degenerate" in capsys.readouterr().out


@pytest.mark.skipif(sys.platform.startswith("win"), reason="SIGTERM delivery test is POSIX-only")
def test_bounded_full_sigterm_flushes_json(tmp_path) -> None:
    import signal
    out = tmp_path / "state.json"
    proc = subprocess.Popen(
        [sys.executable, str(_ROOT / "scripts" / "benchmark_ecdlp.py"),
         "--mode", "bounded-full", "--budget-seconds", "60", "--output", str(out)],
        cwd=str(_ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(3.0)  # let it spend some hops
    proc.send_signal(signal.SIGTERM)
    code = proc.wait(timeout=10)
    assert code == 130
    assert out.is_file()
    record = json.loads(out.read_text(encoding="utf-8"))
    assert record["solution_found"] is False and record["mode"] == "bounded-full"


# --- walkback ----------------------------------------------------------------------------------

def test_walkback_depth_8_recovers() -> None:
    # Correctness + BFS leaf bound only; no wall-clock assertion (each node is a
    # 256-bit halving, ~5s for depth 8 locally, and timing is flaky under CI load).
    record = bench.run_walkback(8, seed=7, output=None)
    assert record["solution_found"] is True
    assert record["steps_taken"] <= (1 << (8 + 1))  # BFS bound 2**(depth+1)


def test_walkback_refuses_deep() -> None:
    with pytest.raises(ValueError, match="SEC_STATE_JOURNAL.md"):
        bench.run_walkback(19, seed=1, output=None)


# --- extrapolate -------------------------------------------------------------------------------

def test_extrapolate_projects_to_the_wall() -> None:
    record = bench.run_extrapolate(seed=1, output=None)
    bits = [row["bits"] for row in record["extrapolation_table"]]
    assert bits == [32, 40, 48, 64, 128]
    assert record["fitted_constant"] > 0
    # steps grow with width (sqrt law): each row's log2 is larger than the last.
    logs = [row["log2_steps"] for row in record["extrapolation_table"]]
    assert logs == sorted(logs)


# --- JSON output -------------------------------------------------------------------------------

def test_output_file_written(tmp_path) -> None:
    out = tmp_path / "attain.json"
    bench.run_attain(20, seed=1, output=out)
    assert out.is_file()
    assert _REQUIRED_FIELDS <= set(json.loads(out.read_text(encoding="utf-8")))
