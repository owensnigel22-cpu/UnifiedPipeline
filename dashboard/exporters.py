"""Export normalized dashboard reports."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

from dashboard.metrics import (
    BenchmarkRow,
    cnf_analysis,
    grouped_analysis,
    solver_summary,
    worker_scaling,
)


def report_json(
    rows: Sequence[BenchmarkRow],
    *,
    solver_summary_data: Mapping[str, object] | None = None,
    worker_scaling_data: Sequence[Mapping[str, object]] | None = None,
    round_analysis: Sequence[Mapping[str, object]] | None = None,
    cube_analysis: Sequence[Mapping[str, object]] | None = None,
    cnf_analysis_data: Mapping[str, object] | None = None,
) -> str:
    """Serialize factual summary, scaling, round, cube, and CNF metrics."""
    report: Mapping[str, object] = {
        "runs": list(rows),
        "solver_summary": solver_summary_data if solver_summary_data is not None else solver_summary(rows),
        "worker_scaling": (
            list(worker_scaling_data)
            if worker_scaling_data is not None
            else worker_scaling(rows)
        ),
        "round_analysis": (
            list(round_analysis) if round_analysis is not None else grouped_analysis(rows, "rounds")
        ),
        "cube_analysis": (
            list(cube_analysis) if cube_analysis is not None else grouped_analysis(rows, "cube_depth")
        ),
        "cnf_analysis": cnf_analysis_data if cnf_analysis_data is not None else cnf_analysis(rows),
    }
    return json.dumps(report, indent=2, sort_keys=True)
