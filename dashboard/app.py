"""Streamlit application for local SAT benchmark results."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import streamlit as st

from dashboard.charts import (
    complexity_frame,
    cube_runtime_frame,
    round_runtime_frame,
    worker_scaling_frame,
)
from dashboard.exporters import report_json
from dashboard.metrics import (
    BenchmarkDataError,
    BenchmarkRow,
    cnf_analysis,
    grouped_analysis,
    parse_benchmark_csv,
    solver_summary,
    worker_scaling,
)
from dashboard.storage import history_count, import_csv_history, load_history

_ROOT = Path(__file__).resolve().parents[1]
_DATABASE = _ROOT / "benchmark_reports" / "benchmark_history.db"
_CSV_CANDIDATES = (
    _ROOT / "benchmark_reports" / "scaling_results.csv",
    _ROOT / "scaling_results.csv",
)


@st.cache_data(show_spinner=False)
def _parse_csv_cached(source_name: str, csv_text: str) -> list[BenchmarkRow]:
    return parse_benchmark_csv(csv_text)


def _load_selected_csv() -> tuple[str, str] | None:
    upload = st.file_uploader("Upload a benchmark CSV", type=("csv",))
    if upload is not None:
        try:
            return upload.name, upload.getvalue().decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            st.error(f"Uploaded file is not UTF-8 CSV: {exc}")
            return None

    existing = [path for path in _CSV_CANDIDATES if path.is_file()]
    if not existing:
        st.info(
            "No scaling CSV found. Run the SAT throughput benchmark or upload a CSV to begin."
        )
        return None

    path = existing[0]
    try:
        return path.name, path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        st.error(f"Could not read benchmark CSV: {exc}")
        return None


def main() -> None:
    st.set_page_config(page_title="KeyLab Benchmark Dashboard", layout="wide")
    st.title("KeyLab SAT Benchmark Dashboard")
    st.caption(
        "Local measurements only. The dashboard reports fields present in imported CSVs; "
        "it does not infer solver propagation strength or cryptanalytic success."
    )
    selected = _load_selected_csv()
    if selected is None:
        return
    source_name, csv_text = selected
    try:
        rows = _parse_csv_cached(source_name, csv_text)
    except BenchmarkDataError as exc:
        st.error(f"Invalid benchmark CSV: {exc}")
        return
    try:
        new_rows = import_csv_history(_DATABASE, source_name, csv_text.encode("utf-8"), rows)
    except (OSError, sqlite3.Error) as exc:
        st.error(f"Could not persist benchmark history: {exc}")
        return
    try:
        total_history_rows = history_count(_DATABASE)
    except (OSError, sqlite3.Error, ValueError) as exc:
        st.error(f"Could not count benchmark history: {exc}")
        return
    st.caption(f"Imported {new_rows} new rows; {total_history_rows} total rows in local history.")
    view = st.radio("Dataset", ("Selected CSV", "Imported history"), horizontal=True)

    if view == "Imported history":
        try:
            active_rows: list[BenchmarkRow] = load_history(_DATABASE)
        except (OSError, sqlite3.Error, ValueError) as exc:
            st.error(f"Could not load benchmark history: {exc}")
            return
    else:
        active_rows = rows

    summary = solver_summary(active_rows)
    scaling_rows = worker_scaling(active_rows)
    round_rows = grouped_analysis(active_rows, "rounds")
    cube_rows = grouped_analysis(active_rows, "cube_depth")
    metric_columns = st.columns(5)
    metric_columns[0].metric("Runs", summary["runs"])
    metric_columns[1].metric("SAT", summary["sat_solves"])
    metric_columns[2].metric("UNSAT", summary["unsat_solves"])
    metric_columns[3].metric("Unknown", summary["unknown_solves"])
    metric_columns[4].metric("Mean runtime", f"{summary['average_runtime']:.3f} s")
    st.metric("Median runtime", f"{summary['median_runtime']:.3f} s")
    st.metric("Unknown outcome rate", f"{summary['unknown_rate_percent']:.1f}%")

    scaling = worker_scaling_frame(active_rows)
    if not scaling.empty:
        st.subheader("Worker scaling")
        st.dataframe(scaling, hide_index=True, use_container_width=True)
        st.line_chart(scaling, x="workers", y="throughput")
        st.line_chart(scaling, x="workers", y="efficiency_percent")
    else:
        st.info("Worker scaling requires worker and throughput/cube-count measurements.")

    complexity = complexity_frame(active_rows)
    st.subheader("CNF complexity")
    if not complexity.empty:
        st.scatter_chart(complexity, x="variables", y="runtime")
        st.scatter_chart(complexity, x="clauses", y="runtime")
    details = cnf_analysis(active_rows)
    st.json(details)
    if details["mean_clause_width"] is None or details["mean_unit_clauses"] is None:
        st.info(
            "Clause width and unit-clause counts are not present in this CSV. "
            "Run `keylab ... --diagnostics-output sat_report.json` for formula structure metrics."
        )

    rounds = round_runtime_frame(active_rows)
    if not rounds.empty:
        st.subheader("Round/step analysis")
        st.dataframe(rounds, hide_index=True, use_container_width=True)
        st.bar_chart(rounds, x="rounds", y="average_runtime")
    cubes = cube_runtime_frame(active_rows)
    if not cubes.empty:
        st.subheader("Cube-depth analysis")
        st.dataframe(cubes, hide_index=True, use_container_width=True)
        st.bar_chart(cubes, x="cube_depth", y="average_runtime")
    st.download_button(
        "Download dashboard report JSON",
        data=report_json(
            active_rows,
            solver_summary_data=summary,
            worker_scaling_data=scaling_rows,
            round_analysis=round_rows,
            cube_analysis=cube_rows,
            cnf_analysis_data=details,
        ),
        file_name="benchmark_report.json",
        mime="application/json",
    )
    st.dataframe(active_rows, hide_index=True, use_container_width=True)


if __name__ == "__main__":
    main()
