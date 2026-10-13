"""Chart-ready dataframes for Streamlit's built-in chart components."""

from __future__ import annotations

from collections.abc import Sequence

import pandas as pd
import streamlit as st

from dashboard.metrics import BenchmarkRow, grouped_analysis, worker_scaling


@st.cache_data(show_spinner=False)
def worker_scaling_frame(rows: Sequence[BenchmarkRow]) -> pd.DataFrame:
    return pd.DataFrame(worker_scaling(rows))


@st.cache_data(show_spinner=False)
def round_runtime_frame(rows: Sequence[BenchmarkRow]) -> pd.DataFrame:
    return pd.DataFrame(grouped_analysis(rows, "rounds"))


@st.cache_data(show_spinner=False)
def cube_runtime_frame(rows: Sequence[BenchmarkRow]) -> pd.DataFrame:
    return pd.DataFrame(grouped_analysis(rows, "cube_depth"))


@st.cache_data(show_spinner=False)
def complexity_frame(rows: Sequence[BenchmarkRow]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "runtime": row["runtime"],
                "variables": row.get("variables"),
                "clauses": row.get("clauses"),
            }
            for row in rows
            if isinstance(row.get("runtime"), (int, float))
            and isinstance(row.get("variables"), int)
            and isinstance(row.get("clauses"), int)
        ]
    )
