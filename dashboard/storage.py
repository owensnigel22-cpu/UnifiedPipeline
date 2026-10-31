"""SQLite persistence for imported benchmark CSV history."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Sequence
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from dashboard.metrics import BenchmarkRow


def history_count(database_path: Path) -> int:
    """Return the total number of stored benchmark rows."""
    if not database_path.exists():
        return 0
    with closing(sqlite3.connect(database_path)) as connection, connection:
        row = connection.execute("SELECT COUNT(*) FROM benchmark_runs").fetchone()
    return int(row[0]) if row is not None else 0


def import_csv_history(
    database_path: Path,
    source_name: str,
    csv_content: bytes,
    rows: Sequence[BenchmarkRow],
) -> int:
    """Import each source row once and return the number of newly stored rows."""
    database_path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(csv_content).hexdigest()
    imported_at = datetime.now(UTC).isoformat()
    with closing(sqlite3.connect(database_path)) as connection, connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS benchmark_runs (
                id INTEGER PRIMARY KEY,
                source_digest TEXT NOT NULL,
                source_name TEXT NOT NULL,
                row_number INTEGER NOT NULL,
                imported_at TEXT NOT NULL,
                data_json TEXT NOT NULL,
                UNIQUE(source_digest, row_number)
            )
            """
        )

        existing_rows = connection.execute(
            "SELECT row_number FROM benchmark_runs WHERE source_digest = ?",
            (digest,),
        ).fetchall()
        existing_numbers = {int(row[0]) for row in existing_rows}
        if len(rows) == len(existing_numbers) and len(existing_numbers) > 0:
            return 0

        pending_rows = [
            (digest, source_name, index, imported_at, json.dumps(row, sort_keys=True))
            for index, row in enumerate(rows, start=1)
            if index not in existing_numbers
        ]
        if not pending_rows:
            return 0

        connection.executemany(
            """
            INSERT OR IGNORE INTO benchmark_runs
                (source_digest, source_name, row_number, imported_at, data_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            pending_rows,
        )
        return len(pending_rows)


def load_history(database_path: Path) -> list[BenchmarkRow]:
    """Return normalized records previously imported into SQLite."""
    if not database_path.exists():
        return []
    with closing(sqlite3.connect(database_path)) as connection, connection:
        rows = connection.execute(
            "SELECT data_json FROM benchmark_runs ORDER BY id"
        ).fetchall()
    return [json.loads(row[0]) for row in rows]
