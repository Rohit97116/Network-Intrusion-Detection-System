from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


class HistoryStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS detection_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    source_filename TEXT NOT NULL,
                    total_records INTEGER NOT NULL,
                    normal_records INTEGER NOT NULL,
                    attack_records INTEGER NOT NULL,
                    top_attack TEXT NOT NULL,
                    avg_confidence REAL NOT NULL,
                    attack_distribution TEXT NOT NULL,
                    export_path TEXT
                )
                """
            )
            connection.commit()

    def create_run(
        self,
        *,
        created_at: str,
        source_filename: str,
        total_records: int,
        normal_records: int,
        attack_records: int,
        top_attack: str,
        avg_confidence: float,
        attack_distribution: dict[str, int],
    ) -> int:
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO detection_runs
                (
                    created_at,
                    source_filename,
                    total_records,
                    normal_records,
                    attack_records,
                    top_attack,
                    avg_confidence,
                    attack_distribution
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    source_filename,
                    total_records,
                    normal_records,
                    attack_records,
                    top_attack,
                    avg_confidence,
                    json.dumps(attack_distribution),
                ),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def update_export_path(self, run_id: int, export_path: str) -> None:
        with self._lock, self._connect() as connection:
            connection.execute(
                "UPDATE detection_runs SET export_path = ? WHERE id = ?",
                (export_path, run_id),
            )
            connection.commit()

    def list_runs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM detection_runs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM detection_runs WHERE id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        attack_distribution = row["attack_distribution"] or "{}"
        return {
            "id": int(row["id"]),
            "created_at": row["created_at"],
            "source_filename": row["source_filename"],
            "total_records": int(row["total_records"]),
            "normal_records": int(row["normal_records"]),
            "attack_records": int(row["attack_records"]),
            "top_attack": row["top_attack"],
            "avg_confidence": float(row["avg_confidence"]),
            "attack_distribution": json.loads(attack_distribution),
            "export_path": row["export_path"],
        }
