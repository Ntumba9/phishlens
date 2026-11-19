"""Local case persistence in SQLite.

Cases live in one SQLite file on this machine. There is deliberately no
authentication or multi-user access control: the API binds to localhost by
default and the database file inherits the operating system's file
permissions. If the app is ever exposed beyond localhost, every stored
email in it is reachable by whoever can reach the port.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone

from .scoring import VERDICTS

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    sender TEXT NOT NULL DEFAULT '',
    verdict TEXT NOT NULL,
    score INTEGER NOT NULL,
    report_json TEXT NOT NULL,
    analyst_verdict TEXT,
    analyst_reason TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(id),
    created_at TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at DESC);
"""

DEFAULT_PATH = os.path.expanduser("~/.phishlens/cases.db")


class CaseStore:
    """Small, explicit store. One connection per call: safe across threads."""

    def __init__(self, path: str = DEFAULT_PATH) -> None:
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def save_case(self, report: dict) -> str:
        """Persist a report dict; returns the new case ID."""
        case_id = uuid.uuid4().hex[:12]
        created_at = report.get("created_at") or datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )
        report = {**report, "case_id": case_id, "created_at": created_at}
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO cases (id, created_at, subject, sender, verdict, score, report_json)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    case_id,
                    created_at,
                    report.get("subject", ""),
                    report.get("from", ""),
                    report.get("verdict", ""),
                    report.get("score", 0),
                    json.dumps(report),
                ),
            )
        return case_id

    def list_cases(
        self, search: str = "", verdict: str = "", limit: int = 200
    ) -> list[dict]:
        """Case summaries, newest first, optionally filtered."""
        clauses = []
        params: list = []
        if search:
            clauses.append("(subject LIKE ? OR sender LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like])
        if verdict in VERDICTS:
            clauses.append("verdict = ?")
            params.append(verdict)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT id, created_at, subject, sender, verdict, score,"
                f" analyst_verdict FROM cases {where}"
                " ORDER BY created_at DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_case(self, case_id: str) -> dict | None:
        """Full case: summary fields, the stored report, notes, override."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM cases WHERE id = ?", (case_id,)
            ).fetchone()
            if row is None:
                return None
            notes = conn.execute(
                "SELECT created_at, body FROM notes WHERE case_id = ?"
                " ORDER BY created_at",
                (case_id,),
            ).fetchall()
        case = dict(row)
        case["report"] = json.loads(case.pop("report_json"))
        case["notes"] = [dict(note) for note in notes]
        return case

    def set_verdict(self, case_id: str, verdict: str, reason: str = "") -> bool:
        """Record the analyst's call. Returns False when the case is missing."""
        if verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {VERDICTS}")
        with self._connect() as conn:
            changed = conn.execute(
                "UPDATE cases SET analyst_verdict = ?, analyst_reason = ? WHERE id = ?",
                (verdict, reason, case_id),
            ).rowcount
            if changed and reason:
                now = datetime.now(timezone.utc).isoformat(timespec="seconds")
                conn.execute(
                    "INSERT INTO notes (case_id, created_at, body) VALUES (?, ?, ?)",
                    (case_id, now, f"Verdict set to {verdict}: {reason}"),
                )
        return bool(changed)

    def add_note(self, case_id: str, body: str) -> bool:
        """Attach a free-text analyst note. Returns False when case missing."""
        with self._connect() as conn:
            exists = conn.execute(
                "SELECT 1 FROM cases WHERE id = ?", (case_id,)
            ).fetchone()
            if not exists:
                return False
            conn.execute(
                "INSERT INTO notes (case_id, created_at, body) VALUES (?, ?, ?)",
                (case_id, datetime.now(timezone.utc).isoformat(timespec="seconds"), body),
            )
        return True
