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

# Triage disposition for a case. "new" until an analyst picks it up,
# "in_review" while being worked, "closed" when handled. Distinct from the
# verdict: the verdict is what the email is, the status is where the work is.
STATUSES = ("new", "in_review", "closed")

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
    tags TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'new'
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
            # Databases created before statuses existed gain the column.
            cols = {row[1] for row in conn.execute("PRAGMA table_info(cases)")}
            if "status" not in cols:
                conn.execute("ALTER TABLE cases ADD COLUMN status TEXT NOT NULL DEFAULT 'new'")

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
        self, search: str = "", verdict: str = "", status: str = "", limit: int = 200
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
        if status in STATUSES:
            clauses.append("status = ?")
            params.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT id, created_at, subject, sender, verdict, score,"
                f" analyst_verdict, status FROM cases {where}"
                " ORDER BY created_at DESC LIMIT ?",
                (*params, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def set_status(self, case_id: str, status: str) -> bool:
        """Move a case through the triage queue. False when case missing."""
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        with self._connect() as conn:
            changed = conn.execute(
                "UPDATE cases SET status = ? WHERE id = ?", (status, case_id)
            ).rowcount
        return bool(changed)

    @staticmethod
    def _pivots(report: dict) -> dict[str, set[str]]:
        """Indicators a case can be grouped on: sender/URL domains, sender
        addresses and attachment hashes, exactly as stored in the report."""
        iocs = report.get("iocs", {})
        return {
            "domain": set(iocs.get("domains", [])),
            "address": set(iocs.get("addresses", [])),
            "sha256": {
                entry.get("sha256", "")
                for entry in iocs.get("file_hashes", [])
                if entry.get("sha256")
            },
        }

    def related_cases(self, case_id: str, limit: int = 20) -> list[dict] | None:
        """Other cases sharing at least one indicator with this one.

        Shared indicators mean the emails are worth reviewing together;
        they do not by themselves prove a common sender or campaign.
        """
        case = self.get_case(case_id)
        if case is None:
            return None
        mine = self._pivots(case["report"])
        related: list[dict] = []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, created_at, subject, sender, verdict, score, status,"
                " report_json FROM cases WHERE id != ? ORDER BY created_at DESC",
                (case_id,),
            ).fetchall()
        for row in rows:
            theirs = self._pivots(json.loads(row["report_json"]))
            shared = [
                f"{kind}:{value}"
                for kind in ("domain", "address", "sha256")
                for value in sorted(mine[kind] & theirs[kind])
            ]
            if shared:
                entry = dict(row)
                entry.pop("report_json")
                entry["shared"] = shared
                related.append(entry)
            if len(related) >= limit:
                break
        return related

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
