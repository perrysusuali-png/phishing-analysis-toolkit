"""
SQLite persistence for the Phishing Analysis Toolkit.

The database stores cases and complete analysis reports locally.
No external database service is required.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = DATA_DIR / "phishing_toolkit.db"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_connection() -> sqlite3.Connection:
    """Return a configured SQLite connection."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10,
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_database() -> None:
    """Create database tables if they do not already exist."""

    with get_connection() as connection:

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                priority TEXT NOT NULL DEFAULT 'Medium',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                analyst_notes TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                report_id TEXT NOT NULL UNIQUE,
                analysis_type TEXT NOT NULL,
                target TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                timestamp TEXT NOT NULL,
                report_json TEXT NOT NULL,

                FOREIGN KEY (case_id)
                    REFERENCES cases(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                weight INTEGER NOT NULL,
                confidence REAL NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                analyzer TEXT NOT NULL,
                indicator TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',

                FOREIGN KEY (analysis_id)
                    REFERENCES analyses(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,

                FOREIGN KEY (analysis_id)
                    REFERENCES analyses(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_cases_updated
                ON cases(updated_at);

            CREATE INDEX IF NOT EXISTS idx_analyses_timestamp
                ON analyses(timestamp);

            CREATE INDEX IF NOT EXISTS idx_findings_analysis
                ON findings(analysis_id);

            CREATE INDEX IF NOT EXISTS idx_iocs_analysis
                ON iocs(analysis_id);
            """
        )


def generate_case_number() -> str:
    """Generate a human-readable case number."""

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    short_id = uuid.uuid4().hex[:6].upper()

    return f"CASE-{timestamp}-{short_id}"


def create_case(
    title: str,
    *,
    priority: str = "Medium",
) -> int:
    """Create a new investigation case and return its database ID."""

    now = _utc_now()
    case_number = generate_case_number()

    with get_connection() as connection:

        cursor = connection.execute(
            """
            INSERT INTO cases (
                case_number,
                title,
                status,
                priority,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                case_number,
                title,
                "Open",
                priority,
                now,
                now,
            ),
        )

        return int(cursor.lastrowid)


def save_analysis(
    report: Any,
    *,
    case_id: int | None = None,
    report_id: str | None = None,
) -> tuple[int, int]:
    """
    Save an AnalysisReport.

    Returns:
        (case_id, analysis_id)
    """

    if report_id is None:
        report_id = uuid.uuid4().hex[:12]

    if case_id is None:
        case_id = create_case(
            title=f"{report.analysis_type} investigation: {report.target}"
        )

    report_data = report.to_dict()

    with get_connection() as connection:

        cursor = connection.execute(
            """
            INSERT INTO analyses (
                case_id,
                report_id,
                analysis_type,
                target,
                risk_score,
                verdict,
                confidence,
                timestamp,
                report_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                report_id,
                report.analysis_type,
                report.target,
                report.risk_score,
                report.verdict,
                report.confidence,
                report.timestamp,
                json.dumps(
                    report_data,
                    ensure_ascii=False,
                ),
            ),
        )

        analysis_id = int(cursor.lastrowid)

        for finding in report.findings:

            connection.execute(
                """
                INSERT INTO findings (
                    analysis_id,
                    category,
                    severity,
                    weight,
                    confidence,
                    description,
                    evidence,
                    analyzer,
                    indicator,
                    metadata_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    finding.category,
                    finding.severity,
                    finding.weight,
                    finding.confidence,
                    finding.description,
                    finding.evidence,
                    finding.analyzer,
                    finding.indicator,
                    json.dumps(
                        finding.metadata,
                        ensure_ascii=False,
                    ),
                ),
            )

        _save_iocs(
            connection,
            analysis_id,
            report.indicators,
        )

        connection.execute(
            """
            UPDATE cases
            SET updated_at = ?
            WHERE id = ?
            """,
            (
                _utc_now(),
                case_id,
            ),
        )

    return case_id, analysis_id


def _save_iocs(
    connection: sqlite3.Connection,
    analysis_id: int,
    indicators: dict[str, Any],
) -> None:
    """Store normalized IOC values."""

    simple_types = {
        "url": indicators.get("urls", []),
        "domain": indicators.get("domains", []),
        "ip": indicators.get("ip_addresses", []),
        "email": indicators.get("emails", []),
    }

    for ioc_type, values in simple_types.items():

        for value in values:

            connection.execute(
                """
                INSERT INTO iocs (
                    analysis_id,
                    ioc_type,
                    value
                )
                VALUES (?, ?, ?)
                """,
                (
                    analysis_id,
                    ioc_type,
                    value,
                ),
            )

    hashes = indicators.get(
        "file_hashes",
        {},
    ) or {}

    for hash_type in (
        "md5",
        "sha1",
        "sha256",
    ):

        for value in hashes.get(hash_type, []):

            connection.execute(
                """
                INSERT INTO iocs (
                    analysis_id,
                    ioc_type,
                    value
                )
                VALUES (?, ?, ?)
                """,
                (
                    analysis_id,
                    hash_type,
                    value,
                ),
            )


def get_analysis_by_report_id(
    report_id: str,
) -> dict[str, Any] | None:
    """Return a saved report by its report ID."""

    with get_connection() as connection:

        row = connection.execute(
            """
            SELECT
                id,
                case_id,
                report_id,
                analysis_type,
                target,
                risk_score,
                verdict,
                confidence,
                timestamp,
                report_json
            FROM analyses
            WHERE report_id = ?
            """,
            (report_id,),
        ).fetchone()

    if row is None:
        return None

    return {
        "id": row["id"],
        "case_id": row["case_id"],
        "report_id": row["report_id"],
        "analysis_type": row["analysis_type"],
        "target": row["target"],
        "risk_score": row["risk_score"],
        "verdict": row["verdict"],
        "confidence": row["confidence"],
        "timestamp": row["timestamp"],
        "report": json.loads(row["report_json"]),
    }


def list_recent_analyses(
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Return recent persisted analyses."""

    limit = max(1, min(int(limit), 100))

    with get_connection() as connection:

        rows = connection.execute(
            """
            SELECT
                id,
                case_id,
                report_id,
                analysis_type,
                target,
                risk_score,
                verdict,
                confidence,
                timestamp
            FROM analyses
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        {
            "id": row["id"],
            "case_id": row["case_id"],
            "report_id": row["report_id"],
            "analysis_type": row["analysis_type"],
            "target": row["target"],
            "risk_score": row["risk_score"],
            "verdict": row["verdict"],
            "confidence_percent": round(
                row["confidence"] * 100
            ),
            "timestamp": row["timestamp"],
        }
        for row in rows
    ]


def get_database_stats() -> dict[str, int]:
    """Return basic persistent database statistics."""

    with get_connection() as connection:

        cases = connection.execute(
            "SELECT COUNT(*) FROM cases"
        ).fetchone()[0]

        analyses = connection.execute(
            "SELECT COUNT(*) FROM analyses"
        ).fetchone()[0]

        findings = connection.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0]

        iocs = connection.execute(
            "SELECT COUNT(*) FROM iocs"
        ).fetchone()[0]

    return {
        "cases": int(cases),
        "analyses": int(analyses),
        "findings": int(findings),
        "iocs": int(iocs),
    }