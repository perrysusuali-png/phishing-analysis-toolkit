
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
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10,
    )

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def init_database() -> None:
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
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    short_id = uuid.uuid4().hex[:6].upper()
    return f"CASE-{timestamp}-{short_id}"


def create_case(
    title: str,
    *,
    priority: str = "Medium",
) -> int:
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
                json.dumps(report_data, ensure_ascii=False),
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
            (_utc_now(), case_id),
        )

    return case_id, analysis_id


def _save_iocs(
    connection: sqlite3.Connection,
    analysis_id: int,
    indicators: dict[str, Any],
) -> None:
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
                INSERT INTO iocs (analysis_id, ioc_type, value)
                VALUES (?, ?, ?)
                """,
                (analysis_id, ioc_type, value),
            )

    hashes = indicators.get("file_hashes", {}) or {}

    for hash_type in ("md5", "sha1", "sha256"):
        for value in hashes.get(hash_type, []):
            connection.execute(
                """
                INSERT INTO iocs (analysis_id, ioc_type, value)
                VALUES (?, ?, ?)
                """,
                (analysis_id, hash_type, value),
            )


def get_analysis_by_report_id(
    report_id: str,
) -> dict[str, Any] | None:
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
    limit = max(1, min(int(limit), 100))

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                a.id,
                a.case_id,
                a.report_id,
                a.analysis_type,
                a.target,
                a.risk_score,
                a.verdict,
                a.confidence,
                a.timestamp,
                COUNT(f.id) AS finding_count
            FROM analyses AS a
            LEFT JOIN findings AS f
                ON f.analysis_id = a.id
            GROUP BY a.id
            ORDER BY a.timestamp DESC, a.id DESC
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
            "confidence_percent": round(row["confidence"] * 100),
            "timestamp": row["timestamp"],
            "finding_count": row["finding_count"],
        }
        for row in rows
    ]


def get_database_stats() -> dict[str, int]:
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


def get_dashboard_stats() -> dict[str, int]:
    with get_connection() as connection:
        summary = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN risk_score >= 70 THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN risk_score >= 35 AND risk_score < 70 THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN LOWER(analysis_type) = 'email' THEN 1 ELSE 0 END) AS email,
                SUM(CASE WHEN LOWER(analysis_type) = 'url' THEN 1 ELSE 0 END) AS url,
                SUM(CASE WHEN LOWER(analysis_type) = 'domain' THEN 1 ELSE 0 END) AS domain,
                SUM(CASE WHEN LOWER(analysis_type) = 'attachment' THEN 1 ELSE 0 END) AS attachment
            FROM analyses
            """
        ).fetchone()

        ioc_rows = connection.execute(
            """
            SELECT ioc_type, COUNT(*) AS total
            FROM iocs
            GROUP BY ioc_type
            """
        ).fetchall()

        case_count = connection.execute(
            "SELECT COUNT(*) FROM cases"
        ).fetchone()[0]

    result = {
        key: int(summary[key] or 0)
        for key in (
            "total",
            "high",
            "suspicious",
            "email",
            "url",
            "domain",
            "attachment",
        )
    }

    result["cases"] = int(case_count)
    result["ioc_urls"] = 0
    result["ioc_domains"] = 0
    result["ioc_ips"] = 0
    result["ioc_emails"] = 0
    result["ioc_hashes"] = 0

    ioc_mapping = {
        "url": "ioc_urls",
        "domain": "ioc_domains",
        "ip": "ioc_ips",
        "email": "ioc_emails",
        "md5": "ioc_hashes",
        "sha1": "ioc_hashes",
        "sha256": "ioc_hashes",
    }

    for row in ioc_rows:
        key = ioc_mapping.get(row["ioc_type"])
        if key:
            result[key] += int(row["total"])

    result["iocs"] = sum(
        result[key]
        for key in (
            "ioc_urls",
            "ioc_domains",
            "ioc_ips",
            "ioc_emails",
            "ioc_hashes",
        )
    )

    denominator = max(result["total"], 1)

    for analysis_type in ("email", "url", "domain", "attachment"):
        result[f"percent_{analysis_type}"] = round(
            result[analysis_type] / denominator * 100
        )

    return result

def list_cases(limit: int = 50) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 100))

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                c.id,
                c.case_number,
                c.title,
                c.status,
                c.priority,
                c.created_at,
                c.updated_at,
                c.analyst_notes,
                COUNT(a.id) AS analysis_count
            FROM cases AS c
            LEFT JOIN analyses AS a ON a.case_id = c.id
            GROUP BY c.id
            ORDER BY c.updated_at DESC, c.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_case_by_id(case_id: int) -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT
                id,
                case_number,
                title,
                status,
                priority,
                created_at,
                updated_at,
                analyst_notes
            FROM cases
            WHERE id = ?
            """,
            (case_id,),
        ).fetchone()

        if row is None:
            return None

        case = dict(row)

        analyses = connection.execute(
            """
            SELECT
                id,
                report_id,
                analysis_type,
                target,
                risk_score,
                verdict,
                confidence,
                timestamp
            FROM analyses
            WHERE case_id = ?
            ORDER BY timestamp DESC, id DESC
            """,
            (case_id,),
        ).fetchall()

    case["analyses"] = [dict(row) for row in analyses]

    return case


def update_case(
    case_id: int,
    *,
    status: str | None = None,
    priority: str | None = None,
    analyst_notes: str | None = None,
) -> dict[str, Any] | None:
    allowed_statuses = {
        "Open",
        "In Progress",
        "Contained",
        "Resolved",
        "Closed",
    }

    allowed_priorities = {
        "Low",
        "Medium",
        "High",
        "Critical",
    }

    if status is not None and status not in allowed_statuses:
        raise ValueError("Invalid case status.")

    if priority is not None and priority not in allowed_priorities:
        raise ValueError("Invalid case priority.")

    if analyst_notes is not None and len(analyst_notes) > 20000:
        raise ValueError("Investigation notes exceed 20000 characters.")

    updates = []
    values = []

    if status is not None:
        updates.append("status = ?")
        values.append(status)

    if priority is not None:
        updates.append("priority = ?")
        values.append(priority)

    if analyst_notes is not None:
        updates.append("analyst_notes = ?")
        values.append(analyst_notes)

    if not updates:
        return get_case_by_id(case_id)

    updates.append("updated_at = ?")
    values.append(_utc_now())
    values.append(case_id)

    with get_connection() as connection:
        cursor = connection.execute(
            f"""
            UPDATE cases
            SET {", ".join(updates)}
            WHERE id = ?
            """,
            values,
        )

        if cursor.rowcount == 0:
            return None

    return get_case_by_id(case_id)
