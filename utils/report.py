"""Shared evidence, risk scoring, and report formatting."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from utils.ioc import empty_ioc_store, merge_iocs
from utils.recommendations import get_recommendations


class Finding:
    """A structured indicator discovered during analysis."""

    VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}

    def __init__(
        self,
        description: str,
        weight: int = 0,
        category: str = "general",
        *,
        severity: str | None = None,
        confidence: float = 1.0,
        evidence: str | None = None,
        analyzer: str | None = None,
        indicator: str | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        self.description = description
        self.weight = max(0, int(weight))
        self.category = category

        self.severity = (
            severity.lower()
            if severity
            else self._severity_from_weight(self.weight)
        )

        if self.severity not in self.VALID_SEVERITIES:
            self.severity = "info"

        self.confidence = max(
            0.0,
            min(1.0, float(confidence)),
        )

        self.evidence = evidence or description
        self.analyzer = analyzer or "unknown"
        self.indicator = indicator or category
        self.metadata = metadata or {}

    @staticmethod
    def _severity_from_weight(weight: int) -> str:
        if weight >= 40:
            return "critical"

        if weight >= 25:
            return "high"

        if weight >= 15:
            return "medium"

        if weight > 0:
            return "low"

        return "info"

    @property
    def confidence_percent(self) -> int:
        return round(self.confidence * 100)

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "weight": self.weight,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_percent": self.confidence_percent,
            "evidence": self.evidence,
            "analyzer": self.analyzer,
            "indicator": self.indicator,
            "metadata": self.metadata,
        }


class AnalysisReport:
    """Aggregates structured findings into an analyst-friendly report."""

    def __init__(self, target: str, analysis_type: str):
        self.target = target
        self.analysis_type = analysis_type
        self.findings: list[Finding] = []

        # Structured indicators of compromise (IOCs)
        self.indicators = empty_ioc_store()

        self.timestamp = datetime.now(timezone.utc).isoformat()

    def add_indicators(self, indicators: dict[str, Any]) -> None:
        """Merge structured IOCs into the report."""

        self.indicators = merge_iocs(
            self.indicators,
            indicators,
        )

    def add(
        self,
        description: str,
        weight: int,
        category: str = "general",
        *,
        severity: str | None = None,
        confidence: float = 1.0,
        evidence: str | None = None,
        analyzer: str | None = None,
        indicator: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Finding:
        """
        Add a structured finding.

        Existing analyzers can continue using the original:
            report.add(description, weight, category)

        New analyzers can provide richer evidence.
        """

        finding = Finding(
            description=description,
            weight=weight,
            category=category,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            analyzer=analyzer or self.analysis_type,
            indicator=indicator,
            metadata=metadata,
        )

        self.findings.append(finding)

        return finding

    @property
    def risk_score(self) -> int:
        """Return the capped aggregate risk score."""

        return min(
            100,
            sum(f.weight for f in self.findings),
        )

    @property
    def verdict(self) -> str:
        score = self.risk_score

        if score >= 70:
            return "HIGH RISK"

        if score >= 35:
            return "SUSPICIOUS"

        if score > 0:
            return "LOW RISK"

        return "NO INDICATORS FOUND"

    @property
    def confidence(self) -> float:
        """
        Estimate overall confidence from findings.

        Zero-weight informational findings do not affect the result.
        """

        weighted = [
            f
            for f in self.findings
            if f.weight > 0
        ]

        if not weighted:
            return 0.0

        total_weight = sum(
            f.weight
            for f in weighted
        )

        if total_weight == 0:
            return 0.0

        return sum(
            f.weight * f.confidence
            for f in weighted
        ) / total_weight

    @property
    def confidence_percent(self) -> int:
        return round(self.confidence * 100)

    @property
    def findings_by_category(self):
        """Group findings by category while preserving insertion order."""

        grouped = {}

        for finding in self.findings:
            grouped.setdefault(
                finding.category,
                [],
            ).append(finding)

        return grouped

    @property
    def findings_by_severity(self):
        """Group findings by severity."""

        grouped = {}

        for finding in self.findings:
            grouped.setdefault(
                finding.severity,
                [],
            ).append(finding)

        return grouped

    @property
    def high_priority_findings(self):
        """Return high and critical findings."""

        priority = {"high", "critical"}

        return [
            finding
            for finding in self.findings
            if finding.severity in priority
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert the complete report into a JSON-compatible dictionary."""

        return {
            "target": self.target,
            "analysis_type": self.analysis_type,
            "timestamp": self.timestamp,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "confidence_percent": self.confidence_percent,
            "finding_count": len(self.findings),
            "high_priority_count": len(
                self.high_priority_findings
            ),
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
            "indicators": self.indicators,
            "recommendations": get_recommendations(
                self.analysis_type,
                self.verdict,
            ),
        }

    def print_summary(self):
        """Print a readable CLI summary."""

        bar_len = 30

        filled = int(
            bar_len * self.risk_score / 100
        )

        bar = (
            "#" * filled
            + "-" * (bar_len - filled)
        )

        print("\n" + "=" * 60)

        print(
            f"  {self.analysis_type.upper()} ANALYSIS: "
            f"{self.target}"
        )

        print("=" * 60)

        print(
            f"  Risk Score : "
            f"{self.risk_score}/100  [{bar}]"
        )

        print(
            f"  Verdict    : {self.verdict}"
        )

        print(
            f"  Confidence : "
            f"{self.confidence_percent}%"
        )

        print(
            f"  Findings   : "
            f"{len(self.findings)}"
        )

        print("-" * 60)

        if not self.findings:
            print(
                "  No suspicious indicators detected."
            )

        else:
            for category, findings in (
                self.findings_by_category.items()
            ):
                print(
                    f"\n  [{category.upper()}]"
                )

                for finding in findings:
                    confidence = (
                        f"{finding.confidence_percent}%"
                    )

                    print(
                        f"    (+{finding.weight:>2}) "
                        f"[{finding.severity.upper():8}] "
                        f"[{confidence:>3}] "
                        f"{finding.description}"
                    )

        print("=" * 60 + "\n")

        recs = get_recommendations(
            self.analysis_type,
            self.verdict,
        )

        if recs["immediate"]:
            print("  WHAT TO DO")
            print("  ----------")

            for step in recs["immediate"]:
                print(f"  - {step}")

            if recs["if_already_interacted"]:
                print(
                    "\n  If you already clicked/opened/entered info:"
                )

                for step in recs[
                    "if_already_interacted"
                ]:
                    print(f"  - {step}")

            print()

    def export_json(self, path: str):
        """Export the complete report as formatted JSON."""

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as fh:
            json.dump(
                self.to_dict(),
                fh,
                indent=2,
            )

        print(
            f"Report exported to {path}"
        )