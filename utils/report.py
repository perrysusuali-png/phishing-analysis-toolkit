"""Risk scoring and report formatting shared by all analyzers."""

import json
from datetime import datetime, timezone

from utils.recommendations import get_recommendations


class Finding:
    """A single risk indicator discovered during analysis."""

    def __init__(self, description, weight, category="general"):
        self.description = description
        self.weight = weight  # points added to the risk score (0-100 scale)
        self.category = category

    def to_dict(self):
        return {
            "description": self.description,
            "weight": self.weight,
            "category": self.category,
        }


class AnalysisReport:
    """Aggregates findings into a risk score and a printable/exportable report."""

    def __init__(self, target, analysis_type):
        self.target = target
        self.analysis_type = analysis_type
        self.findings = []
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def add(self, description, weight, category="general"):
        self.findings.append(Finding(description, weight, category))

    @property
    def risk_score(self):
        return min(100, sum(f.weight for f in self.findings))

    @property
    def verdict(self):
        score = self.risk_score
        if score >= 70:
            return "HIGH RISK"
        if score >= 35:
            return "SUSPICIOUS"
        if score > 0:
            return "LOW RISK"
        return "NO INDICATORS FOUND"

    def to_dict(self):
        return {
            "target": self.target,
            "analysis_type": self.analysis_type,
            "timestamp": self.timestamp,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": get_recommendations(self.analysis_type, self.verdict),
        }

    @property
    def findings_by_category(self):
        """Groups findings by category, preserving first-seen order. Used by the web dashboard."""
        grouped = {}
        for f in self.findings:
            grouped.setdefault(f.category, []).append(f)
        return grouped

    def print_summary(self):
        bar_len = 30
        filled = int(bar_len * self.risk_score / 100)
        bar = "#" * filled + "-" * (bar_len - filled)

        print("\n" + "=" * 60)
        print(f"  {self.analysis_type.upper()} ANALYSIS: {self.target}")
        print("=" * 60)
        print(f"  Risk Score : {self.risk_score}/100  [{bar}]")
        print(f"  Verdict    : {self.verdict}")
        print("-" * 60)

        if not self.findings:
            print("  No suspicious indicators detected.")
        else:
            by_category = {}
            for f in self.findings:
                by_category.setdefault(f.category, []).append(f)

            for category, findings in by_category.items():
                print(f"\n  [{category.upper()}]")
                for f in findings:
                    print(f"    (+{f.weight:>2}) {f.description}")

        print("=" * 60 + "\n")

        recs = get_recommendations(self.analysis_type, self.verdict)
        if recs["immediate"]:
            print("  WHAT TO DO")
            print("  ----------")
            for step in recs["immediate"]:
                print(f"  - {step}")
            if recs["if_already_interacted"]:
                print("\n  If you already clicked/opened/entered info:")
                for step in recs["if_already_interacted"]:
                    print(f"  - {step}")
            print()

    def export_json(self, path):
        with open(path, "w") as fh:
            json.dump(self.to_dict(), fh, indent=2)
        print(f"Report exported to {path}")
