
import pytest

from utils.report import AnalysisReport, Finding


@pytest.mark.parametrize(
    ("weights", "expected"),
    [
        ([], 0),
        ([0], 0),
        ([10, 15], 25),
        ([35, 35], 70),
        ([80, 50], 100),
    ],
)
def test_risk_score_aggregation(weights, expected):
    report = AnalysisReport("example.test", "Domain")

    for weight in weights:
        report.add(f"Finding {weight}", weight)

    assert report.risk_score == expected


@pytest.mark.parametrize(
    ("score", "expected_verdict"),
    [
        (0, "NO INDICATORS FOUND"),
        (1, "LOW RISK"),
        (34, "LOW RISK"),
        (35, "SUSPICIOUS"),
        (69, "SUSPICIOUS"),
        (70, "HIGH RISK"),
        (100, "HIGH RISK"),
    ],
)
def test_verdict_thresholds(score, expected_verdict):
    report = AnalysisReport("example.test", "Domain")

    if score:
        report.add("Synthetic finding", score)

    assert report.verdict == expected_verdict


@pytest.mark.parametrize(
    ("weight", "expected_severity"),
    [
        (0, "info"),
        (1, "low"),
        (14, "low"),
        (15, "medium"),
        (24, "medium"),
        (25, "high"),
        (39, "high"),
        (40, "critical"),
    ],
)
def test_default_severity_matches_weight(weight, expected_severity):
    finding = Finding("Synthetic finding", weight)

    assert finding.severity == expected_severity


def test_negative_weight_is_clamped_to_zero():
    finding = Finding("Synthetic finding", -10)

    assert finding.weight == 0
    assert finding.severity == "info"


def test_invalid_severity_falls_back_to_info():
    finding = Finding(
        "Synthetic finding",
        50,
        severity="unknown",
    )

    assert finding.severity == "info"


def test_confidence_is_weighted_by_finding_weight():
    report = AnalysisReport("example.test", "Domain")
    report.add("Finding A", 10, confidence=1.0)
    report.add("Finding B", 30, confidence=0.5)

    assert report.confidence == pytest.approx(0.625)
    assert report.confidence_percent == 62


def test_zero_weight_findings_do_not_affect_confidence():
    report = AnalysisReport("example.test", "Domain")
    report.add("Informational finding", 0, confidence=1.0)
    report.add("Evidence finding", 20, confidence=0.5)

    assert report.confidence == pytest.approx(0.5)


def test_explicit_severity_can_differ_from_weight_default():
    finding = Finding(
        "Synthetic finding",
        5,
        severity="high",
    )

    assert finding.weight == 5
    assert finding.severity == "high"
