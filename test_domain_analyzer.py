
import pytest

from analyzers import domain_analyzer


class FakeReport:
    def __init__(self, target, analysis_type):
        self.target = target
        self.analysis_type = analysis_type
        self.findings = []

    def add(self, message, score, category):
        self.findings.append((message, score, category))


@pytest.fixture
def configure_analyzer(monkeypatch):
    pytest.importorskip("dns.resolver")

    monkeypatch.setattr(domain_analyzer, "AnalysisReport", FakeReport)
    monkeypatch.setattr(domain_analyzer, "HAS_WHOIS", False)
    monkeypatch.setattr(domain_analyzer, "HAS_DNS", True)
    monkeypatch.setattr(
        domain_analyzer.virustotal_analyzer,
        "is_configured",
        lambda: False,
    )

    return monkeypatch


def test_mx_and_txt_records_are_checked(configure_analyzer):
    calls = []

    def fake_resolve(domain, record_type, lifetime):
        calls.append(record_type)
        return [object()]

    configure_analyzer.setattr(
        domain_analyzer.dns.resolver,
        "resolve",
        fake_resolve,
    )

    report = domain_analyzer.analyze_domain("example.test")

    assert calls == ["MX", "TXT"]
    assert any("MX record(s)" in item[0] for item in report.findings)
    assert any("TXT record(s)" in item[0] for item in report.findings)


def test_txt_is_checked_when_mx_lookup_fails(configure_analyzer):
    calls = []

    def fake_resolve(domain, record_type, lifetime):
        calls.append(record_type)

        if record_type == "MX":
            raise RuntimeError("Simulated MX lookup failure")

        return [object()]

    configure_analyzer.setattr(
        domain_analyzer.dns.resolver,
        "resolve",
        fake_resolve,
    )

    report = domain_analyzer.analyze_domain("example.test")

    assert calls == ["MX", "TXT"]
    assert any("MX lookup failed" in item[0] for item in report.findings)
    assert any("TXT record(s)" in item[0] for item in report.findings)


def test_report_is_returned_when_txt_lookup_fails(configure_analyzer):
    def fake_resolve(domain, record_type, lifetime):
        if record_type == "TXT":
            raise RuntimeError("Simulated TXT lookup failure")

        return [object()]

    configure_analyzer.setattr(
        domain_analyzer.dns.resolver,
        "resolve",
        fake_resolve,
    )

    report = domain_analyzer.analyze_domain("example.test")

    assert isinstance(report, FakeReport)
    assert any("TXT lookup failed" in item[0] for item in report.findings)


def test_empty_domain_returns_report(configure_analyzer):
    report = domain_analyzer.analyze_domain("")

    assert isinstance(report, FakeReport)
    assert report.target == ""
    assert any("No domain was provided" in item[0] for item in report.findings)
