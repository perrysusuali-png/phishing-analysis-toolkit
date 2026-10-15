from app import app, _REPORT_CACHE, _render_result
import utils.database as database
from utils.report import AnalysisReport


def test_report_is_rendered_and_persisted(isolated_database):
    report = AnalysisReport(
        target="local-test.example",
        analysis_type="domain",
    )
    report.add("Synthetic test finding", 25, "Test")

    with app.test_request_context("/"):
        rendered = _render_result(report)

    assert isinstance(rendered, str)
    assert _REPORT_CACHE

    report_id = next(reversed(_REPORT_CACHE))
    stored = database.get_analysis_by_report_id(report_id)

    assert stored is not None
    assert stored["report_id"] == report_id
    assert stored["analysis_type"] == "domain"
    assert stored["target"] == "local-test.example"
