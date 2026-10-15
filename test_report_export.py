import json

from app import app, _REPORT_CACHE, _render_result
import utils.database as database
from utils.report import AnalysisReport


def test_json_export_from_cache_and_database(isolated_database):
    report = AnalysisReport(
        target="export-test.example",
        analysis_type="domain",
    )
    report.add("Synthetic export test finding", 30, "Test")

    with app.test_request_context("/"):
        _render_result(report)

    report_id = next(reversed(_REPORT_CACHE))

    stored = database.get_analysis_by_report_id(report_id)
    assert stored is not None

    with app.test_client() as client:
        cached_response = client.get(f"/report/{report_id}/json")

    assert cached_response.status_code == 200
    cached_data = cached_response.get_json()
    assert cached_data is not None

    _REPORT_CACHE.clear()

    with app.test_client() as client:
        database_response = client.get(f"/report/{report_id}/json")

    assert database_response.status_code == 200
    database_data = database_response.get_json()
    assert database_data is not None


def test_report_exports_to_json_file(tmp_path):
    report = AnalysisReport(
        target="file-export-test.example",
        analysis_type="domain",
    )
    report.add("Synthetic file export finding", 20, "Test")

    output_path = tmp_path / "report.json"
    report.export_json(str(output_path))

    exported = json.loads(output_path.read_text(encoding="utf-8"))

    assert exported["target"] == "file-export-test.example"
    assert exported["analysis_type"] == "domain"
    assert exported["findings"]
