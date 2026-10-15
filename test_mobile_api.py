
import app as app_module
from utils.report import AnalysisReport


def client():
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


def test_mobile_url_api_rejects_missing_url(monkeypatch):
    monkeypatch.setattr(app_module, "APP_ENV", "development")
    monkeypatch.setenv("REQUIRE_AUTH", "false")

    response = client().post(
        "/api/analyze/url",
        json={},
    )

    assert response.status_code == 400
    assert response.get_json()["status"] == "error"


def test_mobile_url_api_rejects_non_json_body(monkeypatch):
    monkeypatch.setattr(app_module, "APP_ENV", "development")
    monkeypatch.setenv("REQUIRE_AUTH", "false")

    response = client().post(
        "/api/analyze/url",
        data="not json",
        content_type="text/plain",
    )

    assert response.status_code == 400


def test_mobile_url_api_returns_structured_report(monkeypatch):
    monkeypatch.setattr(app_module, "APP_ENV", "development")
    monkeypatch.setenv("REQUIRE_AUTH", "false")

    report = AnalysisReport(
        "https://example.com",
        "url",
    )
    report.add(
        "Test finding",
        15,
        "test",
    )

    monkeypatch.setattr(
        app_module,
        "analyze_url",
        lambda target: report,
    )
    monkeypatch.setattr(
        app_module,
        "save_analysis",
        lambda report, report_id=None: None,
    )

    response = client().post(
        "/api/analyze/url",
        json={"url": "https://example.com"},
    )

    body = response.get_json()

    assert response.status_code == 200
    assert body["status"] == "ok"
    assert body["report_id"]
    assert body["report"]["target"] == "https://example.com"
    assert body["report"]["risk_score"] == 15
    assert body["report"]["findings"][0]["description"] == "Test finding"


def test_mobile_url_api_rejects_oversized_url(monkeypatch):
    monkeypatch.setattr(app_module, "APP_ENV", "development")
    monkeypatch.setenv("REQUIRE_AUTH", "false")

    response = client().post(
        "/api/analyze/url",
        json={"url": "a" * (app_module.MAX_URL_LENGTH + 1)},
    )

    assert response.status_code == 400


def test_mobile_url_api_requires_auth_when_enabled(monkeypatch):
    monkeypatch.setattr(app_module, "APP_ENV", "development")
    monkeypatch.setenv("REQUIRE_AUTH", "true")
    monkeypatch.setenv("TOOLKIT_USERNAME", "test-user")
    monkeypatch.setenv("TOOLKIT_PASSWORD", "test-password")

    response = client().post(
        "/api/analyze/url",
        json={"url": "https://example.com"},
    )

    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers
