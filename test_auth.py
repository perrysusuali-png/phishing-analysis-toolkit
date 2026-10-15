
import base64

import pytest
import app as app_module


@pytest.fixture
def client():
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as test_client:
        yield test_client


def test_health_endpoint_remains_public(client):
    response = client.get("/health")
    assert response.status_code == 200


def test_protected_route_rejects_missing_credentials(
    client, monkeypatch
):
    monkeypatch.setattr(app_module, "APP_ENV", "development")
    monkeypatch.setenv("REQUIRE_AUTH", "true")
    monkeypatch.setenv("TOOLKIT_USERNAME", "test-user")
    monkeypatch.setenv("TOOLKIT_PASSWORD", "test-password")

    response = client.get("/api/irt/overview")

    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


def test_protected_route_accepts_valid_credentials(
    client, monkeypatch
):
    monkeypatch.setattr(app_module, "APP_ENV", "development")
    monkeypatch.setenv("REQUIRE_AUTH", "true")
    monkeypatch.setenv("TOOLKIT_USERNAME", "test-user")
    monkeypatch.setenv("TOOLKIT_PASSWORD", "test-password")

    token = base64.b64encode(
        b"test-user:test-password"
    ).decode("ascii")

    response = client.get(
        "/api/irt/overview",
        headers={"Authorization": f"Basic {token}"},
    )

    assert response.status_code != 401

def test_case_update_returns_generic_500_on_unexpected_error(
    client, monkeypatch
):
    monkeypatch.setattr(app_module, "APP_ENV", "development")
    monkeypatch.setenv("REQUIRE_AUTH", "false")

    def raise_unexpected_error(*args, **kwargs):
        raise RuntimeError("private details")

    monkeypatch.setattr(
        app_module, "update_case", raise_unexpected_error
    )

    response = client.patch(
        "/api/irt/cases/1",
        json={"status": "open"},
    )

    assert response.status_code == 500
    assert response.get_json() == {
        "status": "error",
        "message": "Unable to update case.",
    }
    assert b"private details" not in response.data
