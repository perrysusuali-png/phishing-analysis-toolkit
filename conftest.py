import pytest
import utils.database as database
from app import _REPORT_CACHE


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        tmp_path / "phishing_test.db",
    )
    _REPORT_CACHE.clear()
    database.init_database()
    yield
    _REPORT_CACHE.clear()
