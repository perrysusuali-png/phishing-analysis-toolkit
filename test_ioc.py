
from utils.ioc import empty_ioc_store, extract_iocs, merge_iocs


def test_empty_ioc_store_has_consistent_structure():
    result = empty_ioc_store()

    assert result == {
        "urls": [],
        "domains": [],
        "ip_addresses": [],
        "emails": [],
        "file_hashes": {
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
    }


def test_extract_iocs_from_synthetic_text():
    text = (
        "Review https://login.example.test/account "
        "and contact analyst@example.test. "
        "Server: 192.0.2.10"
    )

    result = extract_iocs(text)

    assert "https://login.example.test/account" in result["urls"]
    assert "login.example.test" in result["domains"]
    assert "analyst@example.test" in result["emails"]
    assert "192.0.2.10" in result["ip_addresses"]


def test_merge_iocs_preserves_unique_indicators():
    first = extract_iocs(
        "https://alpha.example.test/a "
        "analyst@example.test"
    )
    second = extract_iocs(
        "https://alpha.example.test/a "
        "security@example.test"
    )

    result = merge_iocs(first, second)

    assert len(result["urls"]) == 1
    assert result["emails"] == [
        "analyst@example.test",
        "security@example.test",
    ]
    assert "urls" in result
    assert "file_hashes" in result
