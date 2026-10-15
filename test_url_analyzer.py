
import re

import pytest


URL_EXTRACTION_RE = re.compile(
    r'https?://[^\s"\'<>\\)]+',
    flags=re.IGNORECASE,
)

URL_TRAILING_PUNCTUATION = ".,!?;:"


def extract_urls(text):
    if not isinstance(text, str) or not text:
        return []

    urls = URL_EXTRACTION_RE.findall(text)

    cleaned_urls = []

    for url in urls:
        cleaned_url = url.rstrip(URL_TRAILING_PUNCTUATION)

        if cleaned_url:
            cleaned_urls.append(cleaned_url)

    return list(dict.fromkeys(cleaned_urls))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Visit https://example.com", ["https://example.com"]),
        ("Visit HTTP://example.com", ["HTTP://example.com"]),
        (
            "Visit https://one.example and https://two.example",
            ["https://one.example", "https://two.example"],
        ),
        (
            "https://example.com https://example.com",
            ["https://example.com"],
        ),
        ("Visit https://example.com.", ["https://example.com"]),
        ("Visit https://example.com,", ["https://example.com"]),
        ("Visit https://example.com!", ["https://example.com"]),
        ("Visit https://example.com?", ["https://example.com"]),
        ("Visit https://example.com;", ["https://example.com"]),
        ("Visit https://example.com:", ["https://example.com"]),
        ("There are no links here", []),
        ("", []),
        (None, []),
        (123, []),
        (["https://example.com"], []),
        ({"url": "https://example.com"}, []),
        (
            "https://first.example then https://second.example then https://first.example",
            ["https://first.example", "https://second.example"],
        ),
    ],
)
def test_extract_urls(text, expected):
    assert extract_urls(text) == expected


def test_extract_urls_does_not_make_network_requests(monkeypatch):
    import requests

    def fail_if_called(*args, **kwargs):
        raise AssertionError("URL extraction must not make network requests")

    monkeypatch.setattr(requests, "get", fail_if_called)

    assert extract_urls("Check https://example.com") == [
        "https://example.com"
    ]
