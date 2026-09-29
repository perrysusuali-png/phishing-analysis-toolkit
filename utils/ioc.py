"""
Static IOC extraction utilities.

This module only extracts indicators from supplied text.
It does NOT visit URLs, resolve domains, execute files, or make
network requests.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlparse


URL_RE = re.compile(
    r"https?://[^\s<>'\"`]+",
    re.IGNORECASE,
)

EMAIL_RE = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)

IPV4_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

TRAILING_URL_CHARS = ".,;:!?)]}>\"'"


def _clean_url(value: str) -> str:
    return value.rstrip(TRAILING_URL_CHARS)


def _valid_ipv4(value: str) -> bool:
    try:
        return isinstance(
            ipaddress.ip_address(value),
            ipaddress.IPv4Address,
        )
    except ValueError:
        return False


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_domains_from_urls(urls: list[str]) -> list[str]:
    domains = set()

    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname

            if hostname:
                hostname = hostname.lower().rstrip(".")

                if not _valid_ip(hostname):
                    domains.add(hostname)

        except ValueError:
            continue

    return sorted(domains)


def _extract_ips(text: str) -> list[str]:
    results = set()

    for candidate in IPV4_RE.findall(text):
        if _valid_ipv4(candidate):
            results.add(candidate)

    return sorted(results)


def _extract_hashes(text: str) -> dict[str, list[str]]:
    sha256 = set(SHA256_RE.findall(text))
    sha1 = set(SHA1_RE.findall(text))
    md5 = set(MD5_RE.findall(text))

    # Prevent shorter hash regexes from accidentally matching
    # inside longer hash strings.
    sha1 = {
        value
        for value in sha1
        if not any(
            value.lower() in sha256_value.lower()
            for sha256_value in sha256
        )
    }

    md5 = {
        value
        for value in md5
        if not any(
            value.lower() in sha1_value.lower()
            for sha1_value in sha1
        )
        and not any(
            value.lower() in sha256_value.lower()
            for sha256_value in sha256
        )
    }

    return {
        "md5": sorted(md5),
        "sha1": sorted(sha1),
        "sha256": sorted(sha256),
    }


def extract_iocs(text: str) -> dict:
    """
    Extract URLs, domains, IP addresses, email addresses,
    and file hashes from supplied text.
    """

    if not text:
        return empty_ioc_store()

    urls = sorted(
        {
            _clean_url(match)
            for match in URL_RE.findall(text)
        }
    )

    emails = sorted(
        {
            value.lower()
            for value in EMAIL_RE.findall(text)
        }
    )

    ips = _extract_ips(text)

    domains = _extract_domains_from_urls(urls)

    hashes = _extract_hashes(text)

    return {
        "urls": urls,
        "domains": domains,
        "ip_addresses": ips,
        "emails": emails,
        "file_hashes": hashes,
    }


def merge_iocs(target: dict, source: dict) -> dict:
    """
    Merge IOC collections while removing duplicates.
    """

    if not target:
        target = empty_ioc_store()

    target.setdefault("urls", [])
    target.setdefault("domains", [])
    target.setdefault("ip_addresses", [])
    target.setdefault("emails", [])

    target.setdefault(
        "file_hashes",
        {
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
    )

    for key in (
        "urls",
        "domains",
        "ip_addresses",
        "emails",
    ):
        values = set(target.get(key, []))
        values.update(source.get(key, []))
        target[key] = sorted(values)

    target_hashes = target["file_hashes"]
    source_hashes = source.get("file_hashes", {})

    for hash_type in (
        "md5",
        "sha1",
        "sha256",
    ):
        values = set(
            target_hashes.get(hash_type, [])
        )

        values.update(
            source_hashes.get(hash_type, [])
        )

        target_hashes[hash_type] = sorted(values)

    return target


def file_hashes(data: bytes) -> dict[str, str]:
    """
    Calculate MD5, SHA-1 and SHA-256 hashes
    for supplied file bytes.
    """

    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def empty_ioc_store() -> dict:
    return {
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