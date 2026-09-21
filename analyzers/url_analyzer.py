"""Heuristic analysis of URLs for phishing indicators."""

import re
from urllib.parse import urlparse

from utils.report import AnalysisReport
from analyzers import virustotal_analyzer

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
    ".click", ".link", ".rest",
}

# Common brands frequently impersonated — used for typosquat similarity checks.
COMMON_BRANDS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "netflix.com", "bankofamerica.com", "chase.com",
    "wellsfargo.com", "dropbox.com", "instagram.com", "linkedin.com",
    "outlook.com", "office365.com", "docusign.com",
]

IP_HOST_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def levenshtein(a, b):
    """Standard edit-distance, no external dependency required."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            current.append(min(
                previous[j] + 1,      # deletion
                current[j - 1] + 1,   # insertion
                previous[j - 1] + cost,  # substitution
            ))
        previous = current
    return previous[-1]


def analyze_url(url, check_vt=True):
    report = AnalysisReport(url, "URL")

    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    host = host.lower()

    # Scheme check
    if parsed.scheme == "http":
        report.add("Uses unencrypted HTTP instead of HTTPS", 10, "transport")

    # Shortener check
    if host in SHORTENERS:
        report.add(f"Uses URL shortener ({host}) which hides the real destination", 20, "obfuscation")

    # IP address as hostname
    if IP_HOST_RE.match(host):
        report.add(f"Hostname is a raw IP address ({host}) rather than a domain", 30, "obfuscation")

    # @ symbol trick (browser ignores everything before @)
    if "@" in url.split("://", 1)[-1]:
        report.add("URL contains '@' — text before it may be a decoy hostname", 35, "obfuscation")

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            report.add(f"Uses a TLD commonly abused for phishing ({tld})", 15, "domain")
            break

    # Excessive subdomains
    subdomain_count = host.count(".")
    if subdomain_count >= 4:
        report.add(f"Unusually deep subdomain structure ({host})", 15, "domain")

    # Hyphens / digit substitution often used to mimic brands
    if host.count("-") >= 2:
        report.add("Multiple hyphens in hostname (common in spoofed domains)", 10, "domain")

    # Typosquat similarity to common brands
    registrable = ".".join(host.split(".")[-2:]) if "." in host else host
    for brand in COMMON_BRANDS:
        if registrable == brand:
            continue
        dist = levenshtein(registrable, brand)
        if 0 < dist <= 2 and len(registrable) >= len(brand) - 2:
            report.add(
                f"Domain '{registrable}' closely resembles known brand '{brand}' "
                f"(edit distance {dist}) — possible typosquat",
                40, "brand-impersonation",
            )
            break
        # substring trick: brand name embedded in a longer suspicious domain
        brand_name = brand.split(".")[0]
        if brand_name in host and registrable != brand:
            report.add(
                f"Hostname contains brand name '{brand_name}' but domain is not "
                f"'{brand}' — possible impersonation",
                35, "brand-impersonation",
            )
            break

    # Path/query tricks
    if any(k in parsed.query.lower() for k in ("redirect", "url=", "next=", "return=")):
        report.add("Query string contains redirect parameters", 15, "obfuscation")

    if len(url) > 120:
        report.add("Unusually long URL (often used to bury the real domain)", 10, "obfuscation")

    if check_vt and virustotal_analyzer.is_configured():
        vt_result = virustotal_analyzer.check_url(url)
        virustotal_analyzer.add_vt_finding(report, vt_result)

    return report


def extract_urls(text):
    """Pull URLs out of arbitrary text (used by the email analyzer)."""
    url_re = re.compile(r"https?://[^\s\"'<>\)]+")
    return url_re.findall(text)
