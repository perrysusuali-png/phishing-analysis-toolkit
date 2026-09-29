import ipaddress
import re
from urllib.parse import parse_qs, unquote, urlparse

from utils.report import AnalysisReport
from utils.ioc import extract_iocs
from analyzers import virustotal_analyzer


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorte.st",
}

SUSPICIOUS_TLDS = {
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".club",
    ".work",
    ".click",
    ".link",
    ".rest",
}

COMMON_BRANDS = {
    "paypal.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "netflix.com",
    "bankofamerica.com",
    "chase.com",
    "wellsfargo.com",
    "dropbox.com",
    "instagram.com",
    "linkedin.com",
    "outlook.com",
    "office365.com",
    "docusign.com",
}

SUSPICIOUS_PATH_TERMS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "account",
    "password",
    "credential",
    "payment",
    "billing",
    "invoice",
    "confirm",
    "update",
    "unlock",
    "authenticate",
    "wallet",
    "recover",
}

SUSPICIOUS_QUERY_KEYS = {
    "redirect",
    "redirect_url",
    "redirect_uri",
    "url",
    "next",
    "return",
    "return_url",
    "continue",
    "dest",
    "destination",
    "target",
}

SUSPICIOUS_FILE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".msi",
    ".dll",
    ".zip",
    ".rar",
    ".7z",
    ".iso",
    ".img",
    ".hta",
}

IPV4_SIMPLE_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

HEX_ESCAPE_RE = re.compile(
    r"%[0-9a-fA-F]{2}"
)

DOUBLE_ENCODING_RE = re.compile(
    r"%25[0-9a-fA-F]{2}|%2525|%255[cC]|%255[fF]"
)


def levenshtein(a, b):
    """Calculate Levenshtein edit distance."""

    if a == b:
        return 0

    if not a:
        return len(b)

    if not b:
        return len(a)

    previous = list(range(len(b) + 1))

    for i, char_a in enumerate(a, start=1):
        current = [i]

        for j, char_b in enumerate(b, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (
                char_a != char_b
            )

            current.append(
                min(
                    insert_cost,
                    delete_cost,
                    replace_cost,
                )
            )

        previous = current

    return previous[-1]


def _normalize_url(url):
    """
    Normalize only for analysis.

    No network request is made and no redirect is followed.
    """

    value = (url or "").strip()

    if not value:
        return value, False

    had_scheme = bool(
        re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
            value,
        )
    )

    if not had_scheme:
        value = "http://" + value

    return value, had_scheme


def _is_valid_ip(host):
    """Return True when host is a valid IPv4 or IPv6 address."""

    if not host:
        return False

    candidate = host.strip("[]")

    try:
        ipaddress.ip_address(candidate)
        return True

    except ValueError:
        return False


def _registrable_domain(host):
    """
    Lightweight registrable-domain fallback.

    This does not implement the complete Public Suffix List.
    It handles common multi-level suffixes such as co.uk and com.au.
    """

    if not host:
        return ""

    host = host.lower().rstrip(".")

    parts = host.split(".")

    if len(parts) <= 2:
        return host

    common_second_level_suffixes = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "com.br",
        "com.cn",
        "com.sg",
        "co.jp",
        "co.za",
    }

    last_two = ".".join(parts[-2:])

    if last_two in common_second_level_suffixes:
        return ".".join(parts[-3:])

    return last_two


def _brand_typosquat(host):
    """
    Detect possible brand-domain impersonation.

    A match is treated as an indicator,
    not proof of malicious activity.
    """

    registrable = _registrable_domain(host)

    if not registrable:
        return []

    matches = []

    for brand in COMMON_BRANDS:
        brand_reg = _registrable_domain(brand)

        if registrable == brand_reg:
            continue

        distance = levenshtein(
            registrable,
            brand_reg,
        )

        if distance <= 2:
            matches.append(
                {
                    "brand": brand,
                    "distance": distance,
                    "type": "edit_distance",
                }
            )

        brand_name = brand_reg.split(".")[0]

        if brand_name and brand_name in registrable:
            matches.append(
                {
                    "brand": brand,
                    "distance": distance,
                    "type": "brand_in_domain",
                }
            )

    return matches


def _path_terms(path):
    """Return suspicious terms found in the decoded URL path."""

    decoded = unquote(
        path or ""
    ).lower()

    return sorted(
        {
            term
            for term in SUSPICIOUS_PATH_TERMS
            if term in decoded
        }
    )


def _query_keys(query):
    """Extract normalized query parameter names."""

    try:
        parsed = parse_qs(
            query or "",
            keep_blank_values=True,
        )

        return {
            key.lower()
            for key in parsed.keys()
        }

    except Exception:
        return set()


def analyze_url(url, check_vt=True):
    """
    Perform static URL analysis.

    Important:
    - No URL is visited.
    - No redirect is followed.
    - No page content is downloaded.
    """

    report = AnalysisReport(
        url,
        "URL",
    )

    normalized_url, had_scheme = _normalize_url(url)

    # ------------------------------------------------------------
    # Empty input
    # ------------------------------------------------------------

    if not normalized_url:
        report.add(
            "URL input is empty",
            0,
            "INPUT",
            severity="info",
            confidence=1.0,
            analyzer="url",
        )

        return report

    # ------------------------------------------------------------
    # URL normalization
    # ------------------------------------------------------------

    if not had_scheme:
        report.add(
            "URL had no explicit scheme; http:// was added only for parsing",
            0,
            "NORMALIZATION",
            severity="info",
            confidence=1.0,
            analyzer="url",
            metadata={
                "normalized_url": normalized_url,
            },
        )

    # ------------------------------------------------------------
    # URL parsing
    # ------------------------------------------------------------

    try:
        parsed = urlparse(
            normalized_url
        )

    except Exception as exc:
        report.add(
            f"Unable to parse URL: {exc}",
            0,
            "PARSING",
            severity="high",
            confidence=1.0,
            analyzer="url",
        )

        return report

    # ------------------------------------------------------------
    # Structured IOC extraction
    # ------------------------------------------------------------
    # This only extracts indicators from the supplied URL.
    # It does not visit or resolve the URL.

    report.add_indicators(
        extract_iocs(url)
    )

    hostname = (
        parsed.hostname or ""
    ).lower().rstrip(".")

    if not hostname:
        report.add(
            "URL does not contain a valid hostname",
            20,
            "PARSING",
            severity="medium",
            confidence=0.95,
            analyzer="url",
        )

        return report

    # ------------------------------------------------------------
    # Report metadata
    # ------------------------------------------------------------

    report.metadata = getattr(
        report,
        "metadata",
        {},
    )

    report.metadata.update(
        {
            "normalized_url": normalized_url,
            "hostname": hostname,
            "scheme": parsed.scheme.lower(),
            "path": parsed.path,
            "query_present": bool(
                parsed.query
            ),
            "fragment_present": bool(
                parsed.fragment
            ),
        }
    )

    # ------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------

    scheme = parsed.scheme.lower()

    if scheme == "http":
        report.add(
            "Uses unencrypted HTTP instead of HTTPS",
            10,
            "TRANSPORT",
            severity="low",
            confidence=1.0,
            analyzer="url",
            indicator="http",
        )

    elif scheme not in {"https", "http"}:
        report.add(
            f"Uses an unusual URL scheme: {scheme}",
            20,
            "TRANSPORT",
            severity="medium",
            confidence=1.0,
            analyzer="url",
            indicator=scheme,
        )

    # ------------------------------------------------------------
    # IP address host
    # ------------------------------------------------------------

    is_ip_address = _is_valid_ip(
        hostname
    )

    if is_ip_address:
        report.add(
            "URL uses a raw IP address instead of a domain name",
            30,
            "HOST",
            severity="high",
            confidence=1.0,
            analyzer="url",
            indicator=hostname,
        )

    elif IPV4_SIMPLE_RE.match(hostname):
        report.add(
            "Hostname resembles an IPv4 address but is not a valid IPv4 address",
            20,
            "HOST",
            severity="medium",
            confidence=0.95,
            analyzer="url",
            indicator=hostname,
        )

    # ------------------------------------------------------------
    # URL credentials / userinfo
    # ------------------------------------------------------------

    if (
        parsed.username is not None
        or parsed.password is not None
    ):
        report.add(
            "URL contains userinfo before the hostname, which can obscure the true destination",
            35,
            "DECEPTION",
            severity="high",
            confidence=1.0,
            analyzer="url",
            indicator=hostname,
        )

    # ------------------------------------------------------------
    # URL shortener
    # ------------------------------------------------------------

    if hostname in SHORTENERS:
        report.add(
            "Uses a URL-shortening service that can hide the final destination",
            20,
            "REDIRECTION",
            severity="medium",
            confidence=1.0,
            analyzer="url",
            indicator=hostname,
        )

    # ------------------------------------------------------------
    # Suspicious TLD
    # ------------------------------------------------------------

    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            report.add(
                (
                    "Uses a TLD that is sometimes associated with "
                    f"disposable or abusive domains: {tld}"
                ),
                8,
                "DOMAIN",
                severity="low",
                confidence=0.55,
                analyzer="url",
                indicator=tld,
            )

            break

    # ------------------------------------------------------------
    # Subdomain depth
    # ------------------------------------------------------------

    labels = [
        part
        for part in hostname.split(".")
        if part
    ]

    # IP addresses must not be interpreted as DNS subdomain labels.
    if not is_ip_address:

        if len(labels) >= 5:
            report.add(
                "Hostname contains many subdomain labels",
                15,
                "DOMAIN",
                severity="medium",
                confidence=0.75,
                analyzer="url",
                evidence={
                    "labels": labels,
                    "label_count": len(labels),
                },
            )

        elif len(labels) >= 4:
            report.add(
                "Hostname contains several subdomain labels",
                8,
                "DOMAIN",
                severity="low",
                confidence=0.65,
                analyzer="url",
                evidence={
                    "labels": labels,
                    "label_count": len(labels),
                },
            )

    # ------------------------------------------------------------
    # Punycode / IDN
    # ------------------------------------------------------------

    if any(
        label.startswith("xn--")
        for label in labels
    ):
        report.add(
            "Hostname contains an IDN/punycode label",
            15,
            "DECEPTION",
            severity="medium",
            confidence=0.95,
            analyzer="url",
            evidence={
                "labels": labels,
            },
        )

    # ------------------------------------------------------------
    # Hyphen analysis
    # ------------------------------------------------------------

    hyphen_count = hostname.count("-")

    if hyphen_count >= 3:
        report.add(
            "Hostname contains many hyphens",
            10,
            "DOMAIN",
            severity="low",
            confidence=0.65,
            analyzer="url",
            evidence={
                "hyphen_count": hyphen_count,
            },
        )

    elif hyphen_count >= 2:
        report.add(
            "Hostname contains multiple hyphens",
            6,
            "DOMAIN",
            severity="low",
            confidence=0.55,
            analyzer="url",
            evidence={
                "hyphen_count": hyphen_count,
            },
        )

    # ------------------------------------------------------------
    # Brand impersonation / typosquatting
    # ------------------------------------------------------------

    typo_matches = _brand_typosquat(
        hostname
    )

    if typo_matches:
        best_match = min(
            typo_matches,
            key=lambda item: item["distance"],
        )

        report.add(
            (
                "Hostname resembles a known brand domain: "
                f"{best_match['brand']}"
            ),
            35,
            "BRAND_IMPERSONATION",
            severity="high",
            confidence=0.85,
            analyzer="url",
            indicator=hostname,
            evidence=typo_matches,
        )

    # ------------------------------------------------------------
    # Port analysis
    # ------------------------------------------------------------

    try:
        port = parsed.port

    except ValueError:
        report.add(
            "URL contains an invalid port value",
            20,
            "NETWORK",
            severity="medium",
            confidence=1.0,
            analyzer="url",
        )

        port = None

    if port is not None:

        normal_port = (
            (
                scheme == "http"
                and port == 80
            )
            or (
                scheme == "https"
                and port == 443
            )
        )

        if not normal_port:
            report.add(
                f"URL uses a non-standard port: {port}",
                12,
                "NETWORK",
                severity="low",
                confidence=1.0,
                analyzer="url",
                indicator=str(port),
            )

    # ------------------------------------------------------------
    # Path analysis
    # ------------------------------------------------------------

    path_terms = _path_terms(
        parsed.path
    )

    if path_terms:
        report.add(
            (
                "Path contains potentially sensitive terms: "
                f"{', '.join(path_terms)}"
            ),
            min(
                20,
                5 * len(path_terms),
            ),
            "PATH",
            severity="medium",
            confidence=0.65,
            analyzer="url",
            evidence={
                "terms": path_terms,
                "path": parsed.path,
            },
        )

    path_lower = unquote(
        parsed.path or ""
    ).lower()

    for extension in SUSPICIOUS_FILE_EXTENSIONS:

        if path_lower.endswith(extension):
            report.add(
                (
                    "URL path ends with a potentially risky "
                    f"file extension: {extension}"
                ),
                20,
                "PAYLOAD",
                severity="medium",
                confidence=0.85,
                analyzer="url",
                indicator=extension,
            )

            break

    # ------------------------------------------------------------
    # Query parameter analysis
    # ------------------------------------------------------------

    query_keys = _query_keys(
        parsed.query
    )

    redirect_keys = sorted(
        query_keys.intersection(
            SUSPICIOUS_QUERY_KEYS
        )
    )

    if redirect_keys:
        report.add(
            (
                "Query string contains parameters "
                "commonly used for redirection"
            ),
            15,
            "REDIRECTION",
            severity="medium",
            confidence=0.8,
            analyzer="url",
            evidence={
                "parameters": redirect_keys,
            },
        )

    # ------------------------------------------------------------
    # Percent encoding
    # ------------------------------------------------------------

    encoded_count = len(
        HEX_ESCAPE_RE.findall(
            normalized_url
        )
    )

    if encoded_count >= 8:
        report.add(
            "URL contains extensive percent-encoding",
            12,
            "ENCODING",
            severity="low",
            confidence=0.75,
            analyzer="url",
            evidence={
                "encoded_sequences": encoded_count,
            },
        )

    if DOUBLE_ENCODING_RE.search(
        normalized_url
    ):
        report.add(
            "URL contains patterns consistent with double encoding",
            20,
            "ENCODING",
            severity="medium",
            confidence=0.85,
            analyzer="url",
        )

    # ------------------------------------------------------------
    # Fragment
    # ------------------------------------------------------------

    if parsed.fragment:
        report.add(
            "URL contains a fragment component",
            0,
            "URL_STRUCTURE",
            severity="info",
            confidence=1.0,
            analyzer="url",
        )

    # ------------------------------------------------------------
    # URL length
    # ------------------------------------------------------------

    if len(normalized_url) > 200:
        report.add(
            "URL is unusually long",
            12,
            "URL_STRUCTURE",
            severity="low",
            confidence=0.8,
            analyzer="url",
            evidence={
                "length": len(normalized_url),
            },
        )

    elif len(normalized_url) > 120:
        report.add(
            "URL is longer than typical web URLs",
            6,
            "URL_STRUCTURE",
            severity="low",
            confidence=0.65,
            analyzer="url",
            evidence={
                "length": len(normalized_url),
            },
        )

    # ------------------------------------------------------------
    # VirusTotal
    # ------------------------------------------------------------

    if check_vt:

        try:
            vt_result = (
                virustotal_analyzer
                .check_url(
                    normalized_url
                )
            )

            virustotal_analyzer.add_vt_finding(
                report,
                vt_result,
                subject_label="URL",
            )

        except Exception as exc:
            report.add(
                f"VirusTotal lookup failed: {exc}",
                0,
                "THREAT_INTELLIGENCE",
                severity="info",
                confidence=0.0,
                analyzer="virustotal",
            )

    return report


def extract_urls(text):
    """
    Extract HTTP(S) URLs from text.

    This function only extracts URL strings.
    It does not visit, resolve, or execute them.
    """

    if not text:
        return []

    urls = re.findall(
        r'https?://[^\s"\'<>\\)]+',
        text,
        flags=re.IGNORECASE,
    )

    # Remove duplicates while preserving order.
    return list(
        dict.fromkeys(urls)
    )