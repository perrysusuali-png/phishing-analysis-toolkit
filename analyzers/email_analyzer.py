"""Parses .eml files and checks headers/body for phishing indicators."""

import email
import re
from email import policy
from email.parser import BytesParser

from utils.report import AnalysisReport
from analyzers.url_analyzer import extract_urls, analyze_url
from analyzers import virustotal_analyzer

URGENCY_PHRASES = [
    "verify your account", "suspended", "urgent action required",
    "confirm your identity", "unusual activity", "click here immediately",
    "your account will be", "act now", "limited time", "password expires",
    "unauthorized login", "security alert", "update your payment",
    "failure to comply", "legal action", "final notice",
]

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "protonmail.com", "mail.com",
}


def _get_addr_domain(addr_field):
    match = re.search(r"@([\w.\-]+)", addr_field or "")
    return match.group(1).lower() if match else ""


def analyze_email(path):
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    report = AnalysisReport(path, "Email")

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    subject = msg.get("Subject", "")

    from_domain = _get_addr_domain(from_header)
    reply_domain = _get_addr_domain(reply_to)
    return_domain = _get_addr_domain(return_path)

    # From / Reply-To mismatch — classic phishing pattern
    if reply_to and reply_domain and from_domain and reply_domain != from_domain:
        report.add(
            f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain})",
            30, "header",
        )

    if return_path and return_domain and from_domain and return_domain != from_domain:
        report.add(
            f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})",
            20, "header",
        )

    # Display name spoofing: "PayPal Support <random123@sketchy.net>"
    display_match = re.match(r'^"?([^"<]+)"?\s*<(.+)>$', from_header.strip())
    if display_match:
        display_name = display_match.group(1).strip().lower()
        for brand in ("paypal", "microsoft", "apple", "amazon", "bank", "google", "netflix"):
            if brand in display_name and brand not in from_domain:
                report.add(
                    f"Display name references '{brand}' but sender domain is '{from_domain}'",
                    35, "spoofing",
                )
                break

    # Authentication headers (best-effort; only present if the MTA added them)
    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        for mechanism in ("spf", "dkim", "dmarc"):
            m = re.search(rf"{mechanism}=(\w+)", auth_results, re.IGNORECASE)
            if m and m.group(1).lower() not in ("pass",):
                report.add(f"{mechanism.upper()} check did not pass ({m.group(1)})", 20, "authentication")
    else:
        report.add("No Authentication-Results header found (SPF/DKIM/DMARC unverifiable)", 10, "authentication")

    # Free-mail sender claiming to be an organization
    if from_domain in FREE_MAIL_DOMAINS and re.search(r"(support|billing|security|admin|no-?reply)", from_header, re.I):
        report.add(
            f"Sender uses a free email domain ({from_domain}) despite an official-sounding address",
            15, "spoofing",
        )

    # Body analysis
    body = _get_body_text(msg)
    lower_body = body.lower()

    matched_phrases = [p for p in URGENCY_PHRASES if p in lower_body]
    if matched_phrases:
        report.add(
            f"Contains {len(matched_phrases)} urgency/pressure phrase(s): "
            + ", ".join(matched_phrases[:3]) + ("..." if len(matched_phrases) > 3 else ""),
            min(30, 8 * len(matched_phrases)), "content",
        )

    if re.search(r"dear (customer|user|valued|member)\b", lower_body):
        report.add("Generic greeting ('Dear Customer' etc.) instead of a personal name", 10, "content")

    # Embedded links
    urls = extract_urls(body)
    if urls:
        report.add(f"Contains {len(urls)} embedded link(s)", 5, "content")
        # Cross-check the worst-scoring link (heuristics only — VT is checked once, below)
        worst = None
        for u in urls[:10]:  # cap to avoid runaway analysis on huge emails
            sub_report = analyze_url(u, check_vt=False)
            if worst is None or sub_report.risk_score > worst.risk_score:
                worst = sub_report
        if worst and worst.risk_score > 0:
            report.add(
                f"Highest-risk embedded link '{worst.target}' scored {worst.risk_score}/100 on its own analysis",
                min(30, worst.risk_score // 2), "content",
            )
        if worst and virustotal_analyzer.is_configured():
            vt_result = virustotal_analyzer.check_url(worst.target)
            virustotal_analyzer.add_vt_finding(report, vt_result)

    # HTML link text vs actual href mismatch (basic check)
    html_part = _get_html_part(msg)
    if html_part:
        mismatches = _find_link_text_mismatches(html_part)
        if mismatches:
            report.add(
                f"{len(mismatches)} link(s) where displayed text doesn't match the actual URL",
                30, "content",
            )

    return report


def _get_body_text(msg):
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
        if parts:
            return "\n".join(parts)
        # fall back to stripped HTML if no plain-text part exists
        html = _get_html_part(msg)
        return re.sub(r"<[^>]+>", " ", html) if html else ""
    else:
        try:
            return msg.get_content()
        except Exception:
            return ""


def _get_html_part(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    return part.get_content()
                except Exception:
                    return ""
    elif msg.get_content_type() == "text/html":
        try:
            return msg.get_content()
        except Exception:
            return ""
    return ""


def _find_link_text_mismatches(html):
    mismatches = []
    for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html, re.IGNORECASE | re.DOTALL):
        href, text = m.group(1), re.sub(r"<[^>]+>", "", m.group(2)).strip()
        text_url_match = re.search(r"https?://[^\s]+", text)
        if text_url_match:
            displayed = text_url_match.group(0)
            if displayed.rstrip("/") != href.rstrip("/") and displayed not in href:
                mismatches.append((displayed, href))
    return mismatches
