"""Optional VirusTotal reputation lookups.

Requires a free VirusTotal API key, set as the VT_API_KEY environment
variable (or in a .env file — see .env.example). Every function degrades
gracefully to a "not configured" result if no key is set, and every
network call is wrapped so a VirusTotal outage never crashes an analysis.

Rate limiting: the free tier allows 4 requests/minute and 500/day. A
module-level, thread-safe throttle enforces a minimum gap between
requests so the toolkit never gets an account rate-limited, even with
multiple users hitting the web dashboard at once.
"""

import base64
import os
import threading
import time

import requests

VT_BASE = "https://www.virustotal.com/api/v3"
_MIN_INTERVAL = 16  # seconds between requests — keeps the free 4/min tier safe

_rate_lock = threading.Lock()
_last_request_time = 0.0


def _get_api_key():
    return os.environ.get("VT_API_KEY", "").strip()


def is_configured():
    return bool(_get_api_key())


def _throttled_request(method, url, **kwargs):
    global _last_request_time
    with _rate_lock:
        elapsed = time.time() - _last_request_time
        if elapsed < _MIN_INTERVAL:
            time.sleep(_MIN_INTERVAL - elapsed)
        response = requests.request(method, url, headers={"x-apikey": _get_api_key()}, timeout=20, **kwargs)
        _last_request_time = time.time()
        return response


def _stats_result(stats, permalink):
    return {
        "status": "ok",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "total_engines": sum(stats.values()) if stats else 0,
        "permalink": permalink,
    }


def check_url(url):
    """Looks up a URL's VirusTotal reputation. Submits it for a first-time scan
    if VirusTotal hasn't seen it before, rather than uploading/visiting it itself."""
    if not is_configured():
        return {"status": "unconfigured"}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    permalink = f"https://www.virustotal.com/gui/url/{url_id}"

    try:
        resp = _throttled_request("GET", f"{VT_BASE}/urls/{url_id}")

        if resp.status_code == 404:
            submit = _throttled_request("POST", f"{VT_BASE}/urls", data={"url": url})
            if submit.status_code >= 400:
                return {"status": "error", "message": f"HTTP {submit.status_code} submitting URL"}
            return {
                "status": "submitted",
                "message": "First time seen by VirusTotal — scan submitted, check the permalink in a minute.",
                "permalink": permalink,
            }

        if resp.status_code == 401:
            return {"status": "error", "message": "Invalid VT_API_KEY"}
        if resp.status_code == 429:
            return {"status": "error", "message": "VirusTotal rate/quota limit reached"}
        resp.raise_for_status()

        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return _stats_result(stats, permalink)

    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": str(e)}


def check_file_hash(sha256):
    """Looks up a file by its SHA256 hash — the file itself is never uploaded."""
    if not is_configured():
        return {"status": "unconfigured"}

    permalink = f"https://www.virustotal.com/gui/file/{sha256}"
    try:
        resp = _throttled_request("GET", f"{VT_BASE}/files/{sha256}")

        if resp.status_code == 404:
            return {"status": "not_found", "message": "Not in VirusTotal's database (may simply be new/rare)"}
        if resp.status_code == 401:
            return {"status": "error", "message": "Invalid VT_API_KEY"}
        if resp.status_code == 429:
            return {"status": "error", "message": "VirusTotal rate/quota limit reached"}
        resp.raise_for_status()

        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return _stats_result(stats, permalink)

    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": str(e)}


def check_domain(domain):
    if not is_configured():
        return {"status": "unconfigured"}

    permalink = f"https://www.virustotal.com/gui/domain/{domain}"
    try:
        resp = _throttled_request("GET", f"{VT_BASE}/domains/{domain}")

        if resp.status_code == 404:
            return {"status": "not_found", "message": "Not in VirusTotal's database"}
        if resp.status_code == 401:
            return {"status": "error", "message": "Invalid VT_API_KEY"}
        if resp.status_code == 429:
            return {"status": "error", "message": "VirusTotal rate/quota limit reached"}
        resp.raise_for_status()

        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return _stats_result(stats, permalink)

    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": str(e)}


def add_vt_finding(report, vt_result, subject_label="This"):
    """Translates a VirusTotal result dict into a Finding on the given report."""
    status = vt_result.get("status")

    if status == "unconfigured":
        return  # silent — VT is opt-in, don't clutter reports for users without a key

    if status == "error":
        report.add(f"VirusTotal lookup failed: {vt_result.get('message', 'unknown error')}", 0, "virustotal")
        return

    if status == "not_found":
        report.add(f"VirusTotal: {vt_result.get('message')}", 0, "virustotal")
        return

    if status == "submitted":
        report.add(f"VirusTotal: {vt_result.get('message')}", 0, "virustotal")
        return

    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)
    total = vt_result.get("total_engines", 0)
    permalink = vt_result.get("permalink", "")

    if malicious > 0:
        weight = min(50, 10 + malicious * 4)
        report.add(
            f"VirusTotal: {malicious}/{total} security vendors flag this as malicious "
            f"({permalink})",
            weight, "virustotal",
        )
    elif suspicious > 0:
        report.add(
            f"VirusTotal: {suspicious}/{total} security vendors flag this as suspicious "
            f"({permalink})",
            15, "virustotal",
        )
    else:
        report.add(f"VirusTotal: 0 malicious detections across {total} vendors", 0, "virustotal")
