#!/usr/bin/env python3
"""
Phishing Analysis Toolkit — Web Dashboard.

Run with:
    py app.py         (Windows)
    python3 app.py    (macOS/Linux)

Then open:
    http://127.0.0.1:5000

This application is designed for local analyst/DFIR use.
It is NOT hardened for public Internet exposure.
"""

from __future__ import annotations

import os
import uuid
from collections import OrderedDict
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from analyzers.attachment_analyzer import analyze_attachment
from analyzers.domain_analyzer import analyze_domain
from analyzers.email_analyzer import analyze_email
from analyzers.url_analyzer import analyze_url
from utils.recommendations import get_recommendations


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

load_dotenv()


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------

app = Flask(__name__)

app.secret_key = os.environ.get(
    "TOOLKIT_SECRET_KEY",
    "dev-only-change-me",
)

# Maximum request/upload size.
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "25"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

# Werkzeug request/form limits.
app.config["MAX_FORM_MEMORY_SIZE"] = MAX_UPLOAD_BYTES
app.config["MAX_FORM_PARTS"] = int(
    os.environ.get("MAX_FORM_PARTS", "10000")
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CACHE_LIMIT = int(os.environ.get("REPORT_CACHE_LIMIT", "50"))

# Restrict uploaded files to types this toolkit is expected to analyze.
ALLOWED_EMAIL_EXTENSIONS = {
    ".eml",
}

# These are intentionally broad because the attachment analyzer should
# inspect many file types rather than relying only on the extension.
BLOCKED_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
}

MAX_URL_LENGTH = 4096
MAX_DOMAIN_LENGTH = 253


# ---------------------------------------------------------------------------
# In-memory report cache
# ---------------------------------------------------------------------------

# OrderedDict gives us simple FIFO eviction while preserving insertion order.
_REPORT_CACHE: OrderedDict[str, object] = OrderedDict()


def _cache_report(report) -> str:
    """
    Store a report in memory and return its short identifier.

    The cache intentionally remains small because this is a local analyst
    dashboard rather than a database-backed multi-user application.
    """

    report_id = uuid.uuid4().hex[:12]

    _REPORT_CACHE[report_id] = report

    while len(_REPORT_CACHE) > CACHE_LIMIT:
        _REPORT_CACHE.popitem(last=False)

    return report_id


def _get_cached_report(report_id: str):
    """
    Retrieve a cached report.

    Moving the report to the end means recently used reports stay available
    slightly longer when the cache is under pressure.
    """

    report = _REPORT_CACHE.get(report_id)

    if report is not None:
        _REPORT_CACHE.move_to_end(report_id)

    return report


def _render_result(report):
    """
    Cache a report and render the result page.
    """

    report_id = _cache_report(report)

    recommendations = get_recommendations(
        report.analysis_type,
        report.verdict,
    )

    return render_template(
        "result.html",
        report=report,
        report_id=report_id,
        recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _allowed_file(filename: str, analysis_type: str) -> bool:
    """
    Validate a filename before saving it.

    This is not a security boundary by itself; the analyzer should still
    inspect the file contents safely.
    """

    suffix = Path(filename).suffix.lower()

    if analysis_type == "email":
        return suffix in ALLOWED_EMAIL_EXTENSIONS

    if analysis_type == "attachment":
        # Block common executable/script formats from being casually uploaded.
        # They can still be investigated later if the policy is changed.
        return suffix not in BLOCKED_EXTENSIONS

    return False


def _save_uploaded_file(file_storage):
    """
    Save an uploaded file using a generated filename.

    Returns:
        (saved_path, original_filename)
    """

    original_name = secure_filename(
        file_storage.filename or "uploaded_file"
    )

    if not original_name:
        original_name = "uploaded_file"

    generated_name = (
        f"{uuid.uuid4().hex}_{original_name}"
    )

    saved_path = UPLOAD_DIR / generated_name

    file_storage.save(saved_path)

    return saved_path, original_name


def _remove_file(path: Path) -> None:
    """
    Best-effort temporary-file cleanup.
    """

    try:
        path.unlink(missing_ok=True)
    except OSError:
        app.logger.warning(
            "Could not remove temporary file: %s",
            path,
        )


def _handle_analyzer_error(
    analysis_type: str,
    error: Exception,
):
    """
    Convert an analyzer failure into a user-friendly response.

    Detailed exception information remains in the server log.
    """

    app.logger.exception(
        "%s analysis failed",
        analysis_type,
    )

    flash(
        f"{analysis_type} analysis failed. "
        "Check the application log for details.",
        "error",
    )

    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(error):
    """
    Handle uploads larger than MAX_CONTENT_LENGTH.
    """

    flash(
        f"That file is too large. "
        f"The maximum upload size is {MAX_UPLOAD_MB} MB.",
        "error",
    )

    return redirect(url_for("index")), 413


@app.errorhandler(400)
def handle_bad_request(error):
    flash(
        "The request could not be processed.",
        "error",
    )

    return redirect(url_for("index")), 400


@app.errorhandler(404)
def handle_not_found(error):
    return redirect(url_for("index"))


@app.errorhandler(500)
def handle_internal_error(error):
    """
    Avoid exposing Python tracebacks to the browser.
    """

    app.logger.exception("Unhandled application error")

    flash(
        "An unexpected application error occurred.",
        "error",
    )

    return redirect(url_for("index")), 500


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Email analysis
# ---------------------------------------------------------------------------

@app.route("/analyze/email", methods=["POST"])
def analyze_email_route():
    file = request.files.get("eml_file")

    if not file or not file.filename:
        flash(
            "Please choose a .eml file to analyze.",
            "error",
        )
        return redirect(url_for("index"))

    if not _allowed_file(file.filename, "email"):
        flash(
            "Only .eml files are accepted for email analysis.",
            "error",
        )
        return redirect(url_for("index"))

    saved_path = None

    try:
        saved_path, original_name = _save_uploaded_file(file)

        app.logger.info(
            "Starting email analysis: %s",
            original_name,
        )

        report = analyze_email(str(saved_path))

        # Present the original filename instead of the generated temp path.
        report.target = original_name

        return _render_result(report)

    except Exception as exc:
        return _handle_analyzer_error(
            "Email",
            exc,
        )

    finally:
        if saved_path:
            _remove_file(saved_path)


# ---------------------------------------------------------------------------
# URL analysis
# ---------------------------------------------------------------------------

@app.route("/analyze/url", methods=["POST"])
def analyze_url_route():
    target = request.form.get("url", "").strip()

    if not target:
        flash(
            "Please enter a URL to analyze.",
            "error",
        )
        return redirect(url_for("index"))

    if len(target) > MAX_URL_LENGTH:
        flash(
            f"The URL is too long. Maximum length is "
            f"{MAX_URL_LENGTH} characters.",
            "error",
        )
        return redirect(url_for("index"))

    try:
        report = analyze_url(target)

        return _render_result(report)

    except Exception as exc:
        return _handle_analyzer_error(
            "URL",
            exc,
        )


# ---------------------------------------------------------------------------
# Attachment analysis
# ---------------------------------------------------------------------------

@app.route("/analyze/attachment", methods=["POST"])
def analyze_attachment_route():
    file = request.files.get("attachment_file")

    if not file or not file.filename:
        flash(
            "Please choose a file to analyze.",
            "error",
        )
        return redirect(url_for("index"))

    if not _allowed_file(file.filename, "attachment"):
        flash(
            "This file type is blocked by the dashboard upload policy.",
            "error",
        )
        return redirect(url_for("index"))

    saved_path = None

    try:
        saved_path, original_name = _save_uploaded_file(file)

        app.logger.info(
            "Starting attachment analysis: %s",
            original_name,
        )

        report = analyze_attachment(str(saved_path))

        # Keep analyst-friendly target information.
        report.target = original_name

        return _render_result(report)

    except Exception as exc:
        return _handle_analyzer_error(
            "Attachment",
            exc,
        )

    finally:
        if saved_path:
            _remove_file(saved_path)


# ---------------------------------------------------------------------------
# Domain analysis
# ---------------------------------------------------------------------------

@app.route("/analyze/domain", methods=["POST"])
def analyze_domain_route():
    target = request.form.get("domain", "").strip()

    if not target:
        flash(
            "Please enter a domain to analyze.",
            "error",
        )
        return redirect(url_for("index"))

    if len(target) > MAX_DOMAIN_LENGTH:
        flash(
            f"The domain is too long. Maximum length is "
            f"{MAX_DOMAIN_LENGTH} characters.",
            "error",
        )
        return redirect(url_for("index"))

    try:
        report = analyze_domain(target)

        return _render_result(report)

    except Exception as exc:
        return _handle_analyzer_error(
            "Domain",
            exc,
        )


# ---------------------------------------------------------------------------
# JSON report export
# ---------------------------------------------------------------------------

@app.route("/report/<report_id>/json")
def download_report_json(report_id):
    report = _get_cached_report(report_id)

    if report is None:
        flash(
            "That report has expired or was never generated.",
            "error",
        )
        return redirect(url_for("index"))

    try:
        data = report.to_dict()
    except Exception as exc:
        return _handle_analyzer_error(
            "Report export",
            exc,
        )

    response = jsonify(data)

    # Tell browsers that this is a downloadable JSON document.
    response.headers["Content-Disposition"] = (
        f'attachment; filename="analysis-{report_id}.json"'
    )

    return response


# ---------------------------------------------------------------------------
# Health/status endpoint
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    """
    Lightweight local health check.

    Useful for debugging the dashboard and future frontend integration.
    """

    return jsonify(
        {
            "status": "ok",
            "service": "phishing-analysis-toolkit",
            "reports_cached": len(_REPORT_CACHE),
            "cache_limit": CACHE_LIMIT,
        }
    )


# ---------------------------------------------------------------------------
# Application startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host = os.environ.get(
        "HOST",
        "127.0.0.1",
    )

    port = int(
        os.environ.get(
            "PORT",
            "5000",
        )
    )

    debug = (
        os.environ
        .get("FLASK_DEBUG", "true")
        .lower()
        == "true"
    )

    if host != "127.0.0.1" and debug:
        print(
            "\n"
            "WARNING:\n"
            "  Flask debug mode is enabled while the application is\n"
            "  listening on a non-localhost address.\n"
            "\n"
            "  The interactive debugger should not be exposed to other\n"
            "  machines.\n"
            "\n"
            "  Set FLASK_DEBUG=false before using a non-localhost HOST.\n"
        )

    print(
        "\n"
        "============================================================\n"
        " Phishing Analysis Toolkit\n"
        "============================================================\n"
        f" URL:          http://{host}:{port}\n"
        f" Upload limit: {MAX_UPLOAD_MB} MB\n"
        f" Report cache: {CACHE_LIMIT}\n"
        f" Debug:        {debug}\n"
        "============================================================\n"
    )

    app.run(
        debug=debug,
        host=host,
        port=port,
    )