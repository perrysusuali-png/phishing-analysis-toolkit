
#!/usr/bin/env python3

from __future__ import annotations

import hmac
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
from utils.database import (
    get_analysis_by_report_id,
    get_case_by_id,
    get_dashboard_stats,
    init_database,
    list_cases,
    list_recent_analyses,
    save_analysis,
    update_case,
)


# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

APP_ENV = os.environ.get("APP_ENV", "development").lower()

app.secret_key = os.environ.get("TOOLKIT_SECRET_KEY")

if not app.secret_key:
    if APP_ENV == "production":
        raise RuntimeError(
            "TOOLKIT_SECRET_KEY must be set in production."
        )

    app.secret_key = "dev-only-change-me"

init_database()

MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "25"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.config["MAX_FORM_MEMORY_SIZE"] = MAX_UPLOAD_BYTES
app.config["MAX_FORM_PARTS"] = int(
    os.environ.get("MAX_FORM_PARTS", "10000")
)

CACHE_LIMIT = max(
    1,
    int(os.environ.get("REPORT_CACHE_LIMIT", "50")),
)

MAX_URL_LENGTH = 4096
MAX_DOMAIN_LENGTH = 253

ALLOWED_EMAIL_EXTENSIONS = {".eml"}

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

_REPORT_CACHE: OrderedDict[str, object] = OrderedDict()


# ============================================================
# DATABASE AND REPORT HELPERS
# ============================================================

def _cache_report(report) -> str:
    report_id = uuid.uuid4().hex[:12]
    _REPORT_CACHE[report_id] = report

    while len(_REPORT_CACHE) > CACHE_LIMIT:
        _REPORT_CACHE.popitem(last=False)

    return report_id


def _get_cached_report(report_id: str):
    report = _REPORT_CACHE.get(report_id)

    if report is not None:
        _REPORT_CACHE.move_to_end(report_id)

    return report


def _build_dashboard():
    dashboard = get_dashboard_stats()
    dashboard["recent"] = list_recent_analyses(10)
    return dashboard


def _render_result(report):
    report_id = _cache_report(report)

    try:
        save_analysis(
            report,
            report_id=report_id,
        )
    except Exception:
        app.logger.exception(
            "Failed to persist analysis report %s",
            report_id,
        )

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


def _allowed_file(filename: str, analysis_type: str) -> bool:
    suffix = Path(filename).suffix.lower()

    if analysis_type == "email":
        return suffix in ALLOWED_EMAIL_EXTENSIONS

    if analysis_type == "attachment":
        return suffix not in BLOCKED_EXTENSIONS

    return False


def _save_uploaded_file(file_storage):
    original_name = secure_filename(
        file_storage.filename or "uploaded_file"
    )

    if not original_name:
        original_name = "uploaded_file"

    generated_name = f"{uuid.uuid4().hex}_{original_name}"
    saved_path = UPLOAD_DIR / generated_name
    file_storage.save(saved_path)

    return saved_path, original_name


def _remove_file(path: Path) -> None:
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
    app.logger.exception("%s analysis failed", analysis_type)

    flash(
        f"{analysis_type} analysis failed. "
        "Check the application log for details.",
        "error",
    )

    return redirect(url_for("index"))


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(RequestEntityTooLarge)
def handle_request_too_large(error):
    flash(
        f"That file is too large. The maximum upload size is "
        f"{MAX_UPLOAD_MB} MB.",
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
    app.logger.exception("Unhandled application error")

    flash(
        "An unexpected application error occurred.",
        "error",
    )

    return redirect(url_for("index")), 500


# ============================================================
# AUTHENTICATION
# ============================================================

@app.before_request
def require_toolkit_auth():
    # Minimal health endpoint for deployment monitoring.
    if request.path == "/health":
        return None

    # Authentication must be enabled explicitly in production.
    if APP_ENV == "production" and (
        os.environ.get("REQUIRE_AUTH", "").lower() != "true"
    ):
        app.logger.error(
            "Production authentication is not enabled."
        )
        return "Service authentication is not configured.", 503

    if os.environ.get("REQUIRE_AUTH", "false").lower() != "true":
        return None

    username = os.environ.get("TOOLKIT_USERNAME", "")
    password = os.environ.get("TOOLKIT_PASSWORD", "")

    if not username or not password:
        app.logger.error(
            "Authentication credentials are not configured."
        )
        return "Service authentication is not configured.", 503

    credentials = request.authorization

    valid = (
        credentials is not None
        and credentials.type.lower() == "basic"
        and hmac.compare_digest(
            credentials.username or "",
            username,
        )
        and hmac.compare_digest(
            credentials.password or "",
            password,
        )
    )

    if not valid:
        return (
            "Authentication required.",
            401,
            {
                "WWW-Authenticate":
                    'Basic realm="Phishing Analysis Toolkit"'
            },
        )

    return None


# ============================================================
# MAIN DASHBOARD
# ============================================================

@app.route("/")
def index():
    dashboard = _build_dashboard()

    return render_template(
        "index.html",
        dashboard=dashboard,
    )


# ============================================================
# EMAIL ANALYSIS
# ============================================================

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
        report.target = original_name

        return _render_result(report)

    except Exception as exc:
        return _handle_analyzer_error("Email", exc)

    finally:
        if saved_path:
            _remove_file(saved_path)


# ============================================================
# URL ANALYSIS
# ============================================================

@app.route("/analyze/url", methods=["POST"])
def analyze_url_route():
    target = request.form.get("url", "").strip()

    if not target:
        flash("Please enter a URL to analyze.", "error")
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
        return _handle_analyzer_error("URL", exc)


# ============================================================
# ATTACHMENT ANALYSIS
# ============================================================

@app.route("/analyze/attachment", methods=["POST"])
def analyze_attachment_route():
    file = request.files.get("attachment_file")

    if not file or not file.filename:
        flash("Please choose a file to analyze.", "error")
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
        report.target = original_name

        return _render_result(report)

    except Exception as exc:
        return _handle_analyzer_error("Attachment", exc)

    finally:
        if saved_path:
            _remove_file(saved_path)


# ============================================================
# DOMAIN ANALYSIS
# ============================================================

@app.route("/analyze/domain", methods=["POST"])
def analyze_domain_route():
    target = request.form.get("domain", "").strip()

    if not target:
        flash("Please enter a domain to analyze.", "error")
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
        return _handle_analyzer_error("Domain", exc)


# ============================================================
# JSON REPORT EXPORT
# ============================================================

@app.route("/report/<report_id>/json")
def download_report_json(report_id):
    report = _get_cached_report(report_id)

    if report is not None:
        try:
            data = report.to_dict()
        except Exception as exc:
            return _handle_analyzer_error("Report export", exc)

    else:
        try:
            stored = get_analysis_by_report_id(report_id)
        except Exception:
            app.logger.exception(
                "Failed to retrieve report %s from SQLite",
                report_id,
            )
            stored = None

        if stored is None:
            flash(
                "That report has expired or was never generated.",
                "error",
            )
            return redirect(url_for("index"))

        data = stored["report"]

    response = jsonify(data)
    response.headers["Content-Disposition"] = (
        f'attachment; filename="analysis-{report_id}.json"'
    )

    return response


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "phishing-analysis-toolkit",
    })


# ============================================================
# INCIDENT RESPONSE AND THREAT INTELLIGENCE API
# ============================================================

@app.route("/api/irt/overview")
def irt_overview():
    try:
        dashboard = get_dashboard_stats()
        recent = list_recent_analyses(10)

        return jsonify({
            "service": "phishing-analysis-toolkit",
            "module": "incident-response-and-threat-intelligence",
            "status": "ok",
            "statistics": dashboard,
            "recent_analyses": recent,
        })

    except Exception:
        app.logger.exception("IRT overview failed")

        return jsonify({
            "status": "error",
            "message": "Unable to retrieve incident response overview.",
        }), 500


@app.route("/api/irt/cases", methods=["GET"])
def irt_list_cases():
    try:
        raw_limit = request.args.get("limit", "50")

        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            return jsonify({
                "status": "error",
                "message": "Limit must be an integer.",
            }), 400

        if not 1 <= limit <= 100:
            return jsonify({
                "status": "error",
                "message": "Limit must be between 1 and 100.",
            }), 400

        cases = list_cases(limit)

        return jsonify({
            "status": "ok",
            "count": len(cases),
            "cases": cases,
        })

    except Exception:
        app.logger.exception("IRT case listing failed")

        return jsonify({
            "status": "error",
            "message": "Unable to retrieve cases.",
        }), 500


@app.route("/api/irt/cases/<int:case_id>", methods=["GET"])
def irt_get_case(case_id):
    try:
        case = get_case_by_id(case_id)

        if case is None:
            return jsonify({
                "status": "error",
                "message": "Case not found.",
            }), 404

        return jsonify({
            "status": "ok",
            "case": case,
        })

    except Exception:
        app.logger.exception("IRT case retrieval failed")

        return jsonify({
            "status": "error",
            "message": "Unable to retrieve case.",
        }), 500


@app.route("/api/irt/cases/<int:case_id>", methods=["PATCH"])
def irt_update_case(case_id):
    data = request.get_json(silent=True)

    if not isinstance(data, dict) or not data:
        return jsonify({
            "status": "error",
            "message": "Provide a non-empty JSON object.",
        }), 400

    allowed_fields = {
        "status",
        "priority",
        "analyst_notes",
    }

    if set(data) - allowed_fields:
        return jsonify({
            "status": "error",
            "message": "Unsupported fields provided.",
        }), 400

    if any(not isinstance(value, str) for value in data.values()):
        return jsonify({
            "status": "error",
            "message": "All field values must be strings.",
        }), 400

    try:
        case = update_case(
            case_id,
            status=data.get("status"),
            priority=data.get("priority"),
            analyst_notes=data.get("analyst_notes"),
        )

        if case is None:
            return jsonify({
                "status": "error",
                "message": "Case not found.",
            }), 404

        return jsonify({
            "status": "ok",
            "message": "Case updated successfully.",
            "case": case,
        })

    except ValueError as error:
        return jsonify({
            "status": "error",
            "message": str(error),
        }), 400

    except Exception:
        app.logger.exception("IRT case update failed")

        return jsonify({
            "status": "error",
            "message": "Unable to update case.",
        }), 500


# ============================================================
# LOCAL DEVELOPMENT SERVER
# ============================================================

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))

    debug = (
        os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    )

    if host != "127.0.0.1" and debug:
        raise RuntimeError(
            "Debug mode must not be enabled on a non-localhost address."
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
        " Dashboard:    Analyst Overview\n"
        " IRT API:      /api/irt/overview\n"
        " IRT Cases:    /api/irt/cases\n"
        "============================================================\n"
    )

    app.run(
        debug=debug,
        host=host,
        port=port,
    )
