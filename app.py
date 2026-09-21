#!/usr/bin/env python3
"""
Phishing Analysis Toolkit — Web Dashboard.

Run with:
    py app.py         (Windows, using the py launcher)
    python3 app.py     (macOS/Linux)

Then open http://127.0.0.1:5000 in your browser.

This is a local-only tool intended for personal/analyst use on a trusted
machine — it is NOT hardened for exposure on a public network.
"""

import os
import uuid

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file

from analyzers.email_analyzer import analyze_email
from analyzers.url_analyzer import analyze_url
from analyzers.attachment_analyzer import analyze_attachment
from analyzers.domain_analyzer import analyze_domain
from utils.recommendations import get_recommendations

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("TOOLKIT_SECRET_KEY", "dev-only-change-me")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB upload cap
# Werkzeug 3.1+ added its own default limits (500 KB form memory, 1000 form
# parts) that can trigger a 413 well before MAX_CONTENT_LENGTH is reached.
# Raise them explicitly so a normal-sized email/attachment upload isn't rejected.
app.config["MAX_FORM_MEMORY_SIZE"] = 25 * 1024 * 1024
app.config["MAX_FORM_PARTS"] = 10_000

# In-memory store of the last few reports, keyed by a short id, so results
# survive a page reload / JSON export without needing a database.
_REPORT_CACHE = {}
_CACHE_LIMIT = 50


def _cache_report(report):
    report_id = uuid.uuid4().hex[:10]
    if len(_REPORT_CACHE) >= _CACHE_LIMIT:
        oldest = next(iter(_REPORT_CACHE))
        _REPORT_CACHE.pop(oldest)
    _REPORT_CACHE[report_id] = report
    return report_id


def _render_result(report):
    report_id = _cache_report(report)
    recommendations = get_recommendations(report.analysis_type, report.verdict)
    return render_template("result.html", report=report, report_id=report_id, recommendations=recommendations)


@app.errorhandler(413)
def too_large(e):
    flash("That file is too large. This toolkit accepts files up to 25 MB.", "error")
    return redirect(url_for("index")), 413


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze/email", methods=["POST"])
def analyze_email_route():
    file = request.files.get("eml_file")
    if not file or file.filename == "":
        flash("Please choose a .eml file to analyze.", "error")
        return redirect(url_for("index"))

    safe_name = f"{uuid.uuid4().hex[:8]}_{os.path.basename(file.filename)}"
    saved_path = os.path.join(UPLOAD_DIR, safe_name)
    file.save(saved_path)

    try:
        report = analyze_email(saved_path)
    finally:
        try:
            os.remove(saved_path)
        except OSError:
            pass

    return _render_result(report)


@app.route("/analyze/url", methods=["POST"])
def analyze_url_route():
    target = request.form.get("url", "").strip()
    if not target:
        flash("Please enter a URL to analyze.", "error")
        return redirect(url_for("index"))

    report = analyze_url(target)
    return _render_result(report)


@app.route("/analyze/attachment", methods=["POST"])
def analyze_attachment_route():
    file = request.files.get("attachment_file")
    if not file or file.filename == "":
        flash("Please choose a file to analyze.", "error")
        return redirect(url_for("index"))

    safe_name = f"{uuid.uuid4().hex[:8]}_{os.path.basename(file.filename)}"
    saved_path = os.path.join(UPLOAD_DIR, safe_name)
    file.save(saved_path)

    try:
        report = analyze_attachment(saved_path)
        # Keep the target label as the original filename, not the temp path
        report.target = file.filename
    finally:
        try:
            os.remove(saved_path)
        except OSError:
            pass

    return _render_result(report)


@app.route("/analyze/domain", methods=["POST"])
def analyze_domain_route():
    target = request.form.get("domain", "").strip()
    if not target:
        flash("Please enter a domain to analyze.", "error")
        return redirect(url_for("index"))

    report = analyze_domain(target)
    return _render_result(report)


@app.route("/report/<report_id>/json")
def download_report_json(report_id):
    report = _REPORT_CACHE.get(report_id)
    if not report:
        flash("That report has expired or was never generated.", "error")
        return redirect(url_for("index"))
    return jsonify(report.to_dict())


if __name__ == "__main__":
    # HOST=127.0.0.1 (default) only allows this PC to open the dashboard.
    # HOST=0.0.0.0 lets other devices on the same network reach it, at
    # http://<this-PC's-local-IP>:5000 — see README for how to find that IP
    # and important security notes before doing this.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "true").lower() == "true"

    if host != "127.0.0.1" and debug:
        print(
            "WARNING: running with debug=True while bound to a non-localhost host "
            "exposes the interactive debugger to your network. Set FLASK_DEBUG=false "
            "in your .env before doing this outside a trusted LAN."
        )

    app.run(debug=debug, host=host, port=port)
