"""Static analysis of file attachments for phishing/malware indicators."""

import hashlib
import os
import re
import zipfile

from utils.report import AnalysisReport
from analyzers import virustotal_analyzer

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".ps1", ".msi", ".jar", ".hta", ".lnk",
}

DOCUMENT_EXTENSIONS = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf"}

MACRO_ENABLED_EXTENSIONS = {".docm", ".xlsm", ".pptm"}


def _hash_file(path):
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            for h in hashes.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashes.items()}


def analyze_attachment(path):
    report = AnalysisReport(path, "Attachment")

    if not os.path.isfile(path):
        report.add(f"File not found: {path}", 0, "error")
        return report

    filename = os.path.basename(path)
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    size = os.path.getsize(path)

    hashes = _hash_file(path)
    for name, value in hashes.items():
        report.add(f"{name.upper()}: {value}", 0, "metadata")

    report.add(f"File size: {size:,} bytes", 0, "metadata")

    # Double extension trick: invoice.pdf.exe
    name_parts = filename.split(".")
    if len(name_parts) > 2:
        second_ext = "." + name_parts[-2].lower()
        if second_ext in DOCUMENT_EXTENSIONS and ext in DANGEROUS_EXTENSIONS:
            report.add(
                f"Double extension disguise: appears to be '{second_ext}' but is actually '{ext}'",
                50, "disguise",
            )

    # Directly dangerous extension
    if ext in DANGEROUS_EXTENSIONS:
        report.add(f"Executable/script file type ({ext}) — high risk as an email attachment", 40, "file-type")

    # Macro-enabled Office formats
    if ext in MACRO_ENABLED_EXTENSIONS:
        report.add(f"Macro-enabled Office format ({ext}) — can execute code on open", 30, "macro")

    # Modern .docx/.xlsx/.pptx are zip archives — check for embedded macro project
    if ext in {".docx", ".xlsx", ".pptx"} and zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
                if any("vbaProject.bin" in n for n in names):
                    report.add(
                        "Contains an embedded VBA macro project despite non-macro extension",
                        45, "macro",
                    )
                if any(re.search(r"\.(exe|scr|js|vbs)$", n, re.I) for n in names):
                    report.add("Archive contains an embedded executable/script file", 45, "embedded")
        except Exception:
            pass

    # Generic zip/archive inspection
    if ext in {".zip", ".rar", ".7z"} and zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    inner_ext = os.path.splitext(name)[1].lower()
                    if inner_ext in DANGEROUS_EXTENSIONS:
                        report.add(f"Archive contains a risky file: {name}", 40, "embedded")
        except Exception:
            report.add("Could not open archive for inspection (may be corrupt or password-protected)", 15, "error")

    # Suspiciously generic/urgent filenames
    if re.search(r"(invoice|receipt|statement|urgent|payment|refund|ticket)", filename, re.I):
        report.add(f"Filename uses a common social-engineering lure pattern: '{filename}'", 10, "naming")

    if size == 0:
        report.add("File is empty (0 bytes)", 5, "metadata")

    if virustotal_analyzer.is_configured():
        vt_result = virustotal_analyzer.check_file_hash(hashes["sha256"])
        virustotal_analyzer.add_vt_finding(report, vt_result)

    return report
