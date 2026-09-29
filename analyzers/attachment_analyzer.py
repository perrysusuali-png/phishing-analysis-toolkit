
"""Static analysis of file attachments for phishing/malware indicators."""

import hashlib
import os
import re
import zipfile

from utils.report import AnalysisReport
from analyzers import virustotal_analyzer


DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".com",
    ".pif",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".ps1",
    ".msi",
    ".jar",
    ".hta",
    ".lnk",
}

DOCUMENT_EXTENSIONS = {
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".pdf",
    ".rtf",
}

MACRO_ENABLED_EXTENSIONS = {
    ".docm",
    ".xlsm",
    ".pptm",
}


def _hash_file(path):
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }

    with open(path, "rb") as fh:
        for chunk in iter(
            lambda: fh.read(65536),
            b"",
        ):
            for hash_object in hashes.values():
                hash_object.update(chunk)

    return {
        name: hash_object.hexdigest()
        for name, hash_object in hashes.items()
    }


def analyze_attachment(path):
    report = AnalysisReport(
        path,
        "Attachment",
    )

    if not os.path.isfile(path):
        report.add(
            f"File not found: {path}",
            0,
            "error",
        )
        return report

    filename = os.path.basename(path)

    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    size = os.path.getsize(path)

    # Calculate file hashes once and reuse them
    # for metadata, IOC extraction, and VirusTotal.
    hashes = _hash_file(path)

    # Store hashes as structured IOCs.
    report.add_indicators(
        {
            "urls": [],
            "domains": [],
            "ip_addresses": [],
            "emails": [],
            "file_hashes": {
                "md5": [hashes["md5"]],
                "sha1": [hashes["sha1"]],
                "sha256": [hashes["sha256"]],
            },
        }
    )

    for name, value in hashes.items():
        report.add(
            f"{name.upper()}: {value}",
            0,
            "metadata",
        )

    report.add(
        f"File size: {size:,} bytes",
        0,
        "metadata",
    )

    # Double extension trick: invoice.pdf.exe
    name_parts = filename.split(".")

    if len(name_parts) > 2:
        second_ext = (
            "."
            + name_parts[-2].lower()
        )

        if (
            second_ext in DOCUMENT_EXTENSIONS
            and ext in DANGEROUS_EXTENSIONS
        ):
            report.add(
                f"Double extension disguise: appears to be "
                f"'{second_ext}' but is actually '{ext}'",
                50,
                "disguise",
            )

    # Directly dangerous extension
    if ext in DANGEROUS_EXTENSIONS:
        report.add(
            f"Executable/script file type ({ext}) "
            "— high risk as an email attachment",
            40,
            "file-type",
        )

    # Macro-enabled Office formats
    if ext in MACRO_ENABLED_EXTENSIONS:
        report.add(
            f"Macro-enabled Office format ({ext}) "
            "— can execute code on open",
            30,
            "macro",
        )

    # Modern Office formats are ZIP archives.
    # Check for embedded macro projects.
    if (
        ext in {".docx", ".xlsx", ".pptx"}
        and zipfile.is_zipfile(path)
    ):
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()

                if any(
                    "vbaProject.bin" in name
                    for name in names
                ):
                    report.add(
                        "Contains an embedded VBA macro "
                        "project despite non-macro extension",
                        45,
                        "macro",
                    )

                if any(
                    re.search(
                        r"\.(exe|scr|js|vbs)$",
                        name,
                        re.IGNORECASE,
                    )
                    for name in names
                ):
                    report.add(
                        "Archive contains an embedded "
                        "executable/script file",
                        45,
                        "embedded",
                    )

        except Exception:
            pass

    # Generic ZIP/archive inspection
    if (
        ext in {".zip", ".rar", ".7z"}
        and zipfile.is_zipfile(path)
    ):
        try:
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    inner_ext = (
                        os.path.splitext(name)[1]
                        .lower()
                    )

                    if (
                        inner_ext
                        in DANGEROUS_EXTENSIONS
                    ):
                        report.add(
                            f"Archive contains a risky file: "
                            f"{name}",
                            40,
                            "embedded",
                        )

        except Exception:
            report.add(
                "Could not open archive for inspection "
                "(may be corrupt or password-protected)",
                15,
                "error",
            )

    # Suspiciously generic/urgent filenames
    if re.search(
        r"(invoice|receipt|statement|urgent|payment|refund|ticket)",
        filename,
        re.IGNORECASE,
    ):
        report.add(
            f"Filename uses a common social-engineering "
            f"lure pattern: '{filename}'",
            10,
            "naming",
        )

    if size == 0:
        report.add(
            "File is empty (0 bytes)",
            5,
            "metadata",
        )

    # Optional VirusTotal hash reputation check.
    # This checks the hash rather than uploading the file.
    if virustotal_analyzer.is_configured():
        vt_result = (
            virustotal_analyzer.check_file_hash(
                hashes["sha256"]
            )
        )

        virustotal_analyzer.add_vt_finding(
            report,
            vt_result,
        )

    return report
