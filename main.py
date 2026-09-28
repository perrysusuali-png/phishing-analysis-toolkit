#!/usr/bin/env python3
"""
Phishing Analysis Toolkit — CLI entry point.

Usage:
    python main.py email <path.eml> [--report out.json]
    python main.py url <url> [--report out.json]
    python main.py attachment <path> [--report out.json]
    python main.py domain <domain> [--report out.json]
"""

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from analyzers.email_analyzer import analyze_email
from analyzers.url_analyzer import analyze_url
from analyzers.attachment_analyzer import analyze_attachment
from analyzers.domain_analyzer import analyze_domain


VERSION = "1.0.0"
MAX_URL_LENGTH = 4096
MAX_DOMAIN_LENGTH = 253


def build_parser():
    parser = argparse.ArgumentParser(
        prog="phishing-toolkit",
        description=(
            "Static, local analysis of emails, URLs, attachments, "
            "and domains for phishing indicators."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    parser.add_argument(
        "--report",
        metavar="PATH",
        help="Export the analysis report as JSON to this path.",
    )

    parser.add_argument(
        "--no-vt",
        action="store_true",
        help="Disable VirusTotal lookups for this run.",
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the normal report summary.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    p_email = subparsers.add_parser(
        "email",
        help="Analyze a .eml email file.",
    )
    p_email.add_argument(
        "path",
        help="Path to the .eml file.",
    )

    p_url = subparsers.add_parser(
        "url",
        help="Analyze a single URL.",
    )
    p_url.add_argument(
        "target",
        help="The URL to analyze.",
    )

    p_attach = subparsers.add_parser(
        "attachment",
        help="Analyze a file attachment.",
    )
    p_attach.add_argument(
        "path",
        help="Path to the file.",
    )

    p_domain = subparsers.add_parser(
        "domain",
        help="Analyze a domain.",
    )
    p_domain.add_argument(
        "target",
        help="The domain to analyze.",
    )

    return parser


def validate_file(path_string):
    path = Path(path_string).expanduser()

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")

    return path


def validate_report_path(path_string):
    path = Path(path_string).expanduser()

    if path.exists() and path.is_dir():
        raise ValueError(f"Report path is a directory: {path}")

    parent = path.parent

    if not parent.exists():
        raise ValueError(
            f"Report directory does not exist: {parent}"
        )

    return path


def validate_url(target):
    target = target.strip()

    if not target:
        raise ValueError("URL cannot be empty.")

    if len(target) > MAX_URL_LENGTH:
        raise ValueError(
            f"URL is too long. Maximum length is {MAX_URL_LENGTH} characters."
        )

    return target


def validate_domain(target):
    target = target.strip().rstrip(".")

    if not target:
        raise ValueError("Domain cannot be empty.")

    if len(target) > MAX_DOMAIN_LENGTH:
        raise ValueError(
            f"Domain is too long. Maximum length is {MAX_DOMAIN_LENGTH} characters."
        )

    return target


def print_cli_header():
    print("=" * 60)
    print(f"Phishing Analysis Toolkit v{VERSION}")
    print("=" * 60)


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.no_vt:
        os.environ.pop("VT_API_KEY", None)

    try:
        if args.command == "email":
            target = validate_file(args.path)
            report = analyze_email(str(target))

        elif args.command == "url":
            target = validate_url(args.target)
            report = analyze_url(target)

        elif args.command == "attachment":
            target = validate_file(args.path)
            report = analyze_attachment(str(target))

        elif args.command == "domain":
            target = validate_domain(args.target)
            report = analyze_domain(target)

        else:
            parser.print_help()
            return 2

    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    except KeyboardInterrupt:
        print("\nAnalysis cancelled.", file=sys.stderr)
        return 130

    except Exception as exc:
        print(
            f"Analysis failed: {exc}",
            file=sys.stderr,
        )
        return 1

    print_cli_header()

    if not args.quiet:
        report.print_summary()

    if args.report:
        try:
            report_path = validate_report_path(args.report)
            report.export_json(str(report_path))
            print(f"\nReport exported to: {report_path}")
        except (ValueError, OSError) as exc:
            print(
                f"Could not export report: {exc}",
                file=sys.stderr,
            )
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())