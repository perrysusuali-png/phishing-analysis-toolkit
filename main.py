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
import sys

from dotenv import load_dotenv
load_dotenv()

from analyzers.email_analyzer import analyze_email
from analyzers.url_analyzer import analyze_url
from analyzers.attachment_analyzer import analyze_attachment
from analyzers.domain_analyzer import analyze_domain


def main():
    parser = argparse.ArgumentParser(
        prog="phishing-toolkit",
        description="Static, local analysis of emails, URLs, attachments, and domains for phishing indicators.",
    )
    parser.add_argument("--report", metavar="PATH", help="Export the report as JSON to this path")

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_email = subparsers.add_parser("email", help="Analyze a .eml email file")
    p_email.add_argument("path", help="Path to the .eml file")

    p_url = subparsers.add_parser("url", help="Analyze a single URL")
    p_url.add_argument("target", help="The URL to analyze")

    p_attach = subparsers.add_parser("attachment", help="Analyze a file attachment")
    p_attach.add_argument("path", help="Path to the file")

    p_domain = subparsers.add_parser("domain", help="Analyze a domain (WHOIS + DNS)")
    p_domain.add_argument("target", help="The domain to analyze")

    args = parser.parse_args()

    try:
        if args.command == "email":
            report = analyze_email(args.path)
        elif args.command == "url":
            report = analyze_url(args.target)
        elif args.command == "attachment":
            report = analyze_attachment(args.path)
        elif args.command == "domain":
            report = analyze_domain(args.target)
        else:
            parser.print_help()
            sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    report.print_summary()

    if args.report:
        report.export_json(args.report)


if __name__ == "__main__":
    main()
