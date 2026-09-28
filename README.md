# Phishing Analysis Toolkit

A defensive toolkit for analyzing suspicious emails, URLs, attachments, and
domains for phishing indicators. It provides both a command-line interface
(CLI) and a Flask web dashboard.

Designed for SOC, IT support, DFIR, and security-learning workflows.

## Features

- **Email analysis** — parses `.eml` files and checks headers, sender
  mismatches, suspicious language, and embedded links.
- **URL analysis** — checks URL structure, IP-based hosts, suspicious TLDs,
  URL shorteners, excessive subdomains, and common phishing patterns.
- **Attachment analysis** — calculates MD5, SHA1, and SHA256 hashes and checks
  filenames/extensions for suspicious characteristics. Files are not executed.
- **Domain analysis** — performs best-effort WHOIS and DNS checks when the
  optional dependencies and network access are available.
- **Risk scoring** — produces a readable analysis report with findings and
  severity information.
- **VirusTotal integration** — optional reputation checks using `VT_API_KEY`.

## Project structure

```text
phishing-toolkit/
├── main.py
├── app.py
├── analyzers/
│   ├── __init__.py
│   ├── attachment_analyzer.py
│   ├── domain_analyzer.py
│   ├── email_analyzer.py
│   ├── url_analyzer.py
│   └── virustotal_analyzer.py
├── utils/
│   ├── __init__.py
│   ├── report.py
│   └── recommendations.py
├── templates/
├── static/
├── samples/
├── uploads/
├── .env.example
├── .gitignore
├── Procfile
├── render.yaml
└── requirements.txt