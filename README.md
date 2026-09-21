# Phishing Analysis Toolkit

A CLI toolkit for analyzing suspicious emails, URLs, attachments, and domains for
phishing indicators. Built for defenders — SOC analysts, IT admins, or anyone
triaging a suspicious email.

## Features

- **Email analysis** — parses `.eml` files: header spoofing checks (SPF/DKIM/DMARC
  presence, From/Reply-To/Return-Path mismatches), suspicious keyword/urgency
  detection, and extraction of embedded links.
- **URL analysis** — flags URL shorteners, IP-address-as-hostname links,
  suspicious TLDs, excessive subdomains, homoglyph/typosquat similarity against a
  list of common brand domains, and `@`-symbol/redirect tricks.
- **Attachment analysis** — hashes files (MD5/SHA1/SHA256), flags risky
  extensions (double extensions, executables disguised as documents), and does
  basic macro-indicator detection for Office files.
- **Domain intel** — WHOIS age lookup and basic DNS record checks (best-effort;
  degrades gracefully if `python-whois`/`dnspython` aren't installed or there's
  no network access).
- **Risk scoring** — every analysis produces a 0–100 risk score with a
  human-readable breakdown, and can export a JSON report.

## Setup

```bash
cd phishing-toolkit
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Open the folder in VS Code:

```bash
code .
```

Recommended VS Code extensions: **Python** (ms-python.python) and **Pylance**.

## VirusTotal integration (optional)

Every analyzer checks VirusTotal's database automatically once you provide
a free API key — no code changes needed.

1. Get a free key at https://www.virustotal.com/gui/join-us
2. Copy `.env.example` to `.env` and paste your key in:
   ```
   VT_API_KEY=your_key_here
   ```
3. Run the toolkit as usual (CLI or `app.py`) — VT checks kick in automatically.

Without a key, the toolkit works exactly as before (heuristics only) and
stays silent about VirusTotal — nothing is required to use it.

**What gets checked, and how:**
- URLs: looked up by URL, or submitted for a first-time scan if VirusTotal hasn't seen it.
- Attachments: only the file's **SHA256 hash** is sent — the file itself is never uploaded.
- Domains: looked up directly.
- Emails: the single riskiest embedded link (by heuristic score) gets one VT check, so a long email with many links doesn't trigger dozens of slow lookups.

**Rate limits:** the free tier allows 4 requests/minute and 500/day. The
toolkit self-throttles (a shared, thread-safe limiter) so it never exceeds
this, even with multiple people using the web dashboard at once — a check
can occasionally take a few extra seconds while it waits its turn.

## Deploying online (Render — free, public URL)

This project is ready to deploy as-is to [Render](https://render.com), a
free host with no credit card required. Your PC doesn't need to stay on —
Render runs it for you.

1. **Push this project to GitHub** (if it isn't already):
   ```bash
   git init
   git add .
   git commit -m "Phishing analysis toolkit"
   ```
   Create a new empty repo on https://github.com/new, then:
   ```bash
   git remote add origin https://github.com/<your-username>/<repo-name>.git
   git branch -M main
   git push -u origin main
   ```

2. **Create a free Render account** at https://render.com (GitHub sign-in is easiest).

3. **New + → Blueprint**, connect the repo you just pushed. Render reads
   `render.yaml` in this project automatically and configures everything —
   build command, start command, and a securely auto-generated
   `TOOLKIT_SECRET_KEY`.

   *(No `render.yaml` support, or you'd rather do it manually? New + → Web
   Service → connect the repo → Build Command: `pip install -r
   requirements.txt` → Start Command: `gunicorn app:app --bind
   0.0.0.0:$PORT`.)*

4. In the service's **Environment** tab, add your `VT_API_KEY` (Render
   prompts for this since it's marked secret in the blueprint and won't be
   stored in the repo). Confirm `FLASK_DEBUG` is `false`.

5. Deploy. Render gives you a live `https://<something>.onrender.com` URL —
   share that with whoever needs it.

**Good to know about the free tier:**
- It sleeps after 15 minutes with no traffic; the next visit takes about a
  minute to wake up. This is normal, not a bug.
- 750 free instance-hours/month — enough to stay live continuously all month.
- Uploaded files are always deleted right after analysis (same as local use),
  so the platform's ephemeral storage isn't an issue. The exported-JSON
  cache resets on restart, so a report link from before a sleep/wake cycle
  may say "expired" — just re-run the analysis.

## Web Dashboard (local)

A local Flask dashboard is included as an alternative to the CLI — same
analyzers underneath, with a browser UI.

```bash
py app.py            # Windows
python3 app.py        # macOS/Linux
```

Then open **http://127.0.0.1:5000** in your browser. Four tabs let you
upload an email or attachment, or paste a URL/domain, and see the risk score
and findings rendered live. Uploaded files are deleted from disk immediately
after analysis. Each result page has an "Export JSON" link.

This is for local/personal use only — `app.run(debug=True)` is not meant to
be exposed on a network or the internet.

## CLI Usage

```bash
# Analyze an email file (.eml)
python main.py email samples/sample_phishing.eml

# Analyze a single URL
python main.py url "http://paypa1-secure.tk/login"

# Analyze a file attachment
python main.py attachment path/to/file.docx

# Analyze a domain
python main.py domain suspicious-domain.com

# Full email analysis + export JSON report
python main.py email samples/sample_phishing.eml --report report.json
```

## Project layout

```
phishing-toolkit/
├── main.py                     # CLI entry point (argparse)
├── app.py                      # Flask web dashboard entry point
├── analyzers/
│   ├── email_analyzer.py       # .eml parsing + header/content checks
│   ├── url_analyzer.py         # URL heuristics + typosquat detection
│   ├── attachment_analyzer.py  # File hashing + risk flags
│   ├── domain_analyzer.py      # WHOIS + DNS lookups
│   └── virustotal_analyzer.py  # Optional VirusTotal reputation checks
├── utils/
│   └── report.py               # Risk scoring + report formatting/export
├── templates/                  # Dashboard HTML (Jinja2)
├── static/style.css            # Dashboard styling
├── uploads/                    # Scratch space for uploads (auto-cleared)
├── samples/
│   └── sample_phishing.eml     # Example email to test against
├── .vscode/                    # Debug configs for one-click F5 runs
├── .env.example                # Copy to .env and add your VirusTotal API key
├── Procfile                    # Production start command (Render/Railway)
├── render.yaml                 # Render Blueprint — one-click deploy config
├── .gitignore
└── requirements.txt
```

## Notes

- This tool does **static, local analysis only** — it never submits files or
  URLs to third-party services, so it's safe to run against live phishing
  samples without tipping off an attacker.
- WHOIS/DNS checks require internet access and the optional dependencies; the
  tool runs fine without them, just with that section skipped.
- This is a triage aid, not a verdict. Always corroborate findings before
  acting on them.
