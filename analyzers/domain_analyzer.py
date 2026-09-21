"""WHOIS/DNS-based domain intel. Degrades gracefully without optional deps or network."""

from datetime import datetime, timezone

from utils.report import AnalysisReport
from analyzers import virustotal_analyzer

try:
    import whois  # python-whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


def analyze_domain(domain):
    domain = domain.lower().strip().removeprefix("http://").removeprefix("https://").split("/")[0]
    report = AnalysisReport(domain, "Domain")

    if not HAS_WHOIS:
        report.add(
            "python-whois not installed — skipping domain age check "
            "(pip install python-whois)",
            0, "info",
        )
    else:
        try:
            w = whois.whois(domain)
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - created).days
                report.add(f"Domain created: {created.date()} ({age_days} days ago)", 0, "metadata")
                if age_days < 30:
                    report.add(f"Domain is very new ({age_days} days old) — common in phishing campaigns", 35, "domain-age")
                elif age_days < 180:
                    report.add(f"Domain is relatively new ({age_days} days old)", 15, "domain-age")
            else:
                report.add("Could not determine domain creation date from WHOIS", 5, "info")

            registrar = getattr(w, "registrar", None)
            if registrar:
                report.add(f"Registrar: {registrar}", 0, "metadata")
        except Exception as e:
            report.add(f"WHOIS lookup failed: {e}", 0, "info")

    if not HAS_DNS:
        report.add(
            "dnspython not installed — skipping DNS record checks "
            "(pip install dnspython)",
            0, "info",
        )
    else:
        try:
            mx_records = dns.resolver.resolve(domain, "MX", lifetime=5)
            report.add(f"Has {len(mx_records)} MX record(s) configured", 0, "metadata")
        except Exception:
            report.add("No MX records found — domain cannot receive mail (unusual for a legit business)", 10, "dns")

        try:
            dns.resolver.resolve(domain, "TXT", lifetime=5)
        except Exception:
            report.add("No TXT records found (SPF/DMARC policies typically live here)", 10, "dns")

    if virustotal_analyzer.is_configured():
        vt_result = virustotal_analyzer.check_domain(domain)
        virustotal_analyzer.add_vt_finding(report, vt_result)

    return report
