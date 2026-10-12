
"""WHOIS and DNS domain intelligence with graceful error handling."""

from datetime import datetime, timezone

from utils.report import AnalysisReport
from analyzers import virustotal_analyzer

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


def analyze_domain(domain):
    domain = (
        domain.lower()
        .strip()
        .removeprefix("http://")
        .removeprefix("https://")
        .split("/")[0]
        .split("?")[0]
        .strip()
    )

    report = AnalysisReport(domain, "Domain")

    if not domain:
        report.add("No domain was provided", 0, "input")
        return report

    if not HAS_WHOIS:
        report.add(
            "python-whois is not installed; skipping domain age check",
            0,
            "info",
        )
    else:
        try:
            whois_result = whois.whois(domain)
            created = whois_result.creation_date

            if isinstance(created, list):
                created = next(
                    (item for item in created if isinstance(item, datetime)),
                    None,
                )

            if isinstance(created, datetime):
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)

                age_days = (
                    datetime.now(timezone.utc) - created.astimezone(timezone.utc)
                ).days

                report.add(
                    f"Domain created: {created.date()} ({age_days} days ago)",
                    0,
                    "metadata",
                )

                if 0 <= age_days < 30:
                    report.add(
                        f"Domain is very new ({age_days} days old)",
                        35,
                        "domain-age",
                    )
                elif 30 <= age_days < 180:
                    report.add(
                        f"Domain is relatively new ({age_days} days old)",
                        15,
                        "domain-age",
                    )
            else:
                report.add(
                    "Could not determine domain creation date from WHOIS",
                    5,
                    "info",
                )

            registrar = getattr(whois_result, "registrar", None)
            if registrar:
                report.add(f"Registrar: {registrar}", 0, "metadata")

        except Exception as exc:
            report.add(f"WHOIS lookup failed: {exc}", 0, "info")

    if not HAS_DNS:
        report.add(
            "dnspython is not installed; skipping DNS record checks",
            0,
            "info",
        )
    else:
        try:
            mx_records = dns.resolver.resolve(domain, "MX", lifetime=5)
            report.add(
                f"Has {len(mx_records)} MX record(s) configured",
                0,
                "metadata",
            )
        except Exception:
            report.add(
                "MX lookup failed or no MX records were found",
                10,
                "dns",
            )

        try:
            txt_records = dns.resolver.resolve(domain, "TXT", lifetime=5)
            report.add(
                f"Has {len(txt_records)} TXT record(s) configured",
                0,
                "metadata",
            )
        except Exception:
            report.add(
                "TXT lookup failed or no TXT records were found; SPF and DMARC policies could not be verified",
                10,
                "dns",
            )

    if virustotal_analyzer.is_configured():
        try:
            vt_result = virustotal_analyzer.check_domain(domain)
            virustotal_analyzer.add_vt_finding(report, vt_result)
        except Exception as exc:
            report.add(
                f"VirusTotal domain lookup failed: {exc}",
                0,
                "info",
            )

    return report
