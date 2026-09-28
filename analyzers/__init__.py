"""
Phishing Analysis Toolkit - Analyzer Package.

This package provides the public analyzer API for analyzing:

    - Email messages (.eml)
    - URLs
    - Domains
    - Attachments/files

Each analyzer returns a report object that should expose:

    - print_summary()
    - export_json()
    - to_dict()

Example
-------
    from analyzers import analyze_url

    report = analyze_url("https://example.com")
    report.print_summary()

You can also import individual analyzers directly:

    from analyzers.url_analyzer import analyze_url
"""

from __future__ import annotations

from .attachment_analyzer import analyze_attachment
from .domain_analyzer import analyze_domain
from .email_analyzer import analyze_email
from .url_analyzer import analyze_url


# ---------------------------------------------------------------------------
# Package metadata
# ---------------------------------------------------------------------------

__version__ = "2.0.0"
__author__ = "Perry Susuali"
__description__ = "Defensive phishing analysis and triage toolkit"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "analyze_attachment",
    "analyze_domain",
    "analyze_email",
    "analyze_url",
]


# ---------------------------------------------------------------------------
# Analyzer registry
# ---------------------------------------------------------------------------
#
# This gives the application a consistent way to discover supported
# analyzers without changing the existing public API.
#
# Example:
#
#     from analyzers import ANALYZERS
#     analyzer = ANALYZERS["url"]
#     report = analyzer("https://example.com")
#
# ---------------------------------------------------------------------------

ANALYZERS = {
    "attachment": analyze_attachment,
    "domain": analyze_domain,
    "email": analyze_email,
    "url": analyze_url,
}


# ---------------------------------------------------------------------------
# Supported analyzer types
# ---------------------------------------------------------------------------

SUPPORTED_ANALYZERS = tuple(ANALYZERS.keys())


def get_analyzer(name: str):
    """
    Return an analyzer function by name.

    Parameters
    ----------
    name:
        Analyzer name. Supported values are:

            attachment
            domain
            email
            url

    Returns
    -------
    callable
        The corresponding analyzer function.

    Raises
    ------
    ValueError
        If the requested analyzer does not exist.

    Examples
    --------
    >>> analyzer = get_analyzer("url")
    >>> report = analyzer("https://example.com")
    """

    if not isinstance(name, str):
        raise TypeError("Analyzer name must be a string.")

    normalized_name = name.strip().lower()

    try:
        return ANALYZERS[normalized_name]
    except KeyError as exc:
        supported = ", ".join(SUPPORTED_ANALYZERS)

        raise ValueError(
            f"Unknown analyzer '{name}'. "
            f"Supported analyzers: {supported}"
        ) from exc


def list_analyzers() -> list[str]:
    """
    Return a list of all supported analyzer names.

    Returns
    -------
    list[str]
        Names of available analyzers.
    """

    return list(SUPPORTED_ANALYZERS)