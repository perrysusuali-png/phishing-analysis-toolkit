"""Maps a report's verdict + analysis type to plain-language next steps.

Kept separate from the analyzers themselves so the advice can be tuned
independently of the detection logic.
"""

_GENERAL_HYGIENE = [
    "Never enter a password or payment details after clicking a link from an unsolicited message.",
    "When in doubt, go to the site directly by typing the address yourself, not by clicking the link.",
    "Verify unexpected requests (money, credentials, urgent action) through a second channel — call the person or company using a number you already trust.",
]

_ALREADY_CLICKED_LINK = [
    "Don't enter any information on the page — close the tab now.",
    "If you already entered a password there, change it immediately on the real site, and change it anywhere else you reused it.",
    "Turn on two-factor authentication on the affected account if it isn't already on.",
]

_ALREADY_OPENED_ATTACHMENT = [
    "Disconnect the device from Wi-Fi/network now to limit any spread.",
    "Run a full scan with your antivirus/endpoint protection.",
    "Notify your IT or security team so they can check for further compromise.",
    "Change passwords used on that device, from a different, clean device.",
]

_REPORT_STEPS = {
    "Email": [
        "Report the email using your mail client's 'Report phishing' button, if it has one.",
        "Forward it to your organization's IT/security team, then delete it.",
        "Block the sender to prevent follow-up messages.",
    ],
    "URL": [
        "Report the URL to Google Safe Browsing (safebrowsing.google.com/safebrowsing/report_phish/) so it gets flagged for other users.",
        "If it arrived via email or message, report and delete that message too.",
    ],
    "Attachment": [
        "Delete the file without opening it.",
        "Report the message it came with to your IT/security team.",
    ],
    "Domain": [
        "Report the domain to its registrar's abuse contact if you have one (often found via a WHOIS lookup).",
        "Add the domain to your organization's blocklist (firewall/DNS filter) if you manage one.",
    ],
}

_DO_NOT = {
    "Email": "Don't click any links or open any attachments in this email, and don't reply to it.",
    "URL": "Don't visit this link, and don't enter any credentials or personal information on it.",
    "Attachment": "Don't open this file, and don't enable macros or 'editing' if a warning appears.",
    "Domain": "Don't enter credentials or personal information on this domain.",
}


def get_recommendations(analysis_type, verdict):
    """Returns a dict with 'immediate' and 'if_already_interacted' step lists."""

    if verdict in ("HIGH RISK", "SUSPICIOUS"):
        immediate = [_DO_NOT.get(analysis_type, "Don't interact with this further.")]
        immediate.extend(_REPORT_STEPS.get(analysis_type, []))

        already = []
        if analysis_type in ("Email", "URL", "Domain"):
            already.extend(_ALREADY_CLICKED_LINK)
        if analysis_type in ("Email", "Attachment"):
            already.extend(_ALREADY_OPENED_ATTACHMENT)
        # de-duplicate while preserving order
        seen = set()
        already = [x for x in already if not (x in seen or seen.add(x))]

        return {"immediate": immediate, "if_already_interacted": already}

    # LOW RISK / NO INDICATORS FOUND — lighter-touch guidance
    return {
        "immediate": [
            "No strong indicators were found, but automated analysis isn't a guarantee — stay cautious if anything about it still feels off.",
        ] + _GENERAL_HYGIENE,
        "if_already_interacted": [],
    }
