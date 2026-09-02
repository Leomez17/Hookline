"""Maps triggered signals to MITRE ATT&CK techniques.

T1566.001 (Spearphishing Attachment) was deliberately never emitted
through Week 3 — nothing parsed attachments, so claiming that mapping
would have been dishonest. Week 4 adds app/signals/attachment_signals.py
and, with it, T1566.001 — but only when an attachment finding actually
fired, never as a blanket tag on every email check. Same honesty rule as
everywhere else in this file: a technique is only claimed when a specific
signal earned it.
"""
from __future__ import annotations

from typing import List

from app.models import CheckType

SENDER_SPOOFING_SIGNALS = {
    "reply-to-mismatch", "display-name-spoofing",
    "spf-fail", "dkim-fail", "dmarc-fail",
}
CREDENTIAL_HARVESTING_SIGNALS = {"urgency-language"}
ATTACHMENT_SIGNALS = {
    "attachment-dangerous-extension",
    "attachment-macro-enabled-document",
    "attachment-double-extension",
    "attachment-hidden-extension-unicode-override",
    "attachment-extension-content-type-mismatch",
}


def techniques_for(check_type: CheckType, signal_names: List[str], score: int) -> List[str]:
    if score <= 0:
        return []

    techniques: set[str] = set()

    for name in signal_names:
        bare = name.split("link:", 1)[-1] if name.startswith("link:") else name
        is_link_related = (
            name.startswith("link:") or name.startswith("ti:")
            or name.startswith("enrich:") or name.startswith("ml:")
            or check_type == CheckType.url
        )
        if is_link_related:
            techniques.add("T1566.002")  # Spearphishing Link — includes confirmed threat-intel hits
        if bare in SENDER_SPOOFING_SIGNALS:
            techniques.add("T1566")  # Phishing (parent) — no dedicated spoofing sub-technique in scope
        if bare in CREDENTIAL_HARVESTING_SIGNALS:
            techniques.add("T1598")  # Phishing for Information
        if bare in ATTACHMENT_SIGNALS:
            techniques.add("T1566.001")  # Spearphishing Attachment

    if techniques and "T1566" not in techniques and not any(t.startswith("T1566.") for t in techniques):
        techniques.add("T1566")

    return sorted(techniques)
