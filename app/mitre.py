"""Maps triggered signals to MITRE ATT&CK techniques.

Kept to the four techniques scoped in the concept brief. T1566.001
(Spearphishing Attachment) is deliberately never emitted yet — Week 1
doesn't parse attachments, so claiming that mapping would be dishonest.
That's a named Phase 2 gap, not an oversight.
"""
from __future__ import annotations

from typing import List

from app.models import CheckType

SENDER_SPOOFING_SIGNALS = {
    "reply-to-mismatch", "display-name-spoofing",
    "spf-fail", "dkim-fail", "dmarc-fail",
}
CREDENTIAL_HARVESTING_SIGNALS = {"urgency-language"}


def techniques_for(check_type: CheckType, signal_names: List[str], score: int) -> List[str]:
    if score <= 0:
        return []

    techniques: set[str] = set()

    for name in signal_names:
        bare = name.split("link:", 1)[-1] if name.startswith("link:") else name
        if name.startswith("link:") or check_type == CheckType.url:
            techniques.add("T1566.002")  # Spearphishing Link
        if bare in SENDER_SPOOFING_SIGNALS:
            techniques.add("T1566")  # Phishing (parent) — no dedicated spoofing sub-technique in scope
        if bare in CREDENTIAL_HARVESTING_SIGNALS:
            techniques.add("T1598")  # Phishing for Information

    if techniques and "T1566" not in techniques and not any(t.startswith("T1566.") for t in techniques):
        techniques.add("T1566")

    return sorted(techniques)
