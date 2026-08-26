"""A small watch-list of commonly-impersonated brands, plus a lightweight
typosquat / homograph check against it.

This intentionally doesn't shell out to dnstwist or hit any network — it's
the Week 1 spike version: pure string distance against a short list. Swapping
in dnstwist-generated permutations (and DNS resolution to see which
candidates are actually registered) is a natural Phase 2 upgrade, see the
concept brief.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Kept short and high-signal on purpose. Extend as needed.
WATCHED_BRANDS = [
    "paypal",
    "microsoft",
    "apple",
    "google",
    "amazon",
    "netflix",
    "outlook",
    "office365",
    "docusign",
    "hmrc",
    "gov.uk",
    "barclays",
    "hsbc",
    "lloyds",
    "santander",
    "natwest",
    "royalmail",
    "dhl",
    "linkedin",
    "facebook",
    "instagram",
    "coinbase",
    "binance",
]


def _levenshtein(a: str, b: str) -> int:
    """Standard edit distance, no external dependency."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current_row = [i]
        for j, cb in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (ca != cb)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row
    return previous_row[-1]


@dataclass
class TyposquatMatch:
    brand: str
    distance: int


def closest_brand_match(domain_label: str) -> Optional[TyposquatMatch]:
    """Return the nearest watched brand to `domain_label` if it's close
    enough to be suspicious but not an exact/legitimate match.

    `domain_label` should be the registrable domain without TLD, e.g.
    "paypa1" from "paypa1.com", or "paypal-secure-login".

    Checks both the full label and its hyphen-separated tokens, so
    "paypa1-secure-login" is compared token-by-token ("paypa1" vs "paypal")
    rather than as one long string that would otherwise swamp the edit
    distance with the unrelated "-secure-login" suffix.
    """
    label = domain_label.lower()
    candidates_to_check = [label] + [t for t in label.split("-") if t]

    best: Optional[TyposquatMatch] = None
    for brand in WATCHED_BRANDS:
        if brand == label:
            continue  # exact match to a real brand name isn't itself suspicious

        if brand in label and len(label) - len(brand) <= 12:
            # e.g. "paypal-secure-login" contains "paypal" but isn't paypal.com
            candidate = TyposquatMatch(brand=brand, distance=0)
            if best is None or candidate.distance < best.distance:
                best = candidate
            continue

        for token in candidates_to_check:
            if token == brand:
                continue
            distance = _levenshtein(token, brand)
            if distance == 0:
                continue
            # Only flag genuinely close misspellings, scaled to brand length.
            threshold = max(1, len(brand) // 4)
            if distance <= threshold:
                candidate = TyposquatMatch(brand=brand, distance=distance)
                if best is None or candidate.distance < best.distance:
                    best = candidate

    return best
