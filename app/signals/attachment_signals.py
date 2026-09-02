"""Attachment signal extraction — Week 4.

The one job of this module is to finally earn the T1566.001 (Spearphishing
Attachment) MITRE tag honestly: Weeks 1-3 never parsed attachments at all,
so app/mitre.py deliberately never emitted it. This is metadata-only
inspection — filename, declared extension, declared Content-Type — never
content/AV scanning of what's actually inside the file. That's a real
limitation (a wholly legitimate-looking .docx can still carry a malicious
payload this won't catch), not a corner cut for time; say so plainly
rather than imply more than this actually checks.

Works off whatever MIME parts `email.message_from_string` finds in the
pasted raw email source — if the user only pastes headers + body with no
attachment parts, there's nothing here to inspect, and this module
contributes nothing (same "no signal" as any other check with nothing to
find).
"""
from __future__ import annotations

import mimetypes
from email import message_from_string
from email.message import Message
from typing import List

Finding = dict

# Extensions that can execute code directly on double-click. Not
# exhaustive (nothing is), but covers the overwhelming majority of
# malware-delivery-by-attachment cases.
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "cpl", "msi", "msp",
    "jar", "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1",
    "hta", "dll", "lnk", "reg", "iso", "img",
}

# Office formats with macros enabled by the file format itself (the "m"
# in docm/xlsm/pptm) — a legitimate business document essentially never
# needs to be sent as one of these; a plain .docx/.xlsx covers the same
# ground without an embedded macro host.
MACRO_ENABLED_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlam", "ppam", "sldm"}

# Extensions the double-extension trick disguises itself as — the
# "innocent-looking" first extension in something like invoice.pdf.exe.
DECOY_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "gif", "txt", "csv", "zip"}

# Content-Types that mean "this is (or claims to be) a Windows executable
# payload" — a mismatch against a filename extension that claims to be a
# document or image is a spoofing attempt either way (real extension
# lying, or declared type lying).
EXECUTABLE_CONTENT_TYPES = {
    "application/x-msdownload", "application/x-msdos-program",
    "application/x-executable", "application/vnd.microsoft.portable-executable",
    "application/octet-stream",
}

# Unicode bidirectional-control characters. The classic trick embeds
# U+202E (Right-to-Left Override) partway through a filename so
# "invoice_txt.exe" *displays* as "invoice_exe.txt" — the extension the
# user sees on screen isn't the extension the OS actually uses to decide
# how to run the file.
BIDI_CONTROL_CHARS = "‪‫‬‭‮⁦⁧⁨⁩"

DANGEROUS_EXTENSION_POINTS = 35
MACRO_ENABLED_POINTS = 30
DOUBLE_EXTENSION_POINTS = 10  # additive, on top of whatever the final extension itself scores
HIDDEN_EXTENSION_POINTS = 35
CONTENT_TYPE_MISMATCH_POINTS = 15


def _extension(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def _iter_attachments(msg: Message):
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename:
            continue
        # A part with a filename but Content-Disposition: inline is
        # typically an embedded image referenced from HTML body content
        # (a company logo, a tracking pixel) — not something a user
        # downloads and runs. Only "attachment" (or an unspecified
        # disposition, which some mail clients omit for real attachments)
        # counts here.
        if part.get_content_disposition() == "inline":
            continue
        yield part, filename


def extract_attachment_features(raw_email: str) -> List[Finding]:
    findings: List[Finding] = []
    msg = message_from_string(raw_email or "")

    for part, filename in _iter_attachments(msg):
        ext = _extension(filename)
        declared_type = (part.get_content_type() or "").lower()

        has_bidi_override = any(ch in filename for ch in BIDI_CONTROL_CHARS)
        if has_bidi_override:
            findings.append({
                "signal": "attachment-hidden-extension-unicode-override",
                "detail": f"Attachment '{filename}' contains a Unicode bidirectional-override character — "
                          f"a classic trick to make a dangerous extension display as something safe",
                "points": HIDDEN_EXTENSION_POINTS,
            })

        if ext in DANGEROUS_EXTENSIONS:
            findings.append({
                "signal": "attachment-dangerous-extension",
                "detail": f"Attachment '{filename}' has an executable extension (.{ext})",
                "points": DANGEROUS_EXTENSION_POINTS,
            })
        elif ext in MACRO_ENABLED_EXTENSIONS:
            findings.append({
                "signal": "attachment-macro-enabled-document",
                "detail": f"Attachment '{filename}' is a macro-enabled Office document (.{ext})",
                "points": MACRO_ENABLED_POINTS,
            })

        if ext in DANGEROUS_EXTENSIONS or ext in MACRO_ENABLED_EXTENSIONS:
            stem = filename[: -(len(ext) + 1)] if ext else filename
            decoy = _extension(stem)
            if decoy in DECOY_EXTENSIONS:
                findings.append({
                    "signal": "attachment-double-extension",
                    "detail": f"Attachment '{filename}' disguises a dangerous file behind a fake '.{decoy}' extension",
                    "points": DOUBLE_EXTENSION_POINTS,
                })

        if declared_type in EXECUTABLE_CONTENT_TYPES and ext and ext not in DANGEROUS_EXTENSIONS:
            guessed_type, _ = mimetypes.guess_type(filename)
            if guessed_type and guessed_type not in EXECUTABLE_CONTENT_TYPES:
                findings.append({
                    "signal": "attachment-extension-content-type-mismatch",
                    "detail": f"Attachment '{filename}' claims to be '{ext}' but was sent as {declared_type}, "
                              f"not the {guessed_type} its extension implies",
                    "points": CONTENT_TYPE_MISMATCH_POINTS,
                })

    return findings
