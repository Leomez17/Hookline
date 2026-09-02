"""Attachment signal tests. Every raw email here is built with Python's
own email.mime helpers and turned back into text with .as_string() — the
same round trip a real mail client's "view source" produces — so these
exercise message_from_string parsing exactly the way scoring.py does,
without needing a corpus of captured phishing samples (and definitely
without embedding any real executable/malware bytes: every attachment
payload here is a placeholder string).
"""
from __future__ import annotations

from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.signals.attachment_signals import extract_attachment_features


def _email_with_attachment(filename: str, content_type: str = "application/octet-stream", disposition: str = "attachment") -> str:
    msg = MIMEMultipart()
    msg["From"] = "sender@example.com"
    msg["Subject"] = "See attached"
    msg.attach(MIMEText("Please see the attached file.", "plain"))

    maintype, subtype = content_type.split("/", 1)
    part = MIMEBase(maintype, subtype)
    part.set_payload("not a real file, just a placeholder for the test")
    part.add_header("Content-Disposition", disposition, filename=filename)
    msg.attach(part)

    return msg.as_string()


def test_no_attachment_yields_no_findings():
    raw = "From: a@example.com\nSubject: hi\n\nJust a plain email, no attachments.\n"
    assert extract_attachment_features(raw) == []


def test_benign_pdf_attachment_yields_no_findings():
    raw = _email_with_attachment("quarterly_report.pdf", content_type="application/pdf")
    assert extract_attachment_features(raw) == []


def test_dangerous_extension_flagged():
    raw = _email_with_attachment("invoice_details.exe")
    findings = extract_attachment_features(raw)
    signals = [f["signal"] for f in findings]
    assert "attachment-dangerous-extension" in signals


def test_macro_enabled_document_flagged():
    raw = _email_with_attachment(
        "Q3_Report.docm",
        content_type="application/vnd.ms-word.document.macroEnabled.12",
    )
    findings = extract_attachment_features(raw)
    signals = [f["signal"] for f in findings]
    assert "attachment-macro-enabled-document" in signals


def test_double_extension_trick_flagged():
    raw = _email_with_attachment("invoice.pdf.exe")
    findings = extract_attachment_features(raw)
    signals = [f["signal"] for f in findings]
    assert "attachment-dangerous-extension" in signals
    assert "attachment-double-extension" in signals


def test_double_extension_only_flagged_when_final_extension_is_dangerous():
    # "photo.jpg.png" is a weird filename but not a dangerous-file disguise
    # — the final extension itself isn't executable/macro-enabled.
    raw = _email_with_attachment("photo.jpg.png", content_type="image/png")
    findings = extract_attachment_features(raw)
    signals = [f["signal"] for f in findings]
    assert "attachment-double-extension" not in signals


def test_unicode_rlo_override_flagged():
    # U+202E (RLO) placed so "gnp.exe" reverses on screen to look like ".exe"
    # sitting before a "png" that never actually follows it in the real name.
    tricky_name = "invoice_‮gnp.exe"
    raw = _email_with_attachment(tricky_name)
    findings = extract_attachment_features(raw)
    signals = [f["signal"] for f in findings]
    assert "attachment-hidden-extension-unicode-override" in signals


def test_content_type_mismatch_flagged():
    # Filename claims to be a PDF, but it was actually sent as a generic
    # executable/binary content-type — the extension is lying, or the
    # Content-Type is, either way worth a (modest) flag.
    raw = _email_with_attachment("statement.pdf", content_type="application/x-msdownload")
    findings = extract_attachment_features(raw)
    signals = [f["signal"] for f in findings]
    assert "attachment-extension-content-type-mismatch" in signals
    # A .pdf with x-msdownload content-type isn't itself a recognised
    # dangerous *extension* — that's a separate, stronger signal.
    assert "attachment-dangerous-extension" not in signals


def test_inline_image_is_not_treated_as_an_attachment():
    # A logo referenced from HTML body content (Content-Disposition: inline)
    # is not something a user downloads and runs — shouldn't be scored.
    raw = _email_with_attachment("logo.exe", disposition="inline")
    assert extract_attachment_features(raw) == []


def test_multiple_attachments_each_scored():
    msg = MIMEMultipart()
    msg["From"] = "sender@example.com"
    msg["Subject"] = "Files"
    msg.attach(MIMEText("Two files attached.", "plain"))
    for filename, content_type in [("readme.txt", "text/plain"), ("payload.scr", "application/octet-stream")]:
        maintype, subtype = content_type.split("/", 1)
        part = MIMEBase(maintype, subtype)
        part.set_payload("placeholder")
        part.add_header("Content-Disposition", "attachment", filename=filename)
        msg.attach(part)

    findings = extract_attachment_features(msg.as_string())
    signals = [f["signal"] for f in findings]
    assert signals == ["attachment-dangerous-extension"]  # only the .scr trips anything
