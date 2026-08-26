# Hookline — Week 1 spike

A phishing & suspicious-link detector. This is the Week 1 build from the
[concept brief](https://claude.ai/code/artifact/9f00a0bf-5b9d-4843-a4da-88be7553a89f):
an end-to-end rules-only path, proving the architecture before any external
API or ML dependency gets added.

Paste a URL or a raw email (headers + body) and get back a 0–100 score, a
plain verdict (`safe` / `suspicious` / `malicious`), the specific evidence
that produced it, and a MITRE ATT&CK tag.

## What's actually implemented

- **URL signals** (`app/signals/url_signals.py`) — IP-literal hosts, `@`
  hidden-destination tricks, URL shorteners, suspicious TLDs, excessive
  subdomains/hyphens, plain HTTP, and typosquat/brand-impersonation
  detection against a small watch-list (`app/signals/brand_watchlist.py`),
  using edit distance the same way `dnstwist` does — just without the DNS
  resolution step, which is a Phase 2 addition.
- **Email signals** (`app/signals/email_signals.py`) — reply-to/sender
  domain mismatches, display-name spoofing, SPF/DKIM/DMARC failures *if*
  the pasted source already carries an `Authentication-Results` header,
  urgency/credential-harvesting language scoring, and it runs the URL
  checks above against every link found in the body.
- **Scoring** (`app/scoring.py`) — a transparent, additive rules engine.
  No black box: every point on the score is traceable to a named signal in
  the evidence list.
- **MITRE mapping** (`app/mitre.py`) — tags results against T1566
  (Phishing), T1566.002 (Spearphishing Link), and T1598 (Phishing for
  Information). T1566.001 (Spearphishing Attachment) is deliberately never
  emitted — attachments aren't parsed yet, so claiming that mapping would
  be dishonest.
- **Threat-intel interface** (`app/threat_intel/`) — a clean seam
  (`ThreatIntelClient` protocol) with a `NullThreatIntelClient` stub. It
  always reports "couldn't check" rather than fabricating a hit. Phase 2
  swaps in real Safe Browsing / VirusTotal / PhishTank clients behind the
  same interface — `main.py` and `scoring.py` won't need to change.
- **Demo UI** (`static/index.html`) — a single page that hits `/check` and
  renders the verdict card, MITRE tags, and evidence list.

## What's deliberately not here yet

No live network calls at all — no WHOIS, no TLS certificate check, no
redirect-chain following, no real SPF/DKIM/DMARC verification, no
threat-intel API calls, no ML scoring layer. That's the whole point of a
Week 1 spike: prove the plumbing with something fast and fully offline,
then add real dependencies one at a time against a codebase that already
works end to end. See the concept brief for the Week 2–4 plan.

## Running it

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open http://127.0.0.1:8000 for the demo UI, or call the API directly:

```bash
curl -X POST http://127.0.0.1:8000/check \
  -H "Content-Type: application/json" \
  -d '{"type": "url", "content": "https://paypa1-secure-login.top/verify"}'
```

Two sample emails are in `sample_data/` — one phishing, one clean — used by
the test suite and handy for manually poking the UI.

## Testing

```bash
pytest -v
```

13 tests covering the URL signals, email signals, and end-to-end scoring
(including that the clean sample stays at score 0 and the phishing sample
lands as `malicious`).

## Project layout

```
app/
  main.py              FastAPI app — GET /, GET /health, POST /check
  models.py            Request/response schemas
  scoring.py           Rules engine + verdict thresholds
  mitre.py             Signal → MITRE technique mapping
  signals/
    url_signals.py      URL feature extraction
    email_signals.py    Email header/body feature extraction
    brand_watchlist.py  Watched brands + typosquat distance check
  threat_intel/
    base.py             ThreatIntelClient interface
    stub.py             Week 1 default (always "no data")
static/
  index.html           Demo UI
tests/                 pytest suite
sample_data/           Sample phishing + legitimate emails
```

## Next steps (Phase 2, from the concept brief)

1. Wire in Safe Browsing, VirusTotal, and PhishTank behind
   `ThreatIntelClient`, with response caching (~24h) so free-tier rate
   limits hold up.
2. Add live WHOIS/RDAP lookups for domain age, and TLS certificate
   issuance-date checks.
3. Add the logistic-regression scoring layer alongside the rules engine —
   not instead of it, so results stay explainable.
4. Attachment parsing, to finally earn the T1566.001 tag honestly.
5. Package as a browser extension / Outlook add-in, and a webhook into
   Sentinel reusing the existing Logic App playbook pattern.
6. The usual deliverable suite — GitHub README (this doubles as a start),
   technical write-up, portfolio HTML page, LinkedIn post.
