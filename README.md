# Hookline — Week 2

A phishing & suspicious-link detector. Built from the
[concept brief](https://claude.ai/code/artifact/9f00a0bf-5b9d-4843-a4da-88be7553a89f):
Week 1 proved the architecture rules-only; Week 2 adds real threat-intel
lookups behind the interface Week 1 left for exactly this.

Paste a URL or a raw email (headers + body) and get back a 0–100 score, a
plain verdict (`safe` / `suspicious` / `malicious`), the specific evidence
that produced it, and a MITRE ATT&CK tag.

## What's actually implemented

- **URL signals** (`app/signals/url_signals.py`) — IP-literal hosts, `@`
  hidden-destination tricks, URL shorteners, suspicious TLDs, excessive
  subdomains/hyphens, plain HTTP, and typosquat/brand-impersonation
  detection against a small watch-list (`app/signals/brand_watchlist.py`),
  using edit distance the same way `dnstwist` does — just without the DNS
  resolution step, which is still a later addition.
- **Email signals** (`app/signals/email_signals.py`) — reply-to/sender
  domain mismatches, display-name spoofing, SPF/DKIM/DMARC failures *if*
  the pasted source already carries an `Authentication-Results` header,
  urgency/credential-harvesting language scoring, and it runs the URL
  checks above against every link found in the body.
- **Threat-intel lookups** (`app/threat_intel/`) — real clients for
  **Google Safe Browsing**, **VirusTotal**, and **PhishTank**, each behind
  the same `ThreatIntelClient` interface Week 1 defined. Every one is
  independently optional: with no key configured, that source reports
  "not configured" rather than failing or being silently skipped — you
  can see exactly which checks did and didn't run in the evidence trail.
  Results are cached in-memory for 24h (`app/threat_intel/cache.py`) so
  repeat lookups don't burn free-tier quota. For an email, only the first
  2 links get threat-intel checks (still capped at 5 for the local
  heuristics) — bounded on purpose so one message can't fan out into
  unlimited API calls.
- **Scoring** (`app/scoring.py`) — a transparent, additive rules engine.
  No black box: every point on the score, local or threat-intel-sourced,
  is traceable to a named signal in the evidence list.
- **MITRE mapping** (`app/mitre.py`) — tags results against T1566
  (Phishing), T1566.002 (Spearphishing Link — now including confirmed
  threat-intel hits), and T1598 (Phishing for Information). T1566.001
  (Spearphishing Attachment) is deliberately never emitted — attachments
  aren't parsed yet, so claiming that mapping would be dishonest.
- **Demo UI** (`static/index.html`) — a single page that hits `/check` and
  renders the verdict card, MITRE tags, and evidence list.

## Setting up API keys

All three are optional and independent — Hookline runs with zero, one,
two, or all three configured.

```bash
cp .env.example .env
```

Then fill in whichever of these you want live:

- **Google Safe Browsing** — free, but licensed for non-commercial use
  only. Enable the API and create a key:
  https://developers.google.com/safe-browsing/v4/get-started
- **VirusTotal** — free tier, rate-limited per-minute/day/month. Sign up
  at https://www.virustotal.com/gui/join-us, then copy your key from
  https://www.virustotal.com/gui/my-apikey. This client only reads
  existing reports — it never submits a new scan, to avoid burning quota.
- **PhishTank** — free, maintained by Cisco Talos. Register and generate
  an app key at https://phishtank.net.

`uvicorn` picks up `.env` automatically on startup (via `python-dotenv`
in `app/main.py`). No restart trick needed beyond the normal one.

## What's deliberately not here yet

No live WHOIS/RDAP lookups, no TLS certificate issuance-date check, no
redirect-chain following, no real (receiving-server-side) SPF/DKIM/DMARC
verification — those still rely on whatever `Authentication-Results`
header the pasted email already carries. No ML scoring layer yet, and no
attachment parsing. See the roadmap below.

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

29 tests. All threat-intel tests mock `requests` directly — none of them
make a real network call, so the suite is safe and fast to run with or
without API keys configured, and can't accidentally burn your quota.

## Project layout

```
app/
  main.py              FastAPI app — GET /, GET /health, POST /check; loads .env on startup
  models.py            Request/response schemas
  scoring.py           Rules engine + threat-intel integration + verdict thresholds
  mitre.py             Signal → MITRE technique mapping
  signals/
    url_signals.py      URL feature extraction
    email_signals.py    Email header/body feature extraction + link extraction
    brand_watchlist.py  Watched brands + typosquat distance check
  threat_intel/
    base.py             ThreatIntelClient interface
    stub.py             Testing utility — always "no data"
    provider.py          Builds the configured client set from env vars
    cache.py             24h TTL cache wrapper
    safe_browsing.py     Google Safe Browsing v4 client
    virustotal.py        VirusTotal v3 client (read-only, no scan submission)
    phishtank.py          PhishTank client
static/
  index.html           Demo UI
tests/                 pytest suite
sample_data/           Sample phishing + legitimate emails
```

## Roadmap

1. ~~Wire in Safe Browsing, VirusTotal, and PhishTank behind
   `ThreatIntelClient`, with response caching so free-tier rate limits
   hold up.~~ **Done — Week 2.**
2. Add live WHOIS/RDAP lookups for domain age, and TLS certificate
   issuance-date checks.
3. Add the logistic-regression scoring layer alongside the rules engine —
   not instead of it, so results stay explainable.
4. Attachment parsing, to finally earn the T1566.001 tag honestly.
5. Package as a browser extension / Outlook add-in, and a webhook into
   Sentinel reusing the existing Logic App playbook pattern.
6. The usual deliverable suite — GitHub README (this doubles as a start),
   technical write-up, portfolio HTML page, LinkedIn post.
