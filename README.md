# Hookline — Week 3

A phishing & suspicious-link detector. Built from the
[concept brief](https://claude.ai/code/artifact/9f00a0bf-5b9d-4843-a4da-88be7553a89f):
Week 1 proved the architecture rules-only, Week 2 added real threat-intel
lookups, and Week 3 adds live domain-age/TLS enrichment plus an
explainable logistic-regression calibration layer on top of both.

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
- **Live enrichment** (`app/enrichment/`) — **off by default**, unlike the
  threat-intel sources above. Turn it on with `ENABLE_LIVE_ENRICHMENT=true`:
  - **RDAP domain-age lookup** (`rdap_client.py`) — via
    [rdap.org](https://rdap.org) as a bootstrap proxy, so Hookline never
    needs its own IANA bootstrap table. Flags a domain registered in the
    last 30 days — phishing infrastructure is disposable almost by
    definition, though age alone is a weak signal (plenty of legitimate
    sites are new too).
  - **TLS certificate check** (`tls_client.py`) — connects directly to
    the submitted host's port 443 and reads the leaf certificate's
    issuance/expiry dates, without verifying the chain (`CERT_NONE`),
    because a self-signed or expired cert is exactly the kind of anomaly
    worth surfacing, not a reason to fail closed before looking. This is
    the one check that talks directly to a potentially hostile,
    user-supplied destination, so it carries its own SSRF guard: every
    resolved address is checked against private/loopback/link-local/
    reserved ranges before a socket opens, and the connection goes to
    that specific validated IP rather than a fresh DNS lookup at connect
    time — closing the DNS-rebinding window in between.
  - Both are cached for 24h (`app/enrichment/cache.py`) and, for an
    email, bounded to the first link only (`ENRICHMENT_LINK_CAP = 1` in
    `app/scoring.py`) — tighter than threat-intel's cap of 2, since this
    is two live round trips per target instead of one API call.
- **Logistic-regression calibration** (`app/ml/`) — a bolt-on scoring
  layer, not a replacement for the rules engine: it looks at *which*
  named signals already fired (local, threat-intel, or enrichment) and
  estimates how much more confident a reviewer should be in the
  combination, adding a further `ml:moderate-confidence` (+12) or
  `ml:high-confidence` (+25) finding to the same evidence list when its
  estimate crosses a threshold. It contributes nothing when nothing else
  fired — it never manufactures a score from zero evidence. Trained
  offline with scikit-learn on a small, honestly-labeled, hand-curated
  set of signal combinations (`app/ml/dataset.py` — this is **not** real
  captured phishing traffic, and the code says so); the resulting
  coefficients are committed as `app/ml/weights.json`, and inference at
  request time (`app/ml/model.py`) is a plain dot product and a sigmoid
  with **zero ML-library dependency** — scikit-learn is only needed to
  regenerate the weights (`scripts/train_model.py`), never to run the
  app. Regenerate with:
  ```bash
  pip install scikit-learn
  python scripts/train_model.py
  ```
- **Scoring** (`app/scoring.py`) — a transparent, additive rules engine.
  No black box: every point on the score — local, threat-intel-sourced,
  enrichment-sourced, or ML-calibrated — is traceable to a named signal
  in the evidence list.
- **MITRE mapping** (`app/mitre.py`) — tags results against T1566
  (Phishing), T1566.002 (Spearphishing Link — now including confirmed
  threat-intel hits and enrichment/ML findings), and T1598 (Phishing for
  Information). T1566.001 (Spearphishing Attachment) is deliberately
  never emitted — attachments aren't parsed yet, so claiming that mapping
  would be dishonest.
- **Demo UI** (`static/index.html`) — a single page that hits `/check` and
  renders the verdict card, MITRE tags, and evidence list.

## Setting up API keys and live enrichment

The three threat-intel keys are optional and independent — Hookline runs
with zero, one, two, or all three configured. Live enrichment is a
separate, single on/off switch, off by default.

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
- **`ENABLE_LIVE_ENRICHMENT`** — set to `true` to turn on the RDAP
  domain-age and TLS certificate checks. No signup needed (RDAP is a free,
  keyless public protocol), but this is the one feature that connects
  directly to whatever host a submitted URL points at, so it's opt-in
  rather than on by default — see the enrichment section above for the
  SSRF guard that goes with it.

`uvicorn` picks up `.env` automatically on startup (via `python-dotenv`
in `app/main.py`). No restart trick needed beyond the normal one.

## What's deliberately not here yet

No redirect-chain following, no real (receiving-server-side) SPF/DKIM/DMARC
verification — those still rely on whatever `Authentication-Results`
header the pasted email already carries. No attachment parsing yet, so
T1566.001 still never fires. See the roadmap below.

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

57 tests. Threat-intel tests mock `requests` directly; enrichment tests
mock `requests` (RDAP) and `socket`/`ssl` (TLS) the same way, including a
dedicated test that the TLS client's SSRF guard actually refuses to
connect when a host resolves only to a private address. None of them
make a real network call, so the suite is safe and fast to run with or
without API keys or `ENABLE_LIVE_ENRICHMENT` set, and can't accidentally
burn your quota or probe a live host.

## Project layout

```
app/
  main.py              FastAPI app — GET /, GET /health, POST /check; loads .env on startup
  models.py            Request/response schemas
  scoring.py           Rules engine + threat-intel + enrichment + ML integration + verdict thresholds
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
  enrichment/
    base.py             EnrichmentClient interface
    provider.py          Builds the RDAP + TLS client set, gated on ENABLE_LIVE_ENRICHMENT
    cache.py             24h TTL cache wrapper
    rdap_client.py        RDAP domain-age lookup (via rdap.org)
    tls_client.py          TLS certificate check, with its own SSRF guard
  ml/
    dataset.py           Hand-curated, honestly-labeled calibration examples
    features.py           Signal-name → ML feature-key normalisation
    model.py               Runtime inference — pure Python, no sklearn dependency
    weights.json            Trained logistic-regression coefficients (committed artifact)
scripts/
  train_model.py        Dev-only: regenerates app/ml/weights.json (needs scikit-learn)
static/
  index.html           Demo UI
tests/                 pytest suite
sample_data/           Sample phishing + legitimate emails
```

## Roadmap

1. ~~Wire in Safe Browsing, VirusTotal, and PhishTank behind
   `ThreatIntelClient`, with response caching so free-tier rate limits
   hold up.~~ **Done — Week 2.**
2. ~~Add live WHOIS/RDAP lookups for domain age, and TLS certificate
   issuance-date checks.~~ **Done — Week 3.**
3. ~~Add the logistic-regression scoring layer alongside the rules engine —
   not instead of it, so results stay explainable.~~ **Done — Week 3.**
4. Attachment parsing, to finally earn the T1566.001 tag honestly.
5. Package as a browser extension / Outlook add-in, and a webhook into
   Sentinel reusing the existing Logic App playbook pattern.
6. The usual deliverable suite — GitHub README (this doubles as a start),
   technical write-up, portfolio HTML page, LinkedIn post.
