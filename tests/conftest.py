"""Test-wide fixtures.

Autouse, so every test starts from a clean slate regardless of what's
sitting in the developer's real .env or shell environment.

tests/test_main.py imports app.main (for the FastAPI app instance),
which calls load_dotenv() at import time -- that's necessary for the
app itself, but as a side effect it pulls whatever .env the developer
actually has configured into os.environ for the rest of the pytest
process, since all test modules share one process.

Most tests are unaffected because they pass explicit fake clients
(threat_intel_clients=[...], enrichment_clients=[...]) rather than
letting run_check build the real ones. But
test_enrichment_disabled_by_default_is_noted_but_scoreless deliberately
exercises the real build_enrichment_clients() provider, to check that
ENABLE_LIVE_ENRICHMENT actually defaults to off -- and that's exactly
where this bit: once a real .env sets ENABLE_LIVE_ENRICHMENT=true (as
happened turning live enrichment on for real use), the test silently
started asserting against a live network call instead of the code's
actual default, and failed with a DNS-resolution error for its
deliberately-nonexistent test domain instead of the expected
"disabled" evidence.

Clearing these before every test closes that gap for good, independent
of whatever API keys or flags a developer has configured locally.
"""
import pytest

_ENV_VARS_TO_ISOLATE = [
    "ENABLE_LIVE_ENRICHMENT",
    "GOOGLE_SAFE_BROWSING_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "PHISHTANK_API_KEY",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in _ENV_VARS_TO_ISOLATE:
        monkeypatch.delenv(var, raising=False)
