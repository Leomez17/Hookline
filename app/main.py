from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# Must run before anything reads GOOGLE_SAFE_BROWSING_API_KEY / VIRUSTOTAL_API_KEY /
# PHISHTANK_API_KEY / ENABLE_LIVE_ENRICHMENT from the environment — those are
# read lazily per-request (see app/threat_intel/provider.py and
# app/enrichment/provider.py), but .env needs to be loaded into the process
# environment once, here, at startup.
load_dotenv()

from app.models import CheckRequest, CheckResponse  # noqa: E402
from app.scoring import run_check  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(
    title="Hookline",
    description=(
        "Phishing & suspicious-link detector — rules engine + threat-intel lookups "
        "(Google Safe Browsing, VirusTotal, PhishTank) + optional live domain-age/TLS "
        "enrichment + an explainable logistic-regression calibration layer + "
        "attachment parsing (metadata-only)."
    ),
    version="0.5.0",
)

# Hookline is meant to run locally next to whatever is checking against it —
# the demo UI (same-origin, doesn't need this), the browser extension
# (already bypasses CORS via its granted host_permissions), or you, poking
# the API from a browser console or a script on a different port. There's no
# session/cookie auth here for a permissive origin list to put at risk, so
# allow_origins=["*"] is fine for a tool that's designed to run on your own
# machine. Tighten this before ever exposing an instance publicly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/check", response_model=CheckResponse)
def check(request: CheckRequest) -> CheckResponse:
    return run_check(request.type, request.content)
