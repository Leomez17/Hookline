from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.models import CheckRequest, CheckResponse
from app.scoring import run_check

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

app = FastAPI(
    title="Hookline",
    description="Phishing & suspicious-link detector — Week 1 spike (rules-only, no external APIs).",
    version="0.1.0",
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
