"""Pydantic request/response schemas for the Hookline API."""
from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class CheckType(str, Enum):
    url = "url"
    email = "email"


class Verdict(str, Enum):
    safe = "safe"
    suspicious = "suspicious"
    malicious = "malicious"


class CheckRequest(BaseModel):
    type: CheckType
    content: str = Field(..., min_length=1, description="A raw URL, or raw email text/headers")


class Evidence(BaseModel):
    signal: str
    detail: str
    points: int


class CheckResponse(BaseModel):
    verdict: Verdict
    score: int = Field(..., ge=0, le=100, description="0 = clean, 100 = high-confidence malicious")
    evidence: List[Evidence]
    mitre_techniques: List[str]
    notes: Optional[str] = None
