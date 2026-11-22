"""FastAPI entry point for the AI-Powered SOC Lab.

Step 10: the application exists, starts, and answers a liveness check.
The triage engine is exposed in step 11; nothing here talks to Splunk.

Run locally (binds to the loopback interface only):
    python -m uvicorn api.main:app --host 127.0.0.1 --port 8001 --reload
"""

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

API_VERSION = "0.1.0"
SERVICE_NAME = "ai-powered-soc-lab"

app = FastAPI(
    title="AI-Powered SOC Lab API",
    version=API_VERSION,
    description="Detection, triage and evidence correlation for a Windows SOC lab.",
)


class HealthResponse(BaseModel):
    """Liveness answer: the process is up and able to serve requests."""

    status: Literal["ok"]
    service: str
    version: str


@app.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    """Liveness probe. Deliberately checks no dependency (Splunk, database)."""
    return HealthResponse(status="ok", service=SERVICE_NAME, version=API_VERSION)
