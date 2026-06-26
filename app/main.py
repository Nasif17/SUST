from __future__ import annotations

from fastapi import FastAPI

from app import __version__
from app.analyzer import analyze_ticket
from app.schemas import AnalyzeTicketRequest, AnalyzeTicketResponse, HealthResponse


app = FastAPI(
    title="QueueStorm Investigator",
    version=__version__,
    description="Deterministic support-ticket analyzer for the SUST Codex Community Hackathon preliminary round.",
)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="queue-storm-investigator", version=__version__)


@app.post("/analyze-ticket", response_model=AnalyzeTicketResponse)
def analyze_ticket_endpoint(payload: AnalyzeTicketRequest) -> AnalyzeTicketResponse:
    return analyze_ticket(payload)
