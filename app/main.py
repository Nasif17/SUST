from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app import __version__
from app.analyzer import analyze_ticket
from app.schemas import AnalyzeTicketRequest, AnalyzeTicketResponse, HealthResponse


ROOT_DIR = Path(__file__).resolve().parents[1]
PUBLIC_DIR = ROOT_DIR / "public"

app = FastAPI(
    title="QueueStorm Investigator",
    version=__version__,
    description="Deterministic support-ticket analyzer for the SUST Codex Community Hackathon preliminary round.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
def interface() -> FileResponse:
    return FileResponse(PUBLIC_DIR / "index.html")


@app.get("/styles.css", include_in_schema=False)
def styles() -> FileResponse:
    return FileResponse(PUBLIC_DIR / "styles.css", media_type="text/css")


@app.get("/app.js", include_in_schema=False)
def script() -> FileResponse:
    return FileResponse(PUBLIC_DIR / "app.js", media_type="application/javascript")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="queue-storm-investigator", version=__version__)


@app.get("/api/health", response_model=HealthResponse, include_in_schema=False)
def api_health() -> HealthResponse:
    return health()


@app.post("/analyze-ticket", response_model=AnalyzeTicketResponse)
def analyze_ticket_endpoint(payload: AnalyzeTicketRequest) -> AnalyzeTicketResponse:
    return analyze_ticket(payload)


@app.post("/api/analyze-ticket", response_model=AnalyzeTicketResponse, include_in_schema=False)
def api_analyze_ticket_endpoint(payload: AnalyzeTicketRequest) -> AnalyzeTicketResponse:
    return analyze_ticket(payload)
