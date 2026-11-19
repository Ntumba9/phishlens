"""FastAPI surface: a tiny UI plus one analysis endpoint.

Local-first: the app binds to 127.0.0.1 by default and never talks to
external services.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .analyzer import analyze, report_to_dict

MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB is generous for a single email

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="PhishLens",
    description="Defensive phishing triage: evidence reports for human review.",
    version="0.1.0",
)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze_email(
    file: UploadFile | None = File(default=None),
    raw: str | None = Form(default=None),
) -> dict:
    """Analyze an uploaded .eml file or pasted raw message source."""
    if file is not None and file.filename:
        data = await file.read()
    elif raw:
        data = raw.encode("utf-8", errors="replace")
    else:
        raise HTTPException(
            status_code=400,
            detail="Provide an .eml file upload or pasted raw message text.",
        )

    if not data.strip():
        raise HTTPException(status_code=400, detail="The message is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Message exceeds 2 MB.")

    return report_to_dict(analyze(data))


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
