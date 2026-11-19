"""FastAPI surface: the analyst workbench.

Local-first: the app binds to 127.0.0.1 by default, never talks to
external services, and stores cases in a local SQLite file (see store.py
for what that does and does not protect).
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .engine import analyze, report_to_dict
from .export import render_handoff, render_html_report
from .ioc import iocs_as_text
from .models import IocSet
from .rules import RULES
from .store import DEFAULT_PATH, CaseStore

MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # attachments make messages bigger
MAX_BATCH_FILES = 20  # one triage batch at a time
# Pre-read ceiling for any state-changing request body: a full batch at the
# per-file cap, plus form overhead. Declared larger than this, a request is
# refused before its body is read into memory.
MAX_REQUEST_BYTES = MAX_BATCH_FILES * MAX_UPLOAD_BYTES + 1024 * 1024

# The app is unauthenticated by design, so it only answers requests addressed
# to a local hostname. Rejecting foreign Host headers blocks DNS-rebinding
# attempts from websites open in the same browser.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="PhishLens",
    description="Defensive phishing triage: evidence reports for human review.",
    version="0.2.0",
)


def _allowed_hosts() -> set[str]:
    extra = os.environ.get("PHISHLENS_ALLOWED_HOSTS", "")
    return _LOCAL_HOSTS | {h.strip().lower() for h in extra.split(",") if h.strip()}


def _header_host(value: str) -> str:
    """Hostname out of a Host or Origin header value, port and scheme dropped."""
    netloc = value.lower().split("://", 1)[-1].split("/", 1)[0]
    # Handle IPv6 literals ([::1]:8000) before splitting off the port.
    return netloc[1:].split("]", 1)[0] if netloc.startswith("[") else netloc.split(":", 1)[0]


@app.middleware("http")
async def local_host_only(request: Request, call_next):
    host = _header_host(request.headers.get("host", ""))
    if host and host not in _allowed_hosts():
        return JSONResponse(
            {"detail": "PhishLens only answers requests addressed to localhost."},
            status_code=403,
        )
    if request.method in _STATE_CHANGING_METHODS:
        # CSRF guard: a website open in the same browser can POST forms at a
        # localhost server, and the Host allowlist does not stop that. Modern
        # browsers send Origin on those POSTs, so a foreign Origin is refused.
        # Requests with no Origin header (curl, scripts) are not browser
        # cross-site requests and are allowed.
        origin = request.headers.get("origin")
        if origin and _header_host(origin) not in _allowed_hosts():
            return JSONResponse(
                {"detail": "State changes are only accepted from a local origin."},
                status_code=403,
            )
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_REQUEST_BYTES:
            return JSONResponse(
                {"detail": "Request body too large."},
                status_code=413,
            )
    return await call_next(request)


def get_store() -> CaseStore:
    """The case store, created once per process from PHISHLENS_DB."""
    store = getattr(app.state, "store", None)
    if store is None:
        store = CaseStore(os.environ.get("PHISHLENS_DB", DEFAULT_PATH))
        app.state.store = store
    return store


def _analyze_and_store(data: bytes) -> dict:
    report = analyze(data)
    report_dict = report_to_dict(report)
    report_dict["case_id"] = get_store().save_case(report_dict)
    return report_dict


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/api/rules")
def list_rules() -> dict:
    """The detection rule registry, so the UI can document itself."""
    return {
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "category": r.category,
                "rationale": r.rationale,
                "reference": r.reference,
            }
            for r in RULES
        ]
    }


@app.post("/api/analyze")
async def analyze_email(
    files: list[UploadFile] | None = File(default=None),
    raw: str | None = Form(default=None),
) -> dict:
    """Analyze one or more .eml files, or pasted raw message source.

    Every analyzed message is stored as a case; the response carries the
    case IDs with the reports.
    """
    reports: list[dict] = []
    uploaded = [f for f in (files or []) if f is not None and f.filename]

    if len(uploaded) > MAX_BATCH_FILES:
        raise HTTPException(
            status_code=400,
            detail=f"At most {MAX_BATCH_FILES} files per batch.",
        )

    if uploaded:
        for upload in uploaded:
            data = await upload.read()
            if not data.strip():
                raise HTTPException(status_code=400, detail=f"{upload.filename} is empty.")
            if len(data) > MAX_UPLOAD_BYTES:
                raise HTTPException(
                    status_code=413, detail=f"{upload.filename} exceeds 10 MB."
                )
            reports.append(_analyze_and_store(data))
    elif raw:
        data = raw.encode("utf-8", errors="replace")
        if not data.strip():
            raise HTTPException(status_code=400, detail="The message is empty.")
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Message exceeds 10 MB.")
        reports.append(_analyze_and_store(data))
    else:
        raise HTTPException(
            status_code=400,
            detail="Provide one or more .eml files, or pasted raw message text.",
        )
    return {"cases": reports}


@app.get("/api/cases")
def list_cases(search: str = "", verdict: str = "", status: str = "") -> dict:
    return {"cases": get_store().list_cases(search=search, verdict=verdict, status=status)}


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> dict:
    case = get_store().get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return case


class VerdictUpdate(BaseModel):
    verdict: str
    reason: str = ""


class NoteCreate(BaseModel):
    body: str


class StatusUpdate(BaseModel):
    status: str


@app.post("/api/cases/{case_id}/verdict")
def set_verdict(case_id: str, update: VerdictUpdate) -> dict:
    try:
        ok = get_store().set_verdict(case_id, update.verdict, update.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not ok:
        raise HTTPException(status_code=404, detail="Case not found.")
    return {"status": "ok"}


@app.post("/api/cases/{case_id}/status")
def set_status(case_id: str, update: StatusUpdate) -> dict:
    try:
        ok = get_store().set_status(case_id, update.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not ok:
        raise HTTPException(status_code=404, detail="Case not found.")
    return {"status": "ok"}


@app.get("/api/cases/{case_id}/related")
def related_cases(case_id: str) -> dict:
    """Cases sharing indicators with this one, for joint review.

    A shared sender domain, URL host or attachment hash groups emails for
    an analyst; it is not proof of a common sender or campaign.
    """
    related = get_store().related_cases(case_id)
    if related is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return {"related": related}


@app.post("/api/cases/{case_id}/notes")
def add_note(case_id: str, note: NoteCreate) -> dict:
    if not note.body.strip():
        raise HTTPException(status_code=400, detail="Note is empty.")
    if not get_store().add_note(case_id, note.body.strip()):
        raise HTTPException(status_code=404, detail="Case not found.")
    return {"status": "ok"}


@app.get("/api/cases/{case_id}/report.html", response_class=HTMLResponse)
def export_report(case_id: str) -> HTMLResponse:
    case = get_store().get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return HTMLResponse(render_html_report(case))


@app.get("/api/cases/{case_id}/report.json")
def export_json(case_id: str) -> JSONResponse:
    """The full stored report as JSON - the raw evidence behind the UI."""
    case = get_store().get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return JSONResponse(
        case["report"],
        headers={"Content-Disposition": f'attachment; filename="phishlens-{case_id}.json"'},
    )


@app.get("/api/cases/{case_id}/handoff.txt", response_class=PlainTextResponse)
def export_handoff(case_id: str) -> PlainTextResponse:
    """Copyable plain-text incident handoff. Nothing is sent anywhere."""
    case = get_store().get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return PlainTextResponse(render_handoff(case))


@app.get("/api/cases/{case_id}/iocs.txt", response_class=PlainTextResponse)
def export_iocs(case_id: str, defanged: bool = True) -> PlainTextResponse:
    case = get_store().get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    ioc_dict = case["report"].get("iocs", {})
    iocs = IocSet(
        domains=ioc_dict.get("domains", []),
        urls=ioc_dict.get("urls", []),
        ips=ioc_dict.get("ips", []),
        addresses=ioc_dict.get("addresses", []),
        file_hashes=ioc_dict.get("file_hashes", []),
    )
    return PlainTextResponse(iocs_as_text(iocs, defanged=defanged))


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
