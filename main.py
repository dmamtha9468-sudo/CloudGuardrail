from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from scanner.analyzers import scan_config

ROOT = Path(__file__).parent
app = FastAPI(title="CloudGuardrail API", version="1.0.0", description="Local-first deployment configuration scanner")


class ScanRequest(BaseModel):
    filename: str = Field(default="pasted-config", min_length=1, max_length=180)
    content: str = Field(min_length=1, max_length=1_000_000)
    file_type: Literal["auto", "dockerfile", "kubernetes", "terraform", "json"] = "auto"


@app.get("/")
def home():
    return FileResponse(ROOT / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "scanner": "CloudGuardrail", "version": app.version}


@app.post("/api/scan")
def scan(request: ScanRequest):
    try:
        findings = scan_config(request.filename, request.content, request.file_type)
    except ValueError as exc:
        raise HTTPException(status_code=413 if "1 MB" in str(exc) else 400, detail=str(exc)) from exc
    counts = {level: sum(1 for item in findings if item["severity"] == level) for level in ("high", "medium", "low")}
    risk_score = min(100, counts["high"] * 28 + counts["medium"] * 13 + counts["low"] * 4)
    return {
        "filename": request.filename,
        "file_type": request.file_type,
        "risk_score": risk_score,
        "counts": counts,
        "total": len(findings),
        "findings": findings,
        "disclaimer": "Rule-based checks identify common patterns; review findings in deployment context.",
    }
