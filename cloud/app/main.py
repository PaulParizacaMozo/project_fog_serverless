from __future__ import annotations

from typing import Any, Dict, Optional, List
import os

from fastapi import FastAPI, Depends, Query
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from auth import require_bearer_token
from contracts.schemas import Alert, SummaryWindow
from storage import FileBackedStore, FirestoreStore


STORE_PATH = os.getenv("STORE_PATH", "/data/store.json")
WEB_DIR = os.getenv("WEB_DIR", "/app/web")

STORE_MODE = os.getenv("STORE_MODE", "file").lower()  # file | firestore
GCP_PROJECT = os.getenv("GCP_PROJECT", "") or os.getenv("GOOGLE_CLOUD_PROJECT", "")

ALERTS_COL = os.getenv("FIRESTORE_ALERTS_COLLECTION", "alerts")
SUMMARIES_COL = os.getenv("FIRESTORE_SUMMARIES_COLLECTION", "summaries_10s")


def build_store():
    if STORE_MODE == "firestore":
        if not GCP_PROJECT:
            raise RuntimeError("STORE_MODE=firestore requires GCP_PROJECT or GOOGLE_CLOUD_PROJECT")
        return FirestoreStore(
            project=GCP_PROJECT,
            alerts_collection=ALERTS_COL,
            summaries_collection=SUMMARIES_COL,
        )
    return FileBackedStore(path=STORE_PATH)


store = build_store()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/healthz")
def healthz():
    # No hagas "len()" de colecciones en Firestore (caro y/o no aplica).
    return {
        "ok": True,
        "store_mode": STORE_MODE,
        "project": GCP_PROJECT if STORE_MODE == "firestore" else None,
    }


@app.post("/ingest/alert")
def ingest_alert(payload: Dict[str, Any], _: None = Depends(require_bearer_token)):
    alert = Alert.model_validate(payload).model_dump()
    store.upsert_alert(alert)
    return {"ok": True, "stored": "alert", "alert_id": alert["alert_id"]}


@app.post("/ingest/summary")
def ingest_summary(payload: Dict[str, Any], _: None = Depends(require_bearer_token)):
    summary = SummaryWindow.model_validate(payload).model_dump()
    store.upsert_summary(summary)
    return {"ok": True, "stored": "summary", "summary_id": summary["summary_id"]}


@app.get("/api/alerts")
def api_alerts(limit: int = Query(default=50, ge=1, le=500)) -> List[Dict[str, Any]]:
    return store.list_alerts(limit=limit)


@app.get("/api/summaries")
def api_summaries(
    since_ms: Optional[int] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=2000),
) -> List[Dict[str, Any]]:
    return store.list_summaries(since_ms=since_ms, limit=limit)


if os.path.isdir(WEB_DIR):
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
