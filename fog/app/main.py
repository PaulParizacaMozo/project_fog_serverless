from __future__ import annotations
from fastapi import FastAPI, Header, HTTPException
from typing import Optional, Dict, Any

from app.logging import log_json
from app.pipeline import FogPipeline
from contracts.schemas import EdgeEvent

from app.config import EDGE_TO_FOG_TOKEN, SINK_MODE, CLOUD_BASE_URL, CLOUD_INGEST_TOKEN
from app.sink import PrintSink, HttpSink

app = FastAPI()
pipeline = FogPipeline()


sink = PrintSink() if SINK_MODE == "print" else HttpSink(CLOUD_BASE_URL, CLOUD_INGEST_TOKEN)

@app.post("/edge/event")
def ingest(evt: EdgeEvent, authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
    alert, summaries = pipeline.process(evt.model_dump())

    if alert:
        sink.send_alert(alert)

    for s in summaries:
        sink.send_summary(s)

    return {"ok": True}

