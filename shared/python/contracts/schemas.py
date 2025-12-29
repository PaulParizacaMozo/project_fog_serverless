from __future__ import annotations
from typing import Any, Dict, Optional, Literal
from pydantic import BaseModel, Field


class EdgeEvent(BaseModel):
    event_time: str
    event_epoch_ms: int
    edge_id: str
    seq: int
    orig_stime: Optional[float] = None
    record: Dict[str, Any]


Severity = Literal["LOW", "MED", "HIGH", "CRIT"]


class Alert(BaseModel):
    type: Literal["ALERT"] = "ALERT"

    alert_id: str
    event_time: str
    event_epoch_ms: int

    received_at: str
    received_epoch_ms: int
    pipeline_lag_ms: int

    fog_id: str
    edge_id: str
    seq: int

    severity: Severity = "HIGH"
    score: float = 1.0
    attack_cat: str
    signal: Dict[str, Any] = Field(default_factory=dict)

    src_token: Optional[str] = None
    dst_token: Optional[str] = None


class SummaryWindow(BaseModel):
    type: Literal["SUMMARY"] = "SUMMARY"

    summary_id: str
    fog_id: str

    window_start: str
    window_end: str
    window_start_ms: int
    window_end_ms: int

    generated_at: str

    events_total: int
    alerts_total: int
    alerts_by_severity: Dict[str, int]

    top_attack_cat: Optional[str] = None
    top_proto: Optional[str] = None
    top_service: Optional[str] = None

    pipeline_lag_ms_p50: Optional[int] = None
    pipeline_lag_ms_p95: Optional[int] = None

    benign_suppressed: int = 0

