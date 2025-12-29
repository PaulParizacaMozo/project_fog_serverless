from __future__ import annotations
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from app.config import FOG_ID
from app.aggregator import TumblingAggregator
from app.privacy import strip_pii
from contracts.utils_time import utc_iso_from_epoch_ms, now_epoch_ms


def stable_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]


class FogPipeline:
    def __init__(self) -> None:
        self.agg = TumblingAggregator()

    def process(self, edge_event: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Returns: (alert_payload_or_None, list_of_summary_payloads_to_print)
        """
        received_ms = now_epoch_ms()

        event_ms = int(edge_event["event_epoch_ms"])
        lag_ms = int(received_ms - event_ms)
        if lag_ms < 0:
            lag_ms = 0

        edge_id = str(edge_event["edge_id"])
        seq = int(edge_event["seq"])

        record_raw = edge_event.get("record", {}) or {}
        record = strip_pii(record_raw)

        # “inferencia” por ground truth
        label = int(record.get("label", 0) or 0)
        attack_cat = record.get("attack_cat") or "unknown"

        # agrega a ventana (si cruza límite, devuelve summaries)
        summaries = self.agg.ingest(event_ms=event_ms, record=record, lag_ms=lag_ms)

        alert_payload: Optional[Dict[str, Any]] = None
        if label == 1:
            # idempotente (estable)
            alert_id = f"{FOG_ID}__{event_ms}__{seq}__{stable_hash(edge_id + '|' + str(seq) + '|' + attack_cat)}"
            alert_payload = {
                "type": "ALERT",
                "alert_id": alert_id,
                "fog_id": FOG_ID,
                "edge_id": edge_id,
                "seq": seq,
                "event_time": edge_event["event_time"],
                "event_epoch_ms": event_ms,
                "received_at": utc_iso_from_epoch_ms(received_ms),
                "received_epoch_ms": received_ms,
                "pipeline_lag_ms": lag_ms,
                "severity": record.get("severity") or "HIGH",
                "score": float(record.get("score") or 1.0),
                "attack_cat": attack_cat,
                "signal": {
                    "proto": record.get("proto"),
                    "service": record.get("service"),
                    "state": record.get("state"),
                },
                "src_token": record.get("src_token"),
                "dst_token": record.get("dst_token"),
            }

        return alert_payload, summaries

