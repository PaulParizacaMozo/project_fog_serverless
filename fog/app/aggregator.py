from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from collections import Counter

from app.config import FOG_ID, WINDOW_MS
from contracts.utils_time import utc_iso_from_epoch_ms, now_epoch_ms


def floor_window_start_ms(event_ms: int) -> int:
    return (event_ms // WINDOW_MS) * WINDOW_MS


def quantile_int(xs: List[int], q: float) -> Optional[int]:
    if not xs:
        return None
    s = sorted(xs)
    idx = int(round((len(s) - 1) * q))
    idx = max(0, min(idx, len(s) - 1))
    return int(s[idx])


@dataclass
class WindowAgg:
    ws: int
    we: int
    events_total: int = 0
    alerts_total: int = 0
    alerts_by_sev: Dict[str, int] = field(default_factory=lambda: {"LOW": 0, "MED": 0, "HIGH": 0, "CRIT": 0})
    attack_cat_counter: Counter = field(default_factory=Counter)
    proto_counter: Counter = field(default_factory=Counter)
    service_counter: Counter = field(default_factory=Counter)
    lags: List[int] = field(default_factory=list)
    benign_suppressed: int = 0

    def add(self, record: Dict[str, Any], lag_ms: int) -> None:
        self.events_total += 1
        self.lags.append(int(lag_ms))

        label = int(record.get("label", 0) or 0)
        attack_cat = record.get("attack_cat")
        proto = record.get("proto")
        service = record.get("service")

        if proto:
            self.proto_counter[proto] += 1
        if service:
            self.service_counter[service] += 1

        if label == 1:
            self.alerts_total += 1
            sev = record.get("severity") or "HIGH"
            if sev not in self.alerts_by_sev:
                sev = "HIGH"
            self.alerts_by_sev[sev] += 1
            if attack_cat:
                self.attack_cat_counter[attack_cat] += 1
        else:
            self.benign_suppressed += 1

    def top1(self, c: Counter) -> Optional[str]:
        if not c:
            return None
        return c.most_common(1)[0][0]


class TumblingAggregator:
    """
    Tumbling window 10s basado en event_time (event_epoch_ms).
    Produce summaries al cerrar ventanas.
    """

    def __init__(self) -> None:
        self.windows: Dict[int, WindowAgg] = {}
        self.last_flushed_we: Optional[int] = None

    def _ensure(self, ws: int) -> WindowAgg:
        we = ws + WINDOW_MS
        agg = self.windows.get(ws)
        if agg is None:
            agg = WindowAgg(ws=ws, we=we)
            self.windows[ws] = agg
        return agg

    def ingest(self, event_ms: int, record: Dict[str, Any], lag_ms: int) -> List[Dict[str, Any]]:
        ws = floor_window_start_ms(event_ms)
        we = ws + WINDOW_MS

        # inicializa cursor de flush
        if self.last_flushed_we is None:
            self.last_flushed_we = we

        summaries: List[Dict[str, Any]] = []

        # si saltamos a una ventana futura, flush de ventanas completas previas
        if we > self.last_flushed_we:
            summaries.extend(self.flush_until(we))

        self._ensure(ws).add(record, lag_ms)
        return summaries

    def flush_until(self, target_we: int) -> List[Dict[str, Any]]:
        """
        Emite summaries en orden hasta antes de target_we.
        """
        out: List[Dict[str, Any]] = []
        assert self.last_flushed_we is not None

        while self.last_flushed_we < target_we:
            ws = self.last_flushed_we - WINDOW_MS
            we = self.last_flushed_we

            agg = self.windows.pop(ws, None)
            if agg is None:
                agg = WindowAgg(ws=ws, we=we)

            payload = {
                "type": "SUMMARY",
                "summary_id": f"{FOG_ID}__{ws}__{we}",
                "fog_id": FOG_ID,
                "window_start": utc_iso_from_epoch_ms(ws),
                "window_end": utc_iso_from_epoch_ms(we),
                "window_start_ms": ws,
                "window_end_ms": we,
                "generated_at": utc_iso_from_epoch_ms(now_epoch_ms()),
                "events_total": agg.events_total,
                "alerts_total": agg.alerts_total,
                "alerts_by_severity": agg.alerts_by_sev,
                "top_attack_cat": agg.top1(agg.attack_cat_counter),
                "top_proto": agg.top1(agg.proto_counter),
                "top_service": agg.top1(agg.service_counter),
                "pipeline_lag_ms_p50": quantile_int(agg.lags, 0.50),
                "pipeline_lag_ms_p95": quantile_int(agg.lags, 0.95),
                "benign_suppressed": agg.benign_suppressed,
            }
            out.append(payload)
            self.last_flushed_we += WINDOW_MS

        return out

