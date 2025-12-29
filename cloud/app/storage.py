from __future__ import annotations

from typing import Any, Dict, List, Optional
import json
import os
from threading import Lock

from google.cloud import firestore


class FileBackedStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = Lock()
        self._data = {"alerts": {}, "summaries": {}}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
            except Exception:
                self._data = {"alerts": {}, "summaries": {}}

    def _flush(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._data, f)
        os.replace(tmp, self.path)

    def upsert_alert(self, alert: Dict[str, Any]) -> None:
        with self._lock:
            self._data["alerts"][alert["alert_id"]] = alert
            self._flush()

    def upsert_summary(self, summary: Dict[str, Any]) -> None:
        with self._lock:
            self._data["summaries"][summary["summary_id"]] = summary
            self._flush()

    def list_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            vals = list(self._data["alerts"].values())
        vals.sort(key=lambda a: a.get("event_epoch_ms", 0), reverse=True)
        return vals[:limit]

    def list_summaries(self, since_ms: Optional[int] = None, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            vals = list(self._data["summaries"].values())
        if since_ms is not None:
            vals = [s for s in vals if int(s.get("window_end_ms", 0)) >= int(since_ms)]
        vals.sort(key=lambda s: s.get("window_end_ms", 0), reverse=True)
        return vals[:limit]


class FirestoreStore:
    def __init__(self, project: str, alerts_collection: str = "alerts", summaries_collection: str = "summaries_10s"):
        self.project = project
        self.client = firestore.Client(project=project)
        self.alerts_col = self.client.collection(alerts_collection)
        self.summaries_col = self.client.collection(summaries_collection)

    def upsert_alert(self, alert: Dict[str, Any]) -> None:
        doc_id = alert["alert_id"]
        self.alerts_col.document(doc_id).set(alert, merge=True)

    def upsert_summary(self, summary: Dict[str, Any]) -> None:
        doc_id = summary["summary_id"]
        self.summaries_col.document(doc_id).set(summary, merge=True)

    def list_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        q = self.alerts_col.order_by("event_epoch_ms", direction=firestore.Query.DESCENDING).limit(limit)
        return [d.to_dict() for d in q.stream()]

    def list_summaries(self, since_ms: Optional[int] = None, limit: int = 200) -> List[Dict[str, Any]]:
        # Nota Firestore: si usas filtro (>=), debes order_by el mismo campo.
        if since_ms is not None:
            q = (
                self.summaries_col.where("window_end_ms", ">=", int(since_ms))
                .order_by("window_end_ms", direction=firestore.Query.DESCENDING)
                .limit(limit)
            )
        else:
            q = self.summaries_col.order_by("window_end_ms", direction=firestore.Query.DESCENDING).limit(limit)
        return [d.to_dict() for d in q.stream()]
