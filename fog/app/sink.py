from __future__ import annotations
import json
import time
from typing import Any, Dict
import requests

from app.logging import log_json


class PrintSink:
    def send_alert(self, alert: Dict[str, Any]) -> None:
        log_json(alert)

    def send_summary(self, summary: Dict[str, Any]) -> None:
        log_json(summary)


class HttpSink:
    def __init__(self, base_url: str, token: str, timeout_s: float = 2.5) -> None:
        self.alert_url = f"{base_url.rstrip('/')}/ingest/alert"
        self.summary_url = f"{base_url.rstrip('/')}/ingest/summary"
        self.headers = {"Authorization": f"Bearer {token}"}
        self.timeout_s = timeout_s

    def _post(self, url: str, payload: Dict[str, Any]) -> None:
        last_err = None
        for i in range(4):
            try:
                r = requests.post(url, json=payload, headers=self.headers, timeout=self.timeout_s)
                if 200 <= r.status_code < 300:
                    return
                last_err = RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
            except Exception as e:
                last_err = e
            time.sleep(0.25 * (2 ** i))
        # no tumba el pipeline
        log_json({"level": "ERROR", "msg": "cloud_post_failed", "url": url, "err": str(last_err)})

    def send_alert(self, alert: Dict[str, Any]) -> None:
        self._post(self.alert_url, alert)

    def send_summary(self, summary: Dict[str, Any]) -> None:
        self._post(self.summary_url, summary)

