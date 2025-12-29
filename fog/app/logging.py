from __future__ import annotations
import json
from typing import Any, Dict


def log_json(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False), flush=True)

