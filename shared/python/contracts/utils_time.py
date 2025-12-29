from __future__ import annotations
from datetime import datetime, timezone


def utc_iso_from_epoch_ms(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def now_epoch_ms() -> int:
    import time
    return int(time.time() * 1000)

