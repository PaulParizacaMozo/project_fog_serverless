from __future__ import annotations
import os


def getenv_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if not v:
        return default
    try:
        return int(v)
    except ValueError:
        return default


def getenv_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if not v:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")


FOG_ID = os.getenv("FOG_ID", "fog-01")
WINDOW_MS = getenv_int("WINDOW_MS", 10_000)

# Si luego quieres proteger Fog, habilitas token (por ahora OFF)
EDGE_TO_FOG_TOKEN = os.getenv("EDGE_TO_FOG_TOKEN", "")

SINK_MODE = os.getenv("SINK_MODE", "print")  # print | http
CLOUD_BASE_URL = os.getenv("CLOUD_BASE_URL", "")
CLOUD_INGEST_TOKEN = os.getenv("CLOUD_INGEST_TOKEN", "")

