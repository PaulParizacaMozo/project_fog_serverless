from __future__ import annotations
from fastapi import Header, HTTPException
import os


INGEST_TOKEN = os.getenv("INGEST_TOKEN", "dev-token")


def require_bearer_token(authorization: str | None = Header(default=None)) -> None:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")

    token = authorization.split(" ", 1)[1].strip()
    if token != INGEST_TOKEN:
        raise HTTPException(status_code=403, detail="invalid token")

