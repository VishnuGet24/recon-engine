"""Consistent /api response helpers (error envelope, timestamps, request ids)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from flask import jsonify


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def api_error(
    *,
    status: int,
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
    request_id: str | None = None,
):
    payload: dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
            "details": details or [],
            "timestamp": utc_now_iso(),
            "requestId": request_id or str(uuid4()),
        }
    }
    response = jsonify(payload)
    response.status_code = status
    return response
