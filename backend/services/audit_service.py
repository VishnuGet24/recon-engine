"""Audit log write helpers."""

from __future__ import annotations

from flask import current_app, has_request_context, request
from sqlalchemy.exc import SQLAlchemyError

from extensions import db
from models import AuditLog


def log_action(
    *,
    action: str,
    resource: str,
    user_id: int | None,
    details: dict | None = None,
    commit: bool = True,
) -> None:
    if has_request_context():
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    else:
        ip_address = "system"

    target = None
    if details and isinstance(details, dict):
        target = details.get("target")

    if target is None:
        target = resource

    entry = AuditLog(
        user_id=user_id,
        action=action,
        target=str(target)[:255] if target is not None else None,
        ip_address=(ip_address or "")[:45],
    )
    db.session.add(entry)

    if not commit:
        return

    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("Failed to write audit log", extra={"action": action, "resource": resource})
