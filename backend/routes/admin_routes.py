"""Admin-only routes for user management."""

from __future__ import annotations

import re

from flask import Blueprint, g, jsonify, render_template, request
from sqlalchemy import func, or_
from sqlalchemy.exc import SQLAlchemyError

from decorators import login_required, permission_required, role_required
from extensions import db
from models import AuditLog, Role, User
from services.audit_service import log_action
from services.auth_service import hash_password, validate_username


bp = Blueprint("admin", __name__, url_prefix="/admin")


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _parse_roles(raw_roles) -> list[str]:
    if isinstance(raw_roles, list):
        names = [str(item).strip().lower() for item in raw_roles if str(item).strip()]
    elif isinstance(raw_roles, str):
        names = [item.strip().lower() for item in raw_roles.split(",") if item.strip()]
    else:
        names = []

    return sorted(set(names or ["basic"]))


def _is_json_request() -> bool:
    if request.is_json:
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept.lower()


def _error_response(message: str, status: int = 400, **extra):
    payload = {"error": message}
    payload.update(extra)
    if _is_json_request():
        return jsonify(payload), status
    roles = Role.query.order_by(Role.name.asc()).all()
    return render_template("create_user.html", roles=roles, error=message), status


@bp.get("/users/new")
@login_required
@role_required("admin")
@permission_required("user:create")
def create_user_page():
    roles = Role.query.order_by(Role.name.asc()).all()
    return render_template("create_user.html", roles=roles)


@bp.post("/users")
@login_required
@role_required("admin")
@permission_required("user:create")
def create_user():
    payload = request.get_json(silent=True) if request.is_json else request.form

    try:
        username = validate_username(payload.get("username", ""))
    except ValueError as exc:
        return _error_response(str(exc), 400)

    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""

    if request.is_json:
        role_names = _parse_roles(payload.get("roles"))
    else:
        role_names = _parse_roles(request.form.getlist("roles"))

    if not _EMAIL_RE.match(email):
        return _error_response("Invalid email address", 400)

    existing = User.query.filter(
        or_(func.lower(User.username) == username.lower(), func.lower(User.email) == email.lower())
    ).first()
    if existing is not None:
        return _error_response("Username or email already exists", 409)

    roles = Role.query.filter(Role.name.in_(role_names)).all()
    found = {role.name for role in roles}
    missing_roles = sorted(set(role_names) - found)
    if missing_roles:
        return _error_response("Unknown roles", 400, missing_roles=missing_roles)

    try:
        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            is_active=True,
        )
        user.roles = roles

        db.session.add(user)
        db.session.commit()

        log_action(
            action="admin.user.created",
            resource="users",
            user_id=g.current_user.id,
            details={"created_user_id": user.id, "username": user.username, "roles": role_names},
        )

        if _is_json_request():
            return jsonify({"message": "User created", "user": user.to_dict()}), 201

        return render_template("create_user.html", roles=Role.query.order_by(Role.name.asc()).all(), success=True), 201

    except ValueError as exc:
        return _error_response(str(exc), 400)

    except SQLAlchemyError:
        db.session.rollback()
        return _error_response("Database error while creating user", 500)


@bp.get("/users")
@login_required
@role_required("admin")
@permission_required("user:read")
def list_users():
    users = User.query.order_by(User.created_at.desc()).limit(500).all()
    return jsonify({"users": [user.to_dict() for user in users]})


@bp.get("/audit-logs")
@login_required
@role_required("admin")
@permission_required("audit:read")
def list_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(500).all()
    return jsonify({"audit_logs": [log.to_dict() for log in logs]})
