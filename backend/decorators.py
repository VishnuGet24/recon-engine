"""Authentication and RBAC decorators."""

from __future__ import annotations

from functools import wraps

from flask import g, jsonify, redirect, request, session, url_for


API_PREFIXES = ("/auth", "/admin", "/scans", "/scan", "/api", "/login", "/logout", "/me", "/csrf")


def _wants_json_response() -> bool:
    if request.path.startswith(API_PREFIXES):
        return True
    if request.is_json:
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept.lower()


def _unauthenticated_response():
    if _wants_json_response():
        return jsonify({"error": "Authentication required"}), 401
    return redirect(url_for("auth.login_page"))


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id") or getattr(g, "current_user", None) is None:
            return _unauthenticated_response()
        return func(*args, **kwargs)

    return wrapper


def permission_required(permission_name: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user is None:
                return _unauthenticated_response()

            if not user.has_permission(permission_name):
                return jsonify({"error": "Forbidden", "required_permission": permission_name}), 403

            return func(*args, **kwargs)

        return wrapper

    return decorator


def role_required(role_name: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user is None:
                return _unauthenticated_response()

            if not user.has_role(role_name):
                return jsonify({"error": "Forbidden", "required_role": role_name}), 403

            return func(*args, **kwargs)

        return wrapper

    return decorator
