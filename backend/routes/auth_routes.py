"""Authentication routes (session-based, no JWT)."""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, redirect, render_template, request, session, url_for

from decorators import login_required
from security import get_csrf_token
from services.audit_service import log_action
from services.auth_service import authenticate_user, clear_session, establish_session


bp = Blueprint("auth", __name__, url_prefix="/auth")
public_bp = Blueprint("auth_public", __name__)


def _is_json_request() -> bool:
    if request.is_json:
        return True
    accept = request.headers.get("Accept", "")
    return "application/json" in accept.lower()


def _login_page_impl():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("frontend_app"))
    return render_template("login.html")


def _login_impl():
    payload = request.get_json(silent=True) if request.is_json else request.form
    identity = (payload.get("username") or payload.get("email") or payload.get("identity") or "").strip()
    password = payload.get("password") or ""

    if not identity or not password:
        if _is_json_request():
            return jsonify({"error": "Username/email and password are required"}), 400
        return render_template("login.html", error="Username/email and password are required"), 400

    user = authenticate_user(identity=identity, password=password)
    if user is None:
        log_action(
            action="auth.login.failed",
            resource="auth",
            user_id=None,
            details={"identity": identity},
        )
        if _is_json_request():
            return jsonify({"error": "Invalid credentials"}), 401
        return render_template("login.html", error="Invalid credentials"), 401

    establish_session(user)
    csrf_token = get_csrf_token(current_app)

    log_action(
        action="auth.login.success",
        resource="auth",
        user_id=user.id,
        details={"identity": identity, "roles": sorted(user.role_names)},
    )

    if _is_json_request():
        return jsonify({"message": "Login successful", "user": user.to_dict(), "csrf_token": csrf_token})

    return redirect(url_for("frontend_app"))


def _logout_impl():
    user = g.current_user
    clear_session()
    log_action(action="auth.logout", resource="auth", user_id=user.id, details={})

    if _is_json_request():
        return jsonify({"message": "Logged out"})

    return redirect(url_for("auth.login_page"))


@bp.get("/csrf")
def csrf_token():
    return jsonify({"csrf_token": get_csrf_token(current_app)})


@public_bp.get("/csrf")
def csrf_token_legacy():
    return jsonify({"csrf_token": get_csrf_token(current_app)})


@bp.get("/login")
def login_page():
    return _login_page_impl()


@public_bp.get("/login")
def login_page_legacy():
    return _login_page_impl()


@bp.post("/login")
def login():
    return _login_impl()


@public_bp.post("/login")
def login_legacy():
    return _login_impl()


@bp.post("/logout")
@login_required
def logout():
    return _logout_impl()


@public_bp.post("/logout")
@login_required
def logout_legacy():
    return _logout_impl()


@bp.get("/me")
@login_required
def me():
    return jsonify(
        {
            "user": g.current_user.to_dict(),
            "session_user_id": session.get("user_id"),
            "csrf_token": get_csrf_token(current_app),
        }
    )


@public_bp.get("/me")
@login_required
def me_legacy():
    return me()
