"""Central request security controls (CSRF + basic rate limiting)."""

from __future__ import annotations

import secrets
import threading
import time
from collections import deque

from flask import Flask, current_app, jsonify, request, session


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class InMemoryRateLimiter:
    """Process-local sliding-window rate limiter."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        now = time.time()
        threshold = now - window_seconds

        with self._lock:
            history = self._events.get(key)
            if history is None:
                history = deque()
                self._events[key] = history

            while history and history[0] < threshold:
                history.popleft()

            if len(history) >= limit:
                retry_after = max(1, int(window_seconds - (now - history[0])))
                return False, retry_after

            history.append(now)
            return True, 0


def get_client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _ensure_csrf_token(app: Flask) -> str:
    token = session.get("csrf_token")
    if token:
        return token

    token = secrets.token_urlsafe(app.config["CSRF_TOKEN_BYTES"])
    session["csrf_token"] = token
    return token


def get_csrf_token(app: Flask) -> str:
    return _ensure_csrf_token(app)


def _csrf_from_request() -> str | None:
    configured_header = current_app.config.get("CSRF_HEADER_NAME", "X-CSRF-Token")
    from_header = (
        request.headers.get(configured_header)
        or request.headers.get("X-CSRF-Token")
        or request.headers.get("X-XSRF-TOKEN")
    )
    if from_header:
        return from_header

    if request.is_json:
        payload = request.get_json(silent=True) or {}
        token = payload.get("csrf_token")
        if token:
            return str(token)

    token = request.form.get("csrf_token")
    if token:
        return token

    return None


def _enforce_rate_limit(app: Flask):
    limiter: InMemoryRateLimiter = app.extensions["rate_limiter"]

    endpoint = request.endpoint or ""
    method = request.method.upper()

    if method != "POST":
        return None

    if endpoint in {"auth.login", "auth_public.login_legacy"}:
        key = f"login:{get_client_ip()}"
        allowed, retry_after = limiter.check(
            key,
            app.config["LOGIN_RATE_LIMIT"],
            app.config["LOGIN_RATE_WINDOW_SEC"],
        )
        if not allowed:
            return jsonify({"error": "Too many login attempts", "retry_after": retry_after}), 429

    if request.path == "/api/auth/login":
        key = f"login:{get_client_ip()}"
        allowed, retry_after = limiter.check(
            key,
            app.config["LOGIN_RATE_LIMIT"],
            app.config["LOGIN_RATE_WINDOW_SEC"],
        )
        if not allowed:
            return jsonify({"error": "Too many login attempts", "retry_after": retry_after}), 429

    scan_paths = {"/scan", "/scans", "/scans/passive", "/scans/active", "/scans/full", "/api/scans"}
    if request.path in scan_paths or endpoint in {
        "scan_public.scan_start",
        "scans.run_scan",
        "scans.run_passive",
        "scans.run_active",
    }:
        user_key = session.get("user_id") or get_client_ip()
        key = f"scan:{user_key}"
        allowed, retry_after = limiter.check(
            key,
            app.config["SCAN_RATE_LIMIT"],
            app.config["SCAN_RATE_WINDOW_SEC"],
        )
        if not allowed:
            return jsonify({"error": "Scan rate limit exceeded", "retry_after": retry_after}), 429

    return None


def _enforce_csrf(app: Flask):
    if request.method.upper() in SAFE_METHODS:
        return None

    # The /api surface uses bearer JWT authentication and does not rely on cookies,
    # so CSRF protections are not required there.
    if request.path.startswith("/api/"):
        return None

    endpoint = request.endpoint or ""
    exempt_endpoints = {
        "auth.csrf_token",
        "auth_public.csrf_token_legacy",
        "healthcheck",
        "static",
    }
    if endpoint in exempt_endpoints:
        return None

    expected = session.get("csrf_token")
    presented = _csrf_from_request()

    if not expected or not presented or not secrets.compare_digest(expected, presented):
        current_app.logger.warning(
            "csrf_validation_failed endpoint=%s ip=%s has_expected=%s has_presented=%s",
            endpoint,
            get_client_ip(),
            bool(expected),
            bool(presented),
        )
        return jsonify({"error": "CSRF validation failed"}), 403

    return None


def init_security_controls(app: Flask) -> None:
    app.extensions["rate_limiter"] = InMemoryRateLimiter()

    @app.before_request
    def _security_before_request():
        _ensure_csrf_token(app)

        rate_limited_response = _enforce_rate_limit(app)
        if rate_limited_response is not None:
            return rate_limited_response

        csrf_response = _enforce_csrf(app)
        if csrf_response is not None:
            return csrf_response

        return None

    @app.after_request
    def _security_after_request(response):
        token = session.get("csrf_token")
        if token:
            response.headers[app.config["CSRF_HEADER_NAME"]] = token

        existing = response.headers.get("Access-Control-Expose-Headers", "")
        header_name = app.config["CSRF_HEADER_NAME"]
        if header_name not in existing:
            expose = f"{existing}, {header_name}" if existing else header_name
            response.headers["Access-Control-Expose-Headers"] = expose

        return response

    @app.context_processor
    def csrf_context_processor():
        return {"csrf_token": lambda: session.get("csrf_token") or _ensure_csrf_token(app)}
