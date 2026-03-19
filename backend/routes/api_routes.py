"""JWT-authenticated /api routes matching BACKEND_API_SPECIFICATION.* docs.

This is a compatibility layer over the existing session-based backend. It:
- issues JWT access/refresh tokens for SPA auth
- exposes /api dashboard + inventory endpoints derived from stored Scan rows
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from io import StringIO
from typing import Any

from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy import desc, text

from extensions import db
from models import AuditLog, Finding, Scan, User
from services.auth_service import authenticate_user
from services.scan_service import generate_findings, run_active_scan, run_full_scan, run_passive_scan, validate_target
from utils.api_response import api_error, utc_now_iso
from utils.jwt_utils import JwtError, access_expiry_iso, decode_token, issue_tokens


bp = Blueprint("api", __name__, url_prefix="/api")

_WILDCARD_DOMAIN_RE = re.compile(r"^\*\.(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")


def _scan_executor() -> ThreadPoolExecutor:
    executor = current_app.extensions.get("api_scan_executor")
    if executor is None:
        max_workers = int(current_app.config.get("API_SCAN_MAX_WORKERS", 4))
        executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="api-scan")
        current_app.extensions["api_scan_executor"] = executor
    return executor


def _asset_id_for_target(target: str) -> str:
    digest = hashlib.sha1(target.encode("utf-8")).hexdigest()
    return digest[:24]


def _relative_time(timestamp: datetime | None) -> str:
    if not timestamp:
        return ""
    now = datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    delta = now - timestamp
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = hours // 24
    return f"{days} day{'s' if days != 1 else ''} ago"


def _scan_findings_count(scan: Scan) -> int:
    results = scan.results_json or {}
    if isinstance(results, dict) and isinstance(results.get("meta"), dict):
        meta_findings = results["meta"].get("findings")
        if isinstance(meta_findings, dict):
            total = meta_findings.get("total")
            try:
                return int(total)
            except (TypeError, ValueError):
                pass

    modules = results.get("modules") if isinstance(results, dict) else {}
    if not isinstance(modules, dict):
        return 0

    risk = modules.get("risk_scoring") if isinstance(modules.get("risk_scoring"), dict) else {}
    if risk.get("status") == "completed" and isinstance(risk.get("data"), dict):
        key_findings = risk["data"].get("key_findings")
        if isinstance(key_findings, list):
            return len(key_findings)

    vuln = modules.get("vulnerability_surface") if isinstance(modules.get("vulnerability_surface"), dict) else {}
    if vuln.get("status") == "completed" and isinstance(vuln.get("data"), dict):
        potential = vuln["data"].get("potential_risks")
        if isinstance(potential, list):
            return len(potential)

    port = modules.get("port_scan") if isinstance(modules.get("port_scan"), dict) else {}
    if port.get("status") == "completed" and isinstance(port.get("data"), dict):
        open_ports = port["data"].get("open_ports")
        if isinstance(open_ports, list):
            return len(open_ports)

    return 0


def _calculate_risk_from_results(mode: str, results: dict[str, Any]) -> tuple[Decimal | None, str | None, Decimal | None]:
    modules = results.get("modules") if isinstance(results, dict) else {}
    if not isinstance(modules, dict):
        modules = {}

    risk_module = modules.get("risk_scoring") if isinstance(modules.get("risk_scoring"), dict) else {}
    if risk_module.get("status") == "completed" and isinstance(risk_module.get("data"), dict):
        risk_data = risk_module["data"]
        raw_score = risk_data.get("attack_surface_score")
        raw_risk = risk_data.get("overall_risk")
        try:
            score_value = Decimal(str(raw_score))
        except Exception:
            score_value = None

        completed_modules = sum(1 for module in modules.values() if isinstance(module, dict) and module.get("status") == "completed")
        total_modules = max(len(modules), 1)
        confidence_pct = Decimal(str(round(60 + (completed_modules / total_modules) * 40, 2)))
        return score_value, str(raw_risk) if raw_risk is not None else None, confidence_pct

    if (mode or "").strip().lower() == "passive":
        return Decimal("2.0"), "Low", Decimal("70.0")

    port_scan_module = modules.get("port_scan") if isinstance(modules.get("port_scan"), dict) else {}
    port_scan_data = port_scan_module.get("data") if port_scan_module.get("status") == "completed" else {}
    open_ports = len((port_scan_data or {}).get("open_ports") or [])
    if open_ports >= 8:
        return Decimal("8.5"), "High", Decimal("85.0")
    if open_ports >= 3:
        return Decimal("6.0"), "Medium", Decimal("80.0")
    return Decimal("3.5"), "Low", Decimal("75.0")


def _scan_type_from_mode(mode: str) -> tuple[str, str]:
    mode = (mode or "").strip().lower()
    if mode == "passive":
        return "quick_scan", "Quick Scan"
    if mode == "active":
        return "custom_scan", "Custom Scan"
    return "full_scan", "Full Scan"


def _scan_status_normalize(status: str | None) -> str:
    value = (status or "").strip().lower()
    if value in {"queued", "pending", "scheduled"}:
        return value if value != "scheduled" else "pending"
    if value in {"running", "in_progress"}:
        return "in_progress"
    if value in {"completed", "failed", "cancelled"}:
        return value
    return "pending"


def _scan_module_data(results: dict[str, Any], module_name: str) -> dict[str, Any]:
    modules = results.get("modules") if isinstance(results, dict) else {}
    if not isinstance(modules, dict):
        return {}
    entry = modules.get(module_name) if isinstance(modules.get(module_name), dict) else {}
    if entry.get("status") != "completed":
        return {}
    data = entry.get("data")
    return data if isinstance(data, dict) else {}


def _scan_logs_from_results(results: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(results, dict):
        return []
    logs = results.get("logs")
    if logs is None and isinstance(results.get("meta"), dict):
        logs = results["meta"].get("logs")
    if not isinstance(logs, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in logs:
        if not isinstance(item, dict):
            continue
        timestamp = item.get("timestamp")
        level = (item.get("level") or "info").strip().lower()
        message = item.get("message")
        if not timestamp or not message:
            continue
        if level not in {"info", "warning", "error"}:
            level = "info"
        normalized.append({"timestamp": str(timestamp), "level": level, "message": str(message)})
    return normalized[-500:]


def _scan_progress_from_results(*, status: str, results: dict[str, Any]) -> int:
    if status in {"completed", "failed", "cancelled"}:
        return 100
    if not isinstance(results, dict):
        return 50 if status == "in_progress" else 0

    meta = results.get("meta") if isinstance(results.get("meta"), dict) else {}
    raw_progress = meta.get("progress")
    try:
        progress = int(raw_progress)
        return max(0, min(progress, 99 if status == "in_progress" else 100))
    except (TypeError, ValueError):
        pass

    modules = results.get("modules")
    if not isinstance(modules, dict) or not modules:
        return 50 if status == "in_progress" else 0

    completed = 0
    for module in modules.values():
        if isinstance(module, dict) and module.get("status") in {"completed", "failed"}:
            completed += 1
    total = max(len(modules), 1)
    return max(1, min(int((completed / total) * 100), 99))


def _scan_assets_from_results(*, scan: Scan, results: dict[str, Any]) -> dict[str, Any]:
    resolved_ips: list[str] = []
    subdomains: list[str] = []
    open_ports: list[int] = []
    technologies: list[str] = []
    vulnerabilities: list[str] = []

    dns_data = _scan_module_data(results, "dns_enum")
    if isinstance(dns_data.get("resolved_ips"), list):
        resolved_ips = [str(ip) for ip in dns_data.get("resolved_ips") if str(ip)]
    elif isinstance(results.get("resolved_ips"), list):
        resolved_ips = [str(ip) for ip in results.get("resolved_ips") if str(ip)]

    sub_data = _scan_module_data(results, "subdomain_enum")
    if isinstance(sub_data.get("subdomains"), list):
        for item in sub_data.get("subdomains") or []:
            if isinstance(item, dict) and item.get("hostname"):
                subdomains.append(str(item["hostname"]))

    port_data = _scan_module_data(results, "port_scan")
    if isinstance(port_data.get("open_ports"), list):
        for p in port_data.get("open_ports") or []:
            try:
                open_ports.append(int(p))
            except (TypeError, ValueError):
                continue
    elif isinstance(results.get("port_scan"), dict) and isinstance(results["port_scan"].get("open_ports"), list):
        for p in results["port_scan"].get("open_ports") or []:
            try:
                open_ports.append(int(p))
            except (TypeError, ValueError):
                continue
    open_ports = sorted(set(open_ports))

    tech_data = _scan_module_data(results, "technology_fingerprint")
    if isinstance(tech_data.get("framework"), list):
        technologies.extend(str(x) for x in tech_data.get("framework") if str(x))
    for key in ("server", "cdn", "reverse_proxy", "waf"):
        value = tech_data.get(key)
        if value:
            technologies.append(str(value))
    technologies = sorted({t for t in technologies if t and t.lower() != "none"})

    vuln_data = _scan_module_data(results, "vulnerability_surface")
    for key in ("potential_risks", "misconfigurations"):
        value = vuln_data.get(key)
        if isinstance(value, list):
            vulnerabilities.extend(str(x) for x in value if str(x))
    vulnerabilities = sorted(set(vulnerabilities))

    http_data = _scan_module_data(results, "http_probe")
    urls: list[str] = []
    if isinstance(http_data.get("redirects"), list):
        urls.extend(str(u) for u in http_data.get("redirects") if str(u))
    elif http_data.get("url"):
        urls.append(str(http_data.get("url")))
    urls = sorted(set(urls))

    unique_assets: set[str] = {str(scan.target)}
    unique_assets.update(resolved_ips)
    unique_assets.update(subdomains)
    unique_assets.update(urls)

    discovered_only = {asset for asset in unique_assets if asset and asset != str(scan.target)}
    return {
        "resolvedIps": resolved_ips,
        "subdomains": subdomains,
        "openPorts": open_ports,
        "technologies": technologies,
        "vulnerabilities": vulnerabilities,
        "urls": urls,
        "assetsDiscovered": len(discovered_only),
    }


def _scan_summary_text(*, scan: Scan, status: str, results: dict[str, Any]) -> str:
    assets = _scan_assets_from_results(scan=scan, results=results)
    risk_data = _scan_module_data(results, "risk_scoring")
    score = risk_data.get("attack_surface_score")
    overall = risk_data.get("overall_risk") or scan.overall_risk

    parts: list[str] = []
    parts.append(f"Target: {scan.target}")
    parts.append(f"Mode: {scan.scan_mode}")
    parts.append(f"Status: {status}")
    if overall:
        parts.append(f"Overall risk: {overall}")
    if score is not None:
        parts.append(f"Attack surface score: {score}")
    parts.append(f"Assets discovered: {assets.get('assetsDiscovered', 0)}")
    parts.append(f"Subdomains: {len(assets.get('subdomains') or [])}")
    parts.append(f"Open ports: {len(assets.get('openPorts') or [])}")
    parts.append(f"Vulnerabilities: {len(assets.get('vulnerabilities') or [])}")
    return " | ".join(parts)


def _user_role(user: User) -> str:
    if user.has_role("admin"):
        return "admin"
    if user.has_permission("scan:active"):
        return "operator"
    return "viewer"


def _api_user_payload(user: User) -> dict[str, Any]:
    return {
        "id": str(user.id),
        "email": user.email,
        "name": user.username,
        "role": _user_role(user),
        "avatar": "",
        "organizationId": "default",
    }


def _require_api_auth() -> tuple[User, dict[str, Any]] | Any:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return api_error(status=401, code="AUTHENTICATION_REQUIRED", message="Missing bearer token")

    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token, expected_type="access")
    except JwtError:
        return api_error(status=401, code="AUTHENTICATION_REQUIRED", message="Invalid or expired token")

    user_id = payload.get("sub")
    try:
        user_int = int(str(user_id))
    except (TypeError, ValueError):
        return api_error(status=401, code="AUTHENTICATION_REQUIRED", message="Invalid token subject")

    user = db.session.get(User, user_int)
    if user is None or not user.is_active:
        return api_error(status=401, code="AUTHENTICATION_REQUIRED", message="User not found or inactive")

    g.api_user = user
    g.api_token_payload = payload
    return user, payload


@bp.get("/auth/session")
def auth_session():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth
    user, token_payload = auth

    return jsonify(
        {
            "user": _api_user_payload(user),
            "permissions": sorted(user.permission_names),
            "sessionExpiry": access_expiry_iso(token_payload),
        }
    )


@bp.post("/auth/login")
def auth_login():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email") or "").strip()
    password = str(payload.get("password") or "")

    if not email or not password:
        details = []
        if not email:
            details.append({"field": "email", "message": "Email is required"})
        if not password:
            details.append({"field": "password", "message": "Password is required"})
        return api_error(status=422, code="VALIDATION_ERROR", message="Invalid request parameters", details=details)

    user = authenticate_user(email, password)
    if user is None:
        return api_error(status=401, code="INVALID_CREDENTIALS", message="Invalid email or password")

    permissions = sorted(user.permission_names)
    tokens = issue_tokens(user_id=user.id, permissions=permissions)

    return jsonify(
        {
            "user": _api_user_payload(user),
            "tokens": {
                "accessToken": tokens.access_token,
                "refreshToken": tokens.refresh_token,
                "expiresIn": tokens.expires_in,
            },
            "permissions": permissions,
        }
    )


@bp.post("/auth/refresh")
def auth_refresh():
    payload = request.get_json(silent=True) or {}
    refresh_token = str(payload.get("refreshToken") or "").strip()
    if not refresh_token:
        return api_error(
            status=422,
            code="VALIDATION_ERROR",
            message="Invalid request parameters",
            details=[{"field": "refreshToken", "message": "Refresh token is required"}],
        )

    try:
        refresh_payload = decode_token(refresh_token, expected_type="refresh")
    except JwtError:
        return api_error(status=401, code="AUTHENTICATION_REQUIRED", message="Invalid or expired refresh token")

    try:
        user_int = int(str(refresh_payload.get("sub")))
    except (TypeError, ValueError):
        return api_error(status=401, code="AUTHENTICATION_REQUIRED", message="Invalid refresh token subject")

    user = db.session.get(User, user_int)
    if user is None or not user.is_active:
        return api_error(status=401, code="AUTHENTICATION_REQUIRED", message="User not found or inactive")

    permissions = sorted(user.permission_names)
    tokens = issue_tokens(user_id=user.id, permissions=permissions)
    return jsonify(
        {
            "accessToken": tokens.access_token,
            "refreshToken": tokens.refresh_token,
            "expiresIn": tokens.expires_in,
        }
    )


@bp.post("/auth/logout")
def auth_logout():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth
    return jsonify({"message": "Logged out successfully"})


@bp.get("/dashboard/metrics")
def dashboard_metrics():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    scans = Scan.query.order_by(desc(Scan.created_at)).limit(250).all()
    unique_assets = {scan.target for scan in scans}
    scored = [scan.risk_score for scan in scans if scan.risk_score is not None]
    avg_score = float(sum(float(x) for x in scored) / len(scored)) if scored else 0.0

    critical_findings = 0
    for scan in scans:
        if (scan.overall_risk or "").lower() in {"high"}:
            critical_findings += _scan_findings_count(scan)

    latest = scans[0] if scans else None
    latest_ts = latest.created_at if latest else None
    next_ts = (latest_ts + timedelta(hours=4)) if latest_ts else None

    return jsonify(
        {
            "totalAssets": {
                "value": len(unique_assets),
                "change": {"percentage": 0, "direction": "neutral", "timeframe": "last month"},
            },
            "criticalFindings": {
                "value": critical_findings,
                "change": {"percentage": 0, "direction": "neutral", "timeframe": "last week"},
            },
            "riskScore": {
                "value": round(avg_score, 2),
                "maxValue": 10,
                "change": {"value": 0, "direction": "neutral", "timeframe": "last scan"},
            },
            "lastScan": {
                "timestamp": latest_ts.isoformat() if latest_ts else None,
                "relativeTime": _relative_time(latest_ts) if latest_ts else "",
                "nextScan": {
                    "timestamp": next_ts.isoformat() if next_ts else None,
                    "relativeTime": "In 4 hours" if next_ts else "",
                },
            },
        }
    )


@bp.get("/dashboard/risk-trend")
def dashboard_risk_trend():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    timeframe = (request.args.get("timeframe") or "30d").strip()
    granularity = (request.args.get("granularity") or "daily").strip()

    days_map = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}
    days = days_map.get(timeframe, 30)
    start = datetime.now(timezone.utc) - timedelta(days=days)

    scans = Scan.query.filter(Scan.created_at >= start).order_by(Scan.created_at.asc()).limit(2000).all()

    data = []
    for scan in scans:
        if scan.risk_score is None or scan.created_at is None:
            continue
        dt = scan.created_at
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        data.append({"date": dt.isoformat(), "dateLabel": dt.strftime("%b %d").replace(" 0", " "), "score": float(scan.risk_score)})

    return jsonify({"data": data, "timeframe": timeframe, "granularity": granularity})


@bp.get("/dashboard/findings-distribution")
def dashboard_findings_distribution():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    scans = Scan.query.order_by(desc(Scan.created_at)).limit(500).all()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for scan in scans:
        overall = (scan.overall_risk or "").strip().lower()
        n = _scan_findings_count(scan)
        if overall == "high" and (scan.risk_score is not None and float(scan.risk_score) >= 8.5):
            counts["critical"] += n
        elif overall == "high":
            counts["high"] += n
        elif overall == "medium":
            counts["medium"] += n
        else:
            counts["low"] += n

    distribution = [
        {"severity": "critical", "count": counts["critical"], "color": "#ef4444"},
        {"severity": "high", "count": counts["high"], "color": "#f97316"},
        {"severity": "medium", "count": counts["medium"], "color": "#eab308"},
        {"severity": "low", "count": counts["low"], "color": "#22c55e"},
    ]
    return jsonify({"distribution": distribution, "total": sum(counts.values())})


@bp.get("/scans/recent")
def scans_recent():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    try:
        limit = min(int(request.args.get("limit") or 10), 50)
        offset = max(int(request.args.get("offset") or 0), 0)
    except ValueError:
        return api_error(status=400, code="VALIDATION_ERROR", message="Invalid pagination parameters")

    query = Scan.query.order_by(desc(Scan.created_at))
    total = query.count()
    scans = query.offset(offset).limit(limit).all()

    items = []
    for scan in scans:
        scan_type, scan_type_label = _scan_type_from_mode(scan.scan_mode)
        status = _scan_status_normalize(scan.status)
        started_at = scan.created_at
        completed_at = scan.completed_at
        duration = None
        if started_at and completed_at:
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)
            if completed_at.tzinfo is None:
                completed_at = completed_at.replace(tzinfo=timezone.utc)
            duration = int((completed_at - started_at).total_seconds())

        items.append(
            {
                "id": str(scan.id),
                "target": scan.target,
                "type": scan_type,
                "typeLabel": scan_type_label,
                "status": status,
                "findings": _scan_findings_count(scan),
                "startedAt": started_at.isoformat() if started_at else None,
                "completedAt": completed_at.isoformat() if completed_at else None,
                "duration": duration,
                "relativeTime": _relative_time(scan.created_at),
            }
        )

    return jsonify({"scans": items, "total": total, "limit": limit, "offset": offset})


def _create_scan_row(*, user: User, target: str, mode: str, status: str) -> Scan:
    scan = Scan(
        user_id=user.id,
        target=target,
        scan_mode=mode,
        status=status,
        results_json={
            "meta": {
                "target": target,
                "mode": mode,
                "requested_mode": mode,
                "started_at": utc_now_iso(),
                "completed_at": None,
                "duration_ms": None,
            },
            "modules": {},
            "target": target,
            "scan_mode": mode,
            "requested_mode": mode,
            "status": status,
        },
    )
    db.session.add(scan)
    db.session.commit()
    return scan


def _run_scan_in_background(*, scan_id: int):
    app = current_app._get_current_object()

    def _job():
        with app.app_context():
            scan = db.session.get(Scan, scan_id)
            if scan is None:
                return
            if scan.status in {"cancelled", "failed", "completed"}:
                return

            def _store_results_update(*, results_patch: dict[str, Any] | None = None, log: dict[str, Any] | None = None):
                current = scan.results_json if isinstance(scan.results_json, dict) else {}
                updated: dict[str, Any] = dict(current)

                meta = updated.get("meta") if isinstance(updated.get("meta"), dict) else {}
                modules = updated.get("modules") if isinstance(updated.get("modules"), dict) else {}
                logs = updated.get("logs") if isinstance(updated.get("logs"), list) else []

                meta = dict(meta)
                modules = dict(modules)
                logs = list(logs)

                if results_patch:
                    if isinstance(results_patch.get("meta"), dict):
                        meta.update(results_patch["meta"])
                    if isinstance(results_patch.get("modules"), dict):
                        modules.update(results_patch["modules"])
                    for key, value in results_patch.items():
                        if key in {"meta", "modules", "logs"}:
                            continue
                        updated[key] = value

                if log:
                    logs.append(log)

                updated["meta"] = meta
                updated["modules"] = modules
                updated["logs"] = logs[-500:]
                scan.results_json = updated
                db.session.commit()

            scan.status = "running"
            _store_results_update(
                results_patch={"status": "running", "meta": {"progress": 0, "current_phase": "initializing", "started_at": utc_now_iso()}},
                log={"timestamp": utc_now_iso(), "level": "info", "message": "Scan started"},
            )

            try:
                def _event_cb(event: dict[str, Any]):
                    try:
                        module_name = str(event.get("module") or "").strip()
                        event_type = str(event.get("type") or "").strip()
                        stage = str(event.get("stage") or module_name or "").strip()
                        progress = event.get("progress")
                        try:
                            progress_int = int(progress) if progress is not None else None
                        except (TypeError, ValueError):
                            progress_int = None

                        patch: dict[str, Any] = {"meta": {}, "modules": {}}
                        if progress_int is not None:
                            patch["meta"]["progress"] = max(0, min(progress_int, 99))
                        if stage:
                            patch["meta"]["current_phase"] = stage

                        log_entry = None
                        if event_type == "module_started" and module_name:
                            patch["modules"][module_name] = {"status": "running"}
                            log_entry = {"timestamp": utc_now_iso(), "level": "info", "message": f"Starting stage: {stage}"}
                        elif event_type == "module_completed" and module_name:
                            patch["modules"][module_name] = {"status": "completed"}
                            log_entry = {"timestamp": utc_now_iso(), "level": "info", "message": f"Completed stage: {stage}"}
                        elif event_type == "module_failed" and module_name:
                            error = str(event.get("error") or "Module failed")
                            patch["modules"][module_name] = {"status": "failed", "error": error}
                            log_entry = {"timestamp": utc_now_iso(), "level": "error", "message": f"Stage failed: {stage} | {error}"}
                        elif event_type == "command_executed":
                            tool = str(event.get("tool") or "").strip()
                            cmd = event.get("cmd") or []
                            rc = event.get("returncode")
                            timed_out = bool(event.get("timed_out"))
                            summary = str(event.get("summary") or "").strip()
                            level = "info"
                            if timed_out or (isinstance(rc, int) and rc != 0):
                                level = "warning"
                            message = f"[{stage}] {tool} rc={rc}"
                            if timed_out:
                                message += " (timeout)"
                            if isinstance(cmd, list) and cmd:
                                message += f" cmd={' '.join(str(x) for x in cmd)}"
                            if summary:
                                message += f" | {summary}"
                            log_entry = {"timestamp": utc_now_iso(), "level": level, "message": message}

                        _store_results_update(results_patch=patch, log=log_entry)
                    except Exception:
                        app.logger.exception("Failed to persist scan progress event")

                if scan.scan_mode == "passive":
                    results = run_passive_scan(
                        scan.target,
                        allow_private_targets=app.config.get("ALLOW_PRIVATE_TARGETS", False),
                        event_cb=_event_cb,
                    )
                elif scan.scan_mode == "active":
                    results = run_active_scan(
                        scan.target,
                        allow_private_targets=app.config.get("ALLOW_PRIVATE_TARGETS", False),
                        event_cb=_event_cb,
                    )
                else:
                    results = run_full_scan(
                        scan.target,
                        allow_private_targets=app.config.get("ALLOW_PRIVATE_TARGETS", False),
                        event_cb=_event_cb,
                    )

                db.session.refresh(scan)
                if scan.status == "cancelled":
                    _store_results_update(
                        results_patch={"status": "cancelled", "meta": {"progress": 100, "current_phase": "cancelled", "completed_at": utc_now_iso()}},
                        log={"timestamp": utc_now_iso(), "level": "warning", "message": "Scan cancelled"},
                    )
                    return

                existing = scan.results_json if isinstance(scan.results_json, dict) else {}
                existing_logs = existing.get("logs") if isinstance(existing.get("logs"), list) else []

                final: dict[str, Any] = results if isinstance(results, dict) else {}
                final = dict(final)
                final_meta = final.get("meta") if isinstance(final.get("meta"), dict) else {}
                final_meta = dict(final_meta)
                final_meta.update({"progress": 100, "current_phase": "completed"})
                final["meta"] = final_meta
                final["logs"] = list(existing_logs)[-500:]
                final["status"] = "completed"

                risk_score, overall_risk, confidence_score = _calculate_risk_from_results(scan.scan_mode, final)
                scan.target = (final.get("meta") or {}).get("target", scan.target)
                scan.status = "completed"
                # Persist findings into the database for /api/findings.
                try:
                    Finding.query.filter(Finding.scan_id == scan.id).delete(synchronize_session=False)
                    payloads = generate_findings(scan_id=scan.id, target=scan.target, results=final)
                    created_at = datetime.now(timezone.utc)

                    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                    for payload in payloads:
                        severity_db = (payload.get("severity") or "low").strip().lower()
                        if severity_db not in {"critical", "high", "medium", "low", "info"}:
                            severity_db = "low"

                        severity_bucket = severity_db
                        if severity_bucket == "info":
                            severity_bucket = "low"
                        if severity_bucket not in severity_counts:
                            severity_bucket = "low"
                        severity_counts[severity_bucket] += 1

                        asset = payload.get("asset") if isinstance(payload.get("asset"), dict) else {}
                        db.session.add(
                            Finding(
                                id=str(payload.get("id")),
                                scan_id=scan.id,
                                severity=severity_db,
                                title=str(payload.get("title") or "")[:255],
                                description=str(payload.get("description") or ""),
                                category=str(payload.get("category") or "reconnaissance"),
                                status=str(payload.get("status") or "open"),
                                asset_name=str(asset.get("name") or scan.target),
                                asset_type=str(asset.get("type") or "domain"),
                                discovered_at=created_at,
                            )
                        )

                    final_meta = dict(final.get("meta") or {})
                    final_meta["findings"] = {
                        "total": sum(severity_counts.values()),
                        "critical": severity_counts["critical"],
                        "high": severity_counts["high"],
                        "medium": severity_counts["medium"],
                        "low": severity_counts["low"],
                    }
                    final["meta"] = final_meta
                    scan.results_json = final
                except Exception:
                    app.logger.exception("Failed to persist scan findings")
                    scan.results_json = final

                scan.risk_score = risk_score
                scan.overall_risk = overall_risk
                scan.confidence_score = confidence_score
                scan.completed_at = datetime.now(timezone.utc)
                db.session.commit()
            except Exception as exc:
                scan.status = "failed"
                existing = scan.results_json if isinstance(scan.results_json, dict) else {}
                existing_logs = existing.get("logs") if isinstance(existing.get("logs"), list) else []
                meta = existing.get("meta") if isinstance(existing.get("meta"), dict) else {}
                meta = dict(meta)
                meta.update(
                    {
                        "completed_at": utc_now_iso(),
                        "progress": 100,
                        "current_phase": "failed",
                    }
                )
                existing["meta"] = meta
                existing["status"] = "failed"
                existing["error"] = str(exc)
                existing["logs"] = list(existing_logs)[-500:] + [
                    {"timestamp": utc_now_iso(), "level": "error", "message": f"Scan failed: {str(exc)}"}
                ]
                scan.results_json = existing
                scan.completed_at = datetime.now(timezone.utc)
                db.session.commit()
            finally:
                db.session.remove()

    _scan_executor().submit(_job)


@bp.post("/scans")
def scans_create():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth
    user, _token_payload = auth

    payload = request.get_json(silent=True) or {}
    targets = payload.get("targets") or []
    if isinstance(targets, str):
        targets = [targets]
    if not isinstance(targets, list):
        targets = []

    scan_type = (payload.get("scanType") or "quick_scan").strip()
    scan_type_map = {"full_scan": "full", "quick_scan": "passive", "custom_scan": "active"}
    mode = scan_type_map.get(scan_type, "passive")

    schedule = payload.get("schedule") or {"type": "immediate", "scheduledAt": None}
    schedule_type = (schedule.get("type") or "immediate").strip()
    scheduled_at_raw = schedule.get("scheduledAt")

    normalized_targets = [str(t).strip() for t in targets if str(t).strip()]
    if not normalized_targets:
        return api_error(
            status=422,
            code="VALIDATION_ERROR",
            message="Invalid request parameters",
            details=[{"field": "targets", "message": "At least one target is required"}],
        )

    raw_target = normalized_targets[0]
    target = raw_target
    if _WILDCARD_DOMAIN_RE.match(raw_target):
        target = raw_target[2:]
    else:
        try:
            network = ipaddress.ip_network(raw_target, strict=False)
            target = str(next(network.hosts(), network.network_address))
        except ValueError:
            target = raw_target

    try:
        validate_target(target)
    except ValueError as exc:
        return api_error(
            status=422,
            code="VALIDATION_ERROR",
            message="Invalid request parameters",
            details=[{"field": "targets[0]", "message": str(exc)}],
        )

    if schedule_type == "scheduled":
        if not scheduled_at_raw:
            return api_error(
                status=422,
                code="VALIDATION_ERROR",
                message="Invalid request parameters",
                details=[{"field": "schedule.scheduledAt", "message": "scheduledAt is required when schedule.type is 'scheduled'"}],
            )
        try:
            scheduled_at = datetime.fromisoformat(str(scheduled_at_raw).replace("Z", "+00:00"))
            if scheduled_at.tzinfo is None:
                scheduled_at = scheduled_at.replace(tzinfo=timezone.utc)
        except ValueError:
            return api_error(
                status=422,
                code="VALIDATION_ERROR",
                message="Invalid request parameters",
                details=[{"field": "schedule.scheduledAt", "message": "scheduledAt must be an ISO8601 timestamp"}],
            )

        delay = (scheduled_at - datetime.now(timezone.utc)).total_seconds()
        if delay <= 0:
            return api_error(
                status=422,
                code="VALIDATION_ERROR",
                message="Invalid request parameters",
                details=[{"field": "schedule.scheduledAt", "message": "scheduledAt must be in the future"}],
            )

        scan = _create_scan_row(user=user, target=target, mode=mode, status="scheduled")

        def _start_later():
            with current_app.app_context():
                scan_row = db.session.get(Scan, scan.id)
                if scan_row is None or scan_row.status == "cancelled":
                    return
                scan_row.status = "queued"
                db.session.commit()
                _run_scan_in_background(scan_id=scan.id)

        timer = threading.Timer(delay, _start_later)
        timer.daemon = True
        timer.start()

        return (
            jsonify(
                {
                    "scanId": str(scan.id),
                    "status": "scheduled",
                    "estimatedStartTime": scheduled_at.isoformat(),
                    "estimatedDuration": 7200 if mode == "full" else 1200 if mode == "active" else 300,
                    "queuePosition": 1,
                    "targetCount": len(normalized_targets),
                    "message": "Scan created successfully",
                }
            ),
            201,
        )

    scan = _create_scan_row(user=user, target=target, mode=mode, status="queued")
    _run_scan_in_background(scan_id=scan.id)

    return (
        jsonify(
            {
                "scanId": str(scan.id),
                "status": "queued",
                "estimatedStartTime": utc_now_iso(),
                "estimatedDuration": 7200 if mode == "full" else 1200 if mode == "active" else 300,
                "queuePosition": 1,
                "targetCount": len(normalized_targets),
                "message": "Scan created successfully",
            }
        ),
        201,
    )


@bp.get("/scans/templates")
def scans_templates():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    return jsonify(
        {
            "templates": [
                {
                    "id": "template-full-security-audit",
                    "name": "Full Security Audit",
                    "description": "Comprehensive scan with all options enabled",
                    "scanType": "full_scan",
                    "options": {
                        "portScanning": True,
                        "sslAnalysis": True,
                        "dnsEnumeration": True,
                        "subdomainDiscovery": True,
                        "technologyDetection": True,
                        "vulnerabilityAssessment": True,
                        "screenshotCapture": True,
                    },
                    "estimatedDuration": 14400,
                    "isDefault": False,
                }
            ]
        }
    )


@bp.post("/scans/validate-targets")
def scans_validate_targets():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    payload = request.get_json(silent=True) or {}
    targets = payload.get("targets") or []
    if isinstance(targets, str):
        targets = [targets]

    if not isinstance(targets, list) or not targets:
        return api_error(
            status=422,
            code="VALIDATION_ERROR",
            message="Invalid request parameters",
            details=[{"field": "targets", "message": "At least one target is required"}],
        )

    valid: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []

    for raw in targets:
        target = str(raw or "").strip()
        if not target:
            invalid.append({"target": target, "reason": "Empty target", "suggestion": None})
            continue

        if _WILDCARD_DOMAIN_RE.match(target):
            valid.append({"target": target, "type": "wildcard_domain", "resolved": False, "ipAddress": None})
            continue

        try:
            network = ipaddress.ip_network(target, strict=False)
            valid.append({"target": target, "type": "cidr", "ipCount": network.num_addresses})
            continue
        except ValueError:
            pass

        try:
            validate_target(target)
            try:
                ipaddress.ip_address(target)
                valid.append({"target": target, "type": "ip", "resolved": True, "ipAddress": target})
            except ValueError:
                valid.append({"target": target, "type": "domain", "resolved": True, "ipAddress": None})
        except ValueError as exc:
            invalid.append({"target": target, "reason": str(exc), "suggestion": None})

    summary = {"totalTargets": len(targets), "validTargets": len(valid), "invalidTargets": len(invalid)}
    return jsonify({"valid": valid, "invalid": invalid, "summary": summary})


@bp.get("/scans/options")
def scans_options():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    options = [
        {
            "key": "portScanning",
            "label": "Port Scanning",
            "description": "Scan for open ports and running services",
            "estimatedTime": 600,
            "requiresElevatedPermissions": False,
            "defaultEnabled": True,
            "category": "network",
        },
        {
            "key": "vulnerabilityAssessment",
            "label": "Vulnerability Assessment",
            "description": "Check for known vulnerabilities (CVEs)",
            "estimatedTime": 3600,
            "requiresElevatedPermissions": False,
            "defaultEnabled": False,
            "category": "security",
        },
    ]

    categories = [
        {"id": "network", "label": "Network Analysis", "description": "Network-level reconnaissance"},
        {"id": "security", "label": "Security Testing", "description": "Vulnerability and security checks"},
    ]

    return jsonify({"options": options, "categories": categories})


@bp.get("/scans/<scan_id>")
def scans_get(scan_id: str):
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    try:
        scan_int = int(scan_id)
    except ValueError:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Scan not found")

    scan = db.session.get(Scan, scan_int)
    if scan is None:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Scan not found")

    results = scan.results_json if isinstance(scan.results_json, dict) else {}
    scan_type, _scan_type_label = _scan_type_from_mode(scan.scan_mode)
    status = _scan_status_normalize(scan.status)
    progress = _scan_progress_from_results(status=status, results=results)

    started_at = scan.created_at
    completed_at = scan.completed_at
    duration = None
    if started_at and completed_at:
        if started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=timezone.utc)
        if completed_at.tzinfo is None:
            completed_at = completed_at.replace(tzinfo=timezone.utc)
        duration = int((completed_at - started_at).total_seconds())

    findings_total = _scan_findings_count(scan)
    findings = {"total": findings_total, "critical": 0, "high": 0, "medium": 0, "low": findings_total}
    if isinstance(results, dict) and isinstance(results.get("meta"), dict):
        meta_findings = results["meta"].get("findings")
        if isinstance(meta_findings, dict):
            for key in ("critical", "high", "medium", "low", "total"):
                try:
                    findings[key] = int(meta_findings.get(key) or 0)
                except (TypeError, ValueError):
                    continue
    assets = _scan_assets_from_results(scan=scan, results=results)
    summary_text = _scan_summary_text(scan=scan, status=status, results=results)
    detailed_report = f"/api/scans/{scan.id}/raw"

    return jsonify(
        {
            "id": str(scan.id),
            "target": scan.target,
            "targets": [scan.target],
            "scanType": scan_type,
            "status": status,
            "progress": progress,
            "startedAt": scan.created_at.isoformat() if scan.created_at else None,
            "completedAt": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration": duration,
            "findings": findings,
            "assetsDiscovered": assets["assetsDiscovered"],
            "options": {},
            "createdBy": {
                "userId": str(scan.user_id) if scan.user_id is not None else None,
                "userName": scan.user.username if scan.user is not None else "",
                "email": scan.user.email if scan.user is not None else "",
            },
            "logs": _scan_logs_from_results(results),
            "results": {"summary": summary_text, "detailedReport": detailed_report},
            "discovery": assets,
            "raw": results,
        }
    )


@bp.get("/scans/<scan_id>/raw")
def scans_get_raw(scan_id: str):
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    try:
        scan_int = int(scan_id)
    except ValueError:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Scan not found")

    scan = db.session.get(Scan, scan_int)
    if scan is None:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Scan not found")

    return jsonify(
        {
            "scanId": str(scan.id),
            "target": scan.target,
            "status": _scan_status_normalize(scan.status),
            "createdAt": scan.created_at.isoformat() if scan.created_at else None,
            "completedAt": scan.completed_at.isoformat() if scan.completed_at else None,
            "results": scan.results_json if isinstance(scan.results_json, dict) else {},
        }
    )


@bp.post("/scans/<scan_id>/cancel")
def scans_cancel(scan_id: str):
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    try:
        scan_int = int(scan_id)
    except ValueError:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Scan not found")

    scan = db.session.get(Scan, scan_int)
    if scan is None:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Scan not found")

    status = _scan_status_normalize(scan.status)
    if status in {"completed", "failed", "cancelled"}:
        return api_error(status=409, code="CONFLICT", message="Scan cannot be cancelled in its current state")

    scan.status = "cancelled"
    db.session.commit()
    return jsonify({"scanId": str(scan.id), "status": "cancelled", "message": "Scan cancelled successfully", "timestamp": utc_now_iso()})


@bp.post("/scans/<scan_id>/retry")
def scans_retry(scan_id: str):
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth
    user, _payload = auth

    try:
        scan_int = int(scan_id)
    except ValueError:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Scan not found")

    scan = db.session.get(Scan, scan_int)
    if scan is None:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Scan not found")

    new_scan = _create_scan_row(user=user, target=scan.target, mode=scan.scan_mode, status="queued")
    _run_scan_in_background(scan_id=new_scan.id)
    return jsonify({"newScanId": str(new_scan.id), "status": "queued", "message": "Scan retried successfully"})


def _assets_latest_by_target() -> dict[str, Scan]:
    scans = Scan.query.order_by(desc(Scan.created_at)).limit(5000).all()
    latest: dict[str, Scan] = {}
    for scan in scans:
        if scan.target not in latest:
            latest[scan.target] = scan
    return latest


def _asset_type_for_target(target: str) -> tuple[str, str]:
    try:
        ipaddress.ip_address(target)
        return "ip_address", "IP Address"
    except ValueError:
        return "domain", "Domain"


def _risk_level(scan: Scan) -> str:
    overall = (scan.overall_risk or "").strip().lower()
    if overall == "high" and (scan.risk_score is not None and float(scan.risk_score) >= 8.5):
        return "critical"
    if overall == "high":
        return "high"
    if overall == "medium":
        return "medium"
    return "low"


@bp.get("/assets")
def assets_list():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    try:
        page = max(int(request.args.get("page") or 1), 1)
        limit = min(max(int(request.args.get("limit") or 10), 1), 100)
    except ValueError:
        return api_error(status=400, code="VALIDATION_ERROR", message="Invalid pagination parameters")

    filter_value = (request.args.get("filter") or "all").strip().lower()
    search = (request.args.get("search") or "").strip().lower()
    risk_levels = [item.strip().lower() for item in request.args.getlist("riskLevel") if item.strip()]
    status_filter = (request.args.get("status") or "").strip().lower() or None
    sort_by = (request.args.get("sortBy") or "lastScan").strip()
    sort_order = (request.args.get("sortOrder") or "desc").strip().lower()
    reverse = sort_order != "asc"

    latest = _assets_latest_by_target()
    rows: list[dict[str, Any]] = []

    for target, scan in latest.items():
        asset_type, type_label = _asset_type_for_target(target)
        if filter_value == "domains" and asset_type != "domain":
            continue
        if filter_value == "ips" and asset_type != "ip_address":
            continue
        if filter_value not in {"all", "domains", "ips", "cloud", "webapps"}:
            continue

        if search and search not in target.lower():
            continue

        risk_level = _risk_level(scan)
        if risk_levels and risk_level not in risk_levels:
            continue

        last_scan_at = scan.created_at
        active = False
        if last_scan_at:
            dt = last_scan_at if last_scan_at.tzinfo else last_scan_at.replace(tzinfo=timezone.utc)
            active = dt >= datetime.now(timezone.utc) - timedelta(days=30)
        status_value = "active" if active else "inactive"
        if status_filter and status_filter != status_value:
            continue

        rows.append(
            {
                "id": _asset_id_for_target(target),
                "asset": target,
                "type": asset_type,
                "typeLabel": type_label,
                "riskLevel": risk_level,
                "findings": _scan_findings_count(scan),
                "lastScan": {
                    "timestamp": scan.created_at.isoformat() if scan.created_at else None,
                    "relativeTime": _relative_time(scan.created_at),
                    "scanId": str(scan.id),
                },
                "status": status_value,
                "metadata": {
                    "ipAddress": None,
                    "cloudProvider": None,
                    "region": None,
                    "tags": [],
                },
                "createdAt": scan.created_at.isoformat() if scan.created_at else None,
                "updatedAt": scan.created_at.isoformat() if scan.created_at else None,
            }
        )

    def _sort_key(item: dict[str, Any]):
        if sort_by == "asset":
            return item["asset"]
        if sort_by == "risk":
            order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            return order.get(item["riskLevel"], 0)
        if sort_by == "findings":
            return item["findings"]
        return item.get("lastScan", {}).get("timestamp") or ""

    rows.sort(key=_sort_key, reverse=reverse)

    total = len(rows)
    start_idx = (page - 1) * limit
    page_items = rows[start_idx : start_idx + limit]
    total_pages = max(1, (total + limit - 1) // limit)

    return jsonify(
        {
            "assets": page_items,
            "pagination": {"total": total, "page": page, "limit": limit, "totalPages": total_pages},
            "filters": {"applied": {"filter": filter_value, "search": search, "riskLevel": risk_levels, "status": status_filter}},
        }
    )


@bp.get("/assets/stats")
def assets_stats():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    latest = _assets_latest_by_target()
    total = len(latest)
    by_type = {"domains": 0, "ipAddresses": 0, "cloudResources": 0, "webApps": 0}
    by_risk = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    active_count = 0
    inactive_count = 0

    for target, scan in latest.items():
        asset_type, _label = _asset_type_for_target(target)
        if asset_type == "domain":
            by_type["domains"] += 1
        elif asset_type == "ip_address":
            by_type["ipAddresses"] += 1

        risk_level = _risk_level(scan)
        by_risk[risk_level] += 1

        last_scan_at = scan.created_at
        active = False
        if last_scan_at:
            dt = last_scan_at if last_scan_at.tzinfo else last_scan_at.replace(tzinfo=timezone.utc)
            active = dt >= datetime.now(timezone.utc) - timedelta(days=30)
        if active:
            active_count += 1
        else:
            inactive_count += 1

    return jsonify(
        {
            "total": total,
            "active": active_count,
            "inactive": inactive_count,
            "atRisk": by_risk["critical"] + by_risk["high"],
            "byType": by_type,
            "byRisk": by_risk,
        }
    )


def _resolve_target_by_asset_id(asset_id: str) -> str | None:
    latest = _assets_latest_by_target()
    for target in latest.keys():
        if _asset_id_for_target(target) == asset_id:
            return target
    return None


@bp.get("/assets/<asset_id>")
def assets_details(asset_id: str):
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    target = _resolve_target_by_asset_id(asset_id)
    if not target:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Asset not found")

    scans = Scan.query.filter_by(target=target).order_by(desc(Scan.created_at)).limit(50).all()
    latest = scans[0] if scans else None
    if latest is None:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Asset not found")

    asset_type, type_label = _asset_type_for_target(target)
    risk_level = _risk_level(latest)
    risk_score = float(latest.risk_score) if latest.risk_score is not None else None

    scan_history = []
    for scan in scans:
        scan_type, _label = _scan_type_from_mode(scan.scan_mode)
        scan_history.append(
            {
                "scanId": str(scan.id),
                "timestamp": scan.created_at.isoformat() if scan.created_at else None,
                "type": scan_type,
                "findings": _scan_findings_count(scan),
                "riskScore": float(scan.risk_score) if scan.risk_score is not None else None,
            }
        )

    findings: list[dict[str, Any]] = []
    results = latest.results_json or {}
    modules = results.get("modules") if isinstance(results, dict) else {}
    risk = modules.get("risk_scoring") if isinstance(modules, dict) else {}
    key_findings = []
    if isinstance(risk, dict) and risk.get("status") == "completed" and isinstance(risk.get("data"), dict):
        key_findings = risk["data"].get("key_findings") or []
    if isinstance(key_findings, list):
        for text in key_findings[:50]:
            title = str(text)
            fid = hashlib.sha1(f"{latest.id}:{title}".encode("utf-8")).hexdigest()[:24]
            findings.append(
                {
                    "id": fid,
                    "severity": risk_level,
                    "title": title[:80],
                    "description": title,
                    "category": "security_misconfiguration",
                    "cvss": None,
                    "cve": None,
                    "discoveredAt": latest.created_at.isoformat() if latest.created_at else None,
                    "status": "open",
                }
            )

    return jsonify(
        {
            "id": asset_id,
            "asset": target,
            "type": asset_type,
            "typeLabel": type_label,
            "riskLevel": risk_level,
            "riskScore": risk_score,
            "findings": len(findings),
            "status": "active",
            "discoveryDate": scans[-1].created_at.isoformat() if scans and scans[-1].created_at else None,
            "lastScan": {"timestamp": latest.created_at.isoformat() if latest.created_at else None, "scanId": str(latest.id), "duration": None},
            "scanHistory": scan_history,
            "findings": findings,
            "metadata": {"ipAddress": None, "ports": [], "technologies": [], "certificates": [], "dns": {"a": [], "aaaa": [], "mx": [], "txt": []}},
            "tags": [],
            "notes": "",
            "assignedTo": None,
        }
    )


@bp.post("/assets/<asset_id>/scan")
def assets_trigger_scan(asset_id: str):
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth
    user, _payload = auth

    target = _resolve_target_by_asset_id(asset_id)
    if not target:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Asset not found")

    payload = request.get_json(silent=True) or {}
    scan_type = (payload.get("scanType") or "quick_scan").strip()
    scan_type_map = {"full_scan": "full", "quick_scan": "passive"}
    mode = scan_type_map.get(scan_type, "passive")

    scan = _create_scan_row(user=user, target=target, mode=mode, status="queued")
    _run_scan_in_background(scan_id=scan.id)

    return jsonify({"scanId": str(scan.id), "status": "queued", "estimatedDuration": 7200 if mode == "full" else 300, "queuePosition": 1, "message": "Scan queued successfully"})


@bp.get("/assets/export")
def assets_export():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    export_format = (request.args.get("format") or "csv").strip().lower()
    filter_value = (request.args.get("filter") or "all").strip().lower()

    latest = _assets_latest_by_target()
    rows = []
    for target, scan in latest.items():
        asset_type, _label = _asset_type_for_target(target)
        if filter_value == "domains" and asset_type != "domain":
            continue
        if filter_value == "ips" and asset_type != "ip_address":
            continue

        rows.append(
            {
                "asset": target,
                "type": asset_type,
                "riskLevel": _risk_level(scan),
                "findings": _scan_findings_count(scan),
                "lastScan": scan.created_at.isoformat() if scan.created_at else None,
                "status": _scan_status_normalize(scan.status),
            }
        )

    filename = f"assets-export-{datetime.now(timezone.utc).date().isoformat()}.{export_format}"

    if export_format == "json":
        response = jsonify(rows)
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    if export_format != "csv":
        return api_error(status=400, code="VALIDATION_ERROR", message="Unsupported export format")

    out = StringIO()
    writer = csv.DictWriter(out, fieldnames=["asset", "type", "riskLevel", "findings", "lastScan", "status"])
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

    response = current_app.response_class(out.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@bp.get("/system/health")
def system_health():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    start = datetime.now(timezone.utc)
    try:
        db.session.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    db_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)

    queued = Scan.query.filter(Scan.status.in_(["queued", "scheduled"])).count()
    running = Scan.query.filter(Scan.status.in_(["running"])).count()

    status = "operational" if db_ok else "degraded"
    return jsonify(
        {
            "status": status,
            "services": {
                "scanner": {"status": "operational", "uptime": 99.99, "activeScans": running, "queuedScans": queued},
                "database": {"status": "operational" if db_ok else "down", "responseTime": db_ms, "connections": 0},
                "api": {"status": "operational", "responseTime": 0, "requestsPerMinute": 0},
            },
            "lastUpdated": utc_now_iso(),
        }
    )


@bp.get("/scans/queue")
def scans_queue():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    queued_scans = Scan.query.filter(Scan.status.in_(["queued", "scheduled"])).order_by(desc(Scan.created_at)).limit(50).all()
    queue = []
    for idx, scan in enumerate(reversed(queued_scans), start=1):
        scan_type, _label = _scan_type_from_mode(scan.scan_mode)
        queue.append(
            {
                "scanId": str(scan.id),
                "position": idx,
                "target": scan.target,
                "scanType": scan_type,
                "priority": "normal",
                "estimatedStartTime": utc_now_iso(),
                "submittedBy": scan.user.username if scan.user else "",
                "submittedAt": scan.created_at.isoformat() if scan.created_at else None,
            }
        )

    return jsonify(
        {
            "activeScans": Scan.query.filter(Scan.status.in_(["running"])).count(),
            "queuedScans": len(queue),
            "completedToday": 0,
            "averageWaitTime": 0,
            "estimatedQueueClearTime": utc_now_iso(),
            "queue": queue,
        }
    )


@bp.get("/findings")
def findings_list():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    scan_id_raw = (request.args.get("scan_id") or request.args.get("scanId") or "").strip()
    severity_filter = (request.args.get("severity") or "").strip().lower() or None
    status_filter = (request.args.get("status") or "").strip().lower() or None
    category_filter = (request.args.get("category") or "").strip().lower() or None

    try:
        page = max(int(request.args.get("page") or 1), 1)
        limit = min(max(int(request.args.get("limit") or 20), 1), 100)
    except ValueError:
        return api_error(status=400, code="VALIDATION_ERROR", message="Invalid pagination parameters")

    query = Finding.query

    if scan_id_raw:
        try:
            scan_id_int = int(scan_id_raw)
        except ValueError:
            return api_error(status=422, code="VALIDATION_ERROR", message="Invalid request parameters", details=[{"field": "scan_id", "message": "scan_id must be an integer"}])
        query = query.filter(Finding.scan_id == scan_id_int)

    if severity_filter:
        query = query.filter(Finding.severity == severity_filter)
    if status_filter:
        query = query.filter(Finding.status == status_filter)
    if category_filter:
        query = query.filter(Finding.category == category_filter)

    total = query.count()
    rows = query.order_by(desc(Finding.discovered_at)).offset((page - 1) * limit).limit(limit).all()
    items = [row.to_api_dict() for row in rows]

    total_pages = max(1, (total + limit - 1) // limit)
    return jsonify({"findings": items, "pagination": {"total": total, "page": page, "limit": limit, "totalPages": total_pages}})


@bp.patch("/findings/<finding_id>")
def findings_update(finding_id: str):
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    payload = request.get_json(silent=True) or {}
    status_value = str(payload.get("status") or "").strip().lower() or "open"
    if status_value not in {"open", "investigating", "mitigated", "false_positive"}:
        status_value = "open"

    finding = db.session.get(Finding, finding_id)
    if finding is None:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Finding not found")

    finding.status = status_value
    db.session.commit()

    return jsonify({"id": finding_id, "status": finding.status, "updatedAt": utc_now_iso(), "message": "Finding updated successfully"})


@bp.get("/notifications")
def notifications_list():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    unread_only = (request.args.get("unreadOnly") or "").strip().lower() in {"1", "true", "yes", "on"}
    try:
        limit = min(max(int(request.args.get("limit") or 20), 1), 50)
        offset = max(int(request.args.get("offset") or 0), 0)
    except ValueError:
        return api_error(status=400, code="VALIDATION_ERROR", message="Invalid pagination parameters")

    logs = AuditLog.query.order_by(desc(AuditLog.created_at)).offset(offset).limit(limit).all()
    notifications = []
    for log in logs:
        action = (log.action or "").lower()
        notif_type = "system_alert"
        severity = "info"
        if "scan.completed" in action:
            notif_type = "scan_completed"
        elif "scan.failed" in action or "scan.validation_failed" in action:
            notif_type = "scan_failed"
            severity = "error"

        notifications.append(
            {
                "id": str(log.id),
                "type": notif_type,
                "title": log.action,
                "message": f"{log.action} {log.target or ''}".strip(),
                "severity": severity,
                "read": False,
                "timestamp": log.created_at.isoformat() if log.created_at else None,
                "relatedEntity": {"type": "scan", "id": str(log.id)},
                "actionUrl": "/",
            }
        )

    if unread_only:
        notifications = [n for n in notifications if not n["read"]]

    return jsonify(
        {
            "notifications": notifications,
            "unreadCount": sum(1 for n in notifications if not n["read"]),
            "total": AuditLog.query.count(),
        }
    )


@bp.post("/notifications/<notification_id>/read")
def notifications_mark_read(notification_id: str):
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth
    return jsonify({"id": notification_id, "read": True, "timestamp": utc_now_iso()})
