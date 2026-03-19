"""Dashboard APIs for Attack Surface Management (ASM) views.

Adds additional /api/dashboard/* endpoints that derive data from persisted Scan
rows and generated Finding records.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from flask import Blueprint, jsonify, request
from sqlalchemy import func

from extensions import db
from models import Finding, Scan
from routes.api_routes import _require_api_auth
from utils.api_response import api_error


bp = Blueprint("dashboard_api", __name__, url_prefix="/api/dashboard")


def _parse_scan_id() -> int | Any:
    raw = (request.args.get("scan_id") or request.args.get("scanId") or "").strip()
    if not raw:
        return api_error(
            status=422,
            code="VALIDATION_ERROR",
            message="Invalid request parameters",
            details=[{"field": "scan_id", "message": "scan_id is required"}],
        )
    try:
        return int(raw)
    except ValueError:
        return api_error(
            status=422,
            code="VALIDATION_ERROR",
            message="Invalid request parameters",
            details=[{"field": "scan_id", "message": "scan_id must be an integer"}],
        )


def _risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 51:
        return "High"
    if score >= 21:
        return "Medium"
    return "Low"


def _severity_bucket(raw: str | None) -> str:
    value = (raw or "").strip().lower()
    if value in {"critical", "high"}:
        return "high"
    if value == "medium":
        return "medium"
    if value == "low":
        return "low"
    if value in {"info", "informational"}:
        return "info"
    return "info"


def _node_risk_level(counts: dict[str, int]) -> str:
    if counts.get("high", 0) > 0:
        return "high"
    if counts.get("medium", 0) > 0:
        return "medium"
    if counts.get("low", 0) > 0:
        return "low"
    return "info"


def _json_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _scan_module_data(results: dict[str, Any], module_name: str) -> dict[str, Any]:
    modules = results.get("modules") if isinstance(results, dict) else {}
    if not isinstance(modules, dict):
        return {}
    entry = modules.get(module_name) if isinstance(modules.get(module_name), dict) else {}
    if entry.get("status") != "completed":
        return {}
    data = entry.get("data")
    return data if isinstance(data, dict) else {}


def _technologies_from_scan(results: dict[str, Any]) -> list[str]:
    tech = _scan_module_data(results, "technology_fingerprint")
    values: set[str] = set()
    if isinstance(tech.get("framework"), list):
        values.update(str(x) for x in tech.get("framework") if str(x))
    for key in ("server", "cdn", "reverse_proxy", "waf"):
        if tech.get(key):
            values.add(str(tech.get(key)))
    return sorted(v for v in values if v and v.lower() != "none")


def _open_ports_from_scan(results: dict[str, Any]) -> list[int]:
    port_data = _scan_module_data(results, "port_scan")
    open_ports = port_data.get("open_ports") if isinstance(port_data.get("open_ports"), list) else []
    values: set[int] = set()
    for p in open_ports:
        try:
            values.add(int(p))
        except (TypeError, ValueError):
            continue
    return sorted(values)


def _primary_ip_from_scan(results: dict[str, Any]) -> str | None:
    dns_data = _scan_module_data(results, "dns_enum")
    if dns_data.get("primary_ip"):
        return str(dns_data.get("primary_ip"))
    resolved = dns_data.get("resolved_ips") if isinstance(dns_data.get("resolved_ips"), list) else []
    if resolved:
        return str(resolved[0])
    fallback = results.get("resolved_ips") if isinstance(results.get("resolved_ips"), list) else []
    if fallback:
        return str(fallback[0])
    return None


def _sum_duration_ms(obj: Any, *, limit: int = 2000) -> int:
    """Sum nested duration_ms fields (best-effort), with a safety cap."""

    total = 0
    seen = 0
    stack: list[Any] = [obj]
    while stack and seen < limit:
        cur = stack.pop()
        seen += 1
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k == "duration_ms" and isinstance(v, (int, float)):
                    total += int(v)
                else:
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return max(0, total)


def _module_duration_seconds(entry: dict[str, Any]) -> int:
    if (entry.get("status") or "").lower() != "completed":
        return 0
    data = entry.get("data")
    if isinstance(data, dict) and isinstance(data.get("duration_ms"), (int, float)):
        return max(0, int(round(float(data.get("duration_ms")) / 1000.0)))
    if isinstance(data, dict):
        summed = _sum_duration_ms(data)
        if summed > 0:
            return max(0, int(round(summed / 1000.0)))
    return 0


MODULE_LABELS: dict[str, str] = {
    "subdomain_enum": "Subdomain Enumeration",
    "dns_enum": "DNS Enumeration",
    "whois": "WHOIS Lookup",
    "port_scan": "Port Scanning",
    "http_probe": "HTTP Probing",
    "url_discovery": "URL Discovery",
    "ssl_check": "SSL Analysis",
    "headers_analysis": "Header Analysis",
    "technology_fingerprint": "Technology Detection",
    "hosting_detection": "Hosting Detection",
    "vulnerability_surface": "Vulnerability Detection",
    "risk_scoring": "Risk Scoring",
    "report_generation": "Report Generation",
}


def _timeline_order(scan_mode: str) -> tuple[str, ...]:
    # Prefer the canonical module order used by the scanner.
    try:
        from services.scan_service import ACTIVE_MODULES, FULL_MODULES, PASSIVE_MODULES

        mode = (scan_mode or "").strip().lower()
        if mode == "active":
            return ACTIVE_MODULES
        if mode == "full":
            return FULL_MODULES
        return PASSIVE_MODULES
    except Exception:
        return ()


@bp.get("/risk-score")
def dashboard_risk_score():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    scan_id = _parse_scan_id()
    if not isinstance(scan_id, int):
        return scan_id

    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Scan not found")

    rows = (
        db.session.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
        .all()
    )

    breakdown = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for severity, count in rows:
        bucket = _severity_bucket(str(severity) if severity is not None else None)
        breakdown[bucket] = int(breakdown.get(bucket, 0)) + int(count or 0)

    overall_score = int(breakdown["high"] * 5 + breakdown["medium"] * 3 + breakdown["low"] * 1)
    risk_level = _risk_level_from_score(overall_score)

    top_rows = (
        db.session.query(Finding.title, Finding.severity)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.discovered_at.desc())
        .limit(250)
        .all()
    )

    severity_weight = {"high": 3, "medium": 2, "low": 1, "info": 0}
    ranked = []
    for title, severity in top_rows:
        bucket = _severity_bucket(str(severity) if severity is not None else None)
        ranked.append((severity_weight[bucket], bucket, str(title or "")))
    ranked.sort(key=lambda x: (x[0], x[2]), reverse=True)

    top_risks: list[dict[str, str]] = []
    seen_titles: set[str] = set()
    for _w, bucket, title in ranked:
        normalized = title.strip()
        if not normalized or normalized in seen_titles:
            continue
        seen_titles.add(normalized)
        top_risks.append({"title": normalized, "severity": bucket})
        if len(top_risks) >= 5:
            break

    return jsonify(
        {
            "scan_id": scan_id,
            "overall_score": overall_score,
            "risk_level": risk_level,
            "breakdown": breakdown,
            "top_risks": top_risks,
        }
    )


@bp.get("/subdomain-map")
def dashboard_subdomain_map():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    scan_id = _parse_scan_id()
    if not isinstance(scan_id, int):
        return scan_id

    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Scan not found")

    results = _json_dict(scan.results_json)
    target = str(scan.target or "").strip()

    sub_data = _scan_module_data(results, "subdomain_enum")
    sub_rows = sub_data.get("subdomains") if isinstance(sub_data.get("subdomains"), list) else []

    technologies = _technologies_from_scan(results)
    open_ports = _open_ports_from_scan(results)
    primary_ip = _primary_ip_from_scan(results)

    hosting = _scan_module_data(results, "hosting_detection")
    hosting_meta = {
        "cloudProvider": hosting.get("cloud_provider"),
        "cdnProvider": hosting.get("cdn_provider"),
        "hostingProvider": hosting.get("hosting_provider"),
    }

    subdomains: list[dict[str, Any]] = []
    for item in sub_rows[:250]:
        if not isinstance(item, dict) or not item.get("hostname"):
            continue
        hostname = str(item.get("hostname")).strip().lower().rstrip(".")
        if not hostname:
            continue
        resolved = item.get("resolved_ips") if isinstance(item.get("resolved_ips"), list) else []
        ip = str(resolved[0]) if resolved else None
        subdomains.append({"hostname": hostname, "ip": ip})

    # Build per-node risk levels from Finding.asset_name (best-effort).
    risk_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"high": 0, "medium": 0, "low": 0, "info": 0})
    asset_names: set[str] = {target, *(row["hostname"] for row in subdomains)}
    finding_rows = (
        db.session.query(Finding.asset_name, Finding.severity)
        .filter(Finding.scan_id == scan_id)
        .filter(Finding.asset_name.in_(list(asset_names)))
        .all()
    )
    for asset_name, severity in finding_rows:
        name = str(asset_name or "").strip().lower()
        if not name:
            continue
        bucket = _severity_bucket(str(severity) if severity is not None else None)
        risk_counts[name][bucket] = int(risk_counts[name].get(bucket, 0)) + 1

    nodes: list[dict[str, Any]] = [
        {
            "id": target,
            "type": "root",
            "riskLevel": _node_risk_level(risk_counts.get(target.lower(), {})),
            "metadata": {
                "ipAddress": primary_ip,
                "technologies": technologies,
                "openPorts": open_ports,
                **hosting_meta,
            },
        }
    ]

    edges: list[dict[str, str]] = []
    for row in subdomains:
        hostname = row["hostname"]
        nodes.append(
            {
                "id": hostname,
                "type": "subdomain",
                "riskLevel": _node_risk_level(risk_counts.get(hostname.lower(), {})),
                "metadata": {
                    "ipAddress": row.get("ip"),
                    "technologies": technologies,
                    "openPorts": open_ports,
                    **hosting_meta,
                },
            }
        )
        edges.append({"source": target, "target": hostname})

    return jsonify({"scan_id": scan_id, "nodes": nodes, "edges": edges})


@bp.get("/scan-timeline")
def dashboard_scan_timeline():
    auth = _require_api_auth()
    if not isinstance(auth, tuple):
        return auth

    scan_id = _parse_scan_id()
    if not isinstance(scan_id, int):
        return scan_id

    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return api_error(status=404, code="RESOURCE_NOT_FOUND", message="Scan not found")

    results = _json_dict(scan.results_json)
    modules = results.get("modules") if isinstance(results.get("modules"), dict) else {}
    if not isinstance(modules, dict):
        modules = {}

    order = _timeline_order(scan.scan_mode)
    ordered_names: list[str] = []
    if order:
        ordered_names.extend([name for name in order if name in modules])
        ordered_names.extend([name for name in modules.keys() if name not in set(ordered_names)])
    else:
        ordered_names = list(modules.keys())

    timeline: list[dict[str, Any]] = []
    for module_name in ordered_names:
        entry = modules.get(module_name) if isinstance(modules.get(module_name), dict) else {}
        status = (entry.get("status") or "unknown").strip().lower()
        timeline.append(
            {
                "stage": MODULE_LABELS.get(module_name, module_name),
                "status": status,
                "duration": _module_duration_seconds(entry),
            }
        )

    return jsonify({"scan_id": scan_id, "timeline": timeline})
