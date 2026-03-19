"""Scan routes protected with session auth and RBAC decorators."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy.exc import SQLAlchemyError

from config import Config
from decorators import login_required, permission_required
from extensions import db
from models import Scan
from services.audit_service import log_action
from services.scan_service import run_active_scan, run_full_scan, run_passive_scan


bp = Blueprint("scans", __name__, url_prefix="/scans")
public_bp = Blueprint("scan_public", __name__)


MODE_PERMISSIONS = {
    "passive": "scan:passive",
    "active": "scan:active",
    "full": "scan:active",
}


def _normalize_scan_mode(raw_mode: str | None) -> str:
    mode = (raw_mode or "passive").strip().lower()
    if mode not in MODE_PERMISSIONS:
        raise ValueError("scan_mode must be one of: passive, active, full")
    return mode


def _authorize_mode(mode: str):
    user = g.current_user
    required_permission = MODE_PERMISSIONS[mode]

    if not user.has_permission(required_permission):
        return jsonify({"error": "Forbidden", "required_permission": required_permission}), 403

    if mode == "full" and not user.has_role("admin"):
        return jsonify({"error": "Forbidden", "required_role": "admin"}), 403

    return None


def _calculate_risk_from_results(mode: str, results: dict) -> tuple[Decimal | None, str | None, Decimal | None]:
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

    if mode == "passive":
        return Decimal("2.0"), "Low", Decimal("70.0")

    port_scan_module = modules.get("port_scan") or {}
    port_scan_data = port_scan_module.get("data") if port_scan_module.get("status") == "completed" else {}
    open_ports = len((port_scan_data or {}).get("open_ports") or [])
    if open_ports >= 8:
        return Decimal("8.5"), "High", Decimal("85.0")
    if open_ports >= 3:
        return Decimal("6.0"), "Medium", Decimal("80.0")
    return Decimal("3.5"), "Low", Decimal("75.0")


def _create_scan_record(user_id: int, target: str, mode: str) -> Scan:
    scan = Scan(
        user_id=user_id,
        target=target,
        scan_mode=mode,
        status="running",
        results_json={
            "meta": {
                "target": target,
                "mode": mode,
                "requested_mode": mode,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "completed_at": None,
                "duration_ms": None,
            },
            "modules": {},
            "target": target,
            "scan_mode": mode,
            "requested_mode": mode,
            "status": "running",
        },
    )
    db.session.add(scan)
    db.session.commit()
    return scan


def _run_scan(mode_override: str | None = None):
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()

    if not target:
        return jsonify({"error": "target is required"}), 400

    try:
        mode = mode_override or _normalize_scan_mode(payload.get("scan_mode"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    deny_response = _authorize_mode(mode)
    if deny_response is not None:
        return deny_response

    user = g.current_user

    log_action(
        action="scan.requested",
        resource="scan",
        user_id=user.id,
        details={"mode": mode, "target": target},
    )

    scan = _create_scan_record(user_id=user.id, target=target, mode=mode)

    try:
        if mode == "passive":
            results = run_passive_scan(target, allow_private_targets=Config.ALLOW_PRIVATE_TARGETS)
        elif mode == "active":
            results = run_active_scan(target, allow_private_targets=Config.ALLOW_PRIVATE_TARGETS)
        else:
            results = run_full_scan(target, allow_private_targets=Config.ALLOW_PRIVATE_TARGETS)

        risk_score, overall_risk, confidence_score = _calculate_risk_from_results(mode, results)

        scan.target = (results.get("meta") or {}).get("target", target)
        scan.status = "completed"
        scan.results_json = results
        scan.risk_score = risk_score
        scan.overall_risk = overall_risk
        scan.confidence_score = confidence_score
        scan.completed_at = datetime.now(timezone.utc)
        db.session.commit()

        log_action(
            action="scan.completed",
            resource="scan",
            user_id=user.id,
            details={"scan_id": scan.id, "mode": mode, "target": scan.target},
        )

        return jsonify({"scan": scan.to_dict()}), 201

    except ValueError as exc:
        scan.status = "failed"
        scan.results_json = {
            "meta": {
                "target": target,
                "mode": mode,
                "requested_mode": mode,
                "started_at": scan.created_at.isoformat() if scan.created_at else None,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "duration_ms": None,
            },
            "modules": {},
            "target": target,
            "scan_mode": mode,
            "requested_mode": mode,
            "status": "failed",
            "error": str(exc),
        }
        scan.completed_at = datetime.now(timezone.utc)
        db.session.commit()

        log_action(
            action="scan.validation_failed",
            resource="scan",
            user_id=user.id,
            details={"scan_id": scan.id, "mode": mode, "target": target, "error": str(exc)},
        )
        return jsonify({"error": str(exc)}), 400

    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("Database error while storing scan")
        return jsonify({"error": "Failed to persist scan result"}), 500

    except Exception as exc:
        db.session.rollback()
        current_app.logger.exception("Unexpected scan failure")

        try:
            failed_scan = db.session.get(Scan, scan.id)
            if failed_scan is not None:
                failed_scan.status = "failed"
                failed_scan.results_json = {
                    "meta": {
                        "target": target,
                        "mode": mode,
                        "requested_mode": mode,
                        "started_at": failed_scan.created_at.isoformat() if failed_scan.created_at else None,
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "duration_ms": None,
                    },
                    "modules": {},
                    "target": target,
                    "scan_mode": mode,
                    "requested_mode": mode,
                    "status": "failed",
                    "error": str(exc),
                }
                failed_scan.completed_at = datetime.now(timezone.utc)
                db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()

        log_action(
            action="scan.failed",
            resource="scan",
            user_id=user.id,
            details={"scan_id": scan.id, "mode": mode, "target": target, "error": str(exc)},
        )
        return jsonify({"error": "Scan execution failed", "detail": str(exc)}), 500


@bp.post("")
@login_required
def run_scan():
    return _run_scan()


@bp.post("/passive")
@login_required
@permission_required("scan:passive")
def run_passive():
    return _run_scan("passive")


@bp.post("/active")
@login_required
@permission_required("scan:active")
def run_active():
    return _run_scan("active")


@bp.post("/full")
@login_required
def run_full():
    return _run_scan("full")


@public_bp.post("/scan")
@login_required
def scan_start():
    return _run_scan()


@bp.get("")
@login_required
@permission_required("scan:read")
def list_scans():
    user = g.current_user
    include_all = request.args.get("all", "false").lower() == "true"

    query = Scan.query.order_by(Scan.created_at.desc())
    if not (include_all and user.has_role("admin")):
        query = query.filter_by(user_id=user.id)

    scans = query.limit(200).all()
    return jsonify({"scans": [item.to_dict() for item in scans]})


@public_bp.get("/scan")
@login_required
@permission_required("scan:read")
def scan_history():
    return list_scans()


@public_bp.get("/scan/history")
@login_required
@permission_required("scan:read")
def scan_history_legacy():
    return list_scans()


@bp.get("/<int:scan_id>")
@login_required
@permission_required("scan:read")
def get_scan(scan_id: int):
    user = g.current_user
    scan = Scan.query.get_or_404(scan_id)

    if scan.user_id != user.id and not user.has_role("admin"):
        return jsonify({"error": "Forbidden"}), 403

    return jsonify({"scan": scan.to_dict()})


@public_bp.get("/scan/<int:scan_id>")
@login_required
@permission_required("scan:read")
def get_scan_legacy(scan_id: int):
    return get_scan(scan_id)
