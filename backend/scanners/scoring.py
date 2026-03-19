"""Context-aware risk scoring for attack-surface assessment."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple


HTTP_EXPOSURE_PORTS = {80, 443, 8080, 8443, 8000}


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _is_usable_payload(payload) -> bool:
    if not isinstance(payload, dict):
        return False
    if not payload:
        return False
    if "error" in payload:
        return False
    status = str(payload.get("status", "")).lower()
    return status != "timeout"


def _collect_open_ports(nmap_data: Dict) -> Set[int]:
    ports: Set[int] = set()
    entries = nmap_data.get("ports", []) if isinstance(nmap_data, dict) else []
    for service in entries:
        try:
            ports.add(int(service.get("port")))
        except (TypeError, ValueError, AttributeError):
            continue
    return ports


def _summary_open_port_count(nmap_data: Dict) -> int:
    if not isinstance(nmap_data, dict):
        return 0
    try:
        return int(nmap_data.get("summary", {}).get("open_ports", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _extract_edge_protection(
    fingerprint_data: Optional[Dict], hosting_data: Optional[Dict]
) -> Tuple[Optional[str], Optional[str]]:
    cdn_provider = None
    waf_provider = None

    if isinstance(fingerprint_data, dict):
        cdn_provider = fingerprint_data.get("cdn") or cdn_provider
        waf_provider = fingerprint_data.get("waf") or waf_provider

    if isinstance(hosting_data, dict):
        cdn_provider = hosting_data.get("cdn_provider") or cdn_provider
        waf_provider = hosting_data.get("waf_provider") or waf_provider

    return (
        str(cdn_provider) if cdn_provider else None,
        str(waf_provider) if waf_provider else None,
    )


def _score_open_ports(open_ports: Set[int], open_port_count: int, protected_edge: bool):
    findings: List[str] = []

    if open_ports:
        all_http_only = open_ports.issubset(HTTP_EXPOSURE_PORTS)
        if all_http_only:
            score = 0.5 if protected_edge else 1.0
            findings.append("Open ports are HTTP/S-only; treated as minimal exposure.")
        else:
            non_http_ports = [port for port in open_ports if port not in HTTP_EXPOSURE_PORTS]
            score = 1.5 + (len(non_http_ports) * 2.5)
            extra_http_ports = max(0, len(open_ports) - len(non_http_ports) - 1)
            score += extra_http_ports * 0.5
            findings.append(f"Open ports detected: {', '.join(map(str, sorted(open_ports)))}")
    elif open_port_count > 0:
        score = 1.0 + max(0, open_port_count - 2) * 1.8
        findings.append(f"Open ports reported in summary: {open_port_count}")
    else:
        return 0.0, findings

    if protected_edge:
        score *= 0.5
        findings.append("CDN/WAF detected; port exposure weight reduced by 50%.")

    return score, findings


def _score_vulnerabilities(nmap_data: Dict):
    score = 0.0
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    entries = nmap_data.get("ports", []) if isinstance(nmap_data, dict) else []
    for service in entries:
        vulns = service.get("vulnerabilities", []) if isinstance(service, dict) else []
        for vuln in vulns:
            cvss = _safe_float(vuln.get("cvss_score", 0.0), 0.0)
            if cvss >= 9.0:
                counts["critical"] += 1
                score += 6.0
            elif cvss >= 7.0:
                counts["high"] += 1
                score += 4.0
            elif cvss >= 4.0:
                counts["medium"] += 1
                score += 2.0
            elif cvss > 0.0:
                counts["low"] += 1
                score += 0.5

    return score, counts


def _score_missing_headers(header_data: Dict):
    if not isinstance(header_data, dict):
        return 0.0, {"high": 0, "medium": 0, "low": 0}

    severity_points = {"high": 1.5, "medium": 1.0, "low": 0.5}
    counts = {"high": 0, "medium": 0, "low": 0}
    score = 0.0

    for details in header_data.values():
        if not isinstance(details, dict):
            continue
        if str(details.get("status", "")).lower() != "missing":
            continue
        severity = str(details.get("severity", "")).lower()
        if severity in severity_points:
            counts[severity] += 1
            score += severity_points[severity]

    # Keep header-only risk impact moderate.
    return min(score, 7.0), counts


def _determine_risk(score: float) -> str:
    if score >= 23:
        return "CRITICAL"
    if score >= 15:
        return "HIGH"
    if score >= 7:
        return "MEDIUM"
    return "LOW"


def _confidence_level(nmap_data, header_data, fingerprint_data) -> str:
    signal_count = 0
    for payload in (nmap_data, header_data, fingerprint_data):
        if _is_usable_payload(payload):
            signal_count += 1

    if signal_count >= 3:
        return "High"
    if signal_count == 2:
        return "Medium"
    return "Low"


def calculate_attack_surface(
    nmap_data, header_data, fingerprint_data, hosting_data=None
):
    """Calculate weighted attack-surface score and confidence."""
    score = 0.0
    findings: List[str] = []

    cdn_provider, waf_provider = _extract_edge_protection(fingerprint_data, hosting_data)
    protected_edge = bool(cdn_provider or waf_provider)

    if cdn_provider:
        findings.append(f"CDN detected: {cdn_provider}")
    if waf_provider:
        findings.append(f"WAF detected: {waf_provider}")

    open_ports = _collect_open_ports(nmap_data)
    open_port_count = _summary_open_port_count(nmap_data)
    port_score, port_findings = _score_open_ports(open_ports, open_port_count, protected_edge)
    score += port_score
    findings.extend(port_findings)

    vuln_score, vuln_counts = _score_vulnerabilities(nmap_data)
    score += vuln_score

    if vuln_counts["critical"]:
        findings.append(f"Critical CVEs (CVSS >= 9): {vuln_counts['critical']}")
    if vuln_counts["high"]:
        findings.append(f"High CVEs (CVSS 7-8.9): {vuln_counts['high']}")
    if vuln_counts["medium"]:
        findings.append(f"Medium CVEs (CVSS 4-6.9): {vuln_counts['medium']}")
    if vuln_counts["low"]:
        findings.append(f"Low CVEs (CVSS < 4): {vuln_counts['low']}")

    header_score, header_counts = _score_missing_headers(header_data)
    score += header_score
    missing_headers_total = sum(header_counts.values())
    if missing_headers_total:
        findings.append(
            "Missing security headers: "
            f"{header_counts['high']} high, "
            f"{header_counts['medium']} medium, "
            f"{header_counts['low']} low"
        )

    framework_detection = {}
    if isinstance(fingerprint_data, dict):
        framework_detection = fingerprint_data.get("framework_detection") or {}

    if framework_detection:
        framework_names = sorted(framework_detection.keys())
        score += min(2.0, len(framework_names) * 0.6)
        findings.append(f"Public framework fingerprinting: {', '.join(framework_names)}")

    if not protected_edge:
        score += 1.5
        findings.append("No CDN/WAF protection detected.")

    has_any_cve = any(vuln_counts.values())
    if not has_any_cve and waf_provider:
        score = max(0.0, score - 2.0)
        findings.append("No CVEs detected and WAF present; score reduced by 2.")

    final_score = round(max(0.0, score), 2)
    return {
        "attack_surface_score": final_score,
        "overall_risk": _determine_risk(final_score),
        "confidence": _confidence_level(nmap_data, header_data, fingerprint_data),
        "key_findings": findings,
    }
