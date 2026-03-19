"""Target validation and scanning service functions."""

from __future__ import annotations

import ipaddress
import logging
import re
import shutil
import socket
import ssl
import time
import hashlib
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import subprocess
from urllib.parse import urlparse

import requests
from typing import Any


logger = logging.getLogger(__name__)

DOMAIN_RE = re.compile(r"^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
COMMON_ACTIVE_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
COMMON_SUBDOMAINS = [
    "www",
    "mail",
    "ftp",
    "api",
    "dev",
    "test",
    "staging",
    "admin",
    "portal",
    "blog",
    "cdn",
    "assets",
    "docs",
    "app",
    "beta",
    "uat",
    "vpn",
    "smtp",
    "imap",
    "ns1",
    "ns2",
]
DNS_RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME")
REQUIRED_SECURITY_HEADERS = {
    "Content-Security-Policy": "high",
    "Strict-Transport-Security": "high",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "medium",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
}
SEVERITY_POINTS = {"high": 3, "medium": 2, "low": 1}
SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    8080: "http-alt",
    8443: "https-alt",
}

PASSIVE_MODULES = ("subdomain_enum", "dns_enum", "whois", "report_generation")
ACTIVE_MODULES = ("port_scan", "http_probe", "ssl_check", "report_generation")
FULL_MODULES = (
    "subdomain_enum",
    "dns_enum",
    "whois",
    "port_scan",
    "http_probe",
    "url_discovery",
    "ssl_check",
    "headers_analysis",
    "technology_fingerprint",
    "hosting_detection",
    "vulnerability_surface",
    "risk_scoring",
    "report_generation",
)

PASSIVE_PROGRESS = {"subdomain_enum": 20, "dns_enum": 35, "whois": 50, "report_generation": 100}
ACTIVE_PROGRESS = {"port_scan": 60, "http_probe": 80, "ssl_check": 85, "report_generation": 100}
FULL_PROGRESS = {
    "subdomain_enum": 20,
    "dns_enum": 35,
    "port_scan": 60,
    "http_probe": 80,
    "url_discovery": 82,
    "technology_fingerprint": 85,
    "vulnerability_surface": 90,
    "risk_scoring": 95,
    "report_generation": 100,
}

MODULE_STAGE = {
    "subdomain_enum": "subdomain_discovery",
    "dns_enum": "dns_resolution",
    "port_scan": "port_scanning",
    "http_probe": "http_probing",
    "url_discovery": "url_discovery",
    "technology_fingerprint": "technology_detection",
    "vulnerability_surface": "vulnerability_detection",
    "report_generation": "report_generation",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tool_available(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def _run_command(
    cmd: list[str],
    *,
    timeout_seconds: int = 90,
    max_stdout_lines: int = 2000,
    max_stderr_lines: int = 200,
    stdin_text: str | None = None,
) -> dict:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            input=stdin_text,
        )
        stdout_lines = (completed.stdout or "").splitlines()
        stderr_lines = (completed.stderr or "").splitlines()
        return {
            "cmd": cmd,
            "returncode": int(completed.returncode),
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "timed_out": False,
            "stdout_lines": stdout_lines[:max_stdout_lines],
            "stdout_truncated": len(stdout_lines) > max_stdout_lines,
            "stderr_lines": stderr_lines[:max_stderr_lines],
            "stderr_truncated": len(stderr_lines) > max_stderr_lines,
        }
    except FileNotFoundError:
        return {
            "cmd": cmd,
            "returncode": None,
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "timed_out": False,
            "error": "tool_not_found",
            "stdout_lines": [],
            "stdout_truncated": False,
            "stderr_lines": [],
            "stderr_truncated": False,
        }
    except subprocess.TimeoutExpired as exc:
        stdout_lines = (exc.stdout or "").splitlines() if isinstance(exc.stdout, str) else []
        stderr_lines = (exc.stderr or "").splitlines() if isinstance(exc.stderr, str) else []
        return {
            "cmd": cmd,
            "returncode": None,
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "timed_out": True,
            "stdout_lines": stdout_lines[:max_stdout_lines],
            "stdout_truncated": len(stdout_lines) > max_stdout_lines,
            "stderr_lines": stderr_lines[:max_stderr_lines],
            "stderr_truncated": len(stderr_lines) > max_stderr_lines,
        }


def _emit_event(context: dict, payload: dict[str, Any]) -> None:
    callback = context.get("event_cb")
    if callback is None:
        return
    if not callable(callback):
        return
    callback(payload)


def normalize_target(raw_target: str) -> str:
    value = (raw_target or "").strip()
    if not value:
        return ""

    if "://" not in value:
        value = f"http://{value}"

    parsed = urlparse(value)
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    return host


def validate_target(target: str) -> None:
    if not target:
        raise ValueError("Target is required")

    try:
        ipaddress.ip_address(target)
        return
    except ValueError:
        pass

    if not DOMAIN_RE.match(target):
        raise ValueError("Target must be a valid domain or IP address")


def resolve_target_ips(target: str) -> list[str]:
    try:
        resolved = socket.getaddrinfo(target, None)
    except socket.gaierror:
        return []

    ips: set[str] = set()
    for item in resolved:
        ip = item[4][0]
        ips.add(ip)
    return sorted(ips)


def _is_private_or_reserved(ip_str: str) -> bool:
    ip_obj = ipaddress.ip_address(ip_str)
    return any(
        [
            ip_obj.is_private,
            ip_obj.is_loopback,
            ip_obj.is_link_local,
            ip_obj.is_multicast,
            ip_obj.is_reserved,
        ]
    )


def enforce_target_policy(target: str, allow_private_targets: bool) -> list[str]:
    resolved_ips = resolve_target_ips(target)

    if allow_private_targets:
        return resolved_ips

    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        target_ip = None

    if target_ip is not None and _is_private_or_reserved(str(target_ip)):
        raise ValueError("Scanning private or reserved targets is disabled")

    for ip in resolved_ips:
        if _is_private_or_reserved(ip):
            raise ValueError("Target resolves to private or reserved IP space")

    return resolved_ips


def _is_ip_target(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _module_data(context: dict, module_name: str) -> dict:
    entry = (context.get("module_results") or {}).get(module_name) or {}
    if entry.get("status") == "completed" and isinstance(entry.get("data"), dict):
        return entry["data"]
    return {}


def _doh_resolve_record(name: str, record_type: str, timeout: float = 3.0) -> list[str]:
    try:
        response = requests.get(
            "https://dns.google/resolve",
            params={"name": name, "type": record_type},
            timeout=timeout,
            headers={"Accept": "application/json"},
        )
        if not response.ok:
            return []
        payload = response.json()
    except Exception:
        return []

    values: list[str] = []
    for answer in payload.get("Answer", []) or []:
        if not isinstance(answer, dict):
            continue
        value = str(answer.get("data", "")).strip().strip('"')
        if not value:
            continue
        if record_type == "MX" and " " in value:
            value = value.split(" ", 1)[1]
        value = value.rstrip(".")
        if value:
            values.append(value)
    return sorted(set(values))


def _collect_dns_records(target: str) -> dict[str, list[str]]:
    if _is_ip_target(target):
        ip_obj = ipaddress.ip_address(target)
        records = {record_type: [] for record_type in DNS_RECORD_TYPES}
        if ip_obj.version == 4:
            records["A"] = [target]
        else:
            records["AAAA"] = [target]
        return records

    records: dict[str, list[str]] = {record_type: [] for record_type in DNS_RECORD_TYPES}
    with ThreadPoolExecutor(max_workers=len(DNS_RECORD_TYPES)) as executor:
        futures = {
            executor.submit(_doh_resolve_record, target, record_type): record_type for record_type in DNS_RECORD_TYPES
        }
        for future in as_completed(futures):
            record_type = futures[future]
            try:
                records[record_type] = future.result()
            except Exception:
                records[record_type] = []
    return records


def _http_probe(target: str) -> dict:
    last_error = "Request failed"
    request_headers = {"User-Agent": "ReconEngine/1.0"}
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        response = None
        try:
            response = requests.get(
                url,
                timeout=(4, 6),
                allow_redirects=True,
                stream=True,
                headers=request_headers,
            )
            snippet = b""
            for chunk in response.iter_content(chunk_size=1024):
                if not chunk:
                    continue
                snippet += chunk
                if len(snippet) >= 5120:
                    break

            response_headers = dict(response.headers)
            return {
                "url": response.url,
                "status_code": response.status_code,
                "headers": response_headers,
                "redirects": [item.url for item in response.history] + [response.url],
                "server_banner": response_headers.get("Server"),
                "html_snippet": snippet.decode(response.encoding or "utf-8", errors="replace")[:5120],
            }
        except requests.RequestException as exc:
            last_error = str(exc)
        finally:
            if response is not None:
                response.close()

    raise RuntimeError(last_error)


def _scan_ports(target: str, ports: list[int], timeout_seconds: float = 0.6) -> dict:
    open_ports: list[int] = []
    closed_ports: list[int] = []

    def check_port(port: int) -> tuple[int, bool]:
        try:
            with socket.create_connection((target, port), timeout=timeout_seconds):
                return port, True
        except OSError:
            return port, False

    with ThreadPoolExecutor(max_workers=min(len(ports), 24)) as executor:
        futures = [executor.submit(check_port, port) for port in ports]
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
            else:
                closed_ports.append(port)

    open_ports.sort()
    closed_ports.sort()

    return {
        "tested_ports": list(ports),
        "open_ports": open_ports,
        "closed_ports": closed_ports,
    }


def _ssl_check(target: str) -> dict:
    def flatten_dn(raw_dn: object) -> dict[str, str]:
        flattened: dict[str, str] = {}
        if not isinstance(raw_dn, (list, tuple)):
            return flattened
        for group in raw_dn:
            if not isinstance(group, (list, tuple)):
                continue
            for item in group:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    flattened[str(item[0])] = str(item[1])
        return flattened

    context = ssl.create_default_context()
    with socket.create_connection((target, 443), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=target) as ssock:
            certificate = ssock.getpeercert()
            cipher = ssock.cipher()
            return {
                "issuer": flatten_dn(certificate.get("issuer")),
                "subject": flatten_dn(certificate.get("subject")),
                "valid_from": certificate.get("notBefore"),
                "valid_to": certificate.get("notAfter"),
                "tls_version": ssock.version(),
                "cipher": cipher[0] if isinstance(cipher, tuple) and cipher else None,
                # compatibility keys
                "ssl_version": ssock.version(),
                "not_before": certificate.get("notBefore"),
                "not_after": certificate.get("notAfter"),
            }


def _rdap_lookup(target: str) -> dict:
    try:
        ipaddress.ip_address(target)
        rdap_url = f"https://rdap.org/ip/{target}"
    except ValueError:
        rdap_url = f"https://rdap.org/domain/{target}"

    response = requests.get(rdap_url, timeout=10)
    response.raise_for_status()
    payload = response.json()

    nameservers = []
    for item in payload.get("nameservers", []):
        if isinstance(item, dict) and item.get("ldhName"):
            nameservers.append(item["ldhName"])

    events: dict[str, str] = {}
    for event in payload.get("events", []):
        if not isinstance(event, dict):
            continue
        event_action = event.get("eventAction")
        event_date = event.get("eventDate")
        if event_action and event_date:
            events[str(event_action)] = str(event_date)

    entity_handles = []
    for entity in payload.get("entities", []):
        if isinstance(entity, dict) and entity.get("handle"):
            entity_handles.append(entity["handle"])

    return {
        "query": target,
        "source": "rdap",
        "rdap_url": rdap_url,
        "handle": payload.get("handle"),
        "name": payload.get("ldhName") or payload.get("name"),
        "status": payload.get("status"),
        "port43": payload.get("port43"),
        "nameservers": nameservers,
        "entities": entity_handles,
        "events": events,
    }


def _query_whois_server(server: str, query: str) -> str:
    with socket.create_connection((server, 43), timeout=10) as connection:
        connection.sendall(f"{query}\r\n".encode("utf-8"))
        response_parts = []
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response_parts.append(chunk.decode("utf-8", errors="replace"))
    return "".join(response_parts)


def _extract_whois_referral(response_text: str) -> str | None:
    for line in response_text.splitlines():
        lowered = line.lower()
        if lowered.startswith("refer:") or lowered.startswith("whois:"):
            _, _, value = line.partition(":")
            referral = value.strip()
            if referral:
                return referral
    return None


def _parse_whois_text(response_text: str) -> dict:
    parsed: dict[str, object] = {"name_servers": []}
    for line in response_text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        normalized_key = key.strip().lower()
        normalized_value = value.strip()
        if not normalized_value:
            continue

        if normalized_key in {"domain name", "domain"} and "domain_name" not in parsed:
            parsed["domain_name"] = normalized_value
        elif normalized_key == "registrar" and "registrar" not in parsed:
            parsed["registrar"] = normalized_value
        elif normalized_key in {"creation date", "created", "registered on"} and "creation_date" not in parsed:
            parsed["creation_date"] = normalized_value
        elif normalized_key in {"registry expiry date", "expiry date", "expiration date"} and "expiration_date" not in parsed:
            parsed["expiration_date"] = normalized_value
        elif normalized_key in {"name server", "nserver"}:
            name_servers = parsed["name_servers"]
            if isinstance(name_servers, list):
                name_servers.append(normalized_value)
        elif normalized_key in {"orgname", "org-name", "organisation"} and "registrant_org" not in parsed:
            parsed["registrant_org"] = normalized_value

    return parsed


def _socket_whois_lookup(target: str) -> dict:
    bootstrap = _query_whois_server("whois.iana.org", target)
    referred_server = _extract_whois_referral(bootstrap) or "whois.iana.org"
    detailed = _query_whois_server(referred_server, target)

    return {
        "query": target,
        "source": "whois",
        "whois_server": referred_server,
        "parsed": _parse_whois_text(detailed),
    }


def _whois_lookup(target: str) -> dict:
    try:
        return _rdap_lookup(target)
    except Exception as rdap_error:
        try:
            socket_whois_result = _socket_whois_lookup(target)
            socket_whois_result["rdap_error"] = str(rdap_error)
            return socket_whois_result
        except Exception as whois_error:
            raise RuntimeError(f"WHOIS lookup failed: rdap={rdap_error}; socket={whois_error}") from whois_error


def _subdomain_enumeration(target: str, *, context: dict | None = None) -> dict:
    if _is_ip_target(target) or target.count(".") < 1:
        raise ValueError("Subdomain enumeration requires a domain target")

    ctx: dict = context or {}
    raw: dict[str, Any] = {"tools": {}}
    candidates: set[str] = set()
    domain = target.strip().lower().rstrip(".")

    if _tool_available("subfinder"):
        subfinder = _run_command(
            ["subfinder", "-silent", "-duc", "-timeout", "10", "-max-time", "1", "-d", domain],
            timeout_seconds=45,
        )
        raw["tools"]["subfinder"] = subfinder
        _emit_event(
            ctx,
            {
                "type": "command_executed",
                "timestamp": _utc_now(),
                "stage": "subdomain_discovery",
                "tool": "subfinder",
                "cmd": subfinder.get("cmd"),
                "returncode": subfinder.get("returncode"),
                "duration_ms": subfinder.get("duration_ms"),
                "timed_out": subfinder.get("timed_out"),
                "summary": f"lines={len(subfinder.get('stdout_lines') or [])}",
            },
        )
        if subfinder.get("returncode") == 0:
            for line in subfinder.get("stdout_lines") or []:
                value = str(line).strip().lower().rstrip(".")
                if value and (value == domain or value.endswith(f".{domain}")):
                    candidates.add(value)

    if _tool_available("assetfinder"):
        assetfinder = _run_command(["assetfinder", "--subs-only", domain], timeout_seconds=30)
        raw["tools"]["assetfinder"] = assetfinder
        _emit_event(
            ctx,
            {
                "type": "command_executed",
                "timestamp": _utc_now(),
                "stage": "subdomain_discovery",
                "tool": "assetfinder",
                "cmd": assetfinder.get("cmd"),
                "returncode": assetfinder.get("returncode"),
                "duration_ms": assetfinder.get("duration_ms"),
                "timed_out": assetfinder.get("timed_out"),
                "summary": f"lines={len(assetfinder.get('stdout_lines') or [])}",
            },
        )
        if assetfinder.get("returncode") == 0:
            for line in assetfinder.get("stdout_lines") or []:
                value = str(line).strip().lower().rstrip(".")
                if value and (value == domain or value.endswith(f".{domain}")):
                    candidates.add(value)

    if _tool_available("amass"):
        amass = _run_command(["amass", "enum", "-silent", "-timeout", "1", "-d", domain], timeout_seconds=45)
        raw["tools"]["amass"] = amass
        _emit_event(
            ctx,
            {
                "type": "command_executed",
                "timestamp": _utc_now(),
                "stage": "subdomain_discovery",
                "tool": "amass",
                "cmd": amass.get("cmd"),
                "returncode": amass.get("returncode"),
                "duration_ms": amass.get("duration_ms"),
                "timed_out": amass.get("timed_out"),
                "summary": f"lines={len(amass.get('stdout_lines') or [])}",
            },
        )
        if amass.get("returncode") == 0:
            suffix = f".{domain}"
            for line in amass.get("stdout_lines") or []:
                text = str(line).strip().lower()
                for match in re.findall(r"[a-z0-9.-]+\.[a-z]{2,63}", text):
                    value = str(match).rstrip(".")
                    if value == domain or value.endswith(suffix):
                        candidates.add(value)

    def resolve_candidate(candidate: str) -> tuple[str, list[str]]:
        a_records = _doh_resolve_record(candidate, "A", timeout=1.5)
        aaaa_records = _doh_resolve_record(candidate, "AAAA", timeout=1.5)
        resolved_ips = [*a_records, *aaaa_records]
        return candidate, resolved_ips

    discovered: list[dict[str, Any]] = []
    if not candidates:
        candidates = {f"{subdomain}.{domain}" for subdomain in COMMON_SUBDOMAINS}
        raw["fallback"] = "common_subdomains"
    else:
        max_candidates = 200
        if len(candidates) > max_candidates:
            raw["originalCandidateCount"] = len(candidates)
            raw["candidateTruncated"] = True
            candidates = set(sorted(candidates)[:max_candidates])

    candidate_list = sorted(candidates)
    enrich_limit = min(25, len(candidate_list))
    resolved_map: dict[str, list[str]] = {}

    if enrich_limit:
        with ThreadPoolExecutor(max_workers=min(enrich_limit, 16)) as executor:
            futures = [executor.submit(resolve_candidate, candidate) for candidate in candidate_list[:enrich_limit]]
            for future in as_completed(futures):
                fqdn, resolved_ips = future.result()
                if resolved_ips:
                    resolved_map[fqdn] = resolved_ips

    for fqdn in candidate_list:
        discovered.append({"hostname": fqdn, "resolved_ips": resolved_map.get(fqdn, [])})

    discovered.sort(key=lambda item: item["hostname"])

    raw["candidateCount"] = len(candidates)
    return {"count": len(discovered), "subdomains": discovered, "raw": raw}


def _module_dns_enum(context: dict) -> dict:
    resolved_ips = context["resolved_ips"]
    ipv6_addresses = [ip for ip in resolved_ips if ":" in ip]
    primary_ip = next((ip for ip in resolved_ips if ":" not in ip), resolved_ips[0] if resolved_ips else None)
    return {
        "primary_ip": primary_ip,
        "resolved_ips": resolved_ips,
        "ipv6_addresses": ipv6_addresses,
        "dns_records": _collect_dns_records(context["target"]),
    }


def _module_whois(context: dict) -> dict:
    return _whois_lookup(context["target"])


def _module_subdomain_enum(context: dict) -> dict:
    return _subdomain_enumeration(context["target"], context=context)


def _module_port_scan(context: dict) -> dict:
    target = context["target"]
    raw: dict[str, Any] = {"tools": {}}

    if _tool_available("naabu"):
        port_list = ",".join(str(port) for port in COMMON_ACTIVE_PORTS)
        attempts = [
            ["naabu", "-host", target, "-silent", "-duc", "-Pn", "-sa", "-p", port_list, "-scan-type", "c"],
            ["naabu", "-host", target, "-silent", "-duc", "-Pn", "-sa", "-p", port_list],
        ]
        for cmd in attempts:
            result = _run_command(cmd, timeout_seconds=180)
            raw["tools"].setdefault("naabu_attempts", []).append(result)
            _emit_event(
                context,
                {
                    "type": "command_executed",
                    "timestamp": _utc_now(),
                    "stage": "port_scanning",
                    "tool": "naabu",
                    "cmd": result.get("cmd"),
                    "returncode": result.get("returncode"),
                    "duration_ms": result.get("duration_ms"),
                    "timed_out": result.get("timed_out"),
                    "summary": f"lines={len(result.get('stdout_lines') or [])}",
                },
            )
            if result.get("returncode") == 0:
                open_ports: set[int] = set()
                for line in result.get("stdout_lines") or []:
                    text = str(line).strip()
                    if ":" not in text:
                        continue
                    try:
                        _host, port_str = text.rsplit(":", 1)
                        open_ports.add(int(port_str))
                    except Exception:
                        continue
                if open_ports:
                    fallback = {
                        "tested_ports": list(COMMON_ACTIVE_PORTS),
                        "open_ports": sorted(open_ports),
                        "closed_ports": [p for p in COMMON_ACTIVE_PORTS if p not in open_ports],
                        "raw": raw,
                    }
                    return fallback

    port_data = _scan_ports(target, COMMON_ACTIVE_PORTS)
    port_data["raw"] = raw
    return port_data


def _module_http_probe(context: dict) -> dict:
    return _http_probe(context["target"])


def _module_url_discovery(context: dict) -> dict:
    target = context["target"]
    if _is_ip_target(target):
        return {"count": 0, "urls": [], "raw": {"skipped": "ip_target"}}

    raw: dict[str, Any] = {"tools": {}}
    urls: set[str] = set()

    if _tool_available("gau"):
        gau = _run_command(["gau", "--subs", "--threads", "4", "--timeout", "20", target], timeout_seconds=90)
        raw["tools"]["gau"] = gau
        _emit_event(
            context,
            {
                "type": "command_executed",
                "timestamp": _utc_now(),
                "stage": "url_discovery",
                "tool": "gau",
                "cmd": gau.get("cmd"),
                "returncode": gau.get("returncode"),
                "duration_ms": gau.get("duration_ms"),
                "timed_out": gau.get("timed_out"),
                "summary": f"lines={len(gau.get('stdout_lines') or [])}",
            },
        )
        if gau.get("returncode") == 0:
            for line in gau.get("stdout_lines") or []:
                value = str(line).strip()
                if value.startswith("http://") or value.startswith("https://"):
                    urls.add(value)

    if _tool_available("waybackurls"):
        wayback = _run_command(["waybackurls"], timeout_seconds=90, stdin_text=f"{target}\n")
        raw["tools"]["waybackurls"] = wayback
        _emit_event(
            context,
            {
                "type": "command_executed",
                "timestamp": _utc_now(),
                "stage": "url_discovery",
                "tool": "waybackurls",
                "cmd": wayback.get("cmd"),
                "returncode": wayback.get("returncode"),
                "duration_ms": wayback.get("duration_ms"),
                "timed_out": wayback.get("timed_out"),
                "summary": f"lines={len(wayback.get('stdout_lines') or [])}",
            },
        )
        if wayback.get("returncode") == 0:
            for line in wayback.get("stdout_lines") or []:
                value = str(line).strip()
                if value.startswith("http://") or value.startswith("https://"):
                    urls.add(value)

    url_list = sorted(urls)
    max_urls = 1500
    truncated = len(url_list) > max_urls
    url_list = url_list[:max_urls]

    return {"count": len(url_list), "urls": url_list, "raw": raw, "truncated": truncated}


def _module_ssl_check(context: dict) -> dict:
    return _ssl_check(context["target"])


def _module_headers_analysis(context: dict) -> dict:
    http_probe_entry = (context.get("module_results") or {}).get("http_probe") or {}
    probe_data = _module_data(context, "http_probe")
    if not probe_data:
        if http_probe_entry.get("status") == "failed":
            raise RuntimeError("HTTP probe data unavailable")
        probe_data = _http_probe(context["target"])

    response_headers = probe_data.get("headers") if isinstance(probe_data, dict) else {}
    if not isinstance(response_headers, dict):
        response_headers = {}
    normalized = {str(key).lower(): str(value) for key, value in response_headers.items()}

    missing_headers: list[str] = []
    present_headers: dict[str, str] = {}
    risk_score = 0
    severity_summary = {"high": 0, "medium": 0, "low": 0, "risk_level": "low"}

    for header_name, severity in REQUIRED_SECURITY_HEADERS.items():
        value = normalized.get(header_name.lower())
        if value is None:
            missing_headers.append(header_name)
            severity_summary[severity] += 1
            risk_score += SEVERITY_POINTS[severity]
        else:
            present_headers[header_name] = value

    if risk_score >= 8:
        severity_summary["risk_level"] = "high"
    elif risk_score >= 4:
        severity_summary["risk_level"] = "medium"

    return {
        "missing_headers": missing_headers,
        "present_headers": present_headers,
        "risk_score": risk_score,
        "severity_summary": severity_summary,
    }


def _contains_any(text: str, patterns: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(pattern in lowered for pattern in patterns)


def _module_technology_fingerprint(context: dict) -> dict:
    http_probe_entry = (context.get("module_results") or {}).get("http_probe") or {}
    probe_data = _module_data(context, "http_probe")
    if not probe_data:
        if http_probe_entry.get("status") == "failed":
            raise RuntimeError("HTTP probe data unavailable")
        probe_data = _http_probe(context["target"])

    headers = probe_data.get("headers") if isinstance(probe_data, dict) else {}
    html = str(probe_data.get("html_snippet") if isinstance(probe_data, dict) else "").lower()
    if not isinstance(headers, dict):
        headers = {}
    headers_lc = {str(key).lower(): str(value) for key, value in headers.items()}
    server_banner = str(probe_data.get("server_banner") or headers.get("Server") or "")

    framework: set[str] = set()
    if _contains_any(html, ("wp-content", "wp-includes", "xmlrpc.php")) or "x-pingback" in headers_lc:
        framework.add("WordPress")
    if _contains_any(html, ("/sites/default/", "drupal-settings-json")) or "drupal" in headers_lc.get("x-generator", "").lower():
        framework.add("Drupal")
    if _contains_any(html, ("joomla!", "com_content", "/media/system/js/")):
        framework.add("Joomla")
    if _contains_any(html, ("data-reactroot", "__react", "react")):
        framework.add("React")
    if _contains_any(html, ("ng-app", "ng-version", "angular")):
        framework.add("Angular")
    if _contains_any(html, ("__next_data__", "/_next/static", "nextjs")):
        framework.add("NextJS")
    if "laravel_session" in headers_lc.get("set-cookie", "").lower() or "laravel" in headers_lc.get("x-powered-by", "").lower():
        framework.add("Laravel")
    if "csrftoken" in headers_lc.get("set-cookie", "").lower() or "django" in headers_lc.get("x-powered-by", "").lower():
        framework.add("Django")

    reverse_proxy = None
    if "nginx" in server_banner.lower():
        reverse_proxy = "Nginx"
    elif "apache" in server_banner.lower():
        reverse_proxy = "Apache"
    elif _contains_any(server_banner, ("envoy", "haproxy", "traefik")):
        reverse_proxy = "Reverse Proxy"

    cdn = None
    waf = None
    if "cf-ray" in headers_lc or "cloudflare" in server_banner.lower():
        cdn = "Cloudflare"
        waf = "Cloudflare WAF"
    elif "x-amz-cf-id" in headers_lc:
        cdn = "AWS CloudFront"
    elif "x-akamai-transformed" in headers_lc:
        cdn = "Akamai"
    elif "x-served-by" in headers_lc and "fastly" in headers_lc.get("x-served-by", "").lower():
        cdn = "Fastly"

    return {
        "framework": sorted(framework),
        "server": server_banner or None,
        "cdn": cdn,
        "reverse_proxy": reverse_proxy,
        "waf": waf,
    }


def _detect_provider_from_text(value: str) -> str | None:
    lowered = (value or "").lower()
    if "cloudflare" in lowered:
        return "Cloudflare"
    if any(token in lowered for token in ("amazonaws", "awsdns", "cloudfront", "amazon")):
        return "AWS"
    if any(token in lowered for token in ("azure", "windows.net", "trafficmanager.net")):
        return "Azure"
    if any(token in lowered for token in ("google", "gcp", "googleusercontent")):
        return "GCP"
    if "digitalocean" in lowered:
        return "DigitalOcean"
    return None


def _reverse_dns(ip_address: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(ip_address)
        return host
    except OSError:
        return None


def _module_hosting_detection(context: dict) -> dict:
    dns_data = _module_data(context, "dns_enum")
    whois_data = _module_data(context, "whois")
    tech_data = _module_data(context, "technology_fingerprint")

    cloud_provider = None
    cdn_provider = None
    hosting_provider = None

    if isinstance(tech_data, dict):
        cdn_provider = tech_data.get("cdn")

    dns_records = dns_data.get("dns_records") if isinstance(dns_data, dict) else {}
    if isinstance(dns_records, dict):
        for nameserver in dns_records.get("NS", []) or []:
            provider = _detect_provider_from_text(str(nameserver))
            if provider:
                if provider == "Cloudflare" and not cdn_provider:
                    cdn_provider = provider
                elif not cloud_provider:
                    cloud_provider = provider
                break

    if isinstance(whois_data, dict):
        candidates = []
        for key in ("name", "handle"):
            value = whois_data.get(key)
            if value:
                candidates.append(str(value))
        parsed = whois_data.get("parsed")
        if isinstance(parsed, dict) and parsed.get("registrant_org"):
            candidates.append(str(parsed.get("registrant_org")))
        for candidate in candidates:
            provider = _detect_provider_from_text(candidate)
            if provider:
                if provider == "Cloudflare" and not cdn_provider:
                    cdn_provider = provider
                elif not cloud_provider:
                    cloud_provider = provider
                break

    resolved_ips = dns_data.get("resolved_ips") if isinstance(dns_data, dict) else context.get("resolved_ips", [])
    if not cloud_provider and isinstance(resolved_ips, list) and resolved_ips:
        ptr = _reverse_dns(str(resolved_ips[0]))
        if ptr:
            cloud_provider = _detect_provider_from_text(ptr)
            hosting_provider = ptr

    if not hosting_provider:
        if cdn_provider:
            hosting_provider = f"{cdn_provider} (CDN-proxied origin)"
        elif cloud_provider:
            hosting_provider = cloud_provider
        elif isinstance(resolved_ips, list) and resolved_ips:
            hosting_provider = f"Unknown ({resolved_ips[0]})"
        else:
            hosting_provider = "Unknown"

    return {
        "cloud_provider": cloud_provider,
        "cdn_provider": cdn_provider,
        "hosting_provider": hosting_provider,
    }


def _module_vulnerability_surface(context: dict) -> dict:
    port_data = _module_data(context, "port_scan")
    header_data = _module_data(context, "headers_analysis")
    tech_data = _module_data(context, "technology_fingerprint")

    open_ports = port_data.get("open_ports") if isinstance(port_data, dict) else []
    missing_headers = header_data.get("missing_headers") if isinstance(header_data, dict) else []
    frameworks = tech_data.get("framework") if isinstance(tech_data, dict) else []
    if not isinstance(open_ports, list):
        open_ports = []
    if not isinstance(missing_headers, list):
        missing_headers = []
    if not isinstance(frameworks, list):
        frameworks = []

    exposed_services = [{"port": int(port), "service": SERVICE_MAP.get(int(port), "unknown")} for port in open_ports]
    potential_risks: list[str] = []
    misconfigurations: list[str] = []

    for port in open_ports:
        if int(port) in {21, 22, 25, 445, 3306, 3389}:
            potential_risks.append(f"Sensitive service exposed on port {port}")
        elif int(port) in {80, 8080}:
            potential_risks.append(f"Unencrypted HTTP service exposed on port {port}")

    for header_name in missing_headers:
        potential_risks.append(f"Missing security header: {header_name}")
        misconfigurations.append(f"Header misconfiguration: {header_name}")

    if frameworks:
        potential_risks.append(f"Technology exposure: {', '.join(frameworks)}")

    return {
        "potential_risks": potential_risks,
        "exposed_services": exposed_services,
        "misconfigurations": misconfigurations,
    }


def _module_risk_scoring(context: dict) -> dict:
    port_data = _module_data(context, "port_scan")
    header_data = _module_data(context, "headers_analysis")
    tech_data = _module_data(context, "technology_fingerprint")
    vuln_data = _module_data(context, "vulnerability_surface")

    open_ports = port_data.get("open_ports") if isinstance(port_data, dict) else []
    severity_summary = header_data.get("severity_summary") if isinstance(header_data, dict) else {}
    frameworks = tech_data.get("framework") if isinstance(tech_data, dict) else []
    misconfigurations = vuln_data.get("misconfigurations") if isinstance(vuln_data, dict) else []
    potential_risks = vuln_data.get("potential_risks") if isinstance(vuln_data, dict) else []

    if not isinstance(open_ports, list):
        open_ports = []
    if not isinstance(severity_summary, dict):
        severity_summary = {}
    if not isinstance(frameworks, list):
        frameworks = []
    if not isinstance(misconfigurations, list):
        misconfigurations = []
    if not isinstance(potential_risks, list):
        potential_risks = []

    score = 0.0
    score += sum(1.5 if int(port) not in {80, 443, 8080, 8443} else 0.5 for port in open_ports)
    score += float(severity_summary.get("high", 0)) * 2.0
    score += float(severity_summary.get("medium", 0)) * 1.0
    score += float(severity_summary.get("low", 0)) * 0.5
    score += min(6.0, len(frameworks) * 1.0)
    score += min(6.0, len(misconfigurations) * 1.5)
    score += min(3.0, len(potential_risks) * 0.5)

    final_score = round(max(0.0, score), 2)
    if final_score >= 13:
        overall_risk = "High"
    elif final_score >= 6:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"

    key_findings: list[str] = []
    if open_ports:
        key_findings.append(f"Open ports: {', '.join(map(str, sorted(set(int(port) for port in open_ports))))}")
    if potential_risks:
        key_findings.extend(potential_risks[:4])
    if frameworks:
        key_findings.append(f"Technologies detected: {', '.join(frameworks)}")

    return {
        "attack_surface_score": final_score,
        "overall_risk": overall_risk,
        "key_findings": key_findings[:8],
    }


MODULE_HANDLERS = {
    "dns_enum": _module_dns_enum,
    "whois": _module_whois,
    "subdomain_enum": _module_subdomain_enum,
    "port_scan": _module_port_scan,
    "http_probe": _module_http_probe,
    "url_discovery": _module_url_discovery,
    "ssl_check": _module_ssl_check,
    "headers_analysis": _module_headers_analysis,
    "technology_fingerprint": _module_technology_fingerprint,
    "hosting_detection": _module_hosting_detection,
    "vulnerability_surface": _module_vulnerability_surface,
    "risk_scoring": _module_risk_scoring,
    "report_generation": lambda context: {
        "generated_at": _utc_now(),
        "notes": "Text report stored in API scan summary; use /api/scans/{id}/raw for full module output.",
    },
}


def _run_modules(
    mode: str,
    target: str,
    module_names: tuple[str, ...],
    allow_private_targets: bool,
    *,
    event_cb: Callable[[dict], None] | None = None,
) -> dict:
    started_perf = time.perf_counter()
    started_at = _utc_now()

    normalized_target = normalize_target(target)
    validate_target(normalized_target)
    resolved_ips = enforce_target_policy(normalized_target, allow_private_targets=allow_private_targets)

    context = {
        "target": normalized_target,
        "resolved_ips": resolved_ips,
        "module_results": {},
        "event_cb": event_cb,
    }

    modules: dict[str, dict] = {}
    total_modules = max(len(module_names), 1)
    progress_map: dict[str, int] = {}
    if mode == "passive":
        progress_map = PASSIVE_PROGRESS
    elif mode == "active":
        progress_map = ACTIVE_PROGRESS
    elif mode == "full":
        progress_map = FULL_PROGRESS

    last_progress = 0
    for idx, module_name in enumerate(module_names, start=1):
        module_handler = MODULE_HANDLERS.get(module_name)
        if module_handler is None:
            logger.error("[SCAN] Module not registered: %s", module_name)
            modules[module_name] = {"status": "failed", "error": "Module handler not registered"}
            context["module_results"] = modules
            continue

        module_target_progress = int(progress_map.get(module_name, int((idx / total_modules) * 100)))
        module_target_progress = max(0, min(module_target_progress, 100))

        if event_cb is not None:
            event_cb(
                {
                    "type": "module_started",
                    "timestamp": _utc_now(),
                    "mode": mode,
                    "target": normalized_target,
                    "module": module_name,
                    "stage": MODULE_STAGE.get(module_name, module_name),
                    "index": idx,
                    "total": total_modules,
                    "progress": last_progress,
                }
            )

        logger.info("[SCAN] Running module: %s", module_name)
        modules[module_name] = {"status": "running"}
        try:
            module_result = module_handler(context)
            modules[module_name] = {"status": "completed", "data": module_result}
            if event_cb is not None:
                event_cb(
                    {
                        "type": "module_completed",
                        "timestamp": _utc_now(),
                        "mode": mode,
                        "target": normalized_target,
                        "module": module_name,
                        "stage": MODULE_STAGE.get(module_name, module_name),
                        "index": idx,
                        "total": total_modules,
                        "progress": module_target_progress,
                    }
                )
            last_progress = max(last_progress, module_target_progress)
        except Exception as exc:
            logger.error("[SCAN] Module failed: %s | %s", module_name, str(exc), exc_info=True)
            modules[module_name] = {"status": "failed", "error": str(exc)}
            if event_cb is not None:
                event_cb(
                    {
                        "type": "module_failed",
                        "timestamp": _utc_now(),
                        "mode": mode,
                        "target": normalized_target,
                        "module": module_name,
                        "stage": MODULE_STAGE.get(module_name, module_name),
                        "index": idx,
                        "total": total_modules,
                        "progress": module_target_progress,
                        "error": str(exc),
                    }
                )
            last_progress = max(last_progress, module_target_progress)
        finally:
            context["module_results"] = modules

    completed_at = _utc_now()
    duration_ms = int((time.perf_counter() - started_perf) * 1000)

    dns_data = _module_data(context, "dns_enum")
    port_scan_data = _module_data(context, "port_scan")

    return {
        "meta": {
            "target": normalized_target,
            "mode": mode,
            "requested_mode": mode,
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_ms": duration_ms,
        },
        "modules": modules,
        "target": normalized_target,
        "scan_mode": mode,
        "requested_mode": mode,
        # Backward compatibility for existing frontend pages.
        "resolved_ips": dns_data.get("resolved_ips", resolved_ips),
        "port_scan": port_scan_data if port_scan_data else {"open_ports": [], "closed_ports": []},
    }


def run_passive_scan(target: str, allow_private_targets: bool = False, *, event_cb: Callable[[dict], None] | None = None) -> dict:
    return _run_modules(
        mode="passive",
        target=target,
        module_names=PASSIVE_MODULES,
        allow_private_targets=allow_private_targets,
        event_cb=event_cb,
    )


def run_active_scan(target: str, allow_private_targets: bool = False, *, event_cb: Callable[[dict], None] | None = None) -> dict:
    return _run_modules(
        mode="active",
        target=target,
        module_names=ACTIVE_MODULES,
        allow_private_targets=allow_private_targets,
        event_cb=event_cb,
    )


def run_full_scan(target: str, allow_private_targets: bool = False, *, event_cb: Callable[[dict], None] | None = None) -> dict:
    return _run_modules(
        mode="full",
        target=target,
        module_names=FULL_MODULES,
        allow_private_targets=allow_private_targets,
        event_cb=event_cb,
    )


def _get_module_entry(results: dict[str, Any], module_name: str) -> dict[str, Any]:
    modules = results.get("modules") if isinstance(results, dict) else {}
    if not isinstance(modules, dict):
        return {}
    entry = modules.get(module_name)
    return entry if isinstance(entry, dict) else {}


def _get_module_data(results: dict[str, Any], module_name: str) -> dict[str, Any]:
    entry = _get_module_entry(results, module_name)
    if entry.get("status") != "completed":
        return {}
    data = entry.get("data")
    return data if isinstance(data, dict) else {}


def _finding_id(*, scan_id: int, title: str, asset_name: str) -> str:
    raw = f"{scan_id}:{asset_name}:{title}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:24]


def _severity_normalize(value: str) -> str:
    lowered = (value or "").strip().lower()
    if lowered in {"critical", "high", "medium", "low", "info", "informational"}:
        if lowered == "informational":
            return "info"
        return lowered
    return "low"


def generate_findings(*, scan_id: int, target: str, results: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert rich module outputs into database-ready findings payloads."""
    target = (target or "").strip().lower().rstrip(".")
    findings: list[dict[str, Any]] = []

    def add_finding(
        *,
        severity: str,
        title: str,
        description: str,
        asset_name: str | None = None,
        asset_type: str = "domain",
        category: str = "reconnaissance",
        status: str = "open",
    ):
        asset_value = (asset_name or target).strip() if (asset_name or target) else target
        finding = {
            "id": _finding_id(scan_id=scan_id, title=title, asset_name=asset_value),
            "severity": _severity_normalize(severity),
            "title": title[:255],
            "description": description,
            "asset": {"name": asset_value, "type": asset_type},
            "category": category,
            "status": status,
        }
        findings.append(finding)

    # subdomain_enum
    sub_data = _get_module_data(results, "subdomain_enum")
    subs = sub_data.get("subdomains") if isinstance(sub_data, dict) else []
    if isinstance(subs, list):
        for item in subs[:200]:
            if not isinstance(item, dict) or not item.get("hostname"):
                continue
            hostname = str(item["hostname"]).strip().lower().rstrip(".")
            resolved = item.get("resolved_ips") if isinstance(item.get("resolved_ips"), list) else []
            add_finding(
                severity="low",
                title=f"Subdomain discovered: {hostname}",
                description=f"Discovered subdomain {hostname}. Resolved IPs: {', '.join(map(str, resolved))}" if resolved else f"Discovered subdomain {hostname}.",
                asset_name=hostname,
                category="reconnaissance",
            )

    # dns_enum
    dns_data = _get_module_data(results, "dns_enum")
    if isinstance(dns_data, dict):
        ips = dns_data.get("resolved_ips") if isinstance(dns_data.get("resolved_ips"), list) else []
        if ips:
            add_finding(
                severity="low",
                title="DNS resolution successful",
                description=f"Target resolves to: {', '.join(map(str, ips[:10]))}{' (truncated)' if len(ips) > 10 else ''}",
                category="reconnaissance",
            )

        records = dns_data.get("dns_records") if isinstance(dns_data.get("dns_records"), dict) else {}
        for record_type in ("MX", "NS", "TXT", "CNAME"):
            values = records.get(record_type) if isinstance(records.get(record_type), list) else []
            if not values:
                continue
            add_finding(
                severity="low",
                title=f"DNS {record_type} record found",
                description=f"{record_type} records: {', '.join(map(str, values[:15]))}{' (truncated)' if len(values) > 15 else ''}",
                category="reconnaissance",
            )

    # port_scan
    port_data = _get_module_data(results, "port_scan")
    open_ports = port_data.get("open_ports") if isinstance(port_data.get("open_ports"), list) else []
    open_ports_int: list[int] = []
    for port in open_ports:
        try:
            open_ports_int.append(int(port))
        except (TypeError, ValueError):
            continue
    open_ports_int = sorted(set(open_ports_int))
    if open_ports_int:
        add_finding(
            severity="medium",
            title=f"Open ports detected: {', '.join(map(str, open_ports_int[:30]))}{'…' if len(open_ports_int) > 30 else ''}",
            description=f"Open ports detected on {target}: {', '.join(map(str, open_ports_int))}.",
            category="exposure",
        )

        sensitive = {21, 22, 25, 445, 3306, 3389}
        for port in open_ports_int:
            if port not in sensitive:
                continue
            service = SERVICE_MAP.get(int(port), "unknown")
            add_finding(
                severity="high",
                title=f"Sensitive service exposed: {service} ({port})",
                description=f"Port {port} ({service}) is open and may expose a sensitive service.",
                category="exposure",
            )

    # http_probe
    http_data = _get_module_data(results, "http_probe")
    if isinstance(http_data, dict) and http_data.get("url"):
        url = str(http_data.get("url") or "")
        status_code = http_data.get("status_code")
        server_banner = http_data.get("server_banner") or (http_data.get("headers") or {}).get("Server")
        add_finding(
            severity="low",
            title="HTTP service detected",
            description=f"HTTP probe succeeded: {url} (status={status_code}). Server: {server_banner or 'unknown'}.",
            category="reconnaissance",
            asset_name=target,
        )
        redirects = http_data.get("redirects") if isinstance(http_data.get("redirects"), list) else []
        if redirects and len(redirects) > 1:
            add_finding(
                severity="low",
                title="HTTP redirects observed",
                description=f"Redirect chain: {' -> '.join(map(str, redirects[:10]))}{' (truncated)' if len(redirects) > 10 else ''}",
                category="reconnaissance",
            )

    # ssl_check
    ssl_data = _get_module_data(results, "ssl_check")
    if isinstance(ssl_data, dict) and ssl_data.get("tls_version"):
        tls_version = str(ssl_data.get("tls_version") or "")
        cipher = ssl_data.get("cipher")
        add_finding(
            severity="low",
            title=f"TLS detected: {tls_version}",
            description=f"TLS handshake succeeded. Version: {tls_version}. Cipher: {cipher or 'unknown'}.",
            category="reconnaissance",
        )
        if tls_version.lower() in {"tlsv1", "tlsv1.0", "tlsv1.1"}:
            add_finding(
                severity="high",
                title="Weak TLS version supported",
                description=f"Server negotiated {tls_version}, which is considered weak. Prefer TLSv1.2+.",
                category="security_misconfiguration",
            )

    # headers_analysis
    headers_data = _get_module_data(results, "headers_analysis")
    if isinstance(headers_data, dict):
        missing = headers_data.get("missing_headers") if isinstance(headers_data.get("missing_headers"), list) else []
        for header in missing[:50]:
            header_name = str(header)
            severity = REQUIRED_SECURITY_HEADERS.get(header_name, "low")
            add_finding(
                severity=severity,
                title=f"Missing security header: {header_name}",
                description=f"The response is missing recommended security header: {header_name}.",
                category="security_misconfiguration",
            )

    # technology_fingerprint
    tech_data = _get_module_data(results, "technology_fingerprint")
    if isinstance(tech_data, dict):
        frameworks = tech_data.get("framework") if isinstance(tech_data.get("framework"), list) else []
        for fw in frameworks[:50]:
            name = str(fw)
            if not name:
                continue
            add_finding(
                severity="low",
                title=f"Technology detected: {name}",
                description=f"Detected technology/framework: {name}.",
                category="reconnaissance",
            )
        for key, label in (("server", "Server banner"), ("cdn", "CDN"), ("reverse_proxy", "Reverse proxy"), ("waf", "WAF")):
            value = tech_data.get(key)
            if not value:
                continue
            add_finding(
                severity="low",
                title=f"{label} detected: {value}",
                description=f"Detected {label.lower()}: {value}.",
                category="reconnaissance",
            )

    # hosting_detection
    host_data = _get_module_data(results, "hosting_detection")
    if isinstance(host_data, dict):
        hosting_provider = host_data.get("hosting_provider")
        cdn_provider = host_data.get("cdn_provider")
        cloud_provider = host_data.get("cloud_provider")
        for label, value in (
            ("Hosting provider", hosting_provider),
            ("CDN provider", cdn_provider),
            ("Cloud provider", cloud_provider),
        ):
            if not value:
                continue
            add_finding(
                severity="low",
                title=f"{label} detected: {value}",
                description=f"{label} detected: {value}.",
                category="reconnaissance",
            )

    # url_discovery
    url_data = _get_module_data(results, "url_discovery")
    urls = url_data.get("urls") if isinstance(url_data.get("urls"), list) else []
    if isinstance(urls, list) and urls:
        add_finding(
            severity="low",
            title=f"URLs discovered ({len(urls)})",
            description=f"Discovered historical/archived URLs for {target}. Sample: {', '.join(map(str, urls[:10]))}{' (truncated)' if len(urls) > 10 else ''}",
            category="reconnaissance",
        )

        interesting = [u for u in urls if isinstance(u, str) and any(token in u.lower() for token in ("/admin", "/login", "/signin", "/api", "/graphql"))]
        for u in interesting[:25]:
            add_finding(
                severity="medium",
                title="Interesting URL discovered",
                description=f"Discovered potentially sensitive URL: {u}",
                category="reconnaissance",
            )

    # WHOIS / OSINT (support both legacy results["osint"]["whois"] and module output)
    whois_data = _get_module_data(results, "whois")
    if not whois_data and isinstance(results.get("osint"), dict):
        legacy_whois = results["osint"].get("whois")
        whois_data = legacy_whois if isinstance(legacy_whois, dict) else {}

    parsed = whois_data.get("parsed") if isinstance(whois_data.get("parsed"), dict) else whois_data
    if isinstance(parsed, dict) and parsed:
        registrar = parsed.get("registrar") or parsed.get("registrant_org") or parsed.get("registrant") or None
        if registrar:
            add_finding(
                severity="low",
                title="Domain registrar detected",
                description=f"Domain registrar: {registrar}",
                category="osint",
            )

        events = parsed.get("events") if isinstance(parsed.get("events"), dict) else {}
        creation_date = parsed.get("creation_date") or parsed.get("created_on") or parsed.get("created") or None
        if not creation_date and isinstance(events, dict) and events:
            creation_date = events.get("registration") or events.get("registered") or events.get("created") or None
        if isinstance(creation_date, (list, tuple)) and creation_date:
            creation_date = creation_date[0]
        if creation_date:
            add_finding(
                severity="low",
                title="Domain creation date",
                description=f"Domain created on: {creation_date}",
                category="osint",
            )

        expiration_date = parsed.get("expiration_date") or parsed.get("expires_on") or parsed.get("expires") or None
        if not expiration_date and isinstance(events, dict) and events:
            expiration_date = events.get("expiration") or events.get("expiry") or events.get("expires") or None
        if isinstance(expiration_date, (list, tuple)) and expiration_date:
            expiration_date = expiration_date[0]
        if expiration_date:
            add_finding(
                severity="low",
                title="Domain expiration date",
                description=f"Domain expires on: {expiration_date}",
                category="osint",
            )

        name_servers = parsed.get("name_servers") or parsed.get("nameservers") or parsed.get("nameServers") or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        if isinstance(name_servers, list) and name_servers:
            normalized = [str(ns).strip().lower().rstrip(".") for ns in name_servers if str(ns).strip()]
            if normalized:
                add_finding(
                    severity="low",
                    title="Name servers discovered",
                    description=f"Name servers: {', '.join(normalized[:25])}{' (truncated)' if len(normalized) > 25 else ''}",
                    category="osint",
                )

    # Risk scoring (support both legacy results["risk_scoring"] and module output)
    risk_data = _get_module_data(results, "risk_scoring")
    if not risk_data:
        legacy_risk = results.get("risk_scoring")
        risk_data = legacy_risk if isinstance(legacy_risk, dict) else {}

    if isinstance(risk_data, dict) and risk_data:
        score_value = risk_data.get("attack_surface_score")
        if score_value is not None:
            add_finding(
                severity="info",
                title="Attack surface score calculated",
                description=f"Attack surface score: {score_value}",
                category="risk_analysis",
            )

        overall = str(risk_data.get("overall_risk") or "").strip()
        if overall:
            overall_lc = overall.lower()
            severity = "medium"
            if overall_lc == "high":
                severity = "high"

            add_finding(
                severity=severity,
                title="Overall risk rating",
                description=f"Overall risk rating: {overall}",
                category="risk_analysis",
            )

        key_findings = risk_data.get("key_findings")
        if isinstance(key_findings, list):
            for item in key_findings[:25]:
                text = str(item).strip()
                if not text:
                    continue
                add_finding(
                    severity="low",
                    title=f"Risk insight: {text[:120]}",
                    description=text,
                    category="risk_analysis",
                )

    # Deduplicate by id while preserving order.
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for finding in findings:
        fid = str(finding.get("id") or "")
        if not fid or fid in seen:
            continue
        seen.add(fid)
        unique.append(finding)
    return unique
