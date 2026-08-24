"""Professional CLI client for the recon backend using /api JWT authentication."""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests
from colorama import Fore, Style, just_fix_windows_console

try:
    from utils.report_generator import generate_pdf_report
except ImportError:
    generate_pdf_report = None


BASE_URL = os.getenv("RECON_API_URL", "http://127.0.0.1:5000").rstrip("/")
LOGIN_ENDPOINT = f"{BASE_URL}/api/auth/login"
SCANS_ENDPOINT = f"{BASE_URL}/api/scans"
REQUEST_TIMEOUT_SECONDS = 30
POLL_INTERVAL_SECONDS = 2

SCAN_MODES: Dict[str, Dict[str, str]] = {
    "1": {"mode": "passive", "scanType": "quick_scan", "name": "Passive (OSINT, subdomains, DNS, WHOIS)"},
    "2": {"mode": "active", "scanType": "custom_scan", "name": "Active (Port scan, HTTP probe, SSL check)"},
    "3": {"mode": "full", "scanType": "full_scan", "name": "Full (All reconnaissance and vulnerability modules)"},
}

SECTION_TITLES = {
    "subdomain_enum": "SUBDOMAIN ENUMERATION",
    "dns_enum": "DNS ENUMERATION",
    "whois": "WHOIS LOOKUP",
    "port_scan": "PORT SCAN & SERVICE DETECTION",
    "http_probe": "HTTP / HTTPS PROBING",
    "url_discovery": "URL & ENDPOINT DISCOVERY",
    "ssl_check": "SSL / TLS CERTIFICATE INSPECTION",
    "headers_analysis": "SECURITY HEADER ANALYSIS",
    "technology_fingerprint": "WEB TECHNOLOGY FINGERPRINTING",
    "hosting_detection": "HOSTING & CLOUD PROVIDER DETECTION",
    "vulnerability_surface": "VULNERABILITY ATTACK SURFACE",
    "risk_scoring": "RISK SCORING & SUMMARY",
}


def _color(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}"


def print_line(char: str = "=", width: int = 78, color: str = Fore.CYAN) -> None:
    print(_color(char * width, color))


def print_header(title: str) -> None:
    print()
    print_line("=")
    print(_color(title.upper(), Fore.CYAN))
    print_line("=")


def print_success(message: str) -> None:
    print(_color(message, Fore.GREEN))


def print_error(message: str) -> None:
    print(_color(message, Fore.RED))


def print_warning(message: str) -> None:
    print(_color(message, Fore.YELLOW))


def format_elapsed(seconds: float) -> str:
    total = int(seconds)
    minutes, secs = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def normalize_target(raw_target: str) -> str:
    cleaned = re.sub(r"^https?://", "", raw_target.strip(), flags=re.IGNORECASE)
    return cleaned.split("/")[0].strip()


def is_valid_target(target: str) -> bool:
    if not target:
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    domain_regex = r"^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
    return bool(re.match(domain_regex, target))


def prompt_target() -> str:
    while True:
        raw_target = input("Enter target domain or IP: ").strip()
        target = normalize_target(raw_target)
        if is_valid_target(target):
            return target
        print_error("Invalid target format. Example: example.com or 8.8.8.8")


def show_scan_mode_menu() -> None:
    print_header("Select Scan Mode")
    for key, info in SCAN_MODES.items():
        print(f"{key}. {info['name']}")
    print(_color("-" * 78, Fore.CYAN))


def prompt_scan_mode() -> Dict[str, str]:
    while True:
        show_scan_mode_menu()
        choice = input("Enter scan mode number (1, 2, or 3, default 1): ").strip() or "1"
        if choice in SCAN_MODES:
            selected = SCAN_MODES[choice]
            print_success(f"Selected scan mode: {selected['mode']} ({selected['scanType']})")
            return selected
        print_error("Invalid scan mode selection. Choose 1, 2, or 3.")


def parse_response_json(response: requests.Response) -> dict:
    try:
        return response.json()
    except ValueError:
        return {"error": f"Backend returned non-JSON response (HTTP {response.status_code}): {response.text[:200]}"}


def login(base_url: str, username: Optional[str] = None, password: Optional[str] = None) -> str:
    """Authenticate with the backend via POST /api/auth/login and return the JWT access token."""
    login_url = f"{base_url}/api/auth/login"

    identity = username or os.getenv("RECON_USER") or os.getenv("RECON_USERNAME") or os.getenv("RECON_EMAIL")
    secret = password or os.getenv("RECON_PASSWORD")

    if not identity:
        identity = input("Enter username or email: ").strip()
    if not secret:
        secret = getpass.getpass("Enter password: ")

    payload = {"email": identity, "password": secret}

    try:
        response = requests.post(
            login_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to connect to authentication server ({login_url}): {exc}") from exc

    data = parse_response_json(response)
    if response.status_code >= 400:
        error_msg = data.get("message") or data.get("error") or f"HTTP {response.status_code}"
        raise RuntimeError(f"Authentication failed: {error_msg}")

    tokens = data.get("tokens", {})
    access_token = tokens.get("accessToken") if isinstance(tokens, dict) else None
    if not access_token:
        access_token = data.get("accessToken") or data.get("token")

    if not access_token:
        raise RuntimeError("Authentication succeeded but no access token was returned.")

    print_success(f"[OK] Authenticated successfully as '{identity}'.")
    return access_token


def start_scan(base_url: str, token: str, target: str, scan_info: Dict[str, str]) -> str:
    """Create a new scan via POST /api/scans with JWT Bearer token."""
    url = f"{base_url}/api/scans"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "targets": [target],
        "scanType": scan_info["scanType"],
        "schedule": {"type": "immediate"},
    }

    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to submit scan request to backend: {exc}") from exc

    data = parse_response_json(response)
    if response.status_code >= 400:
        error = data.get("message") or data.get("error") or f"HTTP {response.status_code}"
        raise RuntimeError(f"Scan request rejected: {error}")

    scan_id = str(data.get("scanId") or data.get("id") or data.get("scan_id") or "")
    if not scan_id:
        raise RuntimeError(f"Backend accepted scan but did not return scanId: {data}")

    print_header("Scan Started")
    print(f"Target      : {target}")
    print(f"Scan ID     : {scan_id}")
    print(f"Scan Mode   : {scan_info['mode']} ({scan_info['scanType']})")
    print(f"Status URL  : {base_url}/api/scans/{scan_id}")
    print_success("[OK] Scan job queued and running.")
    return scan_id


def poll_scan_status(base_url: str, token: str, scan_id: str, started_at: float) -> dict:
    """Poll GET /api/scans/<scan_id> until scan reaches a terminal state."""
    url = f"{base_url}/api/scans/{scan_id}"
    headers = {"Authorization": f"Bearer {token}"}
    spinner = ["|", "/", "-", "\\"]
    spinner_idx = 0
    last_status = None

    while True:
        try:
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
            data = parse_response_json(response)
        except requests.RequestException as exc:
            elapsed = format_elapsed(time.monotonic() - started_at)
            print_warning(
                f"\n[WARNING] Status check failed ({elapsed}): {exc}. "
                f"Retrying in {POLL_INTERVAL_SECONDS}s..."
            )
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        if response.status_code >= 400:
            error = data.get("message") or data.get("error") or f"HTTP {response.status_code}"
            raise RuntimeError(f"Status polling request failed: {error}")

        status = str(data.get("status", "unknown")).lower()
        progress = data.get("progress", 0)
        elapsed = format_elapsed(time.monotonic() - started_at)

        if status != last_status:
            color = Fore.CYAN
            if status in {"completed", "finished"}:
                color = Fore.GREEN
            elif status in {"failed", "error", "cancelled"}:
                color = Fore.RED
            print(_color(f"\n[STATUS] {status.upper()} ({progress}%) | ELAPSED {elapsed}", color))
            last_status = status
        else:
            indicator = spinner[spinner_idx % len(spinner)]
            spinner_idx += 1
            print(
                _color(
                    f"\r[{indicator}] Progress: {progress}% | Waiting for completion... ELAPSED {elapsed}",
                    Fore.CYAN,
                ),
                end="",
                flush=True,
            )

        if status in {"completed", "finished", "failed", "error", "cancelled"}:
            print()
            if status in {"failed", "error", "cancelled"}:
                print_error(f"[ERROR] Scan concluded with status: {status.upper()}")
            else:
                print_success("[OK] Scan finished successfully.")
            return data

        time.sleep(POLL_INTERVAL_SECONDS)


def pretty_json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def colored_risk(risk: str) -> str:
    normalized = str(risk or "").upper()
    if normalized in {"HIGH", "CRITICAL"}:
        return _color(normalized, Fore.RED)
    if normalized == "MEDIUM":
        return _color(normalized, Fore.YELLOW)
    if normalized in {"LOW", "INFO"}:
        return _color(normalized, Fore.GREEN)
    return normalized


def print_risk_highlights(result_payload: dict) -> None:
    raw = result_payload.get("raw", {}) if isinstance(result_payload.get("raw"), dict) else {}
    modules = raw.get("modules", {}) if isinstance(raw.get("modules"), dict) else {}
    risk_module = modules.get("risk_scoring", {})
    risk_data = risk_module.get("data", {}) if isinstance(risk_module.get("data"), dict) else {}

    score = risk_data.get("attack_surface_score")
    risk = risk_data.get("overall_risk")
    findings_summary = result_payload.get("findings", {})

    print_header("Risk Highlights")
    if score is not None or risk is not None:
        print(f"ATTACK SURFACE SCORE : {score if score is not None else 'N/A'}")
        print(f"OVERALL RISK LEVEL   : {colored_risk(str(risk))}")
    if isinstance(findings_summary, dict) and findings_summary:
        print(f"TOTAL FINDINGS       : {findings_summary.get('total', 0)}")
        print(f"  - Critical         : {_color(str(findings_summary.get('critical', 0)), Fore.RED)}")
        print(f"  - High             : {_color(str(findings_summary.get('high', 0)), Fore.RED)}")
        print(f"  - Medium           : {_color(str(findings_summary.get('medium', 0)), Fore.YELLOW)}")
        print(f"  - Low              : {_color(str(findings_summary.get('low', 0)), Fore.GREEN)}")


def print_scan_sections(result_payload: dict) -> None:
    raw = result_payload.get("raw", {}) if isinstance(result_payload.get("raw"), dict) else {}
    modules = raw.get("modules", {}) if isinstance(raw.get("modules"), dict) else {}

    if not modules:
        discovery = result_payload.get("discovery", {})
        if discovery:
            print_header("Discovered Assets")
            print(pretty_json(discovery))
        return

    for mod_name, mod_title in SECTION_TITLES.items():
        if mod_name not in modules:
            continue
        entry = modules[mod_name]
        if not isinstance(entry, dict):
            continue
        status = entry.get("status", "unknown")
        data = entry.get("data", {})
        print_header(f"{mod_title} [{status.upper()}]")
        if status == "completed" and data:
            print(pretty_json(data))
        elif entry.get("error"):
            print_error(f"Error: {entry.get('error')}")


def print_final_result(status_payload: dict, elapsed_seconds: float) -> None:
    status = str(status_payload.get("status", "unknown")).upper()
    print_header("Scan Result Summary")
    status_color = Fore.GREEN if status in {"COMPLETED", "FINISHED"} else Fore.RED
    print(f"FINAL STATUS : {_color(status, status_color)}")
    print(f"TARGET       : {status_payload.get('target', 'N/A')}")
    print(f"SCAN ID      : {status_payload.get('id', 'N/A')}")
    print(f"SCAN TYPE    : {status_payload.get('scanType', 'N/A')}")
    print(f"ELAPSED TIME : {format_elapsed(elapsed_seconds)}")

    print_risk_highlights(status_payload)
    print_scan_sections(status_payload)


def export_pdf_report(status_payload: dict, export_path: str) -> None:
    if generate_pdf_report is None:
        print_error("PDF export unavailable: reportlab is not installed. Install via `pip install reportlab`.")
        return

    if str(status_payload.get("status", "")).lower() in {"failed", "error", "cancelled"}:
        print_warning("Skipping PDF export because scan status is not completed.")
        return

    raw = status_payload.get("raw", {}) if isinstance(status_payload.get("raw"), dict) else {}
    modules = raw.get("modules", {}) if isinstance(raw.get("modules"), dict) else {}

    # Map raw module structure to the structure expected by generate_pdf_report
    risk_data = modules.get("risk_scoring", {}).get("data", {})
    report_data = {
        "target": status_payload.get("target"),
        "url": f"http://{status_payload.get('target')}",
        "selected_scan_types": list(modules.keys()),
        "executed_scan_types": [m for m, d in modules.items() if isinstance(d, dict) and d.get("status") == "completed"],
        "executive_summary": risk_data,
        "nmap": modules.get("port_scan", {}).get("data", {}),
        "ssl": modules.get("ssl_check", {}).get("data", {}),
        "osint": modules.get("whois", {}).get("data", {}),
        "subdomains": modules.get("subdomain_enum", {}).get("data", {}).get("subdomains", []),
        "headers": modules.get("headers_analysis", {}).get("data", {}),
        "technology": modules.get("technology_fingerprint", {}).get("data", {}),
        "hosting_provider": modules.get("hosting_detection", {}).get("data", {}).get("hosting_provider"),
        "cdn_provider": modules.get("hosting_detection", {}).get("data", {}).get("cdn_provider"),
        "waf_provider": modules.get("hosting_detection", {}).get("data", {}).get("waf_provider"),
    }

    report_payload = {
        "scan_datetime": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status": status_payload.get("status"),
        "data": report_data,
    }

    try:
        generate_pdf_report(report_payload, export_path)
        print_success(f"PDF report exported successfully: {export_path}")
    except Exception as exc:
        print_error(f"Failed to generate PDF report: {exc}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cyber Recon CLI Client (JWT Authenticated)")
    parser.add_argument("--url", default=BASE_URL, help=f"Backend API Base URL (default: {BASE_URL})")
    parser.add_argument("--username", "-u", help="Username or email for API login")
    parser.add_argument("--password", "-p", help="Password for API login")
    parser.add_argument("--target", "-t", help="Target domain or IP address")
    parser.add_argument(
        "--mode",
        "-m",
        choices=["1", "2", "3", "passive", "active", "full"],
        help="Scan mode: 1/passive, 2/active, 3/full",
    )
    parser.add_argument("--export", metavar="FILE", help="Export final scan result to PDF (e.g., --export report.pdf)")
    return parser.parse_args()


def main() -> int:
    just_fix_windows_console()
    args = parse_args()
    base_url = args.url.rstrip("/")

    print_header("Cyber Recon CLI")
    print(f"Backend API : {base_url}")
    if args.export:
        print(f"PDF Export  : {args.export}")

    try:
        token = login(base_url=base_url, username=args.username, password=args.password)

        if args.target and is_valid_target(normalize_target(args.target)):
            target = normalize_target(args.target)
        else:
            target = prompt_target()

        if args.mode:
            mode_map = {"passive": "1", "active": "2", "full": "3"}
            mode_key = mode_map.get(args.mode, args.mode)
            scan_info = SCAN_MODES.get(mode_key, SCAN_MODES["1"])
        else:
            scan_info = prompt_scan_mode()

        started_at = time.monotonic()
        scan_id = start_scan(base_url, token, target, scan_info)
        status_payload = poll_scan_status(base_url, token, scan_id, started_at)
        elapsed = time.monotonic() - started_at

        print_final_result(status_payload, elapsed)

        if args.export:
            export_pdf_report(status_payload, args.export)

        return 0

    except KeyboardInterrupt:
        print_error("\nOperation interrupted by user.")
        return 130
    except RuntimeError as exc:
        print_header("Client Error")
        print_error(str(exc))
        return 1
    except Exception as exc:
        print_header("Unexpected Error")
        print_error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
