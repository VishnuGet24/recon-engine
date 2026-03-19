"""Professional CLI client for the recon backend."""

import argparse
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime
from typing import Dict, List

import requests
from colorama import Fore, Style, just_fix_windows_console

from utils.report_generator import generate_pdf_report


BASE_URL = os.getenv("RECON_API_URL", "http://127.0.0.1:5000").rstrip("/")
SCAN_ENDPOINT = f"{BASE_URL}/scan"
STATUS_ENDPOINT = f"{BASE_URL}/status"
REQUEST_TIMEOUT_SECONDS = 30
POLL_INTERVAL_SECONDS = 2

MENU_OPTIONS: Dict[str, str] = {
    "1": "service_detection",
    "2": "ssl",
    "3": "osint",
    "4": "subdomain",
    "5": "headers",
    "6": "technology",
    "7": "waf_detection",
    "8": "hosting",
    "9": "scoring",
    "10": "full",
}

SCAN_MODE_OPTIONS: Dict[str, str] = {
    "1": "passive",
    "2": "active",
    "3": "full",
}

SECTION_TITLES = {
    "nmap": "SERVICE DETECTION",
    "ssl": "SSL/TLS INSPECTION",
    "osint": "DOMAIN OSINT INTELLIGENCE",
    "subdomains": "SUBDOMAIN ENUMERATION",
    "headers": "SECURITY HEADER ANALYSIS",
    "technology": "WEB TECHNOLOGY FINGERPRINTING",
    "waf_detection": "CDN & WAF DETECTION",
    "hosting_provider": "HOSTING PROVIDER IDENTIFICATION",
    "cdn_provider": "CDN PROVIDER",
    "waf_provider": "WAF PROVIDER",
    "executive_summary": "ATTACK SURFACE RISK SCORING",
    "scan_errors": "SCAN ERRORS",
}

SECTION_ORDER = [
    "nmap",
    "ssl",
    "osint",
    "subdomains",
    "headers",
    "technology",
    "waf_detection",
    "hosting_provider",
    "cdn_provider",
    "waf_provider",
    "executive_summary",
    "scan_errors",
]


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


def show_menu() -> None:
    print_header("Select Scan Types")
    print("1. Service Detection")
    print("2. SSL/TLS Inspection")
    print("3. Domain OSINT Intelligence")
    print("4. Subdomain Enumeration")
    print("5. Security Header Analysis")
    print("6. Web Technology Fingerprinting")
    print("7. CDN & WAF Detection")
    print("8. Hosting Provider Identification")
    print("9. Attack Surface Risk Scoring")
    print("10. Run Full Scan")
    print(_color("-" * 78, Fore.CYAN))


def show_scan_mode_menu() -> None:
    print_header("Select Scan Mode")
    print("1. Passive (OSINT, subdomain, technology over HTTP only)")
    print("2. Active (includes Nmap, SSL, headers)")
    print("3. Full (all modules)")
    print(_color("-" * 78, Fore.CYAN))


def prompt_scan_mode() -> str:
    while True:
        show_scan_mode_menu()
        choice = input("Enter scan mode number (default 3): ").strip() or "3"
        if choice in SCAN_MODE_OPTIONS:
            mode = SCAN_MODE_OPTIONS[choice]
            print_success(f"Selected scan mode: {mode}")
            return mode
        print_error("Invalid scan mode selection. Choose 1, 2, or 3.")


def parse_selection(selection: str) -> List[str]:
    tokens = [token.strip() for token in selection.split(",") if token.strip()]
    if not tokens:
        raise ValueError("No selection provided.")

    invalid = [token for token in tokens if token not in MENU_OPTIONS]
    if invalid:
        raise ValueError(f"Invalid option(s): {', '.join(invalid)}")

    if "10" in tokens:
        return ["full"]

    selected: List[str] = []
    for token in tokens:
        scan_key = MENU_OPTIONS[token]
        if scan_key not in selected:
            selected.append(scan_key)
    return selected


def prompt_scan_selection() -> List[str]:
    while True:
        show_menu()
        choice = input("Enter numbers separated by comma (e.g., 1,3,5): ").strip()
        try:
            selected = parse_selection(choice)
            print_success(f"Selected scans: {', '.join(selected)}")
            return selected
        except ValueError as exc:
            print_error(f"Selection error: {exc}")


def parse_response_json(response: requests.Response) -> dict:
    try:
        return response.json()
    except ValueError:
        return {"error": "Backend returned non-JSON response."}


def start_scan(target: str, selected_scans: List[str], scan_mode: str) -> str:
    payload = {"target": target, "scans": selected_scans, "scan_mode": scan_mode}
    try:
        response = requests.post(
            SCAN_ENDPOINT, json=payload, timeout=REQUEST_TIMEOUT_SECONDS
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to connect to backend: {exc}") from exc

    data = parse_response_json(response)
    if response.status_code >= 400:
        error = data.get("error", f"HTTP {response.status_code}")
        raise RuntimeError(f"Scan request rejected: {error}")

    scan_id = data.get("scan_id")
    if not scan_id:
        raise RuntimeError("Backend did not return scan_id.")
    server_selected = data.get("selected_scan_types", selected_scans)
    skipped_scan_types = data.get("skipped_scan_types", [])

    print_header("Scan Started")
    print(f"Target      : {target}")
    print(f"Scan ID     : {scan_id}")
    print(f"Scan Mode   : {scan_mode}")
    print(f"Selected    : {', '.join(server_selected)}")
    if skipped_scan_types:
        print_warning(f"Skipped     : {', '.join(skipped_scan_types)} (not allowed in mode)")
    print(f"Status URL  : {STATUS_ENDPOINT}/{scan_id}")
    print_success("[OK] Scan request accepted.")
    return scan_id


def poll_scan_status(scan_id: str, started_at: float) -> dict:
    url = f"{STATUS_ENDPOINT}/{scan_id}"
    spinner = ["|", "/", "-", "\\"]
    spinner_idx = 0
    last_status = None

    while True:
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
            data = parse_response_json(response)
        except requests.RequestException as exc:
            elapsed = format_elapsed(time.monotonic() - started_at)
            print_warning(
                f"[WARNING] Status check failed ({elapsed}): {exc}. "
                f"Retrying in {POLL_INTERVAL_SECONDS}s..."
            )
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        if response.status_code >= 400:
            error = data.get("error", f"HTTP {response.status_code}")
            raise RuntimeError(f"Status request failed: {error}")

        status = str(data.get("status", "unknown")).lower()
        elapsed = format_elapsed(time.monotonic() - started_at)

        if status != last_status:
            color = Fore.CYAN
            if status in {"completed", "completed_with_errors"}:
                color = Fore.GREEN
            elif status == "error":
                color = Fore.RED
            print(_color(f"[STATUS] {status.upper()} | ELAPSED {elapsed}", color))
            last_status = status
        else:
            indicator = spinner[spinner_idx % len(spinner)]
            spinner_idx += 1
            print(
                _color(
                    f"\r[{indicator}] Waiting for completion... ELAPSED {elapsed}",
                    Fore.CYAN,
                ),
                end="",
                flush=True,
            )

        if status in {"completed", "completed_with_errors", "error"}:
            print()
            if status == "error":
                print_error("[ERROR] Scan failed.")
            else:
                print_success("[OK] Scan finished.")
            return data

        time.sleep(POLL_INTERVAL_SECONDS)


def pretty_json(data) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def colored_risk(risk: str) -> str:
    normalized = str(risk or "").upper()
    if normalized in {"HIGH", "CRITICAL"}:
        return _color(normalized, Fore.RED)
    if normalized == "MEDIUM":
        return _color(normalized, Fore.YELLOW)
    if normalized == "LOW":
        return _color(normalized, Fore.GREEN)
    return normalized


def print_risk_highlights(result_data: dict) -> None:
    summary = result_data.get("executive_summary", {})
    if not isinstance(summary, dict):
        return

    score = summary.get("attack_surface_score")
    risk = summary.get("overall_risk")
    if score is None and risk is None:
        return

    print_header("Risk Highlights")
    score_text = str(score) if score is not None else "N/A"
    print(f"ATTACK SURFACE SCORE : {score_text}")
    print(f"OVERALL RISK LEVEL   : {colored_risk(str(risk))}")


def print_scan_sections(result_data: dict) -> None:
    for key in SECTION_ORDER:
        if key not in result_data:
            continue
        title = SECTION_TITLES.get(key, key.replace("_", " ").upper())
        print_header(title)
        print(pretty_json(result_data[key]))


def print_final_result(status_payload: dict, elapsed_seconds: float) -> None:
    status = str(status_payload.get("status", "unknown")).upper()
    print_header("Scan Result Summary")
    status_color = Fore.GREEN if status in {"COMPLETED", "COMPLETED_WITH_ERRORS"} else Fore.RED
    print(f"FINAL STATUS : {_color(status, status_color)}")
    print(f"ELAPSED TIME : {format_elapsed(elapsed_seconds)}")

    if status == "ERROR":
        print_header("Scan Failed")
        print(pretty_json(status_payload))
        return

    result_data = status_payload.get("data", {})
    if not isinstance(result_data, dict):
        print_header("Unexpected Response")
        print(pretty_json(status_payload))
        return

    print_header("Scan Metadata")
    metadata = {
        "target": result_data.get("target"),
        "url": result_data.get("url"),
        "scan_mode": result_data.get("scan_mode"),
        "selected_scan_types": result_data.get("selected_scan_types"),
        "executed_scan_types": result_data.get("executed_scan_types"),
    }
    print(pretty_json(metadata))

    print_risk_highlights(result_data)
    print_scan_sections(result_data)

    print_header("Raw Response JSON")
    print(pretty_json(status_payload))


def export_pdf_report(status_payload: dict, export_path: str) -> None:
    if str(status_payload.get("status", "")).lower() == "error":
        print_warning("Skipping PDF export because scan status is ERROR.")
        return

    result_data = status_payload.get("data", {})
    if not isinstance(result_data, dict):
        raise RuntimeError("Cannot export report: invalid scan result payload.")

    report_payload = {
        "scan_datetime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status": status_payload.get("status"),
        "data": result_data,
    }
    generate_pdf_report(report_payload, export_path)
    print_success(f"PDF report exported: {export_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cyber Recon CLI client")
    parser.add_argument(
        "--export",
        metavar="FILE",
        help="Export final scan result to PDF (e.g., --export report.pdf)",
    )
    return parser.parse_args()


def main() -> int:
    just_fix_windows_console()
    args = parse_args()

    print_header("Cyber Recon CLI")
    print(f"Backend API: {BASE_URL}")
    if args.export:
        print(f"PDF Export  : {args.export}")

    try:
        target = prompt_target()
        scan_mode = prompt_scan_mode()
        selected_scans = prompt_scan_selection()
        started_at = time.monotonic()
        scan_id = start_scan(target, selected_scans, scan_mode)
        status_payload = poll_scan_status(scan_id, started_at)
        elapsed = time.monotonic() - started_at
        print_final_result(status_payload, elapsed)

        if args.export:
            export_pdf_report(status_payload, args.export)
        return 0
    except KeyboardInterrupt:
        print_error("Operation interrupted by user.")
        return 130
    except RuntimeError as exc:
        print_header("Client Error")
        print_error(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
