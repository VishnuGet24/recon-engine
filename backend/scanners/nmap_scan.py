import nmap
import re

from scanners.exceptions import ModuleTimeoutError
from scanners.vulners_api import fetch_cve_details


def run_nmap_scan(target, timeout_seconds=120):
    """Run an nmap service/vulnerability scan with a hard timeout."""
    scanner = nmap.PortScanner()
    nmap_arguments = (
        f"-sV --script vulners --top-ports 50 "
        f"--host-timeout {int(timeout_seconds)}s --script-timeout 30s"
    )

    try:
        scanner.scan(target, arguments=nmap_arguments, timeout=int(timeout_seconds))
    except nmap.PortScannerTimeout as exc:
        raise ModuleTimeoutError(f"Nmap scan timed out for {target}") from exc
    except Exception as exc:
        if "timed out" in str(exc).lower():
            raise ModuleTimeoutError(f"Nmap scan timed out for {target}") from exc
        raise

    results = {
        "target": target,
        "ports": [],
        "summary": {
            "total_ports": 0,
            "open_ports": 0,
            "total_cves": 0,
            "total_services": 0,
            "highest_cvss": 0.0,
            "risk_level": "Low"
        }
    }

    cve_pattern = re.compile(r"CVE-\d{4}-\d+")
    all_cves = set()
    cve_cache = {}

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            results["summary"]["total_ports"] += len(ports)

            for port in ports:
                port_data = scanner[host][proto][port]

                if port_data["state"] != "open":
                    continue

                results["summary"]["open_ports"] += 1

                service_info = {
                    "port": port,
                    "protocol": proto,
                    "service": port_data.get("name"),
                    "product": port_data.get("product"),
                    "version": port_data.get("version"),
                    "vulnerabilities": []
                }

                # Extract CVEs from script output
                if "script" in port_data:
                    service_cves = set()
                    for script_output in port_data["script"].values():
                        found_cves = cve_pattern.findall(script_output)
                        service_cves.update(found_cves)
                        all_cves.update(found_cves)

                    for cve in sorted(service_cves):
                        if cve not in cve_cache:
                            try:
                                details = fetch_cve_details(cve) or {}
                            except Exception:
                                details = {}

                            raw_cvss = details.get("cvss", 0)
                            try:
                                cvss_score = float(raw_cvss)
                            except (TypeError, ValueError):
                                cvss_score = 0.0

                            cve_cache[cve] = {
                                "cvss_score": cvss_score,
                                "severity": details.get("severity", "Unknown"),
                                "title": details.get("title", ""),
                                "exploit_available": bool(details.get("exploit_available", False))
                            }

                        cached = cve_cache[cve]
                        service_info["vulnerabilities"].append({
                            "cve_id": cve,
                            "cvss_score": cached["cvss_score"],
                            "severity": cached["severity"],
                            "title": cached["title"],
                            "exploit_available": cached["exploit_available"]
                        })

                results["ports"].append(service_info)

    results["summary"]["total_cves"] = len(all_cves)
    results["summary"]["total_services"] = len(results["ports"])

    highest_cvss = 0.0
    for service in results["ports"]:
        for vuln in service.get("vulnerabilities", []):
            cvss = vuln.get("cvss_score", 0.0)
            if isinstance(cvss, (int, float)) and cvss > highest_cvss:
                highest_cvss = float(cvss)

    results["summary"]["highest_cvss"] = highest_cvss

    if highest_cvss >= 9.0:
        results["summary"]["risk_level"] = "Critical"
    elif highest_cvss >= 7.0:
        results["summary"]["risk_level"] = "High"
    elif highest_cvss >= 4.0:
        results["summary"]["risk_level"] = "Medium"
    else:
        results["summary"]["risk_level"] = "Low"

    return results
