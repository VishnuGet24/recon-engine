"""HTTP security header scanner."""

import certifi
import requests
from requests.exceptions import SSLError, Timeout

from scanners.exceptions import ModuleTimeoutError


def scan_security_headers(url):
    """Scan for common web security headers."""
    results = {}

    try:
        if not url.startswith("http"):
            url = f"https://{url}"

        try:
            response = requests.get(url, timeout=10, verify=certifi.where())
        except SSLError:
            response = requests.get(url, timeout=10, verify=False)

        headers = response.headers
        security_headers = {
            "X-Frame-Options": {
                "issue": "Missing protection against clickjacking",
                "severity": "Medium",
            },
            "Content-Security-Policy": {
                "issue": "Missing protection against XSS",
                "severity": "High",
            },
            "Strict-Transport-Security": {
                "issue": "Missing HTTPS enforcement",
                "severity": "High",
            },
            "X-Content-Type-Options": {
                "issue": "Missing MIME sniffing protection",
                "severity": "Medium",
            },
            "Referrer-Policy": {
                "issue": "Missing referrer policy",
                "severity": "Low",
            },
            "Permissions-Policy": {
                "issue": "Missing browser feature restrictions",
                "severity": "Low",
            },
        }

        for header, info in security_headers.items():
            if header in headers:
                results[header] = {"status": "Present", "value": headers[header]}
            else:
                results[header] = {
                    "status": "Missing",
                    "issue": info["issue"],
                    "severity": info["severity"],
                }

        severity_weights = {"High": 3, "Medium": 2, "Low": 1}
        score = 0
        missing_count = 0

        for _, data in results.items():
            if data.get("status") == "Missing":
                missing_count += 1
                score += severity_weights.get(data.get("severity"), 0)

        results["summary"] = {
            "total_missing": missing_count,
            "risk_score": score,
            "risk_level": "High" if score >= 8 else "Medium" if score >= 4 else "Low",
        }
        return results
    except Timeout as exc:
        raise ModuleTimeoutError(f"Header scan timed out for {url}") from exc
    except Exception as exc:
        return {"error": str(exc)}

