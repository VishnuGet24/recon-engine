import requests
from requests.exceptions import Timeout

from scanners.exceptions import ModuleTimeoutError


def fingerprint_technology(url, http_only=False):
    """Identify web technologies and edge protections from HTTP responses."""
    tech = {
        "server": None,
        "reverse_proxy": None,
        "cdn": None,
        "waf": None,
        "framework_detection": {},
    }

    try:
        request_url = url
        if http_only and request_url.startswith("https://"):
            request_url = f"http://{request_url[len('https://') :]}"

        response = requests.get(request_url, timeout=10)
        headers = response.headers
        html = response.text.lower()

        # Server
        server = headers.get("Server", "")
        tech["server"] = server

        if "nginx" in server.lower():
            tech["reverse_proxy"] = "Nginx"

        if "apache" in server.lower():
            tech["reverse_proxy"] = "Apache"

        if "cloudflare" in server.lower():
            tech["cdn"] = "Cloudflare"
            tech["waf"] = "Cloudflare WAF"

        # WordPress
        evidence = []
        if "wp-content" in html:
            evidence.append("wp-content found in HTML")
        if "x-pingback" in headers:
            evidence.append("x-pingback header detected")

        if evidence:
            tech["framework_detection"]["WordPress"] = {
                "confidence": "High",
                "evidence": evidence
            }

        # React
        if "data-reactroot" in html:
            tech["framework_detection"]["React"] = {
                "confidence": "Medium",
                "evidence": ["data-reactroot found"]
            }

        # Laravel
        if "laravel_session" in response.cookies:
            tech["framework_detection"]["Laravel"] = {
                "confidence": "High",
                "evidence": ["laravel_session cookie detected"]
            }

        # ASP.NET
        if "asp.net" in headers.get("X-Powered-By", "").lower():
            tech["framework_detection"]["ASP.NET"] = {
                "confidence": "High",
                "evidence": ["X-Powered-By: ASP.NET"]
            }

        return tech
    except Timeout as exc:
        raise ModuleTimeoutError(f"Technology fingerprint timed out for {url}") from exc
    except Exception as e:
        return {"error": str(e)}
