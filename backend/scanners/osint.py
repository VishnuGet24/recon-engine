import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

import whois

from scanners.exceptions import ModuleTimeoutError


DNS_TIMEOUT_SECONDS = 10
WHOIS_TIMEOUT_SECONDS = 10


def _resolve_domain(target):
    return socket.gethostbyname(target)


def _lookup_whois(target):
    return whois.whois(target)


def run_osint(target):
    """Collect DNS and WHOIS intelligence with timeout-safe execution."""
    result = {}

    # DNS Resolution
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_resolve_domain, target)
            ip = future.result(timeout=DNS_TIMEOUT_SECONDS)
        result["resolved_ip"] = ip
    except FutureTimeoutError as exc:
        raise ModuleTimeoutError(f"OSINT DNS resolution timed out for {target}") from exc
    except Exception as e:
        result["resolved_ip"] = f"DNS resolution failed: {str(e)}"

    # WHOIS using python-whois (NO subprocess)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_lookup_whois, target)
            w = future.result(timeout=WHOIS_TIMEOUT_SECONDS)

        result["whois"] = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
    except FutureTimeoutError as exc:
        raise ModuleTimeoutError(f"OSINT WHOIS lookup timed out for {target}") from exc
    except Exception as e:
        result["whois"] = f"WHOIS failed: {str(e)}"

    return result
