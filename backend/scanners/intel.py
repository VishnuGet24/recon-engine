"""Hosting intelligence utilities with CDN/WAF distinction."""

import ipaddress
import re
from typing import Dict, Optional

import requests


CDN_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "cloudfront": "Amazon CloudFront",
    "imperva": "Imperva",
    "sucuri": "Sucuri",
    "incapsula": "Imperva Incapsula",
    "stackpath": "StackPath",
}


def _extract_nameservers(osint_data: Dict) -> list:
    whois_data = osint_data.get("whois", {}) if isinstance(osint_data, dict) else {}
    if not isinstance(whois_data, dict):
        return []

    nameservers = whois_data.get("name_servers", [])
    if isinstance(nameservers, str):
        nameservers = [nameservers]
    if not isinstance(nameservers, list):
        return []
    return [str(ns).lower() for ns in nameservers]


def _detect_cdn_from_text(value: str) -> Optional[str]:
    lowered = (value or "").lower()
    for keyword, provider in CDN_SIGNATURES.items():
        if keyword in lowered:
            return provider
    return None


def _detect_cdn_provider(osint_data: Dict, fingerprint_data: Optional[Dict]) -> Optional[str]:
    if isinstance(fingerprint_data, dict):
        cdn_name = fingerprint_data.get("cdn")
        if cdn_name:
            return str(cdn_name)

        server_header = fingerprint_data.get("server")
        cdn_from_server = _detect_cdn_from_text(str(server_header))
        if cdn_from_server:
            return cdn_from_server

    for nameserver in _extract_nameservers(osint_data):
        detected = _detect_cdn_from_text(nameserver)
        if detected:
            return detected

    return None


def _detect_waf_provider(cdn_provider: Optional[str], fingerprint_data: Optional[Dict]) -> Optional[str]:
    if isinstance(fingerprint_data, dict):
        waf_name = fingerprint_data.get("waf")
        if waf_name:
            return str(waf_name)
    if cdn_provider == "Cloudflare":
        return "Cloudflare WAF"
    return None


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_target_domain(osint_data: Dict) -> Optional[str]:
    whois_data = osint_data.get("whois", {}) if isinstance(osint_data, dict) else {}
    if not isinstance(whois_data, dict):
        return None

    domain_name = whois_data.get("domain_name")
    if isinstance(domain_name, list) and domain_name:
        return str(domain_name[0])
    if isinstance(domain_name, str) and domain_name:
        return domain_name
    return None


def _extract_resolved_ip(osint_data: Dict) -> Optional[str]:
    resolved_ip = osint_data.get("resolved_ip") if isinstance(osint_data, dict) else None
    if isinstance(resolved_ip, str) and _valid_ip(resolved_ip):
        return resolved_ip
    return None


def _normalize_org(org_value: Optional[str]) -> Optional[str]:
    if not org_value:
        return None
    normalized = str(org_value).strip()
    normalized = re.sub(r"^AS\d+\s+", "", normalized, flags=re.IGNORECASE)
    return normalized or None


def _lookup_ip_owner(ip_address: str) -> Optional[str]:
    # Preferred quick lookup.
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=10)
        if response.ok:
            payload = response.json()
            owner = _normalize_org(payload.get("org"))
            if owner:
                return owner
    except Exception:
        pass

    # RDAP fallback for broader coverage.
    try:
        response = requests.get(f"https://rdap.org/ip/{ip_address}", timeout=10)
        if response.ok:
            payload = response.json()
            for key in ("name", "handle"):
                candidate = payload.get(key)
                if candidate:
                    return str(candidate)
    except Exception:
        pass

    return None


def analyze_hosting(osint_data, fingerprint_data=None):
    """Return hosting and CDN/WAF attribution with CDN-aware handling."""
    cdn_provider = _detect_cdn_provider(osint_data, fingerprint_data)
    waf_provider = _detect_waf_provider(cdn_provider, fingerprint_data)

    if cdn_provider:
        return {
            "hosting_provider": "Behind CDN (Origin Obfuscated)",
            "cdn_provider": cdn_provider,
            "waf_provider": waf_provider,
        }

    resolved_ip = _extract_resolved_ip(osint_data)
    hosting_provider = _lookup_ip_owner(resolved_ip) if resolved_ip else None
    if not hosting_provider:
        hosting_provider = "Unknown Hosting Provider"

    result = {
        "hosting_provider": hosting_provider,
        "cdn_provider": None,
        "waf_provider": waf_provider,
    }

    # If WHOIS has a useful signal, retain it as fallback context.
    domain_name = _extract_target_domain(osint_data)
    if domain_name and result["hosting_provider"] == "Unknown Hosting Provider":
        result["hosting_provider"] = f"Unknown Hosting Provider ({domain_name})"

    return result
