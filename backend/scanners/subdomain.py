import dns.resolver
import dns.exception

from scanners.exceptions import ModuleTimeoutError

# Basic wordlist (you can expand later)
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev",
    "test", "staging", "admin", "portal"
]

def find_subdomains(target):
    """Enumerate common subdomains with resolver timeouts."""
    found = []
    timeout_count = 0
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 3.0
    resolver.lifetime = 10.0

    for sub in COMMON_SUBDOMAINS:
        domain = f"{sub}.{target}"
        try:
            resolver.resolve(domain, "A")
            found.append(domain)
        except dns.exception.Timeout:
            timeout_count += 1
        except Exception:
            pass  # Ignore if subdomain does not exist

    if timeout_count == len(COMMON_SUBDOMAINS):
        raise ModuleTimeoutError(f"Subdomain enumeration timed out for {target}")

    return found
