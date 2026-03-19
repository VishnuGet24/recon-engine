import ssl
import socket

from scanners.exceptions import ModuleTimeoutError


def check_ssl(target):
    """Inspect SSL/TLS metadata for a target with timeout-safe behavior."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                return {
                    "ssl_version": ssock.version(),
                    "cipher": ssock.cipher()
                }
    except socket.timeout as exc:
        raise ModuleTimeoutError(f"SSL scan timed out for {target}") from exc
    except Exception as e:
        return {
            "error": str(e)
        }
