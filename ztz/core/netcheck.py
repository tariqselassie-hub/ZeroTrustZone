"""
Loopback port probes for the ZTZ proxy.

The proxy only protects clients that actually reach it. If another server (e.g.
Ollama with "Expose to network", which binds [::]) holds the same port on a
different address, clients resolving `localhost` to that address bypass ZTZ.
"""

import socket
import urllib.error
import urllib.request
from typing import Dict, List

LOOPBACKS = ("127.0.0.1", "::1")

# Response header the ZTZ proxy adds to everything it serves, so a probe can tell
# the proxy apart from the backend it fronts.
PROXY_HEADER = "X-ZTZ-Proxy"


def is_listening(host: str, port: int, timeout: float = 0.5) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False  # e.g. IPv6 disabled


def probe_hosts(bind_host: str) -> List[str]:
    """Addresses a local client might reach for a proxy bound to bind_host."""
    hosts = list(LOOPBACKS)
    if bind_host not in ("0.0.0.0", "::", "") and bind_host not in hosts:
        hosts.append(bind_host)
    return hosts


def listening_addresses(port: int, hosts: List[str]) -> List[str]:
    return [h for h in hosts if is_listening(h, port)]


def classify_endpoint(host: str, port: int, timeout: float = 1.0) -> str:
    """'closed', 'ztz' (the ZTZ proxy answers) or 'direct' (something else answers)."""
    if not is_listening(host, port):
        return "closed"
    url_host = f"[{host}]" if ":" in host else host
    # Never route a loopback probe through HTTP(S)_PROXY settings.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://{url_host}:{port}/", timeout=timeout) as resp:
            headers = resp.headers
    except urllib.error.HTTPError as e:
        headers = e.headers
    except (OSError, ValueError):
        return "direct"
    return "ztz" if headers.get(PROXY_HEADER) else "direct"


def classify_port(port: int, hosts: List[str] = LOOPBACKS) -> Dict[str, str]:
    return {h: classify_endpoint(h, port) for h in hosts}
