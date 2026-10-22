"""
Loopback port probes for the ZTZ proxy.

The proxy only protects clients that actually reach it. If another server (e.g.
Ollama with "Expose to network", which binds [::]) holds the same port on a
different address, clients resolving `localhost` to that address bypass ZTZ.
"""

import json
import socket
import urllib.error
import urllib.request
from typing import Dict, List, Optional

LOOPBACKS = ("127.0.0.1", "::1")

# Response header the ZTZ proxy adds to everything it serves, so a probe can tell
# the proxy apart from the backend it fronts.
PROXY_HEADER = "X-ZTZ-Proxy"

# Answered by the proxy itself, never forwarded: a probe of / would wait on the
# backend, and with the backend off (Windows retries a refused connect for ~2 s)
# the probe timed out and reported the proxy as 'direct'.
HEALTH_PATH = "/__ztz__/health"


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


def _get_health(host: str, port: int, timeout: float):
    """(headers, body) of GET HEALTH_PATH, or None if nothing answers in time."""
    url_host = f"[{host}]" if ":" in host else host
    # Never route a loopback probe through HTTP(S)_PROXY settings.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://{url_host}:{port}{HEALTH_PATH}", timeout=timeout) as resp:
            return resp.headers, resp.read(4096)
    except urllib.error.HTTPError as e:
        return e.headers, b""
    except (OSError, ValueError):
        return None


def classify_endpoint(host: str, port: int, timeout: float = 1.0) -> str:
    """'closed', 'ztz' (the ZTZ proxy answers) or 'direct' (something else answers)."""
    if not is_listening(host, port):
        return "closed"
    reply = _get_health(host, port, timeout)
    return "ztz" if reply and reply[0].get(PROXY_HEADER) else "direct"


def proxy_upstream_port(host: str, port: int, timeout: float = 1.0) -> Optional[int]:
    """The backend port a ZTZ proxy on host:port forwards to, if it reports one."""
    reply = _get_health(host, port, timeout)
    if not reply or not reply[0].get(PROXY_HEADER):
        return None
    try:
        upstream = json.loads(reply[1]).get("upstream_port")
    except (ValueError, AttributeError):
        return None
    return upstream if isinstance(upstream, int) else None


def classify_port(port: int, hosts: List[str] = LOOPBACKS) -> Dict[str, str]:
    return {h: classify_endpoint(h, port) for h in hosts}
