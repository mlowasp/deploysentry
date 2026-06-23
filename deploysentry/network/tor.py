from __future__ import annotations
import socket
from urllib.parse import urlparse

TOR_WARNING = (
    "Tor mode is intended for authorized defensive verification only, such as testing whether your own assets are "
    "reachable from the Tor network. Do not use it to scan systems you do not own or do not have permission to test."
)


def tor_proxy_reachable(proxy_url: str, timeout: float = 2.0) -> tuple[bool, str | None]:
    p = urlparse(proxy_url)
    if p.scheme not in {"socks4", "socks5"} or not p.hostname or not p.port:
        return False, "Tor proxy must look like socks5://127.0.0.1:9050"
    try:
        with socket.create_connection((p.hostname, p.port), timeout=timeout):
            return True, None
    except OSError as exc:
        return False, str(exc)
