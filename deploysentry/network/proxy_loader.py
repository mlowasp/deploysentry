from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

SUPPORTED_SCHEMES = {"http", "https", "socks4", "socks5"}

@dataclass(frozen=True)
class ProxyEntry:
    url: str
    redacted: str
    label: str


def redact_proxy(url: str) -> str:
    p = urlparse(url)
    if p.username or p.password:
        host = p.hostname or ''
        netloc = f"***:***@{host}"
        if p.port:
            netloc += f":{p.port}"
        return urlunparse((p.scheme, netloc, '', '', '', ''))
    return url


def load_proxies(path: str) -> list[ProxyEntry]:
    entries: list[ProxyEntry] = []
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            raw = line.strip()
            if not raw or raw.startswith('#'):
                continue
            p = urlparse(raw)
            if p.scheme not in SUPPORTED_SCHEMES or not p.hostname or not p.port:
                continue
            label = f"proxy-{len(entries)+1:03d}"
            entries.append(ProxyEntry(url=raw, redacted=redact_proxy(raw), label=label))
    return entries
