from __future__ import annotations
from dataclasses import dataclass
from typing import Literal
import httpx
from pydantic import BaseModel
from deploysentry.models import RouteMetadata, NetworkVerification
from .proxy_loader import load_proxies
from .proxy_pool import ProxyPool
from .tor import tor_proxy_reachable

Mode = Literal['direct','proxy','tor','pro']

@dataclass
class RouteChoice:
    route: RouteMetadata
    proxy_url: str | None = None

class NetworkRouter:
    def __init__(self, *, proxy_file: str | None = None, proxy_mode: str = 'off', tor: bool = False, tor_proxy: str = 'socks5://127.0.0.1:9050', pro: bool = False):
        if tor and proxy_file and proxy_mode != 'off':
            raise ValueError('Tor and custom proxies are mutually exclusive in the MVP.')
        self.proxy_mode = proxy_mode
        self.tor = tor
        self.tor_proxy = tor_proxy
        self.pro = pro
        self.proxy_pool: ProxyPool | None = None
        self.tor_available = False
        self.tor_error: str | None = None
        if proxy_file and proxy_mode != 'off':
            self.proxy_pool = ProxyPool(load_proxies(proxy_file))
        if tor:
            self.tor_available, self.tor_error = tor_proxy_reachable(tor_proxy)
            if not self.tor_available:
                raise ValueError(f'Tor proxy unavailable: {self.tor_error}')

    def verification(self) -> NetworkVerification:
        if self.tor:
            mode = 'tor'
        elif self.proxy_pool and self.proxy_mode != 'off':
            mode = 'proxies'
        elif self.pro:
            mode = 'pro-verification'
        else:
            mode = 'direct'
        return NetworkVerification(
            network_mode=mode,
            tor_enabled=self.tor,
            proxies_enabled=bool(self.proxy_pool and self.proxy_mode != 'off'),
            proxies_loaded=self.proxy_pool.loaded if self.proxy_pool else 0,
            proxies_healthy=self.proxy_pool.healthy if self.proxy_pool else 0,
            proxies_failed=self.proxy_pool.failed_count if self.proxy_pool else 0,
            pro_enabled=self.pro,
            vantage_points_checked=1 if self.pro else 0,
        )

    def choose(self, host: str) -> RouteChoice:
        if self.tor:
            return RouteChoice(RouteMetadata(route_type='tor', route_label='tor-local', proxy_redacted='socks5://127.0.0.1:9050'), self.tor_proxy)
        if self.proxy_pool and self.proxy_mode != 'off':
            proxy = self.proxy_pool.choose(host, self.proxy_mode)
            if proxy:
                return RouteChoice(RouteMetadata(route_type='proxy', route_label=proxy.label, proxy_redacted=proxy.redacted), proxy.url)
        return RouteChoice(RouteMetadata(route_type='direct', route_label='direct'), None)

    def mark_success(self, route: RouteMetadata) -> None:
        if self.proxy_pool and route.route_type == 'proxy':
            self.proxy_pool.mark_success(route.route_label)

    def mark_failure(self, route: RouteMetadata) -> None:
        if self.proxy_pool and route.route_type == 'proxy':
            self.proxy_pool.mark_failure(route.route_label)

    def client_for(self, host: str, timeout: float, headers: dict[str, str]) -> tuple[httpx.AsyncClient, RouteMetadata]:
        choice = self.choose(host)
        kwargs = dict(timeout=timeout, headers=headers, follow_redirects=True, verify=True)
        # httpx 0.27 supports proxy=; older versions may use proxies=. pyproject pins modern enough.
        if choice.proxy_url:
            kwargs['proxy'] = choice.proxy_url
        return httpx.AsyncClient(**kwargs), choice.route
