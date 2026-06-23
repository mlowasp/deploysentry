from __future__ import annotations

import json
import re
from importlib.resources import files

import httpx

from deploysentry.network.router import NetworkRouter

UA = 'DeploySentry/0.1 Defensive Exposure Monitor'
HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")


def load_common_subdomains() -> list[str]:
    """Load common subdomain labels from packaged JSON.

    Users can edit deploysentry/data/common_subdomains.json to tune the MVP
    wordlist without touching scanner code.
    """
    try:
        raw = files('deploysentry.data').joinpath('common_subdomains.json').read_text(encoding='utf-8')
        data = json.loads(raw)
        return [str(x).strip().lower() for x in data if str(x).strip()]
    except Exception:
        # Safe fallback if package data is missing during editable development.
        return [
            'www','app','api','admin','portal','login','dev','test','staging','stage','beta',
            'old','backup','cdn','assets','static','mail','vpn','sso','dashboard','monitoring',
            'status','docs','support','help','blog','shop'
        ]


def _clean_host(value: str, domain: str) -> str | None:
    host = value.strip().strip('.').lower()
    if not host:
        return None
    if host.startswith('*.'):
        host = host[2:]
    if host == domain or host.endswith('.' + domain):
        return host
    return None


async def _get_text(url: str, timeout: float, router: NetworkRouter | None = None, host_for_route: str = '') -> tuple[int, str]:
    headers = {'User-Agent': UA}
    if router is not None:
        client, route = router.client_for(host_for_route or 'external-discovery', timeout, headers)
        async with client:
            r = await client.get(url)
        router.mark_success(route)
        return r.status_code, r.text

    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
        r = await client.get(url)
        return r.status_code, r.text


async def certificate_transparency(domain: str, timeout: float = 8.0, router: NetworkRouter | None = None) -> set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    hosts: set[str] = set()
    try:
        status, text = await _get_text(url, timeout, router, 'crt.sh')
        if status != 200:
            return hosts
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return hosts
        if not isinstance(data, list):
            return hosts
        for row in data:
            name = str(row.get('name_value', '')).lower()
            for part in name.split('\n'):
                clean = _clean_host(part, domain)
                if clean:
                    hosts.add(clean)
    except Exception:
        return hosts
    return hosts


async def rapiddns_subdomains(domain: str, timeout: float = 8.0, router: NetworkRouter | None = None) -> set[str]:
    """Scrape RapidDNS search results for subdomains.

    This intentionally uses the same NetworkRouter as HTTP probing so Tor or
    custom proxies are honored when enabled. Failures are ignored so RapidDNS
    downtime/rate-limiting never breaks the scan.
    """
    url = f"https://rapiddns.io/s/{domain}#result"
    hosts: set[str] = set()
    try:
        status, text = await _get_text(url, timeout, router, 'rapiddns.io')
        if status >= 400:
            return hosts
        for match in HOST_RE.findall(text):
            clean = _clean_host(match, domain)
            if clean:
                hosts.add(clean)
    except Exception:
        return hosts
    return hosts


async def enumerate_subdomains(
    domain: str,
    use_ct: bool = True,
    timeout: float = 8.0,
    router: NetworkRouter | None = None,
    use_rapiddns: bool = True,
) -> list[str]:
    hosts = {domain}
    if use_ct:
        hosts |= await certificate_transparency(domain, timeout=timeout, router=router)
    if use_rapiddns:
        hosts |= await rapiddns_subdomains(domain, timeout=timeout, router=router)
    for word in load_common_subdomains():
        hosts.add(f'{word}.{domain}')
    return sorted(hosts)
