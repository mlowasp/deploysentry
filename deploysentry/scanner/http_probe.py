from __future__ import annotations
import re
import httpx
from deploysentry.models import HTTPService
from deploysentry.network.router import NetworkRouter

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def extract_title(text: str) -> str | None:
    m = TITLE_RE.search(text[:20000])
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200]


def guess_tech(headers: httpx.Headers, text: str) -> list[str]:
    tech: set[str] = set()
    server = headers.get('server','')
    powered = headers.get('x-powered-by','')
    blob = (server + ' ' + powered + ' ' + text[:5000]).lower()
    for name, needle in [('nginx','nginx'),('apache','apache'),('cloudflare','cloudflare'),('laravel','laravel'),('php','php'),('express','express'),('rails','rails'),('django','django'),('wordpress','wp-content')]:
        if needle in blob:
            tech.add(name)
    return sorted(tech)

async def probe_url(host: str, scheme: str, timeout: float, router: NetworkRouter) -> HTTPService:
    url = f'{scheme}://{host}'
    service = HTTPService(host=host, url=url, https_ok=(scheme == 'https'))
    headers = {'User-Agent':'DeploySentry/0.1 Defensive Exposure Monitor'}
    try:
        client, route = router.client_for(host, timeout, headers)
        service.route = route
        async with client:
            r = await client.get(url)
        router.mark_success(route)
        ctype = r.headers.get('content-type')
        text = r.text if 'text' in (ctype or '') or 'html' in (ctype or '') or len(r.content) < 300_000 else ''
        service.status_code = r.status_code
        service.final_url = str(r.url)
        service.title = extract_title(text)
        service.server = r.headers.get('server')
        service.content_type = ctype
        service.content_length = int(r.headers.get('content-length') or len(r.content))
        service.technologies = guess_tech(r.headers, text)
        service.alive = True
        service.https_ok = scheme == 'https'
    except httpx.ConnectError as exc:
        if scheme == 'https':
            service.https_ok = False
            service.tls_error = str(exc)[:250]
    except httpx.TransportError as exc:
        if scheme == 'https':
            service.https_ok = False
            service.tls_error = str(exc)[:250]
        if service.route:
            router.mark_failure(service.route)
    except Exception as exc:
        if scheme == 'https':
            service.https_ok = False
            service.tls_error = str(exc)[:250]
    return service

async def probe_host(host: str, timeout: float, router: NetworkRouter) -> list[HTTPService]:
    # HTTPS first, then HTTP.
    results = [await probe_url(host, 'https', timeout, router), await probe_url(host, 'http', timeout, router)]
    return [r for r in results if r.alive]
