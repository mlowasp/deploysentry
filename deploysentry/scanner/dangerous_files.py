from __future__ import annotations

import asyncio
import json
import random
from importlib.resources import files
from urllib.parse import urljoin

import httpx

from deploysentry.models import Finding
from deploysentry.network.router import NetworkRouter
from deploysentry.utils.hashing import body_hash, similarity
from deploysentry.scanner.http_probe import extract_title
from .detectors import detect

def load_dangerous_paths() -> list[str]:
    """Load dangerous paths from packaged JSON.

    Users can edit deploysentry/data/dangerous_paths.json to add/remove safe
    metadata checks without modifying Python scanner code.
    """
    try:
        raw = files('deploysentry.data').joinpath('dangerous_paths.json').read_text(encoding='utf-8')
        data = json.loads(raw)
        paths = []
        for item in data:
            path = str(item).strip()
            if not path:
                continue
            if not path.startswith('/'):
                path = '/' + path
            paths.append(path)
        return sorted(set(paths))
    except Exception:
        return [
            '/.env','/.env.local','/.env.production','/.env.dev','/.env.backup',
            '/.git/HEAD','/.git/config','/.svn/entries','/.hg/hgrc',
            '/composer.lock','/package-lock.json','/yarn.lock','/pnpm-lock.yaml','/Gemfile.lock',
            '/config/database.yml','/phpinfo.php','/info.php','/test.php',
            '/debug.log','/wp-content/debug.log','/storage/logs/laravel.log',
            '/backup.zip','/backup.tar.gz','/backup.sql','/db.sql','/dump.sql','/database.sql',
            '/app.js.map','/main.js.map','/bundle.js.map',
        ]




class Baseline:
    def __init__(self, status: int, length: int, title: str | None, text: str, h: str):
        self.status = status
        self.length = length
        self.title = title
        self.text = text
        self.hash = h


async def baseline_for(
    client: httpx.AsyncClient,
    service_url: str,
) -> list[Baseline]:
    """Build soft-404 baselines using an already-open client.

    Important: do not create/use an AsyncClient here and then later enter it
    with ``async with client``. httpx raises ``Cannot open a client instance
    more than once`` if a client has already been opened by a request before
    entering its context manager.
    """
    bases: list[Baseline] = []
    for _ in range(2):
        path = f'/__deploysentry_random_{random.randint(100000, 999999)}__'
        try:
            r = await client.get(urljoin(service_url + '/', path.lstrip('/')))
            text = r.text[:50000] if len(r.content) < 500_000 else ''
            bases.append(
                Baseline(
                    r.status_code,
                    len(r.content),
                    extract_title(text),
                    text,
                    body_hash(r.content),
                )
            )
        except Exception:
            pass
    return bases


def looks_like_soft_404(status: int, body: bytes, title: str | None, baselines: list[Baseline]) -> bool:
    if not baselines:
        return False
    text = body[:50000].decode('utf-8', errors='ignore') if len(body) < 500_000 else ''
    h = body_hash(body)
    for b in baselines:
        if status == b.status and h == b.hash:
            return True
        if status == b.status and title and b.title and title == b.title and abs(len(body) - b.length) < 300:
            return True
        if status == b.status and text and similarity(text, b.text) > 0.86:
            return True
    return False


async def scan_service(
    service_url: str,
    host: str,
    timeout: float,
    router: NetworkRouter,
    delay: float = 0.25,
    event_cb=None,
) -> list[Finding]:
    findings: list[Finding] = []
    headers = {'User-Agent': 'DeploySentry/0.1 Defensive Exposure Monitor'}
    client, route = router.client_for(host, timeout, headers)

    try:
        async with client:
            bases = await baseline_for(client, service_url)

            for path in load_dangerous_paths():
                url = urljoin(service_url.rstrip('/') + '/', path.lstrip('/'))
                try:
                    r = await client.get(url)
                    ctype = r.headers.get('content-type', '')
                    text = (
                        r.text[:20000]
                        if ('text' in ctype or 'html' in ctype or 'json' in ctype or len(r.content) < 250_000)
                        else ''
                    )
                    title = extract_title(text)
                    if event_cb:
                        await event_cb({'type': 'path_checked', 'url': url, 'path': path, 'status': r.status_code})
                    if not looks_like_soft_404(r.status_code, r.content, title, bases):
                        finding = detect(path, url, host, r.status_code, dict(r.headers), r.content, route)
                        if finding:
                            findings.append(finding)
                            if event_cb:
                                await event_cb({'type': 'finding_found', 'finding': finding})
                    router.mark_success(route)
                except Exception as exc:
                    router.mark_failure(route)
                    if event_cb:
                        await event_cb({'type': 'scan_error', 'message': f'{url}: {str(exc)[:160]}'})
                await asyncio.sleep(delay)
    except Exception as exc:
        router.mark_failure(route)
        if event_cb:
            await event_cb({'type': 'scan_error', 'message': f'{service_url}: {str(exc)[:160]}'})

    return findings
