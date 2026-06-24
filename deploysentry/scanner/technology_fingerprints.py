from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from urllib.parse import urljoin

import httpx

from deploysentry.models import HTTPService, TechnologyDetection
from deploysentry.network.router import NetworkRouter

USER_AGENT = "DeploySentry/0.1 Defensive Technology Fingerprinter"
TEXT_TYPES = ("text/", "html", "json", "javascript", "xml")
MAX_BODY_BYTES = 150_000
MAX_PATH_PROBES_PER_SERVICE = 24
PATH_PROBE_BATCH_SIZE = 4
PATH_PROBE_CONCURRENCY = 3
MIN_TECH_CONFIDENCE = 0.55


@dataclass(frozen=True)
class FingerprintRule:
    type: str
    value: str
    confidence: float = 0.25
    evidence: str | None = None
    header: str | None = None
    path: str | None = None


@lru_cache(maxsize=1)
def load_fingerprints_cached() -> tuple[dict, ...]:
    """Load JSON-driven technology fingerprints once per process."""
    try:
        data_path = resources.files("deploysentry.data").joinpath("technology_fingerprints.json")
        data = json.loads(data_path.read_text(encoding="utf-8"))
        return tuple(data)
    except Exception:
        return tuple()


def load_fingerprints() -> list[dict]:
    return list(load_fingerprints_cached())


def _clean_text(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", value).strip()


def _extract_title_fast(html: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", html[:50_000], re.I | re.S)
    if not match:
        return None
    return _clean_text(re.sub(r"<[^>]+>", "", match.group(1)))[:250]


def _extract_meta_generators_fast(html: str) -> list[str]:
    """Regex-only generator extraction to avoid BeautifulSoup CPU spikes."""
    head = html[:150_000]
    generators: list[str] = []
    for meta in re.finditer(r"<meta\b[^>]*>", head, re.I | re.S):
        tag = meta.group(0)
        if not re.search(r"\b(?:name|property)\s*=\s*[\"']?generator[\"']?", tag, re.I):
            continue
        content = re.search(r"\bcontent\s*=\s*([\"'])(.*?)\1", tag, re.I | re.S)
        if content:
            value = _clean_text(re.sub(r"<[^>]+>", "", content.group(2)))
            if value:
                generators.append(value)
    return generators


def _header_blob(headers: httpx.Headers) -> str:
    return "\n".join(f"{key}: {value}" for key, value in headers.items()).lower()


def _cookie_blob(headers: httpx.Headers) -> str:
    return "\n".join(headers.get_list("set-cookie")).lower()


def _build_context(headers: httpx.Headers, html: str, final_url: str) -> dict[str, str]:
    """Precompute lower-case blobs once per service."""
    return {
        "html": html.lower(),
        "title": (_extract_title_fast(html) or "").lower(),
        "generators": "\n".join(_extract_meta_generators_fast(html)).lower(),
        "headers": _header_blob(headers),
        "cookies": _cookie_blob(headers),
        "url": final_url.lower(),
    }


def _match_passive_rule(rule: dict, ctx: dict[str, str]) -> str | None:
    rtype = rule.get("type", "")
    value = str(rule.get("value", ""))
    if not value:
        return None

    value_l = value.lower()
    if rtype == "html_contains" and value_l in ctx["html"]:
        return rule.get("evidence") or value
    if rtype == "title_contains" and value_l in ctx["title"]:
        return rule.get("evidence") or f"title contains {value}"
    if rtype == "meta_generator_contains" and value_l in ctx["generators"]:
        return rule.get("evidence") or f"generator contains {value}"
    if rtype == "header_contains" and value_l in ctx["headers"]:
        header = rule.get("header")
        return rule.get("evidence") or (f"{header or 'header'} contains {value}")
    if rtype == "cookie_contains" and value_l in ctx["cookies"]:
        return rule.get("evidence") or f"cookie contains {value}"
    if rtype == "url_contains" and value_l in ctx["url"]:
        return rule.get("evidence") or f"url contains {value}"
    return None



def _extract_version_candidates(text: str, tech_name: str) -> list[str]:
    """Best-effort version extraction from page/generator/evidence text.

    This is deliberately conservative: only return short dotted numeric versions
    near the technology name or common version markers. It never requests extra
    exploit/probe paths.
    """
    if not text:
        return []

    candidates: list[str] = []
    safe_name = re.escape(tech_name)
    patterns = [
        rf"\b{safe_name}\b[^\n\r<>{{}}]{{0,60}}?\b(?:v(?:ersion)?\s*)?([0-9]+(?:\.[0-9]+){{1,4}}[a-z0-9._-]*)\b",
        rf"\b(?:generator|powered by|version|ver)\b[^\n\r<>{{}}]{{0,80}}?\b{safe_name}\b[^\n\r<>{{}}]{{0,60}}?\b([0-9]+(?:\.[0-9]+){{1,4}}[a-z0-9._-]*)\b",
        r"[?&]ver=([0-9]+(?:\.[0-9]+){1,4}[a-z0-9._-]*)\b",
        r"\bv(?:ersion)?[\s:=\"']+([0-9]+(?:\.[0-9]+){1,4}[a-z0-9._-]*)\b",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.I):
            version = match.group(1).strip("'\";,) ")[:40]
            if version and version not in candidates:
                candidates.append(version)
            if len(candidates) >= 3:
                return candidates
    return candidates


def _extract_version_for_detection(name: str, ctx: dict[str, str], ev_items: list[str]) -> str | None:
    search_text = "\n".join([
        ctx.get("generators", ""),
        ctx.get("headers", ""),
        ctx.get("html", "")[:120_000],
        "\n".join(ev_items),
    ])

    aliases = {
        "WordPress": ["WordPress", "wp-includes", "wp-content"],
        "WooCommerce": ["WooCommerce", "woocommerce"],
        "Drupal": ["Drupal"],
        "Joomla": ["Joomla", "Joomla!"],
        "Magento 2": ["Magento", "Magento 2"],
        "Adobe Commerce / Magento": ["Magento", "Adobe Commerce"],
        "Laravel": ["Laravel"],
        "Symfony": ["Symfony"],
        "Django": ["Django"],
        "Next.js": ["Next.js", "NextJS", "next"],
        "Nuxt": ["Nuxt"],
        "Vue.js": ["Vue", "Vue.js"],
        "React": ["React"],
        "Angular": ["Angular"],
        "Vite": ["Vite"],
    }
    for alias in aliases.get(name, [name]):
        versions = _extract_version_candidates(search_text, alias)
        if versions:
            return versions[0]
    return None

def _score_to_confidence(score: float) -> float:
    return max(0.1, min(score, 0.98))


async def _fetch_url(url: str, timeout: float, router: NetworkRouter) -> tuple[int | None, httpx.Headers, str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.8",
    }
    client, route = router.client_for(url, timeout, headers)
    try:
        async with client:
            response = await client.get(url)
        router.mark_success(route)
        ctype = response.headers.get("content-type", "")
        text = ""
        if any(kind in ctype.lower() for kind in TEXT_TYPES) or len(response.content) <= MAX_BODY_BYTES:
            text = response.text[:MAX_BODY_BYTES]
        return response.status_code, response.headers, text, str(response.url)
    except httpx.HTTPError:
        router.mark_failure(route)
        return None, httpx.Headers(), "", url
    except Exception:
        router.mark_failure(route)
        return None, httpx.Headers(), "", url


def _collect_path_rules(fingerprints: list[dict]) -> dict[str, list[tuple[dict, dict]]]:
    path_rules: dict[str, list[tuple[dict, dict]]] = {}
    for fp in fingerprints:
        if not fp.get("path_probe", False):
            continue
        for rule in fp.get("rules", []):
            if rule.get("type") in {"path_exists", "path_body_contains"}:
                path = str(rule.get("path") or rule.get("value") or "").strip()
                if not path.startswith("/"):
                    continue
                path_rules.setdefault(path, []).append((fp, rule))
    return path_rules


async def fingerprint_service(
    service: HTTPService,
    timeout: float,
    router: NetworkRouter,
    emit=None,
) -> list[TechnologyDetection]:
    """Fingerprint technologies for one live service without blocking the TUI."""
    fingerprints = load_fingerprints()
    if not fingerprints:
        return []

    await asyncio.sleep(0)
    status, headers, html, final_url = await _fetch_url(service.url, timeout, router)
    if status is None:
        return []

    scores: dict[str, float] = {}
    evidence: dict[str, list[str]] = {}
    meta: dict[str, dict] = {}

    def add_signal(fp: dict, rule: dict, ev: str) -> None:
        name = fp["name"]
        scores[name] = scores.get(name, 0.0) + float(rule.get("confidence", 0.25))
        evidence.setdefault(name, [])
        if ev not in evidence[name]:
            evidence[name].append(ev[:220])
        meta[name] = fp

    ctx = _build_context(headers, html, final_url)

    for index, fp in enumerate(fingerprints):
        for rule in fp.get("rules", []):
            if rule.get("type") in {"path_exists", "path_body_contains"}:
                continue
            ev = _match_passive_rule(rule, ctx)
            if ev:
                add_signal(fp, rule, ev)
        if index and index % 25 == 0:
            await asyncio.sleep(0)

    path_rules = list(_collect_path_rules(fingerprints).items())[:MAX_PATH_PROBES_PER_SERVICE]
    sem = asyncio.Semaphore(PATH_PROBE_CONCURRENCY)

    async def probe_path(path: str, attached_rules: list[tuple[dict, dict]]) -> None:
        url = urljoin(service.url.rstrip("/") + "/", path.lstrip("/"))
        async with sem:
            p_status, _p_headers, p_text, _p_final = await _fetch_url(url, timeout, router)
        if p_status is None or p_status >= 500:
            return
        p_text_l = p_text.lower()
        for fp, rule in attached_rules:
            rtype = rule.get("type")
            if rtype == "path_exists" and 200 <= p_status < 400:
                add_signal(fp, rule, rule.get("evidence") or f"{path} returned {p_status}")
            elif rtype == "path_body_contains" and 200 <= p_status < 500:
                value = str(rule.get("value") or "")
                if value and value.lower() in p_text_l:
                    add_signal(fp, rule, rule.get("evidence") or f"{path} contains {value}")

    for start in range(0, len(path_rules), PATH_PROBE_BATCH_SIZE):
        batch = path_rules[start:start + PATH_PROBE_BATCH_SIZE]
        results = await asyncio.gather(
            *(probe_path(path, rules) for path, rules in batch),
            return_exceptions=True,
        )
        for item in results:
            if isinstance(item, asyncio.CancelledError):
                raise item
        await asyncio.sleep(0)

    detections: list[TechnologyDetection] = []
    for name, score in sorted(scores.items(), key=lambda item: item[1], reverse=True):
        confidence = _score_to_confidence(score)
        if confidence < MIN_TECH_CONFIDENCE:
            continue
        fp = meta[name]
        ev_items = evidence.get(name, [])[:8]
        detections.append(
            TechnologyDetection(
                name=name,
                category=fp.get("category", "unknown"),
                asset=service.host,
                url=service.url,
                confidence=confidence,
                evidence=ev_items,
                version=_extract_version_for_detection(name, ctx, ev_items),
            )
        )

    if detections and emit:
        for detection in detections:
            await emit({"type": "technology_detected", "technology": detection})
            await asyncio.sleep(0)

    return detections
