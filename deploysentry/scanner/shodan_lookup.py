from __future__ import annotations

import re
from html import unescape
from typing import Iterable

import httpx
from bs4 import BeautifulSoup

from deploysentry.models import ShodanHostInfo, ShodanPort
from deploysentry.network.router import NetworkRouter

SHODAN_BASE_URL = "https://www.shodan.io/host"
UA = "Mozilla/5.0 DeploySentry/0.1 Defensive Deployment Exposure Monitor"


def _clean_text(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", unescape(value)).strip()


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        clean = _clean_text(value)
        if not clean or clean in seen:
            continue
        seen.add(clean)
        out.append(clean)
    return out


def _extract_label_value(soup: BeautifulSoup, labels: list[str]) -> dict[str, str]:
    """Best-effort extraction from the rendered Shodan host page.

    Shodan HTML can change, so this intentionally uses loose text matching
    instead of brittle selectors. When Pro/API JSON is added later, replace this
    module with the structured API response parser.
    """
    lines = [_clean_text(line) for line in soup.get_text("\n", strip=True).splitlines()]
    lines = [line for line in lines if line]
    found: dict[str, str] = {}

    for idx, line in enumerate(lines):
        normalized = line.lower().rstrip(":")
        for label in labels:
            label_norm = label.lower().rstrip(":")
            if normalized == label_norm and idx + 1 < len(lines):
                found[label] = lines[idx + 1]
            elif normalized.startswith(label_norm + ":"):
                value = line.split(":", 1)[1].strip()
                if value:
                    found[label] = value
    return found


def _extract_ports(soup: BeautifulSoup) -> list[ShodanPort]:
    ports: list[ShodanPort] = []
    text = soup.get_text("\n", strip=True)

    # Precise patterns first: 80/tcp, 443/udp, etc.
    for match in re.finditer(r"\b(\d{1,5})/(tcp|udp)\b", text, re.IGNORECASE):
        port = int(match.group(1))
        proto = match.group(2).lower()
        if 1 <= port <= 65535:
            ports.append(ShodanPort(port=port, protocol=proto))

    # Common Shodan visual fragments contain standalone service cards like
    # "80" followed by a banner. Keep this conservative to reduce junk.
    candidates: set[int] = set()
    for element in soup.find_all(["a", "div", "span", "pre", "code"]):
        value = _clean_text(element.get_text(" ", strip=True))
        if not value or len(value) > 1200:
            continue

        # Port at beginning of a card/line, e.g. "443 HTTPS nginx ...".
        m = re.match(r"^(\d{1,5})(?:\s+|$)", value)
        if m:
            port = int(m.group(1))
            if 1 <= port <= 65535:
                candidates.add(port)
                ports.append(ShodanPort(port=port, protocol="tcp", banner=value[:500]))

        for m in re.finditer(r"\bport\s*:?\s*(\d{1,5})\b", value, re.IGNORECASE):
            port = int(m.group(1))
            if 1 <= port <= 65535:
                candidates.add(port)

    # Avoid HTTP status codes and common non-port page numbers that show up in
    # generic HTML. This is passive enrichment, not proof of currently open ports.
    ignored = {200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 429, 500, 502, 503}
    for port in sorted(candidates):
        if port not in ignored:
            ports.append(ShodanPort(port=port, protocol="tcp"))

    deduped: dict[tuple[int, str], ShodanPort] = {}
    for item in ports:
        key = (item.port, item.protocol)
        if key not in deduped or (not deduped[key].banner and item.banner):
            deduped[key] = item

    return sorted(deduped.values(), key=lambda p: (p.port, p.protocol))


def _extract_hostnames(soup: BeautifulSoup) -> list[str]:
    text = soup.get_text("\n", strip=True)
    candidates = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
    ignored = {"www.shodan.io", "shodan.io", "account.shodan.io", "developer.shodan.io"}
    return [host for host in _dedupe(candidates) if host.lower() not in ignored]


def parse_shodan_host_page(ip: str, html: str, url: str) -> ShodanHostInfo:
    soup = BeautifulSoup(html, "html.parser")
    labels = _extract_label_value(soup, ["Organization", "ISP", "ASN", "Country", "City"])
    title = _clean_text(soup.title.string if soup.title else "")

    return ShodanHostInfo(
        ip=ip,
        url=url,
        organization=labels.get("Organization"),
        isp=labels.get("ISP"),
        asn=labels.get("ASN"),
        country=labels.get("Country"),
        city=labels.get("City"),
        hostnames=_extract_hostnames(soup),
        ports=_extract_ports(soup),
        raw_summary=title or None,
    )


async def fetch_shodan_host(
    ip: str,
    router: NetworkRouter | None,
    timeout: float = 10.0,
) -> ShodanHostInfo | None:
    """Fetch and parse Shodan's public host page for passive enrichment.

    This does not connect to or scan the target IP. It only reads Shodan's
    already-indexed host page through the active DeploySentry network route
    direct/Tor/proxy.
    """
    url = f"{SHODAN_BASE_URL}/{ip}"
    headers = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml",
    }

    try:
        if router is not None:
            client, route = router.client_for("www.shodan.io", timeout, headers)
            async with client:
                response = await client.get(url)
            if response.status_code == 200:
                router.mark_success(route)
            else:
                router.mark_failure(route)
        else:
            async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
                response = await client.get(url)

        if response.status_code != 200:
            return None
        if "html" not in response.headers.get("content-type", "").lower():
            return None
        return parse_shodan_host_page(ip=ip, html=response.text, url=url)
    except (httpx.HTTPError, ValueError, RuntimeError):
        return None
