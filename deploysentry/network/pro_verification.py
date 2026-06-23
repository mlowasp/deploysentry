from __future__ import annotations

import os
from urllib.parse import quote

import httpx

VERIFY_BASE_URL = 'https://api.deploysentry.com/verifyKey'


def resolve_api_key(enabled: bool, api_key: str | None, api_key_env: str = 'DEPLOYSENTRY_API_KEY') -> tuple[str | None, str | None]:
    if not enabled:
        return None, None
    key = api_key or os.getenv(api_key_env)
    if not key:
        return None, "Pro Verification Mode requires an API key. Continuing in normal mode."
    return key, None


def redact_api_key(key: str | None) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return "********"
    return key[:10] + "************"


async def verify_api_key(api_key: str, timeout: float = 8.0) -> tuple[bool, str | None]:
    """Validate a Pro API key with the DeploySentry API.

    A valid key must return HTTP 200 from:
    https://api.deploysentry.com/verifyKey/<api_key>

    The key is URL-encoded and never returned in error messages.
    """
    if not api_key:
        return False, 'missing API key'
    url = f"{VERIFY_BASE_URL}/{quote(api_key, safe='')}"
    try:
        async with httpx.AsyncClient(timeout=timeout, headers={'User-Agent': 'DeploySentry/0.1 Defensive Exposure Monitor'}) as client:
            r = await client.get(url)
        if r.status_code == 200:
            return True, None
        return False, f'API key verification failed with HTTP {r.status_code}'
    except Exception as exc:
        return False, f'API key verification failed: {str(exc)[:160]}'
