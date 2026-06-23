from __future__ import annotations
import re
from urllib.parse import urlparse

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

class DomainValidationError(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    value = raw.strip().lower().rstrip('.')
    if not value:
        raise DomainValidationError("Domain is required")
    if value.startswith('*.'):
        raise DomainValidationError("Wildcard domains are not accepted. Enter a concrete root domain.")
    if '://' in value:
        parsed = urlparse(value)
        if parsed.path not in ('', '/') or parsed.params or parsed.query or parsed.fragment:
            raise DomainValidationError("Enter only a domain, not a URL path or query.")
        value = parsed.hostname or ''
    if '/' in value or ':' in value or '*' in value:
        raise DomainValidationError("Enter a plain domain like example.com")
    if not DOMAIN_RE.match(value):
        raise DomainValidationError("Invalid domain format")
    return value
