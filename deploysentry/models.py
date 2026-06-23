from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Literal
from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
RouteType = Literal["direct", "proxy", "tor", "pro"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DNSRecord(BaseModel):
    host: str
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)
    resolved: bool = False
    error: str | None = None


class RouteMetadata(BaseModel):
    route_type: RouteType = "direct"
    route_label: str = "direct"
    proxy_redacted: str | None = None


class HTTPService(BaseModel):
    host: str
    url: str
    status_code: int | None = None
    final_url: str | None = None
    title: str | None = None
    server: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    technologies: list[str] = Field(default_factory=list)
    https_ok: bool | None = None
    tls_error: str | None = None
    alive: bool = False
    route: RouteMetadata = Field(default_factory=RouteMetadata)


class PathCheck(BaseModel):
    service_url: str
    host: str
    path: str
    status_code: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    title: str | None = None
    body_hash: str | None = None
    route: RouteMetadata = Field(default_factory=RouteMetadata)
    error: str | None = None


class Finding(BaseModel):
    id: str
    severity: Severity
    title: str
    asset: str
    url: str
    path: str
    evidence_type: str
    redacted_evidence: list[str] | str
    confidence: float
    recommendation: str
    first_seen: datetime = Field(default_factory=utcnow)
    route: RouteMetadata = Field(default_factory=RouteMetadata)
    pro_verification: dict[str, Any] | None = None


class NetworkVerification(BaseModel):
    network_mode: str = "direct"
    tor_enabled: bool = False
    proxies_enabled: bool = False
    proxies_loaded: int = 0
    proxies_healthy: int = 0
    proxies_failed: int = 0
    pro_enabled: bool = False
    vantage_points_checked: int = 0
    route_differences: list[dict[str, Any]] = Field(default_factory=list)


class ScanConfig(BaseModel):
    domain: str
    timeout: float = 8.0
    concurrency: int = 20
    per_host_concurrency: int = 3
    per_proxy_concurrency: int = 2
    dangerous_delay: float = 0.25
    output_dir: str = "deploysentry-reports"
    report_format: Literal["json", "html", "markdown", "all"] = "all"
    use_ct: bool = True
    use_rapiddns: bool = True
    proxy_file: str | None = None
    proxy_mode: Literal["off", "rotate", "sticky"] = "off"
    tor: bool = False
    tor_proxy: str = "socks5://127.0.0.1:9050"
    pro: bool = False
    api_key: str | None = None
    api_key_env: str = "DEPLOYSENTRY_API_KEY"


class ScanResult(BaseModel):
    target_domain: str
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    subdomains: list[str] = Field(default_factory=list)
    dns_records: list[DNSRecord] = Field(default_factory=list)
    services: list[HTTPService] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    network: NetworkVerification = Field(default_factory=NetworkVerification)
    errors: list[str] = Field(default_factory=list)

    def finish(self) -> None:
        self.finished_at = utcnow()
