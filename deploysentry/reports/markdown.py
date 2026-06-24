from __future__ import annotations
from pathlib import Path
from collections import Counter
from deploysentry.models import ScanResult


def _technology_section(result: ScanResult) -> list[str]:
    if not result.technologies:
        return []
    lines = [
        "",
        "## Technology Fingerprints",
        "",
        "Detected CMS, hosted builders, e-commerce platforms, frameworks, and exposed admin surfaces.",
        "",
        "| Technology | Category | Asset | URL | Confidence | Evidence |",
        "|---|---|---|---|---:|---|",
    ]
    for tech in sorted(result.technologies, key=lambda t: (t.asset, -t.confidence, t.name)):
        evidence = ", ".join(tech.evidence[:5]) or "—"
        lines.append(
            f"| {tech.name} | {tech.version or '—'} | {tech.category} | {tech.asset} | {tech.url} | "
            f"{tech.confidence:.2f} | {evidence} |"
        )
    return lines


def _shodan_section(result: ScanResult) -> list[str]:
    if not result.shodan_hosts:
        return []
    lines = [
        "",
        "## Shodan Passive Enrichment",
        "",
        "This is passive data parsed from Shodan host pages. It is not active port verification.",
        "",
        "| IP | Organization | ASN | Country | Ports |",
        "|---|---|---|---|---|",
    ]
    for host in result.shodan_hosts:
        ports = ", ".join(str(port.port) for port in host.ports[:30])
        if len(host.ports) > 30:
            ports += ", …"
        lines.append(
            f"| {host.ip} | {host.organization or '—'} | {host.asn or '—'} | "
            f"{host.country or '—'} | {ports or '—'} |"
        )
    return lines


def write_markdown_report(result: ScanResult, outdir: Path) -> Path:
    counts = Counter(f.severity for f in result.findings)
    lines = [
        f"# DeploySentry Report: `{result.target_domain}`", "",
        "## Scan Metadata", "",
        f"- Started: {result.started_at}",
        f"- Finished: {result.finished_at}",
        f"- Subdomains found: {len(result.subdomains)}",
        f"- Live services: {len(result.services)}",
        f"- Technologies detected: {len(result.technologies)}",
        f"- Shodan passive hosts: {len(result.shodan_hosts)}",
        "",
        "## Findings by Severity", "",
    ]
    for sev in ['critical','high','medium','low','info']:
        lines.append(f"- {sev.upper()}: {counts.get(sev,0)}")
    lines += ["", "## Network Verification", "", f"- Network mode: {result.network.network_mode}", f"- Tor enabled: {result.network.tor_enabled}", f"- Proxies: {result.network.proxies_loaded} loaded / {result.network.proxies_healthy} healthy / {result.network.proxies_failed} failed", f"- Pro Verification Mode: {result.network.pro_enabled}", "", "## Findings", ""]
    if not result.findings:
        lines.append("No findings detected.")
    for f in result.findings:
        lines += [
            f"### {f.severity.upper()} - {f.title}", "",
            f"- Asset: `{f.asset}`",
            f"- URL: `{f.url}`",
            f"- Path: `{f.path}`",
            f"- Evidence type: `{f.evidence_type}`",
            f"- Safe evidence: `{f.redacted_evidence}`",
            f"- Confidence: {f.confidence}",
            f"- Route: {f.route.route_label}",
            f"- Recommendation: {f.recommendation}", "",
        ]
    lines += _technology_section(result)
    lines += _shodan_section(result)
    path = outdir / 'report.md'
    path.write_text('\n'.join(lines), encoding='utf-8')
    return path
