from __future__ import annotations
from pathlib import Path
from collections import Counter
from deploysentry.models import ScanResult


def write_markdown_report(result: ScanResult, outdir: Path) -> Path:
    counts = Counter(f.severity for f in result.findings)
    lines = [
        f"# DeploySentry Report: `{result.target_domain}`", "",
        "## Scan Metadata", "",
        f"- Started: {result.started_at}",
        f"- Finished: {result.finished_at}",
        f"- Subdomains found: {len(result.subdomains)}",
        f"- Live services: {len(result.services)}",
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
    path = outdir / 'report.md'
    path.write_text('\n'.join(lines), encoding='utf-8')
    return path
