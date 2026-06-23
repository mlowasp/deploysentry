from __future__ import annotations
from pathlib import Path
from datetime import datetime
from deploysentry.models import ScanResult
from .json_report import write_json_report
from .html import write_html_report
from .markdown import write_markdown_report


def report_dir(base: str, domain: str) -> Path:
    ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    path = Path(base) / domain / ts
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_reports(result: ScanResult, base: str, fmt: str = 'all') -> list[Path]:
    out = report_dir(base, result.target_domain)
    paths=[]
    if fmt in ('json','all'): paths.append(write_json_report(result, out))
    if fmt in ('html','all'): paths.append(write_html_report(result, out))
    if fmt in ('markdown','all'): paths.append(write_markdown_report(result, out))
    return paths
