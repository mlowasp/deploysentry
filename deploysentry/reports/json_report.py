from __future__ import annotations
import json
from pathlib import Path
from deploysentry.models import ScanResult


def write_json_report(result: ScanResult, outdir: Path) -> Path:
    path = outdir / 'report.json'
    path.write_text(result.model_dump_json(indent=2), encoding='utf-8')
    return path
