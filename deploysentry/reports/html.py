from __future__ import annotations
from pathlib import Path
from collections import Counter
from jinja2 import Template
from deploysentry.models import ScanResult

HTML = r"""
<!doctype html><html><head><meta charset="utf-8"><title>DeploySentry Report</title>
<style>
body{background:#05070d;color:#d8fff8;font-family:Inter,system-ui,monospace;margin:0;padding:32px} .wrap{max-width:1180px;margin:auto}
h1{color:#39fff3;text-shadow:0 0 16px #39fff3} h2{color:#ff3df2}.card{border:1px solid #39fff3;box-shadow:0 0 18px #123b44;border-radius:12px;padding:18px;margin:16px 0;background:#090d18;overflow:auto}
table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #1e3d4a;padding:8px;text-align:left}.critical{color:#ff2e63}.high{color:#ff8a00}.medium{color:#ffd166}.low{color:#55ff99}.info{color:#39fff3} code{color:#55ff99} a{color:#39fff3}
</style></head><body><div class="wrap"><h1>DEPLOYSENTRY // Report</h1>
<div class="card"><h2>{{ r.target_domain }}</h2><p>Started: {{ r.started_at }}<br>Finished: {{ r.finished_at }}<br>Subdomains: {{ r.subdomains|length }}<br>Live services: {{ r.services|length }}<br>Shodan passive hosts: {{ r.shodan_hosts|length }}</p></div>
<div class="card"><h2>Findings by Severity</h2><ul>{% for sev in sevs %}<li class="{{sev}}">{{ sev|upper }}: {{ counts.get(sev,0) }}</li>{% endfor %}</ul></div>
<div class="card"><h2>Network Verification</h2><p>Mode: <code>{{ r.network.network_mode }}</code><br>Tor: {{ r.network.tor_enabled }}<br>Proxies: {{ r.network.proxies_loaded }} loaded / {{ r.network.proxies_healthy }} healthy / {{ r.network.proxies_failed }} failed<br>Pro Verification Mode: {{ r.network.pro_enabled }}</p></div>
<div class="card"><h2>Findings</h2>{% if not r.findings %}<p>No findings detected.</p>{% endif %}<table><tr><th>Severity</th><th>Title</th><th>Asset</th><th>URL</th><th>Evidence</th><th>Recommendation</th></tr>{% for f in r.findings %}<tr><td class="{{f.severity}}">{{f.severity|upper}}</td><td>{{f.title}}</td><td>{{f.asset}}</td><td><code>{{f.url}}</code></td><td>{{f.redacted_evidence}}</td><td>{{f.recommendation}}</td></tr>{% endfor %}</table></div>
<div class="card"><h2>Shodan Passive Enrichment</h2><p>This is passive data parsed from Shodan host pages. It is not active port verification.</p>{% if not r.shodan_hosts %}<p>No Shodan passive data collected.</p>{% else %}<table><tr><th>IP</th><th>Organization</th><th>ASN</th><th>Country</th><th>Ports</th><th>Source</th></tr>{% for h in r.shodan_hosts %}<tr><td><code>{{h.ip}}</code></td><td>{{h.organization or '—'}}</td><td>{{h.asn or '—'}}</td><td>{{h.country or '—'}}</td><td>{% for p in h.ports[:30] %}{{p.port}}{{ ', ' if not loop.last else '' }}{% endfor %}{% if h.ports|length > 30 %}, …{% endif %}</td><td><a href="{{h.url}}">Shodan</a></td></tr>{% endfor %}</table>{% endif %}</div>
</div></body></html>
"""

def write_html_report(result: ScanResult, outdir: Path) -> Path:
    counts = Counter(f.severity for f in result.findings)
    html = Template(HTML).render(r=result, counts=counts, sevs=['critical','high','medium','low','info'])
    path = outdir / 'report.html'
    path.write_text(html, encoding='utf-8')
    return path
