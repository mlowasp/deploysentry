from __future__ import annotations
import argparse, asyncio, sys
from deploysentry.app import DeploySentryApp
from deploysentry.models import ScanConfig
from deploysentry.scanner.scan_controller import ScanController
from deploysentry.reports.writer import write_reports
from deploysentry.utils.validation import DomainValidationError
from deploysentry.network.tor import TOR_WARNING

SAFETY = "DeploySentry is intended for authorized defensive scanning only. Only scan domains you own or have permission to test."

async def run_scan(args) -> int:
    print(SAFETY)
    if args.tor:
        print(TOR_WARNING)
    cfg = ScanConfig(
        domain=args.domain,
        timeout=min(args.timeout, 30),
        concurrency=min(args.concurrency, 50),
        output_dir=args.output,
        report_format=args.report,
        proxy_file=args.proxies,
        proxy_mode=args.proxy_mode,
        tor=args.tor,
        tor_proxy=args.tor_proxy,
        pro=args.pro,
        api_key=args.api_key,
        api_key_env=args.api_key_env,
        technology_fingerprinting=not args.no_tech_fingerprint,
    )
    async def event(e):
        t=e.get('type')
        if t == 'subdomain_found': print(f"[subdomain] {e['host']}")
        elif t == 'dns_resolved' and e['record'].resolved: print(f"[dns] {e['record'].host}")
        elif t == 'service_found': print(f"[service] {e['service'].url} {e['service'].status_code}")
        elif t == 'finding_found': print(f"[finding] {e['finding'].severity.upper()} {e['finding'].url}")
        elif t == 'shodan_info_found': print(f"[shodan] {e['ip']} {len(e['shodan'].ports)} passive ports")
        elif t == 'technology_detected': print(f"[tech] {e['technology'].name} {e['technology'].url} confidence={e['technology'].confidence:.2f}")
        elif t == 'scan_log': print(f"[log] {e.get('message', '')}")
        elif t == 'scan_error': print(f"[error] {e['message']}")
        elif t == 'scan_finished': print('[done] scan finished')
    try:
        result = await ScanController(cfg, event).run()
    except DomainValidationError as exc:
        print(f'Invalid domain: {exc}', file=sys.stderr); return 2
    except Exception as exc:
        print(f'Scan failed: {exc}', file=sys.stderr); return 1
    paths = write_reports(result, args.output, args.report)
    for p in paths: print(f'Report written: {p}')
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='deploysentry', description='Defensive web surface and deployment exposure monitor')
    sub = p.add_subparsers(dest='cmd')
    scan = sub.add_parser('scan', help='Run a direct scan')
    scan.add_argument('domain')
    scan.add_argument('--report', choices=['json','html','markdown','all'], default='all')
    scan.add_argument('--concurrency', type=int, default=20)
    scan.add_argument('--timeout', type=float, default=8.0)
    scan.add_argument('--output', default='deploysentry-reports')
    scan.add_argument('--proxies')
    scan.add_argument('--proxy-mode', choices=['off','rotate','sticky'], default='off')
    scan.add_argument('--tor', action='store_true')
    scan.add_argument('--tor-proxy', default='socks5://127.0.0.1:9050')
    scan.add_argument('--pro', action='store_true')
    scan.add_argument('--api-key')
    scan.add_argument('--api-key-env', default='DEPLOYSENTRY_API_KEY')
    scan.add_argument('--no-tech-fingerprint', action='store_true', help='Disable CMS/framework/e-commerce fingerprinting')
    return p

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == 'scan':
        return asyncio.run(run_scan(args))
    DeploySentryApp().run()
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
