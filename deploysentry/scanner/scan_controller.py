from __future__ import annotations

import asyncio
from deploysentry.models import ScanConfig, ScanResult, DNSRecord
from deploysentry.utils.validation import normalize_domain
from deploysentry.scanner.dns_enum import enumerate_subdomains
from deploysentry.scanner.resolver import resolve_many
from deploysentry.scanner.http_probe import probe_host
from deploysentry.scanner.dangerous_files import scan_service
from deploysentry.network.router import NetworkRouter
from deploysentry.network.pro_verification import resolve_api_key, verify_api_key, redact_api_key
from deploysentry.scanner.shodan_lookup import fetch_shodan_host

EventCallback = object


class ScanController:
    def __init__(self, config: ScanConfig, event_cb=None):
        self.config = config
        self.event_cb = event_cb
        self.stop_requested = False
        self.router: NetworkRouter | None = None
        self._shodan_seen_ips: set[str] = set()

    async def emit(self, event: dict) -> None:
        if self.event_cb:
            await self.event_cb(event)

    def stop(self) -> None:
        self.stop_requested = True

    async def _resolve_with_cname_expansion(self, initial_hosts: list[str], concurrency: int) -> tuple[list[DNSRecord], list[str]]:
        """Resolve hosts and feed CNAME targets back into the discovery queue.

        This treats CNAMEs as additional assets because an exposed deployment can
        live at the canonical target as well as the original hostname. A seen-set
        prevents loops such as A -> B -> A.
        """
        seen: set[str] = set()
        queued: list[str] = []
        all_records: dict[str, DNSRecord] = {}

        def add_host(host: str) -> None:
            clean = host.strip().strip('.').lower()
            if clean and clean not in seen:
                seen.add(clean)
                queued.append(clean)

        for h in initial_hosts:
            add_host(h)

        idx = 0
        while idx < len(queued):
            if self.stop_requested:
                break
            batch = queued[idx: idx + max(1, concurrency)]
            idx += len(batch)
            records = await resolve_many(batch, concurrency=concurrency)
            for rec in records:
                all_records[rec.host] = rec
                await self.emit({'type': 'dns_resolved', 'record': rec})
                for cname in rec.cname:
                    clean = cname.strip().strip('.').lower()
                    if clean and clean not in seen:
                        add_host(clean)
                        await self.emit({'type': 'subdomain_found', 'host': clean, 'source': 'cname'})

        return list(all_records.values()), sorted(seen)


    async def _enrich_shodan(self, result: ScanResult, dns_records: list[DNSRecord]) -> None:
        """Add passive Shodan host-page enrichment for every discovered A record."""
        if not self.config.shodan_enrichment:
            return
        if self.router is None:
            return

        ip_to_assets: dict[str, set[str]] = {}
        for rec in dns_records:
            for ip in rec.a:
                ip_to_assets.setdefault(ip, set()).add(rec.host)

        if not ip_to_assets:
            return

        sem = asyncio.Semaphore(min(self.config.concurrency, 10))

        async def lookup(ip: str, assets: set[str]) -> None:
            if self.stop_requested or ip in self._shodan_seen_ips:
                return
            self._shodan_seen_ips.add(ip)
            asset_label = ', '.join(sorted(assets)[:3])
            if len(assets) > 3:
                asset_label += ', …'
            await self.emit({'type': 'scan_log', 'message': f'Checking Shodan passive data for {ip}'})
            async with sem:
                if self.stop_requested:
                    return
                info = await fetch_shodan_host(ip=ip, router=self.router, timeout=self.config.timeout)
            if info is None or self.stop_requested:
                return
            result.shodan_hosts.append(info)
            await self.emit({
                'type': 'shodan_info_found',
                'ip': ip,
                'asset': asset_label,
                'assets': sorted(assets),
                'shodan': info,
            })

        await asyncio.gather(*(lookup(ip, assets) for ip, assets in ip_to_assets.items()))

    async def run(self) -> ScanResult:
        cfg = self.config
        cfg.domain = normalize_domain(cfg.domain)
        result = ScanResult(target_domain=cfg.domain)
        await self.emit({'type': 'scan_started', 'domain': cfg.domain})

        key, key_error = resolve_api_key(cfg.pro, cfg.api_key, cfg.api_key_env)
        if key_error:
            result.errors.append(key_error)
            await self.emit({'type': 'scan_error', 'message': key_error})
            cfg.pro = False
        elif key:
            await self.emit({'type': 'scan_error', 'message': f'Verifying Pro API key {redact_api_key(key)}...'})
            valid, verify_error = await verify_api_key(key, timeout=cfg.timeout)
            if not valid:
                msg = verify_error or 'API key verification failed.'
                result.errors.append(msg)
                await self.emit({'type': 'scan_error', 'message': msg})
                cfg.pro = False
            else:
                await self.emit({'type': 'scan_error', 'message': 'Pro API key verified successfully.'})

        self.router = NetworkRouter(
            proxy_file=cfg.proxy_file,
            proxy_mode=cfg.proxy_mode,
            tor=cfg.tor,
            tor_proxy=cfg.tor_proxy,
            pro=cfg.pro,
        )
        result.network = self.router.verification()

        hosts = await enumerate_subdomains(
            cfg.domain,
            use_ct=cfg.use_ct,
            timeout=cfg.timeout,
            router=self.router,
            use_rapiddns=cfg.use_rapiddns,
        )
        result.subdomains = hosts
        for h in hosts:
            await self.emit({'type': 'subdomain_found', 'host': h})
        if self.stop_requested:
            return result

        dns_records, all_hosts = await self._resolve_with_cname_expansion(hosts, concurrency=min(cfg.concurrency, 50))
        result.dns_records = dns_records
        result.subdomains = all_hosts
        resolved_hosts = [r.host for r in dns_records if r.resolved]
        if self.stop_requested:
            return result

        await self._enrich_shodan(result, dns_records)
        if self.stop_requested:
            return result

        sem = asyncio.Semaphore(min(cfg.concurrency, 50))
        services = []

        async def probe(h: str):
            async with sem:
                if self.stop_requested:
                    return []
                found = await probe_host(h, cfg.timeout, self.router)
                for s in found:
                    await self.emit({'type': 'service_found', 'service': s})
                return found

        batches = await asyncio.gather(*(probe(h) for h in resolved_hosts))
        for b in batches:
            services.extend(b)
        result.services = services
        if self.stop_requested:
            return result

        scan_sem = asyncio.Semaphore(min(cfg.per_host_concurrency, 10))

        async def scan(svc):
            async with scan_sem:
                if self.stop_requested:
                    return []
                return await scan_service(svc.url, svc.host, cfg.timeout, self.router, cfg.dangerous_delay, self.emit)

        finding_batches = await asyncio.gather(*(scan(s) for s in services))
        for fb in finding_batches:
            result.findings.extend(fb)

        if self.router:
            result.network = self.router.verification()
        result.finish()
        await self.emit({'type': 'scan_finished', 'result': result})
        return result
