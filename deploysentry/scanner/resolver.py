from __future__ import annotations
import asyncio
import dns.asyncresolver
from deploysentry.models import DNSRecord

async def resolve_host(host: str) -> DNSRecord:
    rec = DNSRecord(host=host)
    resolver = dns.asyncresolver.Resolver()
    async def q(rtype: str) -> list[str]:
        try:
            ans = await resolver.resolve(host, rtype, lifetime=4.0)
            return [str(x).rstrip('.') for x in ans]
        except Exception:
            return []
    rec.a, rec.aaaa, rec.cname = await asyncio.gather(q('A'), q('AAAA'), q('CNAME'))
    rec.resolved = bool(rec.a or rec.aaaa or rec.cname)
    if not rec.resolved:
        rec.error = 'No A/AAAA/CNAME records found'
    return rec

async def resolve_many(hosts: list[str], concurrency: int = 20):
    sem = asyncio.Semaphore(concurrency)
    async def one(h):
        async with sem:
            return await resolve_host(h)
    return await asyncio.gather(*(one(h) for h in hosts))
