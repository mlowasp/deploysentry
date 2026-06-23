from __future__ import annotations
import json
import re
import uuid
from deploysentry.models import Finding, RouteMetadata

ENV_KEYS = ['APP_KEY','APP_ENV','DB_HOST','DB_PASSWORD','AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','MAIL_PASSWORD','STRIPE_SECRET']

RECOMMENDATIONS = {
    'env': 'Block access to dotfiles at the web server/CDN level and rotate any secrets that may have been exposed.',
    'git': 'Block access to VCS metadata directories, remove exposed metadata, and review repository history for leaked secrets.',
    'sourcemap': 'Do not expose production source maps unless intentionally public; remove sourcesContent and restrict access.',
    'backup': 'Remove public backups/dumps from web roots, restrict storage buckets, and rotate any exposed credentials.',
    'debug': 'Disable debug/profiler pages in production and restrict diagnostic endpoints.',
    'lock': 'Review exposed lockfiles for dependency disclosure and restrict access if not intentionally public.',
}

def _id() -> str:
    return 'sz-' + uuid.uuid4().hex[:12]


def detect(path: str, url: str, host: str, status: int, headers: dict[str,str], body: bytes, route: RouteMetadata) -> Finding | None:
    if status not in {200, 206}:
        return None
    ctype = headers.get('content-type','').lower()
    text = body[:200_000].decode('utf-8', errors='ignore')
    low = text.lower()
    length = int(headers.get('content-length') or len(body))

    if path.startswith('/.env'):
        keys = [k for k in ENV_KEYS if re.search(rf'(^|\n){re.escape(k)}\s*=', text)]
        if keys:
            return Finding(id=_id(), severity='critical', title='Exposed environment file', asset=host, url=url, path=path, evidence_type='detected_keys', redacted_evidence=keys, confidence=0.96, recommendation=RECOMMENDATIONS['env'], route=route)

    if path == '/.git/HEAD' and 'refs/heads' in text:
        return Finding(id=_id(), severity='high', title='Exposed Git HEAD metadata', asset=host, url=url, path=path, evidence_type='git_head', redacted_evidence='refs/heads detected', confidence=0.94, recommendation=RECOMMENDATIONS['git'], route=route)
    if path == '/.git/config' and '[core]' in text:
        return Finding(id=_id(), severity='critical', title='Exposed Git config metadata', asset=host, url=url, path=path, evidence_type='git_config', redacted_evidence='[core] detected', confidence=0.95, recommendation=RECOMMENDATIONS['git'], route=route)
    if path in {'/.svn/entries','/.hg/hgrc'} and length > 20:
        return Finding(id=_id(), severity='high', title='Exposed VCS metadata', asset=host, url=url, path=path, evidence_type='vcs_metadata', redacted_evidence=f'{path} appears accessible', confidence=0.80, recommendation=RECOMMENDATIONS['git'], route=route)

    if path.endswith('.map'):
        jsonish = text.strip().startswith('{')
        if jsonish and all(k in low for k in ['version','sources','mappings']):
            ev = ['version', 'sources', 'mappings']
            if 'sourcescontent' in low: ev.append('sourcesContent')
            return Finding(id=_id(), severity='medium', title='Exposed JavaScript source map', asset=host, url=url, path=path, evidence_type='sourcemap_keys', redacted_evidence=ev, confidence=0.88, recommendation=RECOMMENDATIONS['sourcemap'], route=route)

    if path.endswith(('.zip','.tar.gz')):
        if body.startswith(b'PK\x03\x04') or body.startswith(b'\x1f\x8b') or 'application/zip' in ctype or 'gzip' in ctype or length > 100_000:
            return Finding(id=_id(), severity='high', title='Exposed backup archive', asset=host, url=url, path=path, evidence_type='archive_metadata', redacted_evidence=f'content-type={ctype or "unknown"}, length={length}', confidence=0.84, recommendation=RECOMMENDATIONS['backup'], route=route)

    if path.endswith('.sql'):
        if any(x in low for x in ['create table', 'insert into', 'mysqldump', 'postgresql database dump', 'drop table']):
            return Finding(id=_id(), severity='critical', title='Exposed SQL dump', asset=host, url=url, path=path, evidence_type='sql_keywords', redacted_evidence='SQL dump keywords detected', confidence=0.91, recommendation=RECOMMENDATIONS['backup'], route=route)

    if path in {'/phpinfo.php','/info.php','/test.php'} or 'debug' in path:
        indicators = ['phpinfo()', 'laravel', 'symfony profiler', 'rails', 'django', 'stack trace', 'exception', 'whoops']
        hits = [i for i in indicators if i in low]
        if hits:
            return Finding(id=_id(), severity='medium', title='Exposed debug or diagnostic page', asset=host, url=url, path=path, evidence_type='debug_indicators', redacted_evidence=hits[:5], confidence=0.78, recommendation=RECOMMENDATIONS['debug'], route=route)

    if path.endswith(('.lock','pnpm-lock.yaml','Gemfile.lock')) and length > 100 and any(x in low for x in ['version', 'packages', 'dependencies', 'gem', 'resolved']):
        return Finding(id=_id(), severity='low', title='Exposed dependency lockfile', asset=host, url=url, path=path, evidence_type='lockfile_metadata', redacted_evidence='dependency metadata detected', confidence=0.70, recommendation=RECOMMENDATIONS['lock'], route=route)

    return None
