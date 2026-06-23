from __future__ import annotations
import itertools
from collections import defaultdict
from .proxy_loader import ProxyEntry

class ProxyPool:
    def __init__(self, proxies: list[ProxyEntry]):
        self.proxies = proxies
        self._cycle = itertools.cycle(proxies) if proxies else None
        self._sticky: dict[str, ProxyEntry] = {}
        self.failed: set[str] = set()
        self.success_count = defaultdict(int)
        self.fail_count = defaultdict(int)

    def choose(self, host: str, mode: str) -> ProxyEntry | None:
        healthy = [p for p in self.proxies if p.label not in self.failed]
        if not healthy:
            return None
        if mode == 'sticky':
            if host not in self._sticky or self._sticky[host].label in self.failed:
                self._sticky[host] = healthy[abs(hash(host)) % len(healthy)]
            return self._sticky[host]
        if not self._cycle:
            return healthy[0]
        for _ in range(len(self.proxies)):
            p = next(self._cycle)
            if p.label not in self.failed:
                return p
        return None

    def mark_success(self, label: str) -> None:
        self.success_count[label] += 1

    def mark_failure(self, label: str) -> None:
        self.fail_count[label] += 1
        # Do not kill a proxy after one transient error.
        if self.fail_count[label] >= 3 and self.success_count[label] == 0:
            self.failed.add(label)

    @property
    def loaded(self) -> int: return len(self.proxies)
    @property
    def healthy(self) -> int: return len([p for p in self.proxies if p.label not in self.failed])
    @property
    def failed_count(self) -> int: return len(self.failed)
