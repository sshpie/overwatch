"""The ledger — collect, dedupe, severity-sort, and render findings.

A browsing pass revisits the same endpoints many times (SPA re-fetches, polling,
retries), so the same tell fires repeatedly. The ledger keys on
(detector, host, path) so each distinct finding is recorded once with a hit
count, then renders newest-severity-first for a human or as JSON for a pipeline.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .detectors import Finding

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _severity_rank(sev: str) -> int:
    return _SEVERITY_ORDER.get(sev, 99)


@dataclass
class Ledger:
    _by_key: dict = field(default_factory=dict)   # key -> [Finding, hit_count]

    @staticmethod
    def _key(f: Finding):
        from urllib.parse import urlparse
        return (f.detector, urlparse(f.url).netloc.lower(), urlparse(f.url).path)

    def add(self, finding: Finding) -> bool:
        """Record a finding. Returns True if it was new, False if a duplicate."""
        k = self._key(finding)
        if k in self._by_key:
            self._by_key[k][1] += 1
            return False
        self._by_key[k] = [finding, 1]
        return True

    def add_all(self, findings) -> int:
        """Add many; return the count of *new* (non-duplicate) findings."""
        return sum(1 for f in findings if self.add(f))

    def findings(self):
        """All distinct findings, severity-sorted (Critical first)."""
        items = list(self._by_key.values())
        items.sort(key=lambda pair: (_severity_rank(pair[0].severity), pair[0].detector))
        return [f for f, _ in items]

    def counts(self):
        """Severity -> number of distinct findings."""
        out = {}
        for f, _ in self._by_key.values():
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_json(self) -> str:
        rows = []
        for f, hits in sorted(
            self._by_key.values(),
            key=lambda pair: (_severity_rank(pair[0].severity), pair[0].detector),
        ):
            r = f.redacted()
            rows.append({
                "detector": r.detector, "title": r.title, "severity": r.severity,
                "vdt_class": r.vdt_class, "url": r.url, "evidence": r.evidence,
                "hits": hits,
            })
        return json.dumps({"counts": self.counts(), "findings": rows}, indent=2)

    def render(self) -> str:
        """Human-readable report; every value is redacted before it prints."""
        if not self._by_key:
            return "overwatch: no findings (surface may be clean, or nothing was exercised)"
        lines = []
        c = self.counts()
        summary = "  ".join(
            f"{c[s]}×{s}" for s in ("Critical", "High", "Medium", "Low", "Info") if s in c
        )
        lines.append(f"overwatch ledger — {summary}")
        lines.append("─" * 60)
        for f in self.findings():
            r = f.redacted()
            hits = self._by_key[self._key(f)][1]
            seen = f"  (×{hits})" if hits > 1 else ""
            lines.append(f"[{r.severity:^8}] {r.title}{seen}")
            lines.append(f"           {r.url}")
            lines.append(f"           evidence: {r.evidence}")
            lines.append(f"           vdt: {r.vdt_class}")
            lines.append("")
        return "\n".join(lines)
