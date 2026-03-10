"""Alert deduplication, correlation, and severity scoring."""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

_SEVERITY_SCORE = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Alert:
    """Internal alert representation."""

    alert_id: str
    title: str
    description: str
    severity: str
    source: str
    timestamp: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)
    iocs: list[dict[str, Any]] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)
    composite_score: float = 0.0
    correlated_ids: list[str] = field(default_factory=list)
    acknowledged: bool = False


class AlertManager:
    """Manage alert lifecycle: deduplication, correlation, severity scoring.

    Deduplication prevents duplicate alerts within a configurable time
    window.  Correlation groups related alerts into incidents.  Severity
    scoring calculates a composite score from IOC confidence, asset
    criticality, and threat intelligence context.
    """

    def __init__(
        self,
        dedup_window: int = 300,
        rate_limit_per_minute: int = 100,
    ) -> None:
        self._dedup_window = dedup_window
        self._rate_limit = rate_limit_per_minute
        self._seen: dict[str, float] = {}          # fingerprint -> first seen timestamp
        self._alerts: dict[str, Alert] = {}         # alert_id -> Alert
        self._recent_count: list[float] = []        # timestamps for rate limiting
        self._incident_groups: list[list[str]] = [] # groups of correlated alert IDs

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self, alert: Alert) -> Optional[Alert]:
        """Process an alert through dedup, rate-limit, and scoring.

        Returns *None* if the alert is a duplicate or rate-limited.
        """
        if self._is_rate_limited():
            logger.warning("Alert rate limit exceeded; dropping alert: %s", alert.title)
            return None

        fingerprint = self._fingerprint(alert)
        if self._is_duplicate(fingerprint):
            logger.debug("Duplicate alert suppressed: %s", alert.title)
            return None

        alert.composite_score = self._compute_score(alert)
        self._seen[fingerprint] = time.time()
        self._alerts[alert.alert_id] = alert
        self._correlate(alert)
        self._record_rate(time.time())
        return alert

    def acknowledge(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged."""
        alert = self._alerts.get(alert_id)
        if alert:
            alert.acknowledged = True
            return True
        return False

    def get_active_alerts(self) -> list[Alert]:
        """Return all unacknowledged alerts."""
        return [a for a in self._alerts.values() if not a.acknowledged]

    def get_incidents(self) -> list[list[Alert]]:
        """Return correlated alert groups."""
        result = []
        for group_ids in self._incident_groups:
            group = [self._alerts[aid] for aid in group_ids if aid in self._alerts]
            if group:
                result.append(group)
        return result

    def purge_old(self, max_age: int = 86400) -> int:
        """Remove alerts older than *max_age* seconds. Returns count removed."""
        cutoff = time.time() - max_age
        old_ids = [aid for aid, a in self._alerts.items() if a.timestamp < cutoff]
        for aid in old_ids:
            del self._alerts[aid]
        # Clean seen fingerprints
        old_fp = [fp for fp, ts in self._seen.items() if ts < cutoff]
        for fp in old_fp:
            del self._seen[fp]
        return len(old_ids)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fingerprint(self, alert: Alert) -> str:
        """Generate a content-based fingerprint for deduplication."""
        key = f"{alert.title}|{alert.source}|{alert.severity}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _is_duplicate(self, fingerprint: str) -> bool:
        seen_at = self._seen.get(fingerprint)
        if seen_at is None:
            return False
        return (time.time() - seen_at) < self._dedup_window

    def _is_rate_limited(self) -> bool:
        now = time.time()
        self._recent_count = [t for t in self._recent_count if now - t < 60]
        return len(self._recent_count) >= self._rate_limit

    def _record_rate(self, ts: float) -> None:
        self._recent_count.append(ts)

    def _compute_score(self, alert: Alert) -> float:
        """Compute a composite severity score (0–100)."""
        base = _SEVERITY_SCORE.get(alert.severity, 1) * 20
        ioc_bonus = min(len(alert.iocs) * 5, 20)
        return min(float(base + ioc_bonus), 100.0)

    def _correlate(self, alert: Alert) -> None:
        """Group alert with existing incidents sharing common IOCs or title."""
        keywords = set(alert.title.lower().split())
        for group_ids in self._incident_groups:
            for existing_id in group_ids:
                existing = self._alerts.get(existing_id)
                if not existing:
                    continue
                existing_kw = set(existing.title.lower().split())
                if keywords & existing_kw or self._share_iocs(alert, existing):
                    group_ids.append(alert.alert_id)
                    alert.correlated_ids.extend(
                        [aid for aid in group_ids if aid != alert.alert_id]
                    )
                    return
        # No match — start a new incident group
        self._incident_groups.append([alert.alert_id])

    def _share_iocs(self, a: Alert, b: Alert) -> bool:
        a_vals = {ioc.get("value") for ioc in a.iocs}
        b_vals = {ioc.get("value") for ioc in b.iocs}
        return bool(a_vals & b_vals)
