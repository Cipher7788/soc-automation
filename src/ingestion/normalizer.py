"""Log normalizer — converts raw logs to ECS-compatible schema."""

import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)


class NormalizedLog(BaseModel):
    """ECS-compatible normalized log record."""

    timestamp: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_type: Optional[str] = None
    severity: str = "informational"
    rule_id: Optional[str] = None
    rule_description: Optional[str] = None
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    hostname: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    raw_message: Optional[str] = None
    source: str = "unknown"
    extra: dict[str, Any] = {}

    @field_validator("severity")
    @classmethod
    def normalize_severity(cls, v: str) -> str:
        mapping = {
            "0": "informational",
            "1": "informational",
            "2": "informational",
            "3": "low",
            "4": "low",
            "5": "low",
            "6": "medium",
            "7": "medium",
            "8": "high",
            "9": "high",
            "10": "critical",
            "11": "critical",
            "12": "critical",
            "13": "critical",
            "14": "critical",
            "15": "critical",
        }
        return mapping.get(str(v).lower(), str(v).lower())


_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)


def _extract_ip(value: Any) -> Optional[str]:
    if not value:
        return None
    m = _IP_RE.search(str(value))
    return m.group(0) if m else None


def _parse_timestamp(raw: Any) -> str:
    """Return an ISO-8601 UTC timestamp string."""
    if not raw:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(raw, tz=timezone.utc).isoformat()
    ts_str = str(raw)
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return datetime.now(timezone.utc).isoformat()


class LogNormalizer:
    """Normalize raw log records into a common ECS-compatible schema.

    Supports custom field mappings passed as a dictionary during
    construction.
    """

    SEVERITY_FIELD_MAPPINGS = {
        "wazuh": "rule.level",
    }

    def __init__(self, field_mappings: Optional[dict[str, str]] = None) -> None:
        self._field_mappings = field_mappings or {}

    def normalize(self, raw: dict[str, Any], source: str = "unknown") -> NormalizedLog:
        """Normalize a single raw log record."""
        rule = raw.get("rule", {})
        agent = raw.get("agent", {})
        data = raw.get("data", {})
        src_ip_data = data.get("srcip") or data.get("src_ip") or data.get("srcIP")
        dst_ip_data = data.get("dstip") or data.get("dst_ip") or data.get("dstIP")
        network = raw.get("network", {})

        severity_raw = rule.get("level", raw.get("level", "informational"))

        return NormalizedLog(
            timestamp=_parse_timestamp(raw.get("timestamp")),
            source_ip=_extract_ip(src_ip_data or network.get("srcip")),
            destination_ip=_extract_ip(dst_ip_data or network.get("dstip")),
            event_type=raw.get("decoder", {}).get("name") or raw.get("type"),
            severity=str(severity_raw),
            rule_id=str(rule.get("id", "")),
            rule_description=rule.get("description") or rule.get("desc"),
            agent_id=str(agent.get("id", "")),
            agent_name=agent.get("name"),
            hostname=raw.get("hostname") or agent.get("name"),
            user=data.get("srcuser") or data.get("user"),
            process=data.get("process"),
            raw_message=raw.get("full_log") or raw.get("message"),
            source=source,
            extra={k: v for k, v in raw.items() if k not in {
                "timestamp", "rule", "agent", "data", "network",
                "decoder", "type", "full_log", "message", "hostname",
            }},
        )

    def normalize_batch(
        self, records: list[dict[str, Any]], source: str = "unknown"
    ) -> list[NormalizedLog]:
        """Normalize a list of raw log records."""
        normalized = []
        for rec in records:
            try:
                normalized.append(self.normalize(rec, source))
            except Exception as exc:
                logger.warning("Failed to normalize record: %s — %s", rec, exc)
        return normalized
