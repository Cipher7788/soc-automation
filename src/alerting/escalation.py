"""Escalation manager with SLA tracking and automatic escalation."""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class EscalationPolicy:
    """Defines escalation timing and targets for a severity level."""

    severity: str
    sla_seconds: int  # Time before escalation
    contacts: list[str] = field(default_factory=list)  # email / channel IDs


@dataclass
class EscalationRecord:
    """Tracks the escalation state of a single alert."""

    alert_id: str
    severity: str
    created_at: float = field(default_factory=time.time)
    acknowledged_at: Optional[float] = None
    escalation_level: int = 0
    last_escalated_at: Optional[float] = None
    resolved: bool = False


_DEFAULT_POLICIES: list[EscalationPolicy] = [
    EscalationPolicy("critical", sla_seconds=300, contacts=["L1", "L2", "management"]),
    EscalationPolicy("high", sla_seconds=900, contacts=["L1", "L2"]),
    EscalationPolicy("medium", sla_seconds=3600, contacts=["L1"]),
    EscalationPolicy("low", sla_seconds=86400, contacts=["L1"]),
]

_ESCALATION_CHAIN = ["L1", "L2", "L3", "management"]


class EscalationManager:
    """Manage alert escalation policies and SLA timers.

    Tracks alerts and auto-escalates any that have not been acknowledged
    within the SLA window for their severity level.
    """

    def __init__(
        self,
        policies: Optional[list[EscalationPolicy]] = None,
        escalation_callback: Optional[Callable[[EscalationRecord, str], None]] = None,
    ) -> None:
        self._policies: dict[str, EscalationPolicy] = {
            p.severity: p for p in (policies or _DEFAULT_POLICIES)
        }
        self._records: dict[str, EscalationRecord] = {}
        self._callback = escalation_callback

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_alert(self, alert_id: str, severity: str) -> EscalationRecord:
        """Register a new alert for SLA tracking."""
        record = EscalationRecord(alert_id=alert_id, severity=severity)
        self._records[alert_id] = record
        logger.info("Registered alert %s (severity=%s) for SLA tracking", alert_id, severity)
        return record

    def acknowledge(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged, stopping further escalation."""
        record = self._records.get(alert_id)
        if not record:
            return False
        record.acknowledged_at = time.time()
        logger.info("Alert %s acknowledged", alert_id)
        return True

    def resolve(self, alert_id: str) -> bool:
        """Mark an alert as resolved."""
        record = self._records.get(alert_id)
        if not record:
            return False
        record.resolved = True
        return True

    def check_escalations(self) -> list[tuple[EscalationRecord, str]]:
        """Check all active alerts for SLA breaches and escalate as needed.

        Returns a list of (record, contact) tuples that were escalated.
        """
        now = time.time()
        escalated = []
        for record in list(self._records.values()):
            if record.resolved or record.acknowledged_at is not None:
                continue
            policy = self._policies.get(record.severity)
            if not policy:
                continue
            age = now - record.created_at
            if age >= policy.sla_seconds:
                contact = self._get_next_contact(record, policy)
                if contact:
                    record.escalation_level += 1
                    record.last_escalated_at = now
                    logger.warning(
                        "Escalating alert %s (level=%d) to %s",
                        record.alert_id, record.escalation_level, contact,
                    )
                    if self._callback:
                        self._callback(record, contact)
                    escalated.append((record, contact))
        return escalated

    def get_sla_status(self, alert_id: str) -> Optional[dict[str, Any]]:
        """Return SLA status for a given alert."""
        record = self._records.get(alert_id)
        if not record:
            return None
        policy = self._policies.get(record.severity)
        elapsed = time.time() - record.created_at
        return {
            "alert_id": alert_id,
            "severity": record.severity,
            "elapsed_seconds": elapsed,
            "sla_seconds": policy.sla_seconds if policy else None,
            "sla_breached": elapsed >= (policy.sla_seconds if policy else float("inf")),
            "acknowledged": record.acknowledged_at is not None,
            "escalation_level": record.escalation_level,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_next_contact(
        self, record: EscalationRecord, policy: EscalationPolicy
    ) -> Optional[str]:
        chain = policy.contacts if policy.contacts else _ESCALATION_CHAIN
        idx = record.escalation_level
        if idx < len(chain):
            return chain[idx]
        return None
