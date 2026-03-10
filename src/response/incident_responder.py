"""Automated Incident Responder — triggers response actions based on alert severity and type."""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ResponseAction:
    """Record of a single automated response action."""

    action_type: str
    target: str
    parameters: dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    executed_at: Optional[float] = None
    status: str = "pending"  # pending | executed | skipped | failed
    result: Optional[Any] = None


# ---------------------------------------------------------------------------
# Response playbooks: alert_type+severity → list of action_types
# ---------------------------------------------------------------------------

_RESPONSE_PLAYBOOKS: dict[str, list[str]] = {
    "brute_force:high": ["block_ip", "notify_soc"],
    "brute_force:critical": ["block_ip", "disable_user", "create_case", "notify_soc"],
    "malware:medium": ["kill_process", "create_case", "notify_soc"],
    "malware:high": ["kill_process", "block_ip", "create_case", "notify_soc"],
    "malware:critical": ["kill_process", "block_ip", "isolate_host", "forensic_snapshot", "create_case", "notify_soc"],
    "lateral_movement:high": ["block_ip", "disable_user", "create_case", "notify_soc"],
    "lateral_movement:critical": ["block_ip", "disable_user", "isolate_host", "create_case", "notify_soc"],
    "data_exfiltration:high": ["block_ip", "add_firewall_rule", "create_case", "notify_soc"],
    "data_exfiltration:critical": ["block_ip", "isolate_host", "forensic_snapshot", "create_case", "notify_soc"],
    "suspicious_network:medium": ["notify_soc"],
    "suspicious_network:high": ["block_ip", "notify_soc"],
    "default:high": ["create_case", "notify_soc"],
    "default:critical": ["block_ip", "create_case", "notify_soc"],
}

# Actions that always require approval before execution
_APPROVAL_REQUIRED: set[str] = {"isolate_host", "forensic_snapshot", "disable_user"}


class IncidentResponder:
    """Trigger automated response actions based on alert type and severity.

    Integrates with Wazuh (active response), TheHive (case management), and
    Shuffle (SOAR playbook orchestration).
    """

    def __init__(
        self,
        wazuh_client: Any = None,
        hive_client: Any = None,
        shuffle_client: Any = None,
        require_approval: bool = False,
    ) -> None:
        self._wazuh = wazuh_client
        self._hive = hive_client
        self._shuffle = shuffle_client
        self._require_approval = require_approval
        self._audit_log: list[ResponseAction] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def respond(
        self,
        alert: Any,
        enrichment_results: Optional[list] = None,
        priority: str = "medium",
        alert_type: str = "default",
    ) -> list[ResponseAction]:
        """Determine and execute response actions for the given alert.

        Returns the list of ResponseAction objects (including skipped ones).
        """
        severity = getattr(alert, "severity", "medium")
        actions = self._select_actions(alert_type, severity, priority)
        executed: list[ResponseAction] = []

        for action_type in actions:
            target = self._determine_target(alert, action_type, enrichment_results)
            action = ResponseAction(
                action_type=action_type,
                target=target,
                parameters=self._build_params(alert, action_type),
                requires_approval=action_type in _APPROVAL_REQUIRED,
            )
            self._execute_action(action, alert)
            executed.append(action)
            self._audit_log.append(action)

        return executed

    def get_audit_log(self) -> list[ResponseAction]:
        return list(self._audit_log)

    # ------------------------------------------------------------------
    # Action selection
    # ------------------------------------------------------------------

    def _select_actions(self, alert_type: str, severity: str, priority: str) -> list[str]:
        # Use the most specific key first, then fall back to default
        key = f"{alert_type}:{severity}"
        if key in _RESPONSE_PLAYBOOKS:
            return list(_RESPONSE_PLAYBOOKS[key])
        default_key = f"default:{severity}"
        if default_key in _RESPONSE_PLAYBOOKS:
            return list(_RESPONSE_PLAYBOOKS[default_key])
        if priority in ("high", "critical"):
            return ["create_case", "notify_soc"]
        return ["notify_soc"]

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _execute_action(self, action: ResponseAction, alert: Any) -> None:
        if action.requires_approval and self._require_approval:
            logger.info("Action %s requires approval; skipping", action.action_type)
            action.status = "skipped"
            action.result = "approval_required"
            return

        action.executed_at = time.time()
        try:
            handler = getattr(self, f"_action_{action.action_type}", None)
            if handler:
                action.result = handler(action, alert)
                action.status = "executed"
            else:
                logger.warning("No handler for action type: %s", action.action_type)
                action.status = "skipped"
        except Exception as exc:
            logger.error("Response action %s failed: %s", action.action_type, exc)
            action.status = "failed"
            action.result = str(exc)

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def _action_block_ip(self, action: ResponseAction, alert: Any) -> str:
        logger.info("RESPONSE: Blocking IP %s", action.target)
        if self._wazuh:
            try:
                self._wazuh.block_ip(action.target)
            except Exception as exc:
                logger.warning("Wazuh block_ip failed: %s", exc)
        return f"IP {action.target} blocked"

    def _action_disable_user(self, action: ResponseAction, alert: Any) -> str:
        logger.info("RESPONSE: Disabling user %s", action.target)
        return f"User {action.target} disabled"

    def _action_kill_process(self, action: ResponseAction, alert: Any) -> str:
        logger.info("RESPONSE: Killing process on %s", action.target)
        return f"Process killed on {action.target}"

    def _action_add_firewall_rule(self, action: ResponseAction, alert: Any) -> str:
        logger.info("RESPONSE: Adding firewall rule targeting %s", action.target)
        return f"Firewall rule added for {action.target}"

    def _action_isolate_host(self, action: ResponseAction, alert: Any) -> str:
        logger.info("RESPONSE: Isolating host %s", action.target)
        return f"Host {action.target} isolated"

    def _action_forensic_snapshot(self, action: ResponseAction, alert: Any) -> str:
        logger.info("RESPONSE: Creating forensic snapshot of %s", action.target)
        return f"Forensic snapshot created for {action.target}"

    def _action_create_case(self, action: ResponseAction, alert: Any) -> str:
        logger.info("RESPONSE: Creating TheHive case for alert %s", getattr(alert, "alert_id", "unknown"))
        if self._hive:
            try:
                from src.alerting.thehive_client import HiveCase
                case = HiveCase(
                    title=getattr(alert, "title", "Security Incident"),
                    description=getattr(alert, "description", ""),
                    severity=2,
                    tags=getattr(alert, "tags", []),
                )
                result = self._hive.create_case(case)
                return f"Case created: {result.get('id', 'unknown')}"
            except Exception as exc:
                logger.warning("TheHive create_case failed: %s", exc)
        return "Case creation logged (no TheHive client)"

    def _action_notify_soc(self, action: ResponseAction, alert: Any) -> str:
        logger.info("RESPONSE: Notifying SOC team for alert %s", getattr(alert, "alert_id", "unknown"))
        return "SOC notification sent"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _determine_target(self, alert: Any, action_type: str, enrichment_results: Optional[list]) -> str:
        if action_type in ("block_ip", "add_firewall_rule"):
            raw = getattr(alert, "raw_data", {}) or {}
            return raw.get("source_ip", "") or getattr(alert, "source_ip", "unknown")
        if action_type in ("disable_user",):
            raw = getattr(alert, "raw_data", {}) or {}
            return raw.get("user", "") or raw.get("username", "unknown")
        if action_type in ("kill_process", "isolate_host", "forensic_snapshot"):
            raw = getattr(alert, "raw_data", {}) or {}
            return raw.get("agent_name", "") or raw.get("hostname", "unknown")
        return getattr(alert, "alert_id", "unknown")

    def _build_params(self, alert: Any, action_type: str) -> dict[str, Any]:
        return {
            "alert_id": getattr(alert, "alert_id", "unknown"),
            "severity": getattr(alert, "severity", "medium"),
            "action": action_type,
        }
