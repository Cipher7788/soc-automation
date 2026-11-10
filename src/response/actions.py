"""Automated response actions (block IP, isolate host, disable user, forensics)."""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class ActionResult:
    """Result of an automated response action."""

    action: str
    target: str
    success: bool
    timestamp: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class ResponseActions:
    """Collection of automated response actions.

    All critical-severity actions require explicit *confirmed=True*.
    Every action is logged to an audit trail.
    """

    def __init__(
        self,
        wazuh_host: str = "",
        wazuh_token: str = "",
        firewall_api_url: str = "",
        firewall_api_key: str = "",
        timeout: int = 30,
        audit_callback: Optional[Callable[[ActionResult], None]] = None,
    ) -> None:
        self._wazuh_host = wazuh_host.rstrip("/")
        self._wazuh_token = wazuh_token
        self._firewall_api_url = firewall_api_url.rstrip("/")
        self._firewall_api_key = firewall_api_key
        self._timeout = timeout
        self._audit_callback = audit_callback
        self._audit_log: list[ActionResult] = []

    # ------------------------------------------------------------------
    # Public actions
    # ------------------------------------------------------------------

    def block_ip(
        self,
        ip: str,
        reason: str = "",
        confirmed: bool = False,
    ) -> ActionResult:
        """Block a malicious IP via the firewall API."""
        if not confirmed:
            return self._unconfirmed("block_ip", ip)

        if not self._firewall_api_url:
            return self._record(ActionResult(
                action="block_ip", target=ip, success=False,
                error="Firewall API not configured",
            ))

        try:
            response = requests.post(
                f"{self._firewall_api_url}/block",
                json={"ip": ip, "reason": reason},
                headers={"Authorization": f"Bearer {self._firewall_api_key}"},
                timeout=self._timeout,
            )
            response.raise_for_status()
            result = ActionResult(
                action="block_ip",
                target=ip,
                success=True,
                details={"reason": reason},
            )
            logger.info("Blocked IP %s (%s)", ip, reason)
        except Exception as exc:
            result = ActionResult(
                action="block_ip",
                target=ip,
                success=False,
                error=str(exc),
            )
            logger.error("Failed to block IP %s: %s", ip, exc)

        return self._record(result)

    def isolate_host(
        self,
        agent_id: str,
        reason: str = "",
        confirmed: bool = False,
    ) -> ActionResult:
        """Isolate a compromised host via Wazuh active response."""
        if not confirmed:
            return self._unconfirmed("isolate_host", agent_id)

        if not (agent_id.isascii() and agent_id.isdecimal() and len(agent_id) >= 3):
            return self._record(ActionResult(
                action="isolate_host", target=agent_id, success=False,
                error="Expected a single numeric Wazuh agent ID",
            ))
        if not self._wazuh_host or not self._wazuh_token:
            return self._record(ActionResult(
                action="isolate_host", target=agent_id, success=False,
                error="Wazuh active response not configured",
            ))

        try:
            response = requests.put(
                f"{self._wazuh_host}/active-response",
                params={"agents_list": agent_id},
                json={"command": "netsh-isolation"},
                headers={"Authorization": f"Bearer {self._wazuh_token}"},
                timeout=self._timeout,
            )
            response.raise_for_status()
            outcome = response.json().get("data", {})
            if outcome.get("total_failed_items") or agent_id not in outcome.get("affected_items", []):
                raise RuntimeError("Wazuh did not accept the command for the requested agent")
            result = ActionResult(
                action="isolate_host",
                target=agent_id,
                success=True,
                details={"reason": reason},
            )
            logger.info("Wazuh accepted the isolation command for agent %s", agent_id)
        except Exception as exc:
            result = ActionResult(
                action="isolate_host",
                target=agent_id,
                success=False,
                error=str(exc),
            )
            logger.error("Failed to isolate host %s: %s", agent_id, exc)

        return self._record(result)

    def disable_user(
        self,
        username: str,
        reason: str = "",
        confirmed: bool = False,
    ) -> ActionResult:
        """Disable a compromised user account."""
        if not confirmed:
            return self._unconfirmed("disable_user", username)

        return self._record(ActionResult(
            action="disable_user", target=username, success=False,
            details={"reason": reason}, error="Identity provider integration unavailable",
        ))

    def collect_forensics(
        self,
        agent_id: str,
        case_id: str = "",
    ) -> ActionResult:
        """Trigger forensic data collection on a host via Wazuh."""
        if not (agent_id.isascii() and agent_id.isdecimal() and len(agent_id) >= 3):
            return self._record(ActionResult(
                action="collect_forensics", target=agent_id, success=False, details={"case_id": case_id},
                error="Expected a single numeric Wazuh agent ID",
            ))
        if not self._wazuh_host or not self._wazuh_token:
            return self._record(ActionResult(
                action="collect_forensics", target=agent_id, success=False,
                details={"case_id": case_id}, error="Wazuh active response not configured",
            ))

        try:
            response = requests.put(
                f"{self._wazuh_host}/active-response",
                params={"agents_list": agent_id},
                json={"command": "collect-forensics", "arguments": [case_id]},
                headers={"Authorization": f"Bearer {self._wazuh_token}"},
                timeout=self._timeout,
            )
            response.raise_for_status()
            outcome = response.json().get("data", {})
            if outcome.get("total_failed_items") or agent_id not in outcome.get("affected_items", []):
                raise RuntimeError("Wazuh did not accept the command for the requested agent")
            result = ActionResult(
                action="collect_forensics",
                target=agent_id,
                success=True,
                details={"case_id": case_id},
            )
            logger.info("Forensic collection triggered for agent %s", agent_id)
        except Exception as exc:
            result = ActionResult(
                action="collect_forensics",
                target=agent_id,
                success=False,
                error=str(exc),
            )
            logger.error("Failed to collect forensics for %s: %s", agent_id, exc)

        return self._record(result)

    def get_audit_log(self) -> list[ActionResult]:
        """Return all recorded response action results."""
        return list(self._audit_log)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _unconfirmed(self, action: str, target: str) -> ActionResult:
        result = ActionResult(
            action=action,
            target=target,
            success=False,
            error="Action requires confirmation (confirmed=True)",
        )
        logger.info("Action %s on %s skipped: confirmation required", action, target)
        return self._record(result)

    def _record(self, result: ActionResult) -> ActionResult:
        self._audit_log.append(result)
        if self._audit_callback:
            try:
                self._audit_callback(result)
            except Exception as exc:
                logger.error("Audit callback error: %s", exc)
        return result
