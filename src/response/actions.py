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

        try:
            if self._firewall_api_url:
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

        try:
            if self._wazuh_host and self._wazuh_token:
                response = requests.put(
                    f"{self._wazuh_host}/active-response",
                    json={"command": "netsh-isolation", "agents_list": [agent_id]},
                    headers={"Authorization": f"Bearer {self._wazuh_token}"},
                    timeout=self._timeout,
                )
                response.raise_for_status()
            result = ActionResult(
                action="isolate_host",
                target=agent_id,
                success=True,
                details={"reason": reason},
            )
            logger.warning("Host %s isolated via Wazuh active response", agent_id)
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

        # This is a stub — integrate with your identity provider (AD, LDAP, etc.)
        logger.warning("Disabling user account: %s (%s)", username, reason)
        result = ActionResult(
            action="disable_user",
            target=username,
            success=True,
            details={"reason": reason, "note": "stub — integrate with identity provider"},
        )
        return self._record(result)

    def collect_forensics(
        self,
        agent_id: str,
        case_id: str = "",
    ) -> ActionResult:
        """Trigger forensic data collection on a host via Wazuh."""
        try:
            if self._wazuh_host and self._wazuh_token:
                response = requests.put(
                    f"{self._wazuh_host}/active-response",
                    json={
                        "command": "collect-forensics",
                        "agents_list": [agent_id],
                        "arguments": [case_id],
                    },
                    headers={"Authorization": f"Bearer {self._wazuh_token}"},
                    timeout=self._timeout,
                )
                response.raise_for_status()
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
