"""Microsoft Teams Notifier — sends Adaptive Card alerts to a Teams incoming webhook."""

import json
import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "FF0000",  # red
    "high": "FFA500",      # orange
    "medium": "FFD700",    # yellow / gold
    "low": "008000",       # green
}


class TeamsNotifier:
    """Send SOC alert notifications to Microsoft Teams via an incoming webhook.

    Uses the Adaptive Card format for rich formatting with severity colour coding.
    """

    def __init__(self, webhook_url: str = "", timeout: int = 15) -> None:
        self._webhook_url = webhook_url
        self._timeout = timeout

    def send(
        self,
        title: str,
        description: str,
        severity: str,
        details: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Post an Adaptive Card message to the configured Teams channel.

        Returns True on success, False on failure.
        """
        if not self._webhook_url:
            logger.debug("Teams webhook URL not configured; skipping")
            return False

        severity_lower = severity.lower()
        color = _SEVERITY_COLORS.get(severity_lower, "808080")
        facts = self._build_facts(details or {})

        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": f"🚨 SOC ALERT — {severity.upper()}",
                                "size": "Large",
                                "weight": "Bolder",
                                "color": "Attention" if severity_lower in ("critical", "high") else "Warning",
                            },
                            {
                                "type": "TextBlock",
                                "text": title,
                                "size": "Medium",
                                "weight": "Bolder",
                                "wrap": True,
                            },
                            {
                                "type": "TextBlock",
                                "text": description,
                                "wrap": True,
                                "isSubtle": True,
                            },
                            {
                                "type": "FactSet",
                                "facts": facts,
                            },
                        ],
                        "msteams": {
                            "width": "Full",
                        },
                    },
                }
            ],
        }

        try:
            resp = requests.post(
                self._webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            logger.info("Teams alert sent: %s", title)
            return True
        except Exception as exc:
            logger.error("Failed to send Teams alert: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_facts(self, details: dict[str, Any]) -> list[dict[str, str]]:
        """Convert a flat details dict to Adaptive Card FactSet entries."""
        facts = []
        priority_keys = ["severity", "host", "mitre_technique", "response_action", "iocs"]
        for key in priority_keys:
            if key in details:
                facts.append({"title": key.replace("_", " ").title(), "value": str(details[key])})
        for key, val in details.items():
            if key not in priority_keys:
                facts.append({"title": key.replace("_", " ").title(), "value": str(val)})
        return facts
