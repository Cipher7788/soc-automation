"""Multi-channel notification system (email, Slack, webhook)."""

import json
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Optional

import requests
from jinja2 import Environment, BaseLoader

logger = logging.getLogger(__name__)

_EMAIL_TEMPLATE = """
<html><body>
<h2 style="color:red;">SOC Alert: {{ title }}</h2>
<table>
  <tr><td><b>Severity</b></td><td>{{ severity }}</td></tr>
  <tr><td><b>Source</b></td><td>{{ source }}</td></tr>
  <tr><td><b>Score</b></td><td>{{ score }}</td></tr>
</table>
<h3>Description</h3>
<p>{{ description }}</p>
</body></html>
"""

_SLACK_TEMPLATE = """{
  "text": ":rotating_light: *SOC Alert — {{ severity | upper }}*",
  "attachments": [{
    "color": "{% if severity == 'critical' %}danger{% elif severity == 'high' %}warning{% else %}good{% endif %}",
    "title": "{{ title }}",
    "text": "{{ description | truncate(200) }}",
    "fields": [
      {"title": "Severity", "value": "{{ severity }}", "short": true},
      {"title": "Source", "value": "{{ source }}", "short": true},
      {"title": "Score", "value": "{{ score }}", "short": true}
    ]
  }]
}"""

_jinja = Environment(loader=BaseLoader(), autoescape=False)


class Notifier:
    """Send alerts via email, Slack, and generic webhooks.

    Severity-based routing ensures critical alerts are sent immediately
    to all channels while lower-severity alerts use configured channels.
    """

    def __init__(
        self,
        smtp_host: str = "",
        smtp_port: int = 587,
        smtp_username: str = "",
        smtp_password: str = "",
        smtp_from: str = "",
        smtp_to: str = "",
        slack_webhook_url: str = "",
        webhook_url: str = "",
        timeout: int = 15,
    ) -> None:
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._smtp_username = smtp_username
        self._smtp_password = smtp_password
        self._smtp_from = smtp_from
        self._smtp_to = smtp_to
        self._slack_url = slack_webhook_url
        self._webhook_url = webhook_url
        self._timeout = timeout

    def notify(
        self,
        title: str,
        description: str,
        severity: str,
        source: str = "SOC-Automation",
        score: float = 0.0,
        channels: Optional[list[str]] = None,
    ) -> dict[str, bool]:
        """Send a notification on all applicable channels.

        Returns a mapping of channel name to success flag.
        """
        context = {
            "title": title,
            "description": description,
            "severity": severity,
            "source": source,
            "score": score,
        }

        if channels is None:
            # Route by severity
            channels = self._default_channels(severity)

        results: dict[str, bool] = {}

        if "email" in channels:
            results["email"] = self._send_email(context)
        if "slack" in channels:
            results["slack"] = self._send_slack(context)
        if "webhook" in channels:
            results["webhook"] = self._send_webhook(context)

        return results

    # ------------------------------------------------------------------
    # Channel implementations
    # ------------------------------------------------------------------

    def _send_email(self, context: dict[str, Any]) -> bool:
        if not self._smtp_host or not self._smtp_to:
            logger.debug("Email not configured; skipping")
            return False
        try:
            html = _jinja.from_string(_EMAIL_TEMPLATE).render(**context)
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[SOC Alert] {context['severity'].upper()}: {context['title']}"
            msg["From"] = self._smtp_from
            msg["To"] = self._smtp_to
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=self._timeout) as server:
                server.ehlo()
                server.starttls()
                if self._smtp_username:
                    server.login(self._smtp_username, self._smtp_password)
                server.sendmail(self._smtp_from, self._smtp_to.split(","), msg.as_string())
            logger.info("Email alert sent to %s", self._smtp_to)
            return True
        except Exception as exc:
            logger.error("Failed to send email: %s", exc)
            return False

    def _send_slack(self, context: dict[str, Any]) -> bool:
        if not self._slack_url:
            logger.debug("Slack webhook not configured; skipping")
            return False
        try:
            payload_str = _jinja.from_string(_SLACK_TEMPLATE).render(**context)
            payload = json.loads(payload_str)
            response = requests.post(
                self._slack_url, json=payload, timeout=self._timeout
            )
            response.raise_for_status()
            logger.info("Slack alert sent")
            return True
        except Exception as exc:
            logger.error("Failed to send Slack alert: %s", exc)
            return False

    def _send_webhook(self, context: dict[str, Any]) -> bool:
        if not self._webhook_url:
            logger.debug("Webhook URL not configured; skipping")
            return False
        try:
            response = requests.post(
                self._webhook_url, json=context, timeout=self._timeout
            )
            response.raise_for_status()
            logger.info("Webhook alert sent to %s", self._webhook_url)
            return True
        except Exception as exc:
            logger.error("Failed to send webhook alert: %s", exc)
            return False

    def _default_channels(self, severity: str) -> list[str]:
        if severity in ("critical", "high"):
            return ["email", "slack", "webhook"]
        elif severity == "medium":
            return ["slack", "webhook"]
        else:
            return ["webhook"]
