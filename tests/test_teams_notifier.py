"""Tests for the TeamsNotifier module."""

import pytest
from unittest.mock import MagicMock, patch

from src.alerting.teams_notifier import TeamsNotifier


class TestTeamsNotifier:
    @pytest.fixture
    def notifier(self):
        return TeamsNotifier(webhook_url="https://example.webhook.office.com/webhookb2/test")

    def test_send_returns_false_without_webhook_url(self):
        notifier = TeamsNotifier(webhook_url="")
        result = notifier.send("Test", "Description", "high")
        assert result is False

    def test_send_posts_to_webhook_url(self, notifier):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        with patch("requests.post", return_value=mock_resp) as mock_post:
            result = notifier.send("Test Alert", "Description", "high", details={"host": "server-01"})
        mock_post.assert_called_once()
        assert result is True

    def test_send_includes_severity_in_payload(self, notifier):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        import json
        with patch("requests.post", return_value=mock_resp) as mock_post:
            notifier.send("Test", "Desc", "critical")
        call_kwargs = mock_post.call_args[1]
        payload = json.loads(call_kwargs["data"])
        body_text = str(payload)
        assert "CRITICAL" in body_text or "critical" in body_text.lower()

    def test_send_returns_false_on_request_exception(self, notifier):
        with patch("requests.post", side_effect=Exception("Connection error")):
            result = notifier.send("Test", "Desc", "high")
        assert result is False

    def test_build_facts_with_priority_keys(self, notifier):
        details = {"severity": "high", "host": "server-01", "custom_key": "custom_value"}
        facts = notifier._build_facts(details)
        assert len(facts) > 0
        titles = [f["title"] for f in facts]
        assert "Severity" in titles
        assert "Host" in titles

    def test_send_uses_adaptive_card_format(self, notifier):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        import json
        with patch("requests.post", return_value=mock_resp) as mock_post:
            notifier.send("Test", "Desc", "medium")
        call_kwargs = mock_post.call_args[1]
        payload = json.loads(call_kwargs["data"])
        assert payload["type"] == "message"
        assert "attachments" in payload
        attachment = payload["attachments"][0]
        assert "AdaptiveCard" in attachment["content"]["type"]
