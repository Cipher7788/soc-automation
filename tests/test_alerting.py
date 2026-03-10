"""Tests for the alerting module."""

import time
import pytest
from unittest.mock import MagicMock, patch

from src.alerting.thehive_client import TheHiveClient, HiveAlert, HiveCase, TLP_AMBER
from src.alerting.alert_manager import AlertManager, Alert
from src.alerting.notifier import Notifier
from src.alerting.escalation import EscalationManager, EscalationPolicy


# ─── TheHiveClient Tests ──────────────────────────────────────────────────────

class TestTheHiveClient:
    def test_create_alert_calls_api(self):
        client = TheHiveClient("http://thehive:9000", "api-key-123")
        mock_response = MagicMock()
        mock_response.json.return_value = {"id": "alert-1", "status": "New"}
        mock_response.raise_for_status = MagicMock()

        with patch.object(client._session, "post", return_value=mock_response) as mock_post:
            alert = HiveAlert(
                title="Test Alert",
                description="Test description",
                severity=2,
                tags=["test"],
            )
            result = client.create_alert(alert)

        assert result["id"] == "alert-1"
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["json"]["title"] == "Test Alert"

    def test_create_case_calls_api(self):
        client = TheHiveClient("http://thehive:9000", "api-key-123")
        mock_response = MagicMock()
        mock_response.json.return_value = {"id": "case-1", "status": "Open"}
        mock_response.raise_for_status = MagicMock()

        with patch.object(client._session, "post", return_value=mock_response):
            case = HiveCase(title="Test Case", description="Test case description")
            result = client.create_case(case)

        assert result["id"] == "case-1"

    def test_add_observable_calls_api(self):
        client = TheHiveClient("http://thehive:9000", "api-key-123")
        mock_response = MagicMock()
        mock_response.json.return_value = {"id": "obs-1"}
        mock_response.raise_for_status = MagicMock()

        with patch.object(client._session, "post", return_value=mock_response):
            result = client.add_observable(
                case_id="case-1",
                data_type="ip",
                data="192.168.1.1",
                message="Suspicious IP",
            )

        assert result["id"] == "obs-1"

    def test_get_case_calls_api(self):
        client = TheHiveClient("http://thehive:9000", "api-key-123")
        mock_response = MagicMock()
        mock_response.json.return_value = {"id": "case-1", "title": "Test"}
        mock_response.raise_for_status = MagicMock()

        with patch.object(client._session, "get", return_value=mock_response):
            result = client.get_case("case-1")

        assert result["id"] == "case-1"

    def test_update_case(self):
        client = TheHiveClient("http://thehive:9000", "api-key-123")
        mock_response = MagicMock()
        mock_response.json.return_value = {"id": "case-1", "status": "InProgress"}
        mock_response.raise_for_status = MagicMock()

        with patch.object(client._session, "patch", return_value=mock_response):
            result = client.update_case("case-1", {"status": "InProgress"})

        assert result["status"] == "InProgress"

    def test_auth_header_is_set(self):
        client = TheHiveClient("http://thehive:9000", "my-api-key")
        assert "Authorization" in client._session.headers
        assert "my-api-key" in client._session.headers["Authorization"]


# ─── AlertManager Tests ────────────────────────────────────────────────────────

class TestAlertManager:
    def test_process_new_alert(self, alert_manager, sample_alert):
        result = alert_manager.process(sample_alert)
        assert result is not None
        assert result.alert_id == sample_alert.alert_id

    def test_deduplication_suppresses_duplicate(self, alert_manager):
        alert1 = Alert(
            alert_id="dup-001",
            title="Brute Force",
            description="test",
            severity="high",
            source="wazuh",
        )
        alert2 = Alert(
            alert_id="dup-002",
            title="Brute Force",
            description="test",
            severity="high",
            source="wazuh",
        )
        result1 = alert_manager.process(alert1)
        result2 = alert_manager.process(alert2)

        assert result1 is not None
        assert result2 is None  # Duplicate should be suppressed

    def test_deduplication_allows_after_window(self):
        manager = AlertManager(dedup_window=1)  # 1 second window
        alert1 = Alert(
            alert_id="a1", title="Test", description="d", severity="low", source="wazuh"
        )
        alert2 = Alert(
            alert_id="a2", title="Test", description="d", severity="low", source="wazuh"
        )
        manager.process(alert1)
        time.sleep(1.1)  # Wait for dedup window to expire
        result = manager.process(alert2)
        assert result is not None

    def test_composite_score_calculation(self, alert_manager, sample_alert):
        result = alert_manager.process(sample_alert)
        assert result is not None
        assert result.composite_score > 0

    def test_get_active_alerts(self, alert_manager, sample_alert):
        alert_manager.process(sample_alert)
        active = alert_manager.get_active_alerts()
        assert len(active) == 1

    def test_acknowledge_alert(self, alert_manager, sample_alert):
        alert_manager.process(sample_alert)
        ok = alert_manager.acknowledge(sample_alert.alert_id)
        assert ok
        assert not alert_manager.get_active_alerts()

    def test_purge_old_alerts(self):
        manager = AlertManager(dedup_window=1)
        old_alert = Alert(
            alert_id="old-1",
            title="Old Alert",
            description="d",
            severity="low",
            source="wazuh",
            timestamp=time.time() - 100_000,
        )
        manager._alerts[old_alert.alert_id] = old_alert
        removed = manager.purge_old(max_age=86400)
        assert removed == 1

    def test_correlation_groups_related_alerts(self, alert_manager):
        a1 = Alert(
            alert_id="c1",
            title="Brute Force Login",
            description="d",
            severity="high",
            source="wazuh",
            iocs=[{"type": "ip", "value": "1.2.3.4"}],
        )
        a2 = Alert(
            alert_id="c2",
            title="Brute Force Escalation",
            description="d",
            severity="high",
            source="wazuh",
            iocs=[{"type": "ip", "value": "1.2.3.4"}],
        )
        alert_manager.process(a1)
        alert_manager.process(a2)
        incidents = alert_manager.get_incidents()
        assert len(incidents) >= 1


# ─── Notifier Tests ────────────────────────────────────────────────────────────

class TestNotifier:
    def test_notify_no_channels_configured(self, notifier):
        results = notifier.notify(
            title="Test", description="desc", severity="low"
        )
        # No channels configured — webhook returns False
        assert isinstance(results, dict)

    def test_severity_routing_critical(self, notifier):
        channels = notifier._default_channels("critical")
        assert "email" in channels
        assert "slack" in channels
        assert "webhook" in channels

    def test_severity_routing_medium(self, notifier):
        channels = notifier._default_channels("medium")
        assert "email" not in channels
        assert "slack" in channels

    def test_severity_routing_low(self, notifier):
        channels = notifier._default_channels("low")
        assert channels == ["webhook"]

    def test_send_slack_no_url(self, notifier):
        result = notifier._send_slack({"title": "t", "description": "d", "severity": "low", "source": "s", "score": 0})
        assert result is False

    def test_send_webhook_no_url(self, notifier):
        result = notifier._send_webhook({"title": "t", "description": "d", "severity": "low", "source": "s", "score": 0})
        assert result is False

    def test_send_slack_success(self):
        notifier = Notifier(slack_webhook_url="http://slack.test/webhook")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            result = notifier._send_slack({
                "title": "t", "description": "d", "severity": "critical",
                "source": "wazuh", "score": 95.0
            })

        assert result is True

    def test_send_webhook_success(self):
        notifier = Notifier(webhook_url="http://webhook.test/alert")
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            result = notifier._send_webhook({
                "title": "t", "description": "d", "severity": "high",
                "source": "wazuh", "score": 80.0
            })

        assert result is True


# ─── EscalationManager Tests ──────────────────────────────────────────────────

class TestEscalationManager:
    def test_register_alert(self, escalation_manager):
        record = escalation_manager.register_alert("alert-001", "high")
        assert record.alert_id == "alert-001"
        assert record.severity == "high"
        assert not record.acknowledged_at

    def test_acknowledge_stops_escalation(self, escalation_manager):
        escalation_manager.register_alert("alert-002", "medium")
        ok = escalation_manager.acknowledge("alert-002")
        assert ok
        record = escalation_manager._records["alert-002"]
        assert record.acknowledged_at is not None

    def test_resolve_alert(self, escalation_manager):
        escalation_manager.register_alert("alert-003", "low")
        ok = escalation_manager.resolve("alert-003")
        assert ok
        assert escalation_manager._records["alert-003"].resolved

    def test_check_escalations_no_breach(self, escalation_manager):
        escalation_manager.register_alert("fresh-alert", "high")
        escalated = escalation_manager.check_escalations()
        # Newly created alert should not breach SLA immediately
        assert len(escalated) == 0

    def test_check_escalations_with_breach(self):
        callback_calls = []
        manager = EscalationManager(
            policies=[EscalationPolicy("critical", sla_seconds=1, contacts=["L1"])],
            escalation_callback=lambda r, c: callback_calls.append((r, c)),
        )
        manager.register_alert("breach-alert", "critical")
        time.sleep(1.1)
        escalated = manager.check_escalations()
        assert len(escalated) == 1
        assert len(callback_calls) == 1

    def test_get_sla_status(self, escalation_manager):
        escalation_manager.register_alert("sla-001", "medium")
        status = escalation_manager.get_sla_status("sla-001")
        assert status is not None
        assert status["severity"] == "medium"
        assert not status["sla_breached"]

    def test_get_sla_status_missing_alert(self, escalation_manager):
        status = escalation_manager.get_sla_status("nonexistent")
        assert status is None
