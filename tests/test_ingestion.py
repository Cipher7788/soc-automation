"""Tests for the log ingestion module."""

import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone

from src.ingestion.wazuh_client import WazuhClient, WazuhAuthError
from src.ingestion.log_collector import LogCollector
from src.ingestion.normalizer import LogNormalizer, NormalizedLog


# ─── WazuhClient Tests ────────────────────────────────────────────────────────

class TestWazuhClient:
    def test_authenticate_success(self):
        client = WazuhClient("https://wazuh:55000", "user", "pass", verify_ssl=False)
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": {"token": "jwt-token-123"}}
        mock_response.raise_for_status = MagicMock()

        with patch.object(client._session, "get", return_value=mock_response):
            token = client.authenticate()

        assert token == "jwt-token-123"
        assert client._token == "jwt-token-123"

    def test_authenticate_failure_raises(self):
        import requests
        client = WazuhClient("https://wazuh:55000", "user", "wrongpass", verify_ssl=False)
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError("401")

        with patch.object(client._session, "get", return_value=mock_response):
            with pytest.raises(WazuhAuthError):
                client.authenticate()

    def test_get_alerts_calls_paginate(self):
        client = WazuhClient("https://wazuh:55000", "user", "pass", verify_ssl=False)
        client._token = "jwt"
        client._token_expiry = datetime(9999, 1, 1, tzinfo=timezone.utc)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "affected_items": [{"id": "1"}, {"id": "2"}],
                "total_affected_items": 2,
            }
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(client._session, "get", return_value=mock_response):
            alerts = client.get_alerts(time_range=60)

        assert len(alerts) == 2

    def test_get_agents(self):
        client = WazuhClient("https://wazuh:55000", "user", "pass", verify_ssl=False)
        client._token = "jwt"
        client._token_expiry = datetime(9999, 1, 1, tzinfo=timezone.utc)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "affected_items": [{"id": "001", "name": "agent1"}],
                "total_affected_items": 1,
            }
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(client._session, "get", return_value=mock_response):
            agents = client.get_agents()

        assert len(agents) == 1
        assert agents[0]["name"] == "agent1"

    def test_token_auto_refresh(self):
        """Token should refresh when expired."""
        client = WazuhClient("https://wazuh:55000", "user", "pass", verify_ssl=False)
        # Set expired token
        client._token = "old-token"
        client._token_expiry = datetime(2000, 1, 1, tzinfo=timezone.utc)

        auth_response = MagicMock()
        auth_response.json.return_value = {"data": {"token": "new-token"}}
        auth_response.raise_for_status = MagicMock()

        data_response = MagicMock()
        data_response.json.return_value = {
            "data": {"affected_items": [], "total_affected_items": 0}
        }
        data_response.raise_for_status = MagicMock()

        with patch.object(client._session, "get", side_effect=[auth_response, data_response]):
            client.get_alerts()

        assert client._token == "new-token"


# ─── LogCollector Tests ───────────────────────────────────────────────────────

class TestLogCollector:
    def test_collect_once_calls_wazuh(self, wazuh_client, sample_wazuh_alert):
        wazuh_client.get_alerts.return_value = [sample_wazuh_alert]
        collector = LogCollector(wazuh_client=wazuh_client, poll_interval=60)

        logs = collector.collect_once()

        wazuh_client.get_alerts.assert_called_once()
        assert len(logs) == 1
        assert logs[0]["_source"] == "wazuh"

    def test_collect_once_handles_wazuh_error(self, wazuh_client):
        wazuh_client.get_alerts.side_effect = Exception("Connection refused")
        collector = LogCollector(wazuh_client=wazuh_client)

        logs = collector.collect_once()

        assert logs == []

    def test_callback_is_invoked(self, wazuh_client, sample_wazuh_alert):
        wazuh_client.get_alerts.return_value = [sample_wazuh_alert]
        collector = LogCollector(wazuh_client=wazuh_client)

        received = []
        collector.register_callback(received.extend)
        collector.collect_once()

        assert len(received) == 1

    def test_flush_buffer(self, wazuh_client, sample_wazuh_alert):
        wazuh_client.get_alerts.return_value = [sample_wazuh_alert]
        collector = LogCollector(wazuh_client=wazuh_client)
        collector.collect_once()

        items = collector.flush_buffer()
        assert len(items) == 1
        assert collector.flush_buffer() == []

    def test_stop_sets_running_false(self, wazuh_client):
        collector = LogCollector(wazuh_client=wazuh_client)
        collector.stop()
        assert collector._running is False


# ─── LogNormalizer Tests ──────────────────────────────────────────────────────

class TestLogNormalizer:
    def test_normalize_wazuh_alert(self, sample_wazuh_alert):
        normalizer = LogNormalizer()
        result = normalizer.normalize(sample_wazuh_alert, source="wazuh")

        assert isinstance(result, NormalizedLog)
        assert result.source == "wazuh"
        assert result.source_ip == "192.168.1.100"
        assert result.destination_ip == "10.0.0.1"
        assert result.agent_name == "web-server-01"
        assert result.rule_description == "Multiple failed login attempts"
        assert result.user == "admin"

    def test_severity_normalization(self):
        normalizer = LogNormalizer()
        raw = {
            "timestamp": "2024-01-01T00:00:00Z",
            "rule": {"level": 12, "description": "test"},
            "agent": {},
            "data": {},
        }
        result = normalizer.normalize(raw)
        assert result.severity == "critical"

    def test_normalize_batch_skips_bad_records(self):
        normalizer = LogNormalizer()
        records = [
            {"timestamp": "2024-01-01T00:00:00Z", "rule": {}, "agent": {}, "data": {}},
            None,  # type: ignore — bad record
            {"timestamp": "2024-01-01T00:00:01Z", "rule": {}, "agent": {}, "data": {}},
        ]
        # Should not raise; bad records are logged and skipped
        results = normalizer.normalize_batch(records)  # type: ignore
        assert len(results) >= 1

    def test_timestamp_parsing_iso(self):
        normalizer = LogNormalizer()
        raw = {
            "timestamp": "2024-06-15T14:30:00.000Z",
            "rule": {},
            "agent": {},
            "data": {},
        }
        result = normalizer.normalize(raw)
        assert "2024-06-15" in result.timestamp

    def test_normalize_missing_fields(self):
        normalizer = LogNormalizer()
        result = normalizer.normalize({})
        assert result.source_ip is None
        assert result.severity == "informational"
