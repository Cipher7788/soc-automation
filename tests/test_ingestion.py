"""Tests for the log ingestion module."""

import pytest
from unittest.mock import MagicMock, patch
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

    def test_get_alerts_scrolls_and_clears_search(self):
        client = WazuhClient(
            "https://wazuh:55000", "manager-user", "manager-pass",
            indexer_url="https://indexer:9200",
            indexer_username="reader", indexer_password="secret",
            indexer_verify_ssl="indexer-ca.pem",
        )
        pages = [
            {"_scroll_id": "initial", "hits": {"hits": [
                {"_index": "wazuh-alerts-1", "_id": "1", "_source": {"rule": {"id": "101"}}},
            ]}},
            {"_scroll_id": "final", "hits": {"hits": []}},
        ]
        responses = [MagicMock(json=MagicMock(return_value=page)) for page in pages]
        with (
            patch.object(client._indexer, "post", side_effect=responses) as post,
            patch.object(client._indexer, "delete") as delete,
            patch.object(client._session, "get") as manager_get,
        ):
            alerts = client.get_alerts(time_range=60)

        assert alerts == [{"rule": {"id": "101"}, "_wazuh_document_id": ("wazuh-alerts-1", "1")}]
        assert client._indexer.auth == ("reader", "secret")
        assert client._indexer.verify == "indexer-ca.pem"
        assert post.call_args_list[0].args[0] == "https://indexer:9200/wazuh-alerts-*/_search"
        assert post.call_args_list[1].kwargs["json"]["scroll_id"] == "initial"
        assert delete.call_args.kwargs["json"] == {"scroll_id": ["final"]}
        manager_get.assert_not_called()

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
            client.get_agents()

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

    def test_flush_buffer(self, wazuh_client):
        wazuh_client.get_alerts.return_value = [{"id": "1"}, {"id": "2"}]
        collector = LogCollector(wazuh_client=wazuh_client, batch_size=1)
        assert collector.collect_once()[0]["id"] == "1"

        items = collector.flush_buffer()
        assert [item["id"] for item in items] == ["2"]
        assert collector.flush_buffer() == []

    def test_collect_once_drains_batches_and_skips_seen_alerts(self, wazuh_client):
        wazuh_client.get_alerts.side_effect = [
            [{"id": "1"}, {"id": "2"}],
            [{"id": "1"}, {"id": "2"}, {"id": "3"}],
        ]
        collector = LogCollector(wazuh_client=wazuh_client, batch_size=1)

        assert [collector.collect_once()[0]["id"] for _ in range(3)] == ["1", "2", "3"]
        assert wazuh_client.get_alerts.call_count == 2

    def test_wazuh_indexed_fields(self):
        result = LogNormalizer().normalize({
            "timestamp": "2024-06-15T19:00:00.000+0530",
            "fullLog": "Suspicious login",
        }, source="wazuh")
        assert result.timestamp == "2024-06-15T13:30:00+00:00"
        assert result.raw_message == "Suspicious login"

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
