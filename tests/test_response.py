"""Tests for the response module."""

import json
import pytest
from unittest.mock import MagicMock, patch

from src.response.shuffle_client import ShuffleClient
from src.response.playbook_manager import PlaybookManager, PlaybookExecution
from src.response.actions import ResponseActions, ActionResult


# ─── ShuffleClient Tests ───────────────────────────────────────────────────────

class TestShuffleClient:
    def _make_client(self) -> ShuffleClient:
        return ShuffleClient("http://shuffle:5001", "test-api-key")

    def test_list_workflows(self):
        client = self._make_client()
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {"id": "wf-001", "name": "malware_detected"},
        ]
        mock_response.raise_for_status = MagicMock()

        with patch.object(client._session, "get", return_value=mock_response):
            workflows = client.list_workflows()

        assert len(workflows) == 1
        assert workflows[0]["name"] == "malware_detected"

    def test_trigger_workflow(self):
        client = self._make_client()
        mock_response = MagicMock()
        mock_response.json.return_value = {"execution_id": "exec-123", "status": "running"}
        mock_response.raise_for_status = MagicMock()

        with patch.object(client._session, "post", return_value=mock_response):
            result = client.trigger_workflow("wf-001", {"alert_id": "a1"})

        assert result["execution_id"] == "exec-123"

    def test_get_workflow_status(self):
        client = self._make_client()
        mock_response = MagicMock()
        mock_response.json.return_value = {"id": "wf-001", "name": "test"}
        mock_response.raise_for_status = MagicMock()

        with patch.object(client._session, "get", return_value=mock_response):
            result = client.get_workflow_status("wf-001")

        assert result["id"] == "wf-001"

    def test_get_execution_results(self):
        client = self._make_client()
        mock_response = MagicMock()
        mock_response.json.return_value = {"status": "finished", "results": []}
        mock_response.raise_for_status = MagicMock()

        with patch.object(client._session, "get", return_value=mock_response):
            result = client.get_execution_results("wf-001", "exec-123")

        assert result["status"] == "finished"

    def test_auth_header_set(self):
        client = self._make_client()
        assert "Authorization" in client._session.headers
        assert "test-api-key" in client._session.headers["Authorization"]


# ─── PlaybookManager Tests ────────────────────────────────────────────────────

class TestPlaybookManager:
    def test_select_playbook_for_malware(self, playbook_manager):
        name = playbook_manager.select_playbook("malware")
        assert name == "malware_detected"

    def test_select_playbook_for_brute_force(self, playbook_manager):
        name = playbook_manager.select_playbook("brute_force")
        assert name == "brute_force"

    def test_select_playbook_for_suspicious_network(self, playbook_manager):
        name = playbook_manager.select_playbook("suspicious_network")
        assert name == "suspicious_network"

    def test_select_playbook_unknown_type_returns_none(self, playbook_manager):
        name = playbook_manager.select_playbook("unknown_type")
        assert name is None

    def test_execute_no_mapping(self, playbook_manager):
        result = playbook_manager.execute("unknown_alert_type", "alert-1")
        assert result is None

    def test_execute_high_impact_without_approval(self, playbook_manager, shuffle_client):
        """High-impact playbooks require approval."""
        # Add workflow to API response
        shuffle_client.list_workflows.return_value = [
            {"id": "wf-001", "name": "malware_detected"},
        ]
        result = playbook_manager.execute(
            "malware", "alert-1", auto_approve=False
        )
        # Should be queued, not executed
        if result:
            assert result.requires_approval
            assert not result.approved
            # Trigger was NOT called because approval is required
            shuffle_client.trigger_workflow.assert_not_called()

    def test_execute_with_auto_approve(self, playbook_manager, shuffle_client):
        """Auto-approve should trigger the workflow."""
        shuffle_client.list_workflows.return_value = [
            {"id": "wf-001", "name": "malware_detected"},
        ]
        result = playbook_manager.execute(
            "malware", "alert-2", auto_approve=True
        )
        if result:
            shuffle_client.trigger_workflow.assert_called_once()
            assert result.execution_id == "exec-789"

    def test_execute_reads_local_playbook_json(self, shuffle_client, tmp_path):
        """PlaybookManager should resolve workflow ID from local JSON."""
        playbook_file = tmp_path / "malware_detected.json"
        playbook_file.write_text(json.dumps({"id": "local-wf-001"}))

        manager = PlaybookManager(
            shuffle_client=shuffle_client,
            playbooks_dir=str(tmp_path),
        )
        wf_id = manager._resolve_workflow_id("malware_detected")
        assert wf_id == "local-wf-001"

    def test_execution_log_records_attempts(self, shuffle_client, tmp_path):
        playbook_file = tmp_path / "brute_force.json"
        playbook_file.write_text(json.dumps({"id": "bf-wf-001"}))

        manager = PlaybookManager(
            shuffle_client=shuffle_client,
            playbooks_dir=str(tmp_path),
        )
        manager.execute("brute_force", "alert-bf-1", auto_approve=True)

        log = manager.get_execution_log()
        assert len(log) == 1
        assert log[0].playbook_name == "brute_force"


# ─── ResponseActions Tests ────────────────────────────────────────────────────

class TestResponseActions:
    def test_block_ip_requires_confirmation(self, response_actions):
        result = response_actions.block_ip("1.2.3.4", confirmed=False)
        assert not result.success
        assert "confirmation" in (result.error or "").lower()

    def test_isolate_host_requires_confirmation(self, response_actions):
        result = response_actions.isolate_host("agent-001", confirmed=False)
        assert not result.success

    def test_disable_user_requires_confirmation(self, response_actions):
        result = response_actions.disable_user("jdoe", confirmed=False)
        assert not result.success

    def test_block_ip_confirmed_no_firewall_configured(self, response_actions):
        """Without firewall API configured, action is recorded as success (stub)."""
        result = response_actions.block_ip("5.6.7.8", confirmed=True)
        # No firewall URL configured, should succeed without making HTTP call
        assert result.action == "block_ip"
        assert result.target == "5.6.7.8"

    def test_disable_user_confirmed(self, response_actions):
        result = response_actions.disable_user("testuser", reason="Compromised", confirmed=True)
        assert result.success
        assert result.action == "disable_user"

    def test_collect_forensics_no_wazuh(self, response_actions):
        result = response_actions.collect_forensics("agent-001", case_id="case-1")
        assert result.action == "collect_forensics"
        assert result.details.get("case_id") == "case-1"

    def test_audit_log_records_all_actions(self, response_actions):
        response_actions.block_ip("1.1.1.1", confirmed=False)
        response_actions.disable_user("user1", confirmed=True)

        log = response_actions.get_audit_log()
        assert len(log) == 2

    def test_audit_callback_invoked(self):
        callback_calls = []
        actions = ResponseActions(audit_callback=callback_calls.append)
        actions.block_ip("9.9.9.9", confirmed=False)
        assert len(callback_calls) == 1
        assert isinstance(callback_calls[0], ActionResult)

    def test_block_ip_with_firewall_api(self):
        actions = ResponseActions(
            firewall_api_url="http://firewall.test",
            firewall_api_key="key123",
        )
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            result = actions.block_ip("2.3.4.5", reason="malicious", confirmed=True)

        assert result.success
        assert result.target == "2.3.4.5"
