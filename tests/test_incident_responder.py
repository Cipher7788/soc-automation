"""Tests for the IncidentResponder module."""

import pytest
from unittest.mock import MagicMock

from src.response.incident_responder import IncidentResponder, ResponseAction
from src.alerting.alert_manager import Alert


@pytest.fixture
def sample_alert():
    return Alert(
        alert_id="resp-test-001",
        title="Brute Force Attack",
        description="Multiple failed SSH logins",
        severity="high",
        source="wazuh",
        tags=["brute_force"],
        iocs=[{"type": "ip", "value": "1.2.3.4", "confidence": 0.9}],
        raw_data={"source_ip": "1.2.3.4", "agent_name": "web-server-01"},
    )


@pytest.fixture
def responder():
    wazuh = MagicMock()
    hive = MagicMock()
    hive.create_case.return_value = {"id": "case-001"}
    shuffle = MagicMock()
    return IncidentResponder(wazuh_client=wazuh, hive_client=hive, shuffle_client=shuffle)


class TestIncidentResponder:
    def test_respond_returns_list_of_actions(self, responder, sample_alert):
        actions = responder.respond(sample_alert, alert_type="brute_force")
        assert isinstance(actions, list)
        assert len(actions) > 0

    def test_response_actions_are_response_action_instances(self, responder, sample_alert):
        actions = responder.respond(sample_alert, alert_type="brute_force")
        assert all(isinstance(a, ResponseAction) for a in actions)

    def test_block_ip_action_executed_for_brute_force_high(self, responder, sample_alert):
        actions = responder.respond(sample_alert, alert_type="brute_force")
        action_types = [a.action_type for a in actions]
        assert "block_ip" in action_types

    def test_actions_have_valid_status(self, responder, sample_alert):
        actions = responder.respond(sample_alert, alert_type="brute_force")
        for action in actions:
            assert action.status in ("executed", "skipped", "failed", "pending")

    def test_audit_log_contains_executed_actions(self, responder, sample_alert):
        responder.respond(sample_alert, alert_type="brute_force")
        log = responder.get_audit_log()
        assert len(log) > 0

    def test_approval_required_actions_skipped_when_flag_set(self, sample_alert):
        responder = IncidentResponder(require_approval=True)
        actions = responder.respond(sample_alert, alert_type="malware", priority="critical")
        for action in actions:
            if action.requires_approval:
                assert action.status == "skipped"

    def test_default_alert_type_produces_fallback_actions(self, responder, sample_alert):
        sample_alert.severity = "high"
        actions = responder.respond(sample_alert, alert_type="unknown_type")
        assert len(actions) > 0

    def test_response_action_dataclass_fields(self):
        action = ResponseAction(
            action_type="block_ip",
            target="1.2.3.4",
            parameters={"reason": "test"},
        )
        assert action.status == "pending"
        assert action.executed_at is None
        assert action.requires_approval is False
