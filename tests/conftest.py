"""Shared test fixtures for SOC Automation test suite."""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from src.ingestion.wazuh_client import WazuhClient
from src.ingestion.log_collector import LogCollector
from src.ingestion.normalizer import LogNormalizer
from src.detection.ioc_detector import IOCDetector
from src.detection.threat_intel import ThreatIntelManager
from src.detection.ml_analyzer import MLAnalyzer
from src.detection.rules_engine import RulesEngine
from src.alerting.thehive_client import TheHiveClient
from src.alerting.alert_manager import AlertManager, Alert
from src.alerting.notifier import Notifier
from src.alerting.escalation import EscalationManager
from src.response.shuffle_client import ShuffleClient
from src.response.playbook_manager import PlaybookManager
from src.response.actions import ResponseActions


@pytest.fixture
def sample_wazuh_alert() -> dict:
    return {
        "timestamp": "2024-01-15T10:30:00.000Z",
        "rule": {
            "id": "5710",
            "level": 8,
            "description": "Multiple failed login attempts",
            "groups": ["authentication_failures"],
        },
        "agent": {
            "id": "001",
            "name": "web-server-01",
        },
        "data": {
            "srcip": "192.168.1.100",
            "dstip": "10.0.0.1",
            "srcuser": "admin",
        },
        "decoder": {"name": "sshd"},
        "full_log": "Failed password for admin from 192.168.1.100 port 22 ssh2",
    }


@pytest.fixture
def sample_wazuh_alert_malware() -> dict:
    return {
        "timestamp": "2024-01-15T11:00:00.000Z",
        "rule": {
            "id": "87105",
            "level": 12,
            "description": "Malware detected by ClamAV",
            "groups": ["malware"],
        },
        "agent": {"id": "002", "name": "endpoint-01"},
        "data": {
            "srcip": "10.0.0.50",
            "file": "/tmp/evil.exe",
        },
        "full_log": "Malware detected: Trojan.Generic in /tmp/evil.exe",
    }


@pytest.fixture
def wazuh_client() -> WazuhClient:
    client = MagicMock(spec=WazuhClient)
    return client


@pytest.fixture
def ioc_detector() -> IOCDetector:
    return IOCDetector()


@pytest.fixture
def threat_intel_manager() -> ThreatIntelManager:
    return ThreatIntelManager()


@pytest.fixture
def ml_analyzer(tmp_path) -> MLAnalyzer:
    model_path = str(tmp_path / "test_model.pkl")
    return MLAnalyzer(model_path=model_path)


@pytest.fixture
def rules_engine(tmp_path) -> RulesEngine:
    rules_file = tmp_path / "test_rules.yml"
    rules_file.write_text("""
rules:
  - id: "TEST-001"
    name: "Test Brute Force"
    description: "Test rule for brute force detection"
    severity: "high"
    logic: "OR"
    conditions:
      - field: "rule_description"
        operator: "contains"
        value: "failed login"
      - field: "severity"
        operator: "gte"
        value: "8"
    tags:
      - "test"
      - "brute-force"

  - id: "TEST-002"
    name: "Test Malware"
    description: "Test rule for malware detection"
    severity: "critical"
    logic: "AND"
    conditions:
      - field: "rule_description"
        operator: "contains"
        value: "malware"
    tags:
      - "test"
      - "malware"
""")
    return RulesEngine(rules_dir=str(tmp_path))


@pytest.fixture
def thehive_client() -> TheHiveClient:
    client = MagicMock(spec=TheHiveClient)
    client.create_alert.return_value = {"id": "alert-123", "status": "New"}
    client.create_case.return_value = {"id": "case-456", "status": "Open"}
    return client


@pytest.fixture
def alert_manager() -> AlertManager:
    return AlertManager(dedup_window=300)


@pytest.fixture
def notifier() -> Notifier:
    return Notifier()


@pytest.fixture
def escalation_manager() -> EscalationManager:
    return EscalationManager()


@pytest.fixture
def shuffle_client() -> ShuffleClient:
    client = MagicMock(spec=ShuffleClient)
    client.trigger_workflow.return_value = {"execution_id": "exec-789", "status": "running"}
    client.list_workflows.return_value = [
        {"id": "wf-001", "name": "malware_detected"},
        {"id": "wf-002", "name": "brute_force"},
        {"id": "wf-003", "name": "suspicious_network"},
    ]
    return client


@pytest.fixture
def playbook_manager(shuffle_client, tmp_path) -> PlaybookManager:
    return PlaybookManager(
        shuffle_client=shuffle_client,
        playbooks_dir=str(tmp_path),
    )


@pytest.fixture
def response_actions() -> ResponseActions:
    return ResponseActions()


@pytest.fixture
def sample_alert() -> Alert:
    return Alert(
        alert_id="test-alert-001",
        title="Test Security Alert",
        description="Test alert for unit testing",
        severity="high",
        source="wazuh",
        tags=["test", "brute-force"],
        iocs=[{"type": "ip", "value": "192.168.1.100", "confidence": 0.8}],
    )
