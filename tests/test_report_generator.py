"""Tests for the ReportGenerator module."""

import json
import os
import pytest

from src.reporting.report_generator import ReportGenerator


@pytest.fixture
def report_gen(tmp_path):
    return ReportGenerator(reports_dir=str(tmp_path / "reports"))


@pytest.fixture
def sample_incident():
    return {
        "incident_id": "TEST001",
        "attack_type": "Brute Force",
        "severity": "high",
        "mitre_technique": "T1110",
        "iocs": [{"type": "ip", "value": "1.2.3.4", "confidence": 0.9}],
        "response_actions": [{"action_type": "block_ip", "target": "1.2.3.4", "status": "executed", "result": "success"}],
        "timeline": [{"time": "2024-01-01T10:00:00Z", "event": "Brute force detected"}],
        "recommendations": ["Review firewall rules", "Enable MFA"],
    }


class TestReportGenerator:
    def test_generate_report_json_valid(self, report_gen, sample_incident):
        output = report_gen.generate_report(sample_incident, fmt="json")
        parsed = json.loads(output)
        assert parsed["incident_id"] == "TEST001"

    def test_generate_report_html_contains_incident_id(self, report_gen, sample_incident):
        output = report_gen.generate_report(sample_incident, fmt="html")
        assert "TEST001" in output

    def test_generate_report_markdown_contains_incident_id(self, report_gen, sample_incident):
        output = report_gen.generate_report(sample_incident, fmt="markdown")
        assert "TEST001" in output

    def test_report_saved_to_disk(self, report_gen, sample_incident):
        report_gen.generate_report(sample_incident, fmt="json")
        report_files = os.listdir(report_gen._reports_dir)
        assert len(report_files) > 0

    def test_default_fields_populated_when_missing(self, report_gen):
        output = report_gen.generate_report({}, fmt="json")
        parsed = json.loads(output)
        assert "incident_id" in parsed
        assert "generated_at" in parsed
        assert "recommendations" in parsed

    def test_generate_summary_report_returns_string(self, report_gen):
        alerts = [{"title": "Alert 1", "severity": "high"}, {"title": "Alert 2", "severity": "low"}]
        output = report_gen.generate_summary_report(alerts, time_range="last 24 hours")
        assert isinstance(output, str)
        assert len(output) > 0

    def test_generate_summary_report_json(self, report_gen):
        alerts = [{"severity": "high"}, {"severity": "medium"}]
        output = report_gen.generate_summary_report(alerts, fmt="json")
        parsed = json.loads(output)
        assert "total_alerts" in parsed
        assert parsed["total_alerts"] == 2
