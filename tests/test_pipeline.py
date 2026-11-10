"""Regression coverage for the orchestrator's high-priority alert path."""

from types import SimpleNamespace

import pytest

from config.settings import settings
from src.main import SOCOrchestrator


@pytest.mark.asyncio
async def test_high_priority_alert_writes_report(monkeypatch, tmp_path, sample_wazuh_alert):
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    monkeypatch.setattr(settings.wazuh, "indexer_url", "https://indexer:9200")
    monkeypatch.setattr(settings.thehive, "api_key", "")
    monkeypatch.setattr(settings.shuffle, "api_key", "")
    monkeypatch.setattr(settings.threat_intel, "abuseipdb_api_key", "")
    monkeypatch.setattr(settings.threat_intel, "virustotal_api_key", "")
    monkeypatch.setattr(settings.threat_intel, "otx_api_key", "otx-only")

    app = SOCOrchestrator()
    monkeypatch.setattr(app.collector, "collect_once", lambda: [sample_wazuh_alert])
    monkeypatch.setattr(app.rules_engine, "evaluate", lambda _: [
        SimpleNamespace(rule_name="Brute force detected", severity="high")
    ])
    monkeypatch.setattr(app.ioc_detector, "detect", lambda _: [
        SimpleNamespace(ioc_type="ip", value="192.0.2.10", confidence=0.9)
    ])
    enriched = []
    monkeypatch.setattr(app.threat_intel_enricher, "enrich_batch", lambda iocs: enriched.extend(iocs) or [])
    monkeypatch.setattr(app.alert_prioritizer, "prioritize", lambda _: SimpleNamespace(priority="low"))
    monkeypatch.setattr(app.notifier, "notify", lambda **_: {})
    monkeypatch.setattr(app.teams_notifier, "send", lambda **_: False)

    await app._cycle()

    report, = tmp_path.glob("*.html")
    assert "Brute Force" in report.read_text(encoding="utf-8")
    assert enriched[0]["value"] == "192.0.2.10"
