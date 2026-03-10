"""Tests for the ThreatIntelEnricher module."""

import pytest
from unittest.mock import MagicMock, patch

from src.enrichment.threat_intel_enricher import ThreatIntelEnricher, EnrichmentResult


class TestThreatIntelEnricher:
    @pytest.fixture
    def enricher(self):
        return ThreatIntelEnricher(cache_ttl=3600)

    def test_enrich_without_api_keys_returns_unknown(self, enricher):
        result = enricher.enrich("185.1.2.3", "ip")
        assert isinstance(result, EnrichmentResult)
        assert result.ioc_value == "185.1.2.3"
        assert result.ioc_type == "ip"
        assert result.reputation == "Unknown"

    def test_enrich_result_has_required_fields(self, enricher):
        result = enricher.enrich("malware.example.com", "domain")
        assert hasattr(result, "ioc_value")
        assert hasattr(result, "ioc_type")
        assert hasattr(result, "reputation")
        assert hasattr(result, "confidence_score")
        assert hasattr(result, "sources")
        assert hasattr(result, "details")
        assert hasattr(result, "enriched_at")

    def test_enrich_result_reputation_values(self, enricher):
        result = enricher.enrich("8.8.8.8", "ip")
        assert result.reputation in ("Malicious", "Suspicious", "Clean", "Unknown")

    def test_enrich_batch_returns_list(self, enricher):
        iocs = [
            {"value": "1.2.3.4", "type": "ip"},
            {"value": "malware.example.com", "type": "domain"},
        ]
        results = enricher.enrich_batch(iocs)
        assert len(results) == 2
        assert all(isinstance(r, EnrichmentResult) for r in results)

    def test_cache_prevents_redundant_api_calls(self, enricher):
        with patch.object(enricher, "_query_virustotal_ip") as mock_vt:
            enricher._vt_key = "fake-key"
            mock_vt.return_value = {"source": "VirusTotal", "confidence": 0.0}
            enricher.enrich("10.0.0.1", "ip")
            enricher.enrich("10.0.0.1", "ip")
            mock_vt.assert_called_once()

    def test_str_representation(self, enricher):
        result = EnrichmentResult(
            ioc_value="1.2.3.4",
            ioc_type="ip",
            reputation="Malicious",
            confidence_score=92.0,
            sources=["AbuseIPDB"],
        )
        output = str(result)
        assert "1.2.3.4" in output
        assert "Malicious" in output
        assert "92%" in output

    def test_aggregate_malicious_when_high_confidence(self, enricher):
        results = [{"source": "AbuseIPDB", "confidence": 80.0}]
        agg = enricher._aggregate("1.2.3.4", "ip", results)
        assert agg.reputation == "Malicious"

    def test_aggregate_suspicious_when_medium_confidence(self, enricher):
        results = [{"source": "AbuseIPDB", "confidence": 40.0}]
        agg = enricher._aggregate("1.2.3.4", "ip", results)
        assert agg.reputation == "Suspicious"

    def test_aggregate_unknown_when_all_errors(self, enricher):
        results = [{"source": "AbuseIPDB", "error": "timeout"}]
        agg = enricher._aggregate("1.2.3.4", "ip", results)
        assert agg.reputation == "Unknown"
