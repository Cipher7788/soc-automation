"""Tests for the MITREMapper module."""

import pytest
from src.detection.mitre_mapper import MITREMapper, MITRETechnique, MITRE_TECHNIQUE_DB


class TestMITREMapper:
    @pytest.fixture
    def mapper(self):
        return MITREMapper()

    def test_technique_db_has_minimum_entries(self, mapper):
        assert len(mapper._db) >= 20

    def test_get_technique_returns_correct_entry(self, mapper):
        t = mapper.get_technique("T1059.001")
        assert t is not None
        assert t.technique_id == "T1059.001"
        assert "PowerShell" in t.name

    def test_get_technique_unknown_returns_none(self, mapper):
        result = mapper.get_technique("T9999")
        assert result is None

    def test_map_alert_powershell_keyword(self, mapper):
        techniques = mapper.map_alert(alert_title="Suspicious PowerShell execution detected")
        ids = [t.technique_id for t in techniques]
        assert "T1059.001" in ids

    def test_map_alert_brute_force_keyword(self, mapper):
        techniques = mapper.map_alert(alert_title="Brute force attack detected")
        ids = [t.technique_id for t in techniques]
        assert "T1110" in ids

    def test_map_alert_credential_dump(self, mapper):
        techniques = mapper.map_alert(alert_title="Credential dumping via mimikatz")
        ids = [t.technique_id for t in techniques]
        assert "T1003" in ids

    def test_map_alert_no_match_returns_empty(self, mapper):
        techniques = mapper.map_alert(alert_title="heartbeat")
        assert isinstance(techniques, list)

    def test_map_alert_with_tags(self, mapper):
        techniques = mapper.map_alert(tags=["powershell", "lateral movement"])
        ids = [t.technique_id for t in techniques]
        assert len(ids) > 0

    def test_list_techniques_all(self, mapper):
        all_techniques = mapper.list_techniques()
        assert len(all_techniques) >= 20

    def test_list_techniques_by_tactic(self, mapper):
        cred_access = mapper.list_techniques(tactic="Credential Access")
        assert len(cred_access) > 0
        for t in cred_access:
            assert "Credential Access" in t.tactic

    def test_technique_url_populated(self, mapper):
        t = mapper.get_technique("T1003")
        assert t.url.startswith("https://attack.mitre.org/techniques/")

    def test_mitre_technique_dataclass(self):
        t = MITRETechnique(
            technique_id="T1234",
            name="Test Technique",
            tactic=["Execution"],
            description="A test technique",
        )
        assert "T1234" in t.url
