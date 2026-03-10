"""Tests for the IOCDatabase module."""

import json
import os
import pytest

from src.enrichment.ioc_database import IOCDatabase, IOCEntry


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test_ioc_database.json")
    return IOCDatabase(db_path=db_path)


class TestIOCDatabase:
    def test_database_creates_empty_file_on_init(self, tmp_path):
        path = str(tmp_path / "new_db.json")
        db = IOCDatabase(db_path=path)
        assert os.path.exists(path)

    def test_add_ioc_returns_true_for_new_entry(self, db):
        entry = IOCEntry(value="1.2.3.4", type="ip", source="test", confidence=80.0)
        result = db.add_ioc(entry)
        assert result is True

    def test_add_ioc_returns_false_for_duplicate(self, db):
        entry = IOCEntry(value="1.2.3.4", type="ip", source="test", confidence=80.0)
        db.add_ioc(entry)
        result = db.add_ioc(entry)
        assert result is False

    def test_exists_returns_true_after_add(self, db):
        entry = IOCEntry(value="evil.com", type="domain", source="test", confidence=90.0)
        db.add_ioc(entry)
        assert db.exists("evil.com", "domain") is True

    def test_exists_returns_false_for_missing(self, db):
        assert db.exists("nothere.com", "domain") is False

    def test_remove_ioc_returns_true_when_removed(self, db):
        entry = IOCEntry(value="5.6.7.8", type="ip")
        db.add_ioc(entry)
        result = db.remove_ioc("5.6.7.8", "ip")
        assert result is True
        assert db.exists("5.6.7.8", "ip") is False

    def test_remove_ioc_returns_false_when_not_found(self, db):
        result = db.remove_ioc("nothere.ip", "ip")
        assert result is False

    def test_search_returns_matching_entries(self, db):
        db.add_ioc(IOCEntry(value="192.168.1.100", type="ip", source="test"))
        db.add_ioc(IOCEntry(value="192.168.1.200", type="ip", source="test"))
        results = db.search("192.168.1")
        assert len(results) >= 2

    def test_import_from_list_adds_multiple(self, db):
        count = db.import_from_list(["1.1.1.1", "2.2.2.2", "3.3.3.3"], ioc_type="ip", source="batch")
        assert count == 3
        assert db.exists("1.1.1.1", "ip")

    def test_export_json_valid(self, db):
        db.add_ioc(IOCEntry(value="test.com", type="domain"))
        exported = db.export("json")
        parsed = json.loads(exported)
        assert "malicious_domains" in parsed

    def test_export_csv_contains_headers(self, db):
        db.add_ioc(IOCEntry(value="1.2.3.4", type="ip"))
        csv_output = db.export("csv")
        assert "value" in csv_output
        assert "type" in csv_output

    def test_get_malicious_ips_returns_set(self, db):
        db.add_ioc(IOCEntry(value="1.2.3.4", type="ip"))
        ips = db.get_malicious_ips()
        assert isinstance(ips, set)
        assert "1.2.3.4" in ips

    def test_persistence_after_reload(self, tmp_path):
        path = str(tmp_path / "persist_db.json")
        db1 = IOCDatabase(db_path=path)
        db1.add_ioc(IOCEntry(value="persist.com", type="domain"))

        db2 = IOCDatabase(db_path=path)
        assert db2.exists("persist.com", "domain")
