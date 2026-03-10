"""Tests for the IOC detection module."""

import pytest
import time

from src.detection.ioc_detector import IOCDetector, IOCMatch
from src.detection.ml_analyzer import MLAnalyzer, AnomalyResult
from src.detection.rules_engine import RulesEngine, RuleMatch


# ─── IOCDetector Tests ────────────────────────────────────────────────────────

class TestIOCDetector:
    def test_detects_known_malicious_ip(self, ioc_detector):
        matches = ioc_detector.detect("Connection from 198.51.100.1 port 443")
        ip_matches = [m for m in matches if m.ioc_type == "ip"]
        assert len(ip_matches) > 0
        assert any(m.value == "198.51.100.1" for m in ip_matches)

    def test_detects_known_malicious_domain(self, ioc_detector):
        matches = ioc_detector.detect("DNS query for malware.example.com")
        domain_matches = [m for m in matches if m.ioc_type == "domain"]
        assert len(domain_matches) > 0
        assert any(m.value == "malware.example.com" for m in domain_matches)

    def test_detects_known_malicious_hash(self, ioc_detector):
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        matches = ioc_detector.detect(f"File hash: {md5_hash}")
        hash_matches = [m for m in matches if m.ioc_type == "md5"]
        assert len(hash_matches) > 0
        assert any(m.value == md5_hash for m in hash_matches)

    def test_detects_url_with_malicious_domain(self, ioc_detector):
        matches = ioc_detector.detect("Request to http://malware.example.com/payload.exe")
        url_matches = [m for m in matches if m.ioc_type == "url"]
        assert len(url_matches) > 0

    def test_detects_email_with_malicious_domain(self, ioc_detector):
        matches = ioc_detector.detect("Sender: attacker@malware.example.com")
        email_matches = [m for m in matches if m.ioc_type == "email"]
        assert len(email_matches) > 0

    def test_no_match_clean_text(self, ioc_detector):
        matches = ioc_detector.detect("Normal HTTP request from 10.0.0.1 to google.com")
        # 10.0.0.1 is not in blocklist; google.com is not malicious
        assert not any(m.confidence > 0.9 for m in matches)

    def test_confidence_scores_are_valid(self, ioc_detector):
        matches = ioc_detector.detect("Connection to 198.51.100.1")
        for m in matches:
            assert 0.0 <= m.confidence <= 1.0

    def test_caching(self, ioc_detector):
        text = "Traffic from 198.51.100.1"
        result1 = ioc_detector.detect(text)
        result2 = ioc_detector.detect(text)
        assert result1 is result2  # Same object from cache

    def test_add_malicious_ip(self, ioc_detector):
        ioc_detector.add_malicious_ip("1.2.3.4")
        matches = ioc_detector.detect("Connection from 1.2.3.4")
        ip_matches = [m for m in matches if m.value == "1.2.3.4"]
        assert len(ip_matches) > 0

    def test_add_malicious_domain(self, ioc_detector):
        ioc_detector.add_malicious_domain("evil-new.com")
        matches = ioc_detector.detect("DNS query for evil-new.com")
        domain_matches = [m for m in matches if m.ioc_type == "domain"]
        assert any(m.value == "evil-new.com" for m in domain_matches)

    def test_sha256_detection(self, ioc_detector):
        sha256 = "a" * 64
        ioc_detector.add_malicious_hash(sha256)
        matches = ioc_detector.detect(f"File: {sha256}")
        sha256_matches = [m for m in matches if m.ioc_type == "sha256"]
        assert len(sha256_matches) > 0

    def test_empty_text_returns_no_matches(self, ioc_detector):
        matches = ioc_detector.detect("")
        assert matches == []


# ─── MLAnalyzer Tests ─────────────────────────────────────────────────────────

class TestMLAnalyzer:
    def test_extract_features_returns_correct_keys(self, ml_analyzer):
        log_batch = [
            {
                "source_ip": "192.168.1.1",
                "destination_ip": "8.8.8.8",
                "rule_description": "failed login attempt",
                "event_type": "authentication",
                "timestamp": "2024-01-15T10:00:00+00:00",
                "bytes": 1024,
            }
        ]
        features = ml_analyzer.extract_features(log_batch)
        for feat in MLAnalyzer.FEATURE_NAMES:
            assert feat in features

    def test_analyze_without_training_returns_no_anomaly(self, ml_analyzer):
        features = {f: 0.0 for f in MLAnalyzer.FEATURE_NAMES}
        result = ml_analyzer.analyze(features)
        assert isinstance(result, AnomalyResult)
        # Without training, no anomaly detected
        assert result.is_anomaly is False

    def test_train_and_analyze(self, ml_analyzer):
        """Test that training enables anomaly detection."""
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            pytest.skip("scikit-learn not available")

        # Generate normal training data
        training_data = []
        for _ in range(50):
            training_data.append({
                "login_frequency": 2.0,
                "unique_source_ips": 1.0,
                "failed_auth_count": 0.0,
                "hour_of_day": 9.0,
                "data_transfer_bytes": 1000.0,
                "unique_destinations": 2.0,
                "event_count": 10.0,
            })

        ml_analyzer.train(training_data)
        assert ml_analyzer._trained

        # Normal features should not be anomalous
        normal_features = {
            "login_frequency": 2.0,
            "unique_source_ips": 1.0,
            "failed_auth_count": 0.0,
            "hour_of_day": 9.0,
            "data_transfer_bytes": 1000.0,
            "unique_destinations": 2.0,
            "event_count": 10.0,
        }
        result = ml_analyzer.analyze(normal_features)
        assert isinstance(result, AnomalyResult)
        assert 0.0 <= result.anomaly_score <= 1.0

    def test_analyze_batch(self, ml_analyzer, sample_wazuh_alert):
        log_batch = [sample_wazuh_alert]
        result = ml_analyzer.analyze_batch(log_batch)
        assert isinstance(result, AnomalyResult)

    def test_train_insufficient_data_warning(self, ml_analyzer, caplog):
        import logging
        with caplog.at_level(logging.WARNING):
            ml_analyzer.train([{"login_frequency": 1.0}])
        # Should log a warning about insufficient data

    def test_model_persistence(self, ml_analyzer, tmp_path):
        """Test that model can be saved and loaded."""
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            pytest.skip("scikit-learn not available")

        training_data = [
            {f: 1.0 for f in MLAnalyzer.FEATURE_NAMES} for _ in range(20)
        ]
        ml_analyzer.train(training_data)
        assert ml_analyzer._trained

        # Create a new analyzer with the same path — should load the model
        model_path = ml_analyzer._model_path
        new_analyzer = MLAnalyzer(model_path=model_path)
        assert new_analyzer._trained


# ─── RulesEngine Tests ────────────────────────────────────────────────────────

class TestRulesEngine:
    def test_load_rules(self, rules_engine):
        assert len(rules_engine._rules) == 2

    def test_evaluate_matching_rule(self, rules_engine):
        log = {
            "rule_description": "failed login attempt",
            "severity": "8",
            "source_ip": "192.168.1.1",
        }
        matches = rules_engine.evaluate(log)
        assert len(matches) > 0
        assert any(m.rule_id == "TEST-001" for m in matches)

    def test_evaluate_no_match(self, rules_engine):
        log = {
            "rule_description": "routine audit log",
            "severity": "2",
        }
        matches = rules_engine.evaluate(log)
        # TEST-001 requires "failed login" or severity >= 8
        # TEST-002 requires "malware" — neither should match
        matching_ids = [m.rule_id for m in matches]
        assert "TEST-001" not in matching_ids
        assert "TEST-002" not in matching_ids

    def test_evaluate_malware_rule(self, rules_engine):
        log = {"rule_description": "malware detected by AV scanner"}
        matches = rules_engine.evaluate(log)
        assert any(m.rule_id == "TEST-002" for m in matches)

    def test_rule_severity_returned(self, rules_engine):
        log = {"rule_description": "failed login attempt"}
        matches = rules_engine.evaluate(log)
        high_matches = [m for m in matches if m.severity == "high"]
        assert len(high_matches) > 0

    def test_evaluate_batch(self, rules_engine):
        logs = [
            {"rule_description": "failed login"},
            {"rule_description": "malware detected"},
            {"rule_description": "normal heartbeat"},
        ]
        results = rules_engine.evaluate_batch(logs)
        assert len(results) == 3

    def test_reload_rules(self, rules_engine):
        initial_count = len(rules_engine._rules)
        rules_engine.reload_rules()
        assert len(rules_engine._rules) == initial_count

    def test_condition_operators(self, tmp_path):
        rules_file = tmp_path / "op_rules.yml"
        rules_file.write_text("""
rules:
  - id: "OP-001"
    name: "Level GT Test"
    severity: "medium"
    logic: "AND"
    conditions:
      - field: "level"
        operator: "gt"
        value: 5
  - id: "OP-002"
    name: "Regex Test"
    severity: "low"
    logic: "AND"
    conditions:
      - field: "message"
        operator: "regex"
        value: "error|fail"
""")
        engine = RulesEngine(rules_dir=str(tmp_path))
        matches_gt = engine.evaluate({"level": 10})
        matches_regex = engine.evaluate({"message": "connection error"})

        assert any(m.rule_id == "OP-001" for m in matches_gt)
        assert any(m.rule_id == "OP-002" for m in matches_regex)

    def test_nested_field_access(self, tmp_path):
        rules_file = tmp_path / "nested_rules.yml"
        rules_file.write_text("""
rules:
  - id: "NEST-001"
    name: "Nested Field Test"
    severity: "low"
    logic: "AND"
    conditions:
      - field: "rule.description"
        operator: "contains"
        value: "test"
""")
        engine = RulesEngine(rules_dir=str(tmp_path))
        matches = engine.evaluate({"rule": {"description": "test alert"}})
        assert any(m.rule_id == "NEST-001" for m in matches)
