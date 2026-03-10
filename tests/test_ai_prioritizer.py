"""Tests for the AlertPrioritizer module."""

import pytest
from src.detection.ai_prioritizer import AlertPrioritizer, PriorityResult


class TestAlertPrioritizer:
    @pytest.fixture
    def prioritizer(self, tmp_path):
        return AlertPrioritizer(model_path=str(tmp_path / "prioritizer.pkl"))

    def test_prioritize_returns_priority_result(self, prioritizer):
        features = {f: 0.0 for f in AlertPrioritizer.FEATURES}
        result = prioritizer.prioritize(features)
        assert isinstance(result, PriorityResult)

    def test_priority_levels_are_valid(self, prioritizer):
        features = {f: 0.5 for f in AlertPrioritizer.FEATURES}
        result = prioritizer.prioritize(features)
        assert result.priority in ("low", "medium", "high", "critical")

    def test_high_risk_features_produce_high_priority(self, prioritizer):
        features = {
            "ip_reputation": 90.0,
            "is_known_ioc": 1.0,
            "rule_severity_score": 90.0,
            "anomaly_score": 0.9,
            "process_name_risk": 1.0,
            "user_privilege": 1.0,
            "hour_of_day": 3.0,  # off-hours
            "log_frequency": 0.1,
        }
        result = prioritizer.prioritize(features)
        assert result.priority in ("high", "critical")

    def test_low_risk_features_produce_low_priority(self, prioritizer):
        features = {f: 0.0 for f in AlertPrioritizer.FEATURES}
        result = prioritizer.prioritize(features)
        assert result.priority in ("low", "medium")

    def test_recommended_action_is_non_empty(self, prioritizer):
        features = {f: 0.0 for f in AlertPrioritizer.FEATURES}
        result = prioritizer.prioritize(features)
        assert result.recommended_action != ""

    def test_method_is_rule_based_without_training(self, prioritizer):
        features = {f: 0.0 for f in AlertPrioritizer.FEATURES}
        result = prioritizer.prioritize(features)
        assert result.method == "rule-based"

    def test_train_with_sufficient_data(self, prioritizer):
        try:
            from sklearn.ensemble import GradientBoostingClassifier
        except ImportError:
            pytest.skip("scikit-learn not available")

        training_data = []
        for _ in range(15):
            row = {f: 0.0 for f in AlertPrioritizer.FEATURES}
            row["label"] = "low"
            training_data.append(row)
        for _ in range(15):
            row = {f: 0.8 for f in AlertPrioritizer.FEATURES}
            row["label"] = "high"
            training_data.append(row)

        prioritizer.train(training_data)
        assert prioritizer._trained

    def test_train_insufficient_data_does_not_train(self, prioritizer):
        data = [{"label": "low"}]
        prioritizer.train(data)
        assert not prioritizer._trained

    def test_save_and_load_model(self, prioritizer, tmp_path):
        try:
            from sklearn.ensemble import GradientBoostingClassifier
        except ImportError:
            pytest.skip("scikit-learn not available")

        training_data = []
        for _ in range(15):
            row = {f: 0.0 for f in AlertPrioritizer.FEATURES}
            row["label"] = "low"
            training_data.append(row)
        for _ in range(15):
            row = {f: 0.9 for f in AlertPrioritizer.FEATURES}
            row["label"] = "critical"
            training_data.append(row)

        prioritizer.train(training_data)
        assert prioritizer._trained

        new_prioritizer = AlertPrioritizer(model_path=prioritizer._model_path)
        assert new_prioritizer._trained
