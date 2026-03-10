"""AI-Based Alert Prioritizer — uses GradientBoostingClassifier with rule-based fallback."""

import logging
import os
import pickle
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)

PRIORITY_LEVELS = ("low", "medium", "high", "critical")


@dataclass
class PriorityResult:
    """Result of the alert prioritization step."""

    priority: str  # low | medium | high | critical
    confidence: float  # 0–1
    recommended_action: str
    score: float  # raw weighted score used for rule-based fallback
    method: str  # "ml" | "rule-based"


# Feature weights for the rule-based fallback (higher = riskier)
_FEATURE_WEIGHTS: dict[str, float] = {
    "log_frequency": -0.05,       # high frequency = more common = less risky
    "ip_reputation": 0.30,        # high reputation score = bad
    "process_name_risk": 0.25,    # high process risk = bad
    "user_privilege": 0.15,       # admin = riskier
    "hour_of_day": 0.05,          # off-hours = slightly riskier
    "is_known_ioc": 0.35,         # known IOC = very risky
    "rule_severity_score": 0.25,  # high rule severity = bad
    "anomaly_score": 0.20,        # high anomaly score = bad
}

_RECOMMENDED_ACTIONS: dict[str, str] = {
    "low": "Log and monitor",
    "medium": "Assign to analyst for review",
    "high": "Escalate to Tier-2, trigger playbook",
    "critical": "Auto-escalate, trigger all response playbooks",
}


class AlertPrioritizer:
    """Prioritize alerts using ML (GradientBoostingClassifier) or rule-based scoring.

    If no trained model is available the class falls back to a weighted scoring
    heuristic that maps the feature vector to a 0–100 risk score.
    """

    FEATURES = list(_FEATURE_WEIGHTS.keys())

    def __init__(self, model_path: str = "models/prioritizer.pkl") -> None:
        self._model_path = model_path
        self._model: Optional[Any] = None
        self._label_encoder: Optional[Any] = None
        self._trained = False
        self._load_model()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def prioritize(self, alert_features: dict[str, float]) -> PriorityResult:
        """Return a PriorityResult for the given feature dict."""
        features = self._normalize_features(alert_features)
        if self._trained and self._model is not None:
            return self._ml_prioritize(features)
        return self._rule_based_prioritize(features)

    def train(self, training_data: list[dict[str, Any]]) -> None:
        """Train the GradientBoostingClassifier on labelled training data.

        Each item in *training_data* must have all feature keys plus a
        'label' key with a value from ('low', 'medium', 'high', 'critical').
        """
        try:
            from sklearn.ensemble import GradientBoostingClassifier
            from sklearn.preprocessing import LabelEncoder
            import numpy as np
        except ImportError:
            logger.warning("scikit-learn not available; cannot train ML model")
            return

        if len(training_data) < 10:
            logger.warning("Insufficient training data (%d samples); need ≥ 10", len(training_data))
            return

        X = []
        y = []
        for item in training_data:
            features = self._normalize_features(item)
            row = [features.get(f, 0.0) for f in self.FEATURES]
            X.append(row)
            y.append(item.get("label", "medium"))

        X_arr = np.array(X)
        le = LabelEncoder()
        y_enc = le.fit_transform(y)

        clf = GradientBoostingClassifier(n_estimators=100, random_state=42)
        clf.fit(X_arr, y_enc)

        self._model = clf
        self._label_encoder = le
        self._trained = True
        logger.info("AlertPrioritizer trained on %d samples", len(training_data))
        self.save_model()

    def save_model(self) -> None:
        os.makedirs(os.path.dirname(self._model_path) or ".", exist_ok=True)
        with open(self._model_path, "wb") as fh:
            pickle.dump({"model": self._model, "label_encoder": self._label_encoder}, fh)
        logger.info("Prioritizer model saved to %s", self._model_path)

    def load_model(self) -> bool:
        return self._load_model()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_model(self) -> bool:
        if not os.path.exists(self._model_path):
            return False
        try:
            with open(self._model_path, "rb") as fh:
                data = pickle.load(fh)
            self._model = data.get("model")
            self._label_encoder = data.get("label_encoder")
            self._trained = True
            logger.info("Prioritizer model loaded from %s", self._model_path)
            return True
        except Exception as exc:
            logger.warning("Failed to load prioritizer model: %s", exc)
            return False

    def _normalize_features(self, features: dict[str, Any]) -> dict[str, float]:
        """Ensure all expected feature keys exist as floats normalised to the 0–1 range.

        Some raw feature values may arrive pre-scaled to 0–100 (e.g. ip_reputation
        from AbuseIPDB, rule_severity_score, anomaly_score). These are divided by
        100 so that the final weighted sum stays in the 0–1 range expected by the
        rule-based scoring function.
        """
        out: dict[str, float] = {}
        for key in self.FEATURES:
            val = features.get(key, 0.0)
            if isinstance(val, bool):
                val = float(val)
            try:
                out[key] = float(val)
            except (TypeError, ValueError):
                out[key] = 0.0
        # Normalise to 0–1 where the raw value may be 0–100
        if out.get("ip_reputation", 0) > 1:
            out["ip_reputation"] = out["ip_reputation"] / 100.0
        if out.get("rule_severity_score", 0) > 1:
            out["rule_severity_score"] = out["rule_severity_score"] / 100.0
        if out.get("anomaly_score", 0) > 1:
            out["anomaly_score"] = out["anomaly_score"] / 100.0
        # hour_of_day: off-hours (0–6, 18–23) score higher
        hour = out.get("hour_of_day", 12.0)
        out["hour_of_day"] = 1.0 if (hour < 6 or hour >= 18) else 0.0
        return out

    def _rule_based_prioritize(self, features: dict[str, float]) -> PriorityResult:
        score = 0.0
        for feature, weight in _FEATURE_WEIGHTS.items():
            score += features.get(feature, 0.0) * weight

        # Clamp to 0–1
        score = max(0.0, min(1.0, score))

        if score >= 0.75:
            priority = "critical"
        elif score >= 0.50:
            priority = "high"
        elif score >= 0.25:
            priority = "medium"
        else:
            priority = "low"

        return PriorityResult(
            priority=priority,
            confidence=score,
            recommended_action=_RECOMMENDED_ACTIONS[priority],
            score=score,
            method="rule-based",
        )

    def _ml_prioritize(self, features: dict[str, float]) -> PriorityResult:
        try:
            import numpy as np
            row = np.array([[features.get(f, 0.0) for f in self.FEATURES]])
            pred_enc = self._model.predict(row)[0]
            proba = self._model.predict_proba(row)[0]
            priority = self._label_encoder.inverse_transform([pred_enc])[0]
            confidence = float(proba.max())
            raw_score = sum(features.get(f, 0.0) * w for f, w in _FEATURE_WEIGHTS.items())
            return PriorityResult(
                priority=priority,
                confidence=confidence,
                recommended_action=_RECOMMENDED_ACTIONS.get(priority, "Review"),
                score=raw_score,
                method="ml",
            )
        except Exception as exc:
            logger.warning("ML prioritization failed (%s); falling back to rule-based", exc)
            return self._rule_based_prioritize(features)
