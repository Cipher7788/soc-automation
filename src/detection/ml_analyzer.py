"""AI/ML anomaly detection using scikit-learn Isolation Forest."""

import logging
import os
import pickle
from dataclasses import dataclass, field
from typing import Any, Optional

import numpy as np

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available — ML analysis disabled")


@dataclass
class AnomalyResult:
    """Result of an ML anomaly analysis."""

    anomaly_score: float
    is_anomaly: bool
    features_used: list[str]
    explanation: str
    raw_score: float = 0.0


class MLAnalyzer:
    """Anomaly detection engine using Isolation Forest.

    Analyzes behavioural features extracted from log data, trains on
    baseline "normal" behaviour, and flags statistical deviations.
    """

    FEATURE_NAMES = [
        "login_frequency",
        "unique_source_ips",
        "failed_auth_count",
        "hour_of_day",
        "data_transfer_bytes",
        "unique_destinations",
        "event_count",
    ]

    def __init__(
        self,
        model_path: str = "models/isolation_forest.pkl",
        contamination: float = 0.05,
        n_estimators: int = 100,
    ) -> None:
        self._model_path = model_path
        self._contamination = contamination
        self._n_estimators = n_estimators
        self._model: Optional[Any] = None
        self._scaler: Optional[Any] = None
        self._trained = False

        if _SKLEARN_AVAILABLE:
            self._load_or_init()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_features(self, log_batch: list[dict[str, Any]]) -> dict[str, float]:
        """Extract numerical features from a batch of log records."""
        source_ips: set[str] = set()
        dest_ips: set[str] = set()
        failed_auth = 0
        total_bytes = 0
        hours: list[int] = []

        for log in log_batch:
            if log.get("source_ip"):
                source_ips.add(log["source_ip"])
            if log.get("destination_ip"):
                dest_ips.add(log["destination_ip"])

            rule_desc = str(log.get("rule_description", "")).lower()
            if any(kw in rule_desc for kw in ("failed", "invalid", "denied", "unauthorized")):
                failed_auth += 1

            total_bytes += int(log.get("bytes", 0))

            ts = log.get("timestamp", "")
            if ts:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(ts)
                    hours.append(dt.hour)
                except Exception:
                    pass

        return {
            "login_frequency": len([l for l in log_batch if "login" in str(l.get("event_type", "")).lower()]),
            "unique_source_ips": float(len(source_ips)),
            "failed_auth_count": float(failed_auth),
            "hour_of_day": float(sum(hours) / len(hours)) if hours else 12.0,
            "data_transfer_bytes": float(total_bytes),
            "unique_destinations": float(len(dest_ips)),
            "event_count": float(len(log_batch)),
        }

    def train(self, training_data: list[dict[str, float]]) -> None:
        """Train the Isolation Forest on normal behaviour feature vectors."""
        if not _SKLEARN_AVAILABLE:
            logger.warning("Cannot train: scikit-learn not available")
            return

        if len(training_data) < 10:
            logger.warning("Insufficient training samples (%d)", len(training_data))
            return

        X = np.array([[row[f] for f in self.FEATURE_NAMES] for row in training_data])
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)
        self._model = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=42,
        )
        self._model.fit(X_scaled)
        self._trained = True
        logger.info("MLAnalyzer trained on %d samples", len(training_data))
        self._save()

    def analyze(self, features: dict[str, float]) -> AnomalyResult:
        """Analyze a feature vector and return an anomaly score."""
        if not _SKLEARN_AVAILABLE or not self._trained:
            return AnomalyResult(
                anomaly_score=0.0,
                is_anomaly=False,
                features_used=self.FEATURE_NAMES,
                explanation="ML model not trained; skipping anomaly detection.",
            )

        vector = np.array([[features.get(f, 0.0) for f in self.FEATURE_NAMES]])
        scaled = self._scaler.transform(vector)  # type: ignore[union-attr]
        raw_score = float(self._model.decision_function(scaled)[0])  # type: ignore[union-attr]
        prediction = int(self._model.predict(scaled)[0])  # type: ignore[union-attr]

        # Isolation Forest: -1 = anomaly, 1 = normal
        is_anomaly = prediction == -1
        # Normalise score to 0-1 (lower decision_function = more anomalous)
        anomaly_score = max(0.0, min(1.0, 0.5 - raw_score))

        explanation = self._build_explanation(features, is_anomaly)
        return AnomalyResult(
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            features_used=self.FEATURE_NAMES,
            explanation=explanation,
            raw_score=raw_score,
        )

    def analyze_batch(self, log_batch: list[dict[str, Any]]) -> AnomalyResult:
        """Extract features from *log_batch* and run anomaly analysis."""
        features = self.extract_features(log_batch)
        return self.analyze(features)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._model_path) or ".", exist_ok=True)
        with open(self._model_path, "wb") as f:
            pickle.dump({"model": self._model, "scaler": self._scaler}, f)
        logger.info("ML model saved to %s", self._model_path)

    def _load_or_init(self) -> None:
        if os.path.exists(self._model_path):
            try:
                with open(self._model_path, "rb") as f:
                    state = pickle.load(f)
                self._model = state["model"]
                self._scaler = state["scaler"]
                self._trained = True
                logger.info("ML model loaded from %s", self._model_path)
            except Exception as exc:
                logger.warning("Failed to load ML model: %s", exc)
        else:
            self._model = IsolationForest(
                n_estimators=self._n_estimators,
                contamination=self._contamination,
                random_state=42,
            )
            self._scaler = StandardScaler()

    def _build_explanation(self, features: dict[str, float], is_anomaly: bool) -> str:
        if not is_anomaly:
            return "Behaviour within normal baseline."
        anomalous = []
        thresholds = {
            "failed_auth_count": 5,
            "unique_source_ips": 20,
            "data_transfer_bytes": 100_000_000,
            "login_frequency": 50,
        }
        for feat, threshold in thresholds.items():
            if features.get(feat, 0) > threshold:
                anomalous.append(feat.replace("_", " "))
        if anomalous:
            return f"Anomalous behaviour detected in: {', '.join(anomalous)}."
        return "Statistical anomaly detected based on combined feature vector."
