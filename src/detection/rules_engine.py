"""YAML-based detection rules engine with hot-reload support."""

import glob
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class RuleMatch:
    """Represents a detection rule match."""

    rule_id: str
    rule_name: str
    severity: str
    description: str
    matched_conditions: list[str] = field(default_factory=list)
    score: int = 0


class RulesEngine:
    """Load and evaluate YAML-based detection rules against log records.

    Rules support field matching, threshold checks, time windows, and
    boolean logic (AND/OR/NOT).  Rules can be hot-reloaded by calling
    :meth:`reload_rules`.
    """

    def __init__(self, rules_dir: str = "rules") -> None:
        self._rules_dir = rules_dir
        self._rules: list[dict[str, Any]] = []
        self._last_load: float = 0.0
        self._counters: dict[str, list[float]] = {}  # rule_id -> list of event timestamps
        self.load_rules()

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def load_rules(self) -> None:
        """Load all YAML rule files from the configured directory."""
        self._rules = []
        pattern = os.path.join(self._rules_dir, "*.yml")
        files = glob.glob(pattern)
        for filepath in sorted(files):
            try:
                with open(filepath, encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if isinstance(data, dict) and "rules" in data:
                    self._rules.extend(data["rules"])
                elif isinstance(data, list):
                    self._rules.extend(data)
            except Exception as exc:
                logger.error("Failed to load rules from %s: %s", filepath, exc)
        self._last_load = time.time()
        logger.info("Loaded %d detection rules from %s", len(self._rules), self._rules_dir)

    def reload_rules(self) -> None:
        """Hot-reload rules from disk."""
        logger.info("Hot-reloading detection rules")
        self.load_rules()

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, log: dict[str, Any]) -> list[RuleMatch]:
        """Evaluate all loaded rules against a single log record."""
        matches: list[RuleMatch] = []
        for rule in self._rules:
            try:
                match = self._eval_rule(rule, log)
                if match:
                    matches.append(match)
            except Exception as exc:
                logger.debug("Rule evaluation error (%s): %s", rule.get("id"), exc)
        return matches

    def evaluate_batch(self, logs: list[dict[str, Any]]) -> dict[int, list[RuleMatch]]:
        """Evaluate rules against each log in a batch.

        Returns a mapping of log index → list of matches.
        """
        return {i: self.evaluate(log) for i, log in enumerate(logs)}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _eval_rule(self, rule: dict[str, Any], log: dict[str, Any]) -> Optional[RuleMatch]:
        conditions = rule.get("conditions", [])
        logic = rule.get("logic", "AND").upper()
        threshold = rule.get("threshold")

        results = [self._eval_condition(cond, log) for cond in conditions]

        if logic == "AND":
            passed = all(results)
        elif logic == "OR":
            passed = any(results)
        elif logic == "NOT":
            passed = not any(results)
        else:
            passed = all(results)

        if not passed:
            return None

        # Threshold / time-window check
        if threshold:
            rule_id = rule.get("id", "unknown")
            window = threshold.get("time_window", 60)
            count = threshold.get("count", 1)
            now = time.time()
            events = self._counters.setdefault(rule_id, [])
            events.append(now)
            # Prune old events outside window
            self._counters[rule_id] = [t for t in events if now - t <= window]
            if len(self._counters[rule_id]) < count:
                return None

        matched_labels = [
            cond.get("field", "unknown") for cond, r in zip(conditions, results) if r
        ]
        return RuleMatch(
            rule_id=str(rule.get("id", "unknown")),
            rule_name=str(rule.get("name", "Unnamed Rule")),
            severity=str(rule.get("severity", "medium")).lower(),
            description=str(rule.get("description", "")),
            matched_conditions=matched_labels,
            score=_SEVERITY_ORDER.get(str(rule.get("severity", "medium")).lower(), 2) * 25,
        )

    def _eval_condition(self, condition: dict[str, Any], log: dict[str, Any]) -> bool:
        field_path = condition.get("field", "")
        operator = condition.get("operator", "equals")
        value = condition.get("value")

        log_value = self._get_field(log, field_path)

        if operator == "equals":
            return str(log_value) == str(value)
        elif operator == "contains":
            return str(value).lower() in str(log_value).lower()
        elif operator == "startswith":
            return str(log_value).lower().startswith(str(value).lower())
        elif operator == "regex":
            return bool(re.search(str(value), str(log_value)))
        elif operator == "gt":
            try:
                return float(log_value) > float(value)
            except (TypeError, ValueError):
                return False
        elif operator == "lt":
            try:
                return float(log_value) < float(value)
            except (TypeError, ValueError):
                return False
        elif operator == "gte":
            try:
                return float(log_value) >= float(value)
            except (TypeError, ValueError):
                return False
        elif operator == "in":
            return log_value in (value if isinstance(value, (list, set)) else [value])
        elif operator == "exists":
            return log_value is not None and log_value != ""
        else:
            logger.debug("Unknown operator: %s", operator)
            return False

    def _get_field(self, obj: dict[str, Any], path: str) -> Any:
        """Retrieve a possibly-nested field using dot notation."""
        parts = path.split(".")
        current: Any = obj
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current
