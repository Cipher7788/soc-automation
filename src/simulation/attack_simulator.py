"""Attack Simulator — generates realistic attack log entries for SOC pipeline testing."""

import logging
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

_SCENARIOS_DIR = os.path.join(os.path.dirname(__file__), "scenarios")


@dataclass
class SimulationStep:
    """A single step within an attack scenario."""

    action: str
    log_template: str
    expected_detection: str = ""

    def generate_log(self, context: dict[str, Any]) -> dict[str, Any]:
        """Render the log_template with context variables."""
        try:
            rendered = self.log_template.format(**context)
        except KeyError:
            rendered = self.log_template
        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "message": rendered,
            "action": self.action,
            "expected_detection": self.expected_detection,
            "_simulated": True,
        }


@dataclass
class AttackScenario:
    """A complete attack scenario composed of multiple steps."""

    name: str
    description: str
    mitre_technique: str
    severity: str
    steps: list[SimulationStep] = field(default_factory=list)


class AttackSimulator:
    """Load and execute attack scenarios to generate test log data.

    Scenarios are defined in YAML files in *scenarios_dir*.  Simulated log
    entries can be injected directly into the SOC pipeline for end-to-end
    testing without needing live attack traffic.
    """

    def __init__(self, scenarios_dir: str = _SCENARIOS_DIR) -> None:
        self._scenarios_dir = scenarios_dir
        self._scenarios: dict[str, AttackScenario] = {}
        self._load_scenarios()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_scenarios(self) -> list[str]:
        """Return the names of all loaded attack scenarios."""
        return list(self._scenarios.keys())

    def simulate(self, scenario_name: str, context: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
        """Run a named scenario and return the generated log entries."""
        scenario = self._scenarios.get(scenario_name)
        if not scenario:
            raise ValueError(f"Unknown scenario: {scenario_name!r}. Available: {self.list_scenarios()}")

        ctx = self._default_context()
        if context:
            ctx.update(context)

        logs = []
        for step in scenario.steps:
            log = step.generate_log(ctx)
            log["scenario"] = scenario_name
            log["mitre_technique"] = scenario.mitre_technique
            log["severity"] = scenario.severity
            logs.append(log)
            logger.debug("Simulated step: %s → %s", step.action, log["message"])

        return logs

    def get_scenario(self, name: str) -> Optional[AttackScenario]:
        return self._scenarios.get(name)

    # ------------------------------------------------------------------
    # Scenario loading
    # ------------------------------------------------------------------

    def _load_scenarios(self) -> None:
        if not os.path.isdir(self._scenarios_dir):
            logger.warning("Scenarios directory not found: %s", self._scenarios_dir)
            return
        for filename in os.listdir(self._scenarios_dir):
            if not filename.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(self._scenarios_dir, filename)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                scenario = self._parse_scenario(data)
                self._scenarios[scenario.name] = scenario
                logger.debug("Loaded attack scenario: %s", scenario.name)
            except Exception as exc:
                logger.error("Failed to load scenario %s: %s", filename, exc)

    def _parse_scenario(self, data: dict[str, Any]) -> AttackScenario:
        steps = [
            SimulationStep(
                action=s["action"],
                log_template=s["log_template"],
                expected_detection=s.get("expected_detection", ""),
            )
            for s in data.get("steps", [])
        ]
        return AttackScenario(
            name=data["name"],
            description=data.get("description", ""),
            mitre_technique=data.get("mitre_technique", ""),
            severity=data.get("severity", "medium"),
            steps=steps,
        )

    # ------------------------------------------------------------------
    # Context helpers
    # ------------------------------------------------------------------

    def _default_context(self) -> dict[str, Any]:
        return {
            "src_ip": random.choice([
                f"192.168.1.{random.randint(2, 254)}",
                f"10.0.0.{random.randint(2, 254)}",
            ]),
            "dst_ip": "10.0.0.1",
            "username": random.choice(["admin", "user1", "svc_account", "root"]),
            "hostname": random.choice(["web-server-01", "db-server-02", "endpoint-03"]),
            "port": random.choice([22, 80, 443, 3389, 445]),
            "process": random.choice(["powershell.exe", "cmd.exe", "python.exe", "bash"]),
            "hash": "d41d8cd98f00b204e9800998ecf8427e",
            "domain": "malware.example.com",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "attempt_count": random.randint(5, 50),
        }
