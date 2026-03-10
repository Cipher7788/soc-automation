"""Tests for the AttackSimulator module."""

import pytest
import os

from src.simulation.attack_simulator import AttackSimulator, AttackScenario, SimulationStep


@pytest.fixture
def simulator():
    return AttackSimulator()


class TestAttackSimulator:
    def test_list_scenarios_returns_list(self, simulator):
        scenarios = simulator.list_scenarios()
        assert isinstance(scenarios, list)

    def test_scenarios_loaded_from_yaml(self, simulator):
        assert len(simulator.list_scenarios()) >= 5

    def test_known_scenario_names(self, simulator):
        scenarios = simulator.list_scenarios()
        assert "brute_force_ssh" in scenarios
        assert "credential_dumping" in scenarios
        assert "data_exfiltration" in scenarios

    def test_simulate_returns_log_entries(self, simulator):
        logs = simulator.simulate("brute_force_ssh")
        assert isinstance(logs, list)
        assert len(logs) > 0

    def test_simulated_logs_have_required_fields(self, simulator):
        logs = simulator.simulate("brute_force_ssh")
        for log in logs:
            assert "timestamp" in log
            assert "message" in log
            assert "action" in log

    def test_simulate_unknown_scenario_raises(self, simulator):
        with pytest.raises(ValueError, match="Unknown scenario"):
            simulator.simulate("nonexistent_scenario")

    def test_simulate_with_custom_context(self, simulator):
        logs = simulator.simulate("port_scan", context={"src_ip": "10.99.99.99"})
        combined = " ".join(log["message"] for log in logs)
        assert "10.99.99.99" in combined

    def test_simulate_attaches_mitre_technique(self, simulator):
        logs = simulator.simulate("brute_force_ssh")
        for log in logs:
            assert "mitre_technique" in log
            assert log["mitre_technique"] != ""

    def test_simulation_step_generate_log(self):
        step = SimulationStep(
            action="test_action",
            log_template="Failed login from {src_ip} to {hostname}",
            expected_detection="brute_force",
        )
        ctx = {"src_ip": "1.2.3.4", "hostname": "server-01"}
        log = step.generate_log(ctx)
        assert "1.2.3.4" in log["message"]
        assert "server-01" in log["message"]
        assert log["action"] == "test_action"

    def test_simulator_loads_custom_scenarios(self, tmp_path):
        scenario_file = tmp_path / "custom.yml"
        scenario_file.write_text("""
name: custom_test
description: A custom test scenario
mitre_technique: T1234
severity: low
steps:
  - action: test_step
    log_template: "Custom log from {src_ip}"
    expected_detection: custom_detection
""")
        sim = AttackSimulator(scenarios_dir=str(tmp_path))
        assert "custom_test" in sim.list_scenarios()
        logs = sim.simulate("custom_test")
        assert len(logs) == 1
