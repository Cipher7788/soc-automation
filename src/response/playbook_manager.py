"""Playbook manager — maps alert types to Shuffle playbooks."""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from src.response.shuffle_client import ShuffleClient

logger = logging.getLogger(__name__)


@dataclass
class PlaybookExecution:
    """Audit record for a playbook execution."""

    playbook_id: str
    playbook_name: str
    alert_id: str
    execution_id: str = ""
    status: str = "pending"
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    requires_approval: bool = False
    approved: bool = False
    result: dict[str, Any] = field(default_factory=dict)


# Default mapping: alert type → playbook name
_DEFAULT_MAPPING: dict[str, str] = {
    "malware": "malware_detected",
    "brute_force": "brute_force",
    "suspicious_network": "suspicious_network",
    "lateral_movement": "suspicious_network",
    "data_exfiltration": "suspicious_network",
    "privilege_escalation": "malware_detected",
}

_HIGH_IMPACT_PLAYBOOKS = {"malware_detected", "brute_force"}


class PlaybookManager:
    """Map alert types to playbooks and track execution lifecycle.

    High-impact playbooks require explicit approval before execution.
    All executions are recorded as :class:`PlaybookExecution` objects
    for audit purposes.
    """

    def __init__(
        self,
        shuffle_client: ShuffleClient,
        playbooks_dir: str = "playbooks",
        alert_type_mapping: Optional[dict[str, str]] = None,
    ) -> None:
        self._shuffle = shuffle_client
        self._playbooks_dir = playbooks_dir
        self._mapping = alert_type_mapping or dict(_DEFAULT_MAPPING)
        self._executions: list[PlaybookExecution] = []
        self._workflow_cache: dict[str, str] = {}  # name -> workflow_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def select_playbook(self, alert_type: str) -> Optional[str]:
        """Return the playbook name for a given alert type."""
        return self._mapping.get(alert_type.lower())

    def execute(
        self,
        alert_type: str,
        alert_id: str,
        context: Optional[dict[str, Any]] = None,
        auto_approve: bool = False,
    ) -> Optional[PlaybookExecution]:
        """Select and execute the appropriate playbook for an alert.

        For high-impact playbooks, *auto_approve* must be ``True`` or
        the execution will be queued pending approval.
        """
        playbook_name = self.select_playbook(alert_type)
        if not playbook_name:
            logger.info("No playbook mapped for alert type: %s", alert_type)
            return None

        workflow_id = self._resolve_workflow_id(playbook_name)
        if not workflow_id:
            logger.warning("Cannot resolve workflow ID for playbook: %s", playbook_name)
            return None

        requires_approval = playbook_name in _HIGH_IMPACT_PLAYBOOKS
        execution = PlaybookExecution(
            playbook_id=workflow_id,
            playbook_name=playbook_name,
            alert_id=alert_id,
            requires_approval=requires_approval,
        )

        if requires_approval and not auto_approve:
            logger.info(
                "Playbook %s requires approval for alert %s; queuing",
                playbook_name, alert_id,
            )
            self._executions.append(execution)
            return execution

        self._run(execution, context or {})
        return execution

    def approve_and_execute(
        self, execution: PlaybookExecution, context: Optional[dict[str, Any]] = None
    ) -> PlaybookExecution:
        """Approve a pending high-impact execution and run it."""
        execution.approved = True
        self._run(execution, context or {})
        return execution

    def get_execution_log(self) -> list[PlaybookExecution]:
        """Return full audit trail of playbook executions."""
        return list(self._executions)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run(self, execution: PlaybookExecution, context: dict[str, Any]) -> None:
        try:
            result = self._shuffle.trigger_workflow(
                execution.playbook_id,
                execution_argument={"alert_id": execution.alert_id, **context},
            )
            execution.execution_id = result.get("execution_id", "")
            execution.status = "running"
            execution.result = result
            self._executions.append(execution)
            logger.info(
                "Playbook %s triggered (execution=%s)",
                execution.playbook_name, execution.execution_id,
            )
        except Exception as exc:
            execution.status = "failed"
            execution.finished_at = time.time()
            self._executions.append(execution)
            logger.error("Failed to execute playbook %s: %s", execution.playbook_name, exc)

    def _resolve_workflow_id(self, name: str) -> Optional[str]:
        """Resolve a playbook name to a Shuffle workflow ID.

        First checks the local JSON definition, then queries the API.
        """
        if name in self._workflow_cache:
            return self._workflow_cache[name]

        # Try loading from local JSON file
        local_path = os.path.join(self._playbooks_dir, f"{name}.json")
        if os.path.exists(local_path):
            try:
                with open(local_path, encoding="utf-8") as f:
                    data = json.load(f)
                workflow_id = data.get("id") or data.get("workflow_id")
                if workflow_id:
                    self._workflow_cache[name] = workflow_id
                    return workflow_id
            except Exception as exc:
                logger.warning("Failed to read playbook file %s: %s", local_path, exc)

        # Fall back to API lookup
        try:
            workflows = self._shuffle.list_workflows()
            for wf in workflows:
                if wf.get("name") == name:
                    wid = wf.get("id")
                    if wid:
                        self._workflow_cache[name] = wid
                        return wid
        except Exception as exc:
            logger.warning("Failed to list Shuffle workflows: %s", exc)

        return None
