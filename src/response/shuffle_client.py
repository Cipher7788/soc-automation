"""Shuffle SOAR API client."""

import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


class ShuffleClient:
    """Client for the Shuffle SOAR REST API.

    Supports workflow triggering, status retrieval, and execution
    result fetching.
    """

    def __init__(
        self,
        url: str,
        api_key: str,
        timeout: int = 30,
    ) -> None:
        self._base_url = url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        })

    # ------------------------------------------------------------------
    # Workflows
    # ------------------------------------------------------------------

    def list_workflows(self) -> list[dict[str, Any]]:
        """Return all available workflows."""
        response = self._session.get(
            f"{self._base_url}/api/v1/workflows",
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json()

    def trigger_workflow(
        self,
        workflow_id: str,
        execution_argument: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Trigger a Shuffle workflow execution.

        Returns execution metadata including the execution ID.
        """
        payload = {"execution_argument": execution_argument or {}}
        response = self._session.post(
            f"{self._base_url}/api/v1/workflows/{workflow_id}/execute",
            json=payload,
            timeout=self._timeout,
        )
        response.raise_for_status()
        data = response.json()
        logger.info("Triggered Shuffle workflow %s; execution=%s", workflow_id, data.get("execution_id"))
        return data

    def get_workflow_status(self, workflow_id: str) -> dict[str, Any]:
        """Get the details of a specific workflow."""
        response = self._session.get(
            f"{self._base_url}/api/v1/workflows/{workflow_id}",
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json()

    def get_execution_results(self, workflow_id: str, execution_id: str) -> dict[str, Any]:
        """Retrieve the results of a specific workflow execution."""
        response = self._session.get(
            f"{self._base_url}/api/v1/workflows/{workflow_id}/executions/{execution_id}",
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json()
