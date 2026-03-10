"""TheHive API client for alert and case management."""

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

# TLP / PAP levels
TLP_WHITE = 0
TLP_GREEN = 1
TLP_AMBER = 2
TLP_RED = 3

PAP_WHITE = 0
PAP_GREEN = 1
PAP_AMBER = 2
PAP_RED = 3


@dataclass
class HiveAlert:
    """Structured TheHive alert."""

    title: str
    description: str
    severity: int = 2  # 1=Low, 2=Medium, 3=High
    source: str = "SOC-Automation"
    source_ref: str = ""
    alert_type: str = "external"
    tlp: int = TLP_AMBER
    pap: int = PAP_AMBER
    tags: list[str] = field(default_factory=list)
    observables: list[dict[str, Any]] = field(default_factory=list)
    custom_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class HiveCase:
    """Structured TheHive case."""

    title: str
    description: str
    severity: int = 2
    tlp: int = TLP_AMBER
    pap: int = PAP_AMBER
    tags: list[str] = field(default_factory=list)
    tasks: list[dict[str, Any]] = field(default_factory=list)
    custom_fields: dict[str, Any] = field(default_factory=dict)


class TheHiveClient:
    """Client for the TheHive v5 API.

    Supports alert creation, case management, and observable attachment.
    Authentication is via API key.
    """

    def __init__(
        self,
        url: str,
        api_key: str,
        timeout: int = 30,
        verify_ssl: bool = True,
    ) -> None:
        self._base_url = url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._verify_ssl = verify_ssl
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        })
        self._session.verify = self._verify_ssl

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def create_alert(self, alert: HiveAlert) -> dict[str, Any]:
        """Create an alert in TheHive."""
        payload: dict[str, Any] = {
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "source": alert.source,
            "sourceRef": alert.source_ref or f"soc-{id(alert)}",
            "type": alert.alert_type,
            "tlp": alert.tlp,
            "pap": alert.pap,
            "tags": alert.tags,
        }
        if alert.observables:
            payload["observables"] = alert.observables
        if alert.custom_fields:
            payload["customFields"] = alert.custom_fields

        response = self._session.post(
            f"{self._base_url}/api/v1/alert",
            json=payload,
            timeout=self._timeout,
        )
        response.raise_for_status()
        logger.info("Created TheHive alert: %s", alert.title)
        return response.json()

    def search_alerts(self, query: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
        """Search for alerts in TheHive."""
        payload = query or {"query": []}
        response = self._session.post(
            f"{self._base_url}/api/v1/alert/_search",
            json=payload,
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------

    def create_case(self, case: HiveCase) -> dict[str, Any]:
        """Create a new case in TheHive."""
        payload: dict[str, Any] = {
            "title": case.title,
            "description": case.description,
            "severity": case.severity,
            "tlp": case.tlp,
            "pap": case.pap,
            "tags": case.tags,
        }
        if case.tasks:
            payload["tasks"] = case.tasks
        if case.custom_fields:
            payload["customFields"] = case.custom_fields

        response = self._session.post(
            f"{self._base_url}/api/v1/case",
            json=payload,
            timeout=self._timeout,
        )
        response.raise_for_status()
        logger.info("Created TheHive case: %s", case.title)
        return response.json()

    def get_case(self, case_id: str) -> dict[str, Any]:
        """Retrieve a case by ID."""
        response = self._session.get(
            f"{self._base_url}/api/v1/case/{case_id}",
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json()

    def update_case(self, case_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update fields on an existing case."""
        response = self._session.patch(
            f"{self._base_url}/api/v1/case/{case_id}",
            json=updates,
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json()

    # ------------------------------------------------------------------
    # Observables
    # ------------------------------------------------------------------

    def add_observable(
        self,
        case_id: str,
        data_type: str,
        data: str,
        message: str = "",
        tags: Optional[list[str]] = None,
        tlp: int = TLP_AMBER,
    ) -> dict[str, Any]:
        """Add an observable to a case."""
        payload = {
            "dataType": data_type,
            "data": data,
            "message": message,
            "tlp": tlp,
            "tags": tags or [],
        }
        response = self._session.post(
            f"{self._base_url}/api/v1/case/{case_id}/observable",
            json=payload,
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.json()
