"""Wazuh API client for log ingestion."""

import logging
import time
from typing import Any, Optional
from datetime import datetime, timezone, timedelta

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class WazuhAuthError(Exception):
    """Raised when authentication with Wazuh fails."""


class WazuhClient:
    """Client for interacting with the Wazuh REST API.

    Handles JWT authentication with auto-refresh, retry logic with
    exponential backoff, and pagination for large result sets.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_ssl: bool = False,
        timeout: int = 30,
    ) -> None:
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.verify = self.verify_ssl
        return session

    def authenticate(self) -> str:
        """Authenticate with Wazuh and return a JWT token."""
        url = f"{self.host}/security/user/authenticate"
        try:
            response = self._session.get(
                url,
                auth=(self.username, self.password),
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            token = data["data"]["token"]
            self._token = token
            self._token_expiry = datetime.now(timezone.utc) + timedelta(seconds=900)
            logger.info("Wazuh authentication successful")
            return token
        except requests.HTTPError as exc:
            raise WazuhAuthError(f"Wazuh authentication failed: {exc}") from exc

    def _get_token(self) -> str:
        """Return a valid JWT token, refreshing if necessary."""
        if (
            self._token is None
            or self._token_expiry is None
            or datetime.now(timezone.utc) >= self._token_expiry
        ):
            self.authenticate()
        return self._token  # type: ignore[return-value]

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token()}"}

    def _get(self, path: str, params: Optional[dict] = None) -> dict[str, Any]:
        url = f"{self.host}{path}"
        response = self._session.get(
            url,
            headers=self._headers(),
            params=params,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def _paginate(self, path: str, params: Optional[dict] = None) -> list[dict[str, Any]]:
        """Fetch all pages for a paginated Wazuh endpoint."""
        params = params or {}
        params.setdefault("limit", 500)
        params["offset"] = 0
        results: list[dict[str, Any]] = []

        while True:
            data = self._get(path, params)
            items = data.get("data", {}).get("affected_items", [])
            results.extend(items)
            total = data.get("data", {}).get("total_affected_items", 0)
            params["offset"] += len(items)
            if params["offset"] >= total or not items:
                break
        return results

    def get_alerts(self, time_range: int = 60) -> list[dict[str, Any]]:
        """Fetch alerts from Wazuh within the last *time_range* minutes."""
        since = (datetime.now(timezone.utc) - timedelta(minutes=time_range)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        params = {
            "q": f"timestamp>{since}",
            "sort": "-timestamp",
        }
        logger.debug("Fetching Wazuh alerts since %s", since)
        return self._paginate("/alerts", params)

    def get_agents(self) -> list[dict[str, Any]]:
        """Fetch all registered Wazuh agents."""
        return self._paginate("/agents")

    def get_agent_events(self, agent_id: str) -> list[dict[str, Any]]:
        """Fetch recent events for a specific agent."""
        return self._paginate(f"/agents/{agent_id}/events")

    def get_vulnerabilities(self) -> list[dict[str, Any]]:
        """Fetch vulnerability data from all agents."""
        return self._paginate("/vulnerability")
