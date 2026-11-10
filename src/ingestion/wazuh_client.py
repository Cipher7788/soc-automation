"""Wazuh API client for log ingestion."""

import logging
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
        verify_ssl: bool | str = True,
        timeout: int = 30,
        *,
        indexer_url: str = "",
        indexer_username: str = "",
        indexer_password: str = "",
        indexer_verify_ssl: bool | str = True,
    ) -> None:
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._session = self._build_session(verify_ssl)
        self._indexer_url = indexer_url.rstrip("/")
        self._indexer = self._build_session(indexer_verify_ssl)
        if indexer_username:
            self._indexer.auth = (indexer_username, indexer_password)

    def _build_session(self, verify_ssl: bool | str) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.verify = verify_ssl
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
        """Read a complete snapshot of recent alerts from the Wazuh Indexer."""
        if not self._indexer_url:
            raise ValueError("Set WAZUH_INDEXER_URL to collect Wazuh alerts")

        since = (datetime.now(timezone.utc) - timedelta(minutes=time_range)).isoformat()
        scroll_url = f"{self._indexer_url}/_search/scroll"
        scroll_id = None
        alerts = []
        try:
            response = self._indexer.post(
                f"{self._indexer_url}/wazuh-alerts-*/_search",
                params={"scroll": "1m", "allow_no_indices": "true", "allow_partial_search_results": "false"},
                json={"size": 500, "sort": ["_doc"], "query": {"range": {"timestamp": {"gte": since}}}},
                timeout=self.timeout,
            )
            while True:
                response.raise_for_status()
                page = response.json()
                scroll_id = page.get("_scroll_id", scroll_id)
                if page.get("timed_out") or page.get("_shards", {}).get("failed"):
                    raise RuntimeError("Wazuh Indexer returned incomplete search results")
                hits = page["hits"]["hits"]
                if not hits:
                    return alerts
                if not scroll_id:
                    raise RuntimeError("Wazuh Indexer did not return a scroll ID")
                alerts.extend(
                    {**hit["_source"], "_wazuh_document_id": (hit["_index"], hit["_id"])}
                    for hit in hits
                )
                response = self._indexer.post(
                    scroll_url, json={"scroll": "1m", "scroll_id": scroll_id}, timeout=self.timeout,
                )
        finally:
            if scroll_id:
                try:
                    self._indexer.delete(
                        scroll_url, json={"scroll_id": [scroll_id]}, timeout=self.timeout,
                    ).raise_for_status()
                except requests.RequestException:
                    logger.warning("Could not clear Wazuh Indexer scroll; it will expire")

    def get_agents(self) -> list[dict[str, Any]]:
        """Fetch all registered Wazuh agents."""
        return self._paginate("/agents")

    def get_agent_events(self, agent_id: str) -> list[dict[str, Any]]:
        """Fetch recent events for a specific agent."""
        return self._paginate(f"/agents/{agent_id}/events")

    def get_vulnerabilities(self) -> list[dict[str, Any]]:
        """Fetch vulnerability data from all agents."""
        return self._paginate("/vulnerability")
