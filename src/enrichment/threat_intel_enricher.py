"""Threat Intelligence Enricher — queries VirusTotal, AbuseIPDB, and AlienVault OTX."""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class EnrichmentResult:
    """Result of enriching a single IOC against threat intelligence APIs."""

    ioc_value: str
    ioc_type: str
    reputation: str  # Malicious | Suspicious | Clean | Unknown
    confidence_score: float  # 0–100
    sources: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    enriched_at: float = field(default_factory=time.time)

    def __str__(self) -> str:
        return (
            f"{self.ioc_type.upper()}: {self.ioc_value}\n"
            f"Reputation: {self.reputation}\n"
            f"Source: {', '.join(self.sources)}\n"
            f"Confidence: {self.confidence_score:.0f}%"
        )


class ThreatIntelEnricher:
    """Enrich IOCs by querying VirusTotal, AbuseIPDB, and AlienVault OTX.

    Results are cached for *cache_ttl* seconds to avoid redundant API calls.
    """

    VT_API_URL = "https://www.virustotal.com/api/v3"
    ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2"
    OTX_API_URL = "https://otx.alienvault.com/api/v1"

    def __init__(
        self,
        virustotal_api_key: str = "",
        abuseipdb_api_key: str = "",
        otx_api_key: str = "",
        cache_ttl: int = 3600,
        timeout: int = 10,
    ) -> None:
        self._vt_key = virustotal_api_key
        self._abuse_key = abuseipdb_api_key
        self._otx_key = otx_api_key
        self._cache_ttl = cache_ttl
        self._timeout = timeout
        self._cache: dict[str, tuple[EnrichmentResult, float]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich(self, ioc_value: str, ioc_type: str) -> EnrichmentResult:
        """Enrich a single IOC and return a consolidated result.

        ioc_type should be one of: "ip", "domain", "md5", "sha1", "sha256", "url".
        """
        cache_key = f"{ioc_type}:{ioc_value}"
        cached = self._cache.get(cache_key)
        if cached and (time.time() - cached[1]) < self._cache_ttl:
            logger.debug("Cache hit for %s", cache_key)
            return cached[0]

        results: list[dict[str, Any]] = []

        if ioc_type == "ip":
            if self._vt_key:
                results.append(self._query_virustotal_ip(ioc_value))
            if self._abuse_key:
                results.append(self._query_abuseipdb(ioc_value))
            if self._otx_key:
                results.append(self._query_otx_ip(ioc_value))
        elif ioc_type == "domain":
            if self._vt_key:
                results.append(self._query_virustotal_domain(ioc_value))
            if self._otx_key:
                results.append(self._query_otx_domain(ioc_value))
        elif ioc_type in ("md5", "sha1", "sha256"):
            if self._vt_key:
                results.append(self._query_virustotal_hash(ioc_value))
        elif ioc_type == "url":
            if self._vt_key:
                results.append(self._query_virustotal_url(ioc_value))

        enriched = self._aggregate(ioc_value, ioc_type, results)
        self._cache[cache_key] = (enriched, time.time())
        return enriched

    def enrich_batch(self, iocs: list[dict[str, str]]) -> list[EnrichmentResult]:
        """Enrich a list of IOCs.  Each dict must have 'value' and 'type' keys."""
        return [self.enrich(ioc["value"], ioc["type"]) for ioc in iocs]

    # ------------------------------------------------------------------
    # VirusTotal
    # ------------------------------------------------------------------

    def _query_virustotal_ip(self, ip: str) -> dict[str, Any]:
        try:
            resp = requests.get(
                f"{self.VT_API_URL}/ip_addresses/{ip}",
                headers={"x-apikey": self._vt_key},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            return {
                "source": "VirusTotal",
                "malicious_votes": malicious,
                "total_votes": total,
                "confidence": (malicious / total) * 100,
                "raw": data,
            }
        except Exception as exc:
            logger.warning("VirusTotal IP query failed: %s", exc)
            return {"source": "VirusTotal", "error": str(exc)}

    def _query_virustotal_domain(self, domain: str) -> dict[str, Any]:
        try:
            resp = requests.get(
                f"{self.VT_API_URL}/domains/{domain}",
                headers={"x-apikey": self._vt_key},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            return {
                "source": "VirusTotal",
                "malicious_votes": malicious,
                "total_votes": total,
                "confidence": (malicious / total) * 100,
                "raw": data,
            }
        except Exception as exc:
            logger.warning("VirusTotal domain query failed: %s", exc)
            return {"source": "VirusTotal", "error": str(exc)}

    def _query_virustotal_hash(self, file_hash: str) -> dict[str, Any]:
        try:
            resp = requests.get(
                f"{self.VT_API_URL}/files/{file_hash}",
                headers={"x-apikey": self._vt_key},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            return {
                "source": "VirusTotal",
                "malicious_votes": malicious,
                "total_votes": total,
                "confidence": (malicious / total) * 100,
                "raw": data,
            }
        except Exception as exc:
            logger.warning("VirusTotal hash query failed: %s", exc)
            return {"source": "VirusTotal", "error": str(exc)}

    def _query_virustotal_url(self, url: str) -> dict[str, Any]:
        import base64
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            resp = requests.get(
                f"{self.VT_API_URL}/urls/{url_id}",
                headers={"x-apikey": self._vt_key},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            return {
                "source": "VirusTotal",
                "malicious_votes": malicious,
                "total_votes": total,
                "confidence": (malicious / total) * 100,
                "raw": data,
            }
        except Exception as exc:
            logger.warning("VirusTotal URL query failed: %s", exc)
            return {"source": "VirusTotal", "error": str(exc)}

    # ------------------------------------------------------------------
    # AbuseIPDB
    # ------------------------------------------------------------------

    def _query_abuseipdb(self, ip: str) -> dict[str, Any]:
        try:
            resp = requests.get(
                f"{self.ABUSEIPDB_API_URL}/check",
                headers={"Key": self._abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "source": "AbuseIPDB",
                "confidence": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", ""),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", ""),
                "raw": data,
            }
        except Exception as exc:
            logger.warning("AbuseIPDB query failed: %s", exc)
            return {"source": "AbuseIPDB", "error": str(exc)}

    # ------------------------------------------------------------------
    # AlienVault OTX
    # ------------------------------------------------------------------

    def _query_otx_ip(self, ip: str) -> dict[str, Any]:
        try:
            resp = requests.get(
                f"{self.OTX_API_URL}/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": self._otx_key},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            confidence = min(pulse_count * 10, 100)
            return {
                "source": "AlienVault OTX",
                "pulse_count": pulse_count,
                "confidence": confidence,
                "reputation": data.get("reputation", 0),
                "raw": data,
            }
        except Exception as exc:
            logger.warning("OTX IP query failed: %s", exc)
            return {"source": "AlienVault OTX", "error": str(exc)}

    def _query_otx_domain(self, domain: str) -> dict[str, Any]:
        try:
            resp = requests.get(
                f"{self.OTX_API_URL}/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": self._otx_key},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            confidence = min(pulse_count * 10, 100)
            return {
                "source": "AlienVault OTX",
                "pulse_count": pulse_count,
                "confidence": confidence,
                "raw": data,
            }
        except Exception as exc:
            logger.warning("OTX domain query failed: %s", exc)
            return {"source": "AlienVault OTX", "error": str(exc)}

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def _aggregate(
        self, ioc_value: str, ioc_type: str, results: list[dict[str, Any]]
    ) -> EnrichmentResult:
        """Combine results from multiple sources into a single EnrichmentResult."""
        if not results:
            return EnrichmentResult(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                reputation="Unknown",
                confidence_score=0.0,
            )

        valid = [r for r in results if "error" not in r]
        sources = [r["source"] for r in valid]
        confidences = [r.get("confidence", 0.0) for r in valid]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        details = {r["source"]: r for r in results}

        if avg_confidence >= 70:
            reputation = "Malicious"
        elif avg_confidence >= 30:
            reputation = "Suspicious"
        elif valid:
            reputation = "Clean"
        else:
            reputation = "Unknown"

        return EnrichmentResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            reputation=reputation,
            confidence_score=avg_confidence,
            sources=sources,
            details=details,
        )
