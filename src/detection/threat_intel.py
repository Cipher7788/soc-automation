"""Threat intelligence feed integration (AbuseIPDB, VirusTotal, OTX)."""

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelResult:
    """Aggregated result from threat intelligence lookups."""

    indicator: str
    indicator_type: str
    malicious: bool
    confidence: float
    sources: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


class _RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, calls_per_minute: int) -> None:
        self._min_interval = 60.0 / max(calls_per_minute, 1)
        self._last_call = 0.0

    def wait(self) -> None:
        elapsed = time.time() - self._last_call
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_call = time.time()


class ThreatIntelManager:
    """Manage threat intelligence lookups across multiple feeds.

    Integrates with AbuseIPDB, VirusTotal, and OTX AlienVault. Results
    are cached with a configurable TTL to reduce API usage.
    """

    def __init__(
        self,
        abuseipdb_key: str = "",
        virustotal_key: str = "",
        otx_key: str = "",
        cache_ttl: int = 3600,
        timeout: int = 15,
    ) -> None:
        self._abuseipdb_key = abuseipdb_key
        self._virustotal_key = virustotal_key
        self._otx_key = otx_key
        self._cache_ttl = cache_ttl
        self._timeout = timeout
        self._cache: dict[str, tuple[ThreatIntelResult, float]] = {}
        self._rl_abuse = _RateLimiter(calls_per_minute=10)
        self._rl_vt = _RateLimiter(calls_per_minute=4)
        self._rl_otx = _RateLimiter(calls_per_minute=60)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup_ip(self, ip: str) -> ThreatIntelResult:
        """Look up an IP address across all configured feeds."""
        cached = self._get_cached(ip)
        if cached:
            return cached

        sources: list[str] = []
        details: dict[str, Any] = {}
        malicious = False
        confidence = 0.0

        if self._abuseipdb_key:
            result = self._abuseipdb_lookup(ip)
            if result:
                sources.append("abuseipdb")
                details["abuseipdb"] = result
                score = result.get("abuseConfidenceScore", 0)
                if score > 50:
                    malicious = True
                    confidence = max(confidence, score / 100.0)

        if self._otx_key:
            result = self._otx_lookup(ip, "IPv4")
            if result:
                sources.append("otx")
                details["otx"] = result
                if result.get("pulse_count", 0) > 0:
                    malicious = True
                    confidence = max(confidence, 0.7)

        intel = ThreatIntelResult(
            indicator=ip,
            indicator_type="ip",
            malicious=malicious,
            confidence=confidence,
            sources=sources,
            details=details,
        )
        self._set_cached(ip, intel)
        return intel

    def lookup_hash(self, hash_val: str) -> ThreatIntelResult:
        """Look up a file hash via VirusTotal."""
        cached = self._get_cached(hash_val)
        if cached:
            return cached

        sources: list[str] = []
        details: dict[str, Any] = {}
        malicious = False
        confidence = 0.0

        if self._virustotal_key:
            result = self._virustotal_lookup(hash_val, "file")
            if result:
                sources.append("virustotal")
                details["virustotal"] = result
                positives = result.get("positives", 0)
                total = result.get("total", 1)
                if positives > 0:
                    malicious = True
                    confidence = positives / total

        intel = ThreatIntelResult(
            indicator=hash_val,
            indicator_type="hash",
            malicious=malicious,
            confidence=confidence,
            sources=sources,
            details=details,
        )
        self._set_cached(hash_val, intel)
        return intel

    def lookup_domain(self, domain: str) -> ThreatIntelResult:
        """Look up a domain via OTX and VirusTotal."""
        cached = self._get_cached(domain)
        if cached:
            return cached

        sources: list[str] = []
        details: dict[str, Any] = {}
        malicious = False
        confidence = 0.0

        if self._otx_key:
            result = self._otx_lookup(domain, "domain")
            if result:
                sources.append("otx")
                details["otx"] = result
                if result.get("pulse_count", 0) > 0:
                    malicious = True
                    confidence = max(confidence, 0.7)

        if self._virustotal_key:
            result = self._virustotal_lookup(domain, "domain")
            if result:
                sources.append("virustotal")
                details["virustotal"] = result
                positives = result.get("positives", 0)
                total = result.get("total", 1)
                if positives > 0:
                    malicious = True
                    confidence = max(confidence, positives / total)

        intel = ThreatIntelResult(
            indicator=domain,
            indicator_type="domain",
            malicious=malicious,
            confidence=confidence,
            sources=sources,
            details=details,
        )
        self._set_cached(domain, intel)
        return intel

    # ------------------------------------------------------------------
    # Internal feed implementations
    # ------------------------------------------------------------------

    def _abuseipdb_lookup(self, ip: str) -> Optional[dict[str, Any]]:
        self._rl_abuse.wait()
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self._abuseipdb_key, "Accept": "application/json"},
                timeout=self._timeout,
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except Exception as exc:
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
            return None

    def _virustotal_lookup(self, indicator: str, kind: str) -> Optional[dict[str, Any]]:
        self._rl_vt.wait()
        endpoints = {
            "file": f"https://www.virustotal.com/api/v3/files/{indicator}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}",
            "url": "https://www.virustotal.com/api/v3/urls",
        }
        url = endpoints.get(kind, endpoints["file"])
        try:
            response = requests.get(
                url,
                headers={"x-apikey": self._virustotal_key},
                timeout=self._timeout,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            return {
                "positives": stats.get("malicious", 0),
                "total": sum(stats.values()) or 1,
                "raw": data,
            }
        except Exception as exc:
            logger.warning("VirusTotal lookup failed for %s: %s", indicator, exc)
            return None

    def _otx_lookup(self, indicator: str, kind: str) -> Optional[dict[str, Any]]:
        self._rl_otx.wait()
        url = f"https://otx.alienvault.com/api/v1/indicators/{kind}/{indicator}/general"
        try:
            response = requests.get(
                url,
                headers={"X-OTX-API-KEY": self._otx_key},
                timeout=self._timeout,
            )
            response.raise_for_status()
            data = response.json()
            return {
                "pulse_count": data.get("pulse_info", {}).get("count", 0),
                "raw": data,
            }
        except Exception as exc:
            logger.warning("OTX lookup failed for %s: %s", indicator, exc)
            return None

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _get_cached(self, key: str) -> Optional[ThreatIntelResult]:
        entry = self._cache.get(key)
        if entry and (time.time() - entry[1]) < self._cache_ttl:
            return entry[0]
        return None

    def _set_cached(self, key: str, result: ThreatIntelResult) -> None:
        self._cache[key] = (result, time.time())
