"""IOC detection engine for IP, domain, hash, URL, and email matching."""

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class IOCMatch:
    """Represents a single IOC detection match."""

    ioc_type: str
    value: str
    confidence: float
    source: str
    details: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
_SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
_SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
_URL_RE = re.compile(
    r"https?://[^\s/$.?#].[^\s]*",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Known-bad IPs / domains / hashes used as a built-in blocklist (demo values)
_KNOWN_MALICIOUS_IPS: set[str] = {
    "198.51.100.1",
    "203.0.113.99",
    "10.0.0.254",  # example internal bad actor
}
_KNOWN_MALICIOUS_DOMAINS: set[str] = {
    "malware.example.com",
    "c2.badactor.net",
    "phishing.evil.org",
}
_KNOWN_MALICIOUS_HASHES: set[str] = {
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty file (demo)
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1 of empty file (demo)
}


class IOCDetector:
    """Detect Indicators of Compromise in log data.

    Checks text against pattern matching, a built-in blocklist, and
    optional external threat intel results (injected via cache).
    """

    def __init__(
        self,
        malicious_ips: Optional[set[str]] = None,
        malicious_domains: Optional[set[str]] = None,
        malicious_hashes: Optional[set[str]] = None,
        cache_ttl: int = 3600,
    ) -> None:
        self._malicious_ips: set[str] = malicious_ips or set(_KNOWN_MALICIOUS_IPS)
        self._malicious_domains: set[str] = malicious_domains or set(_KNOWN_MALICIOUS_DOMAINS)
        self._malicious_hashes: set[str] = malicious_hashes or set(_KNOWN_MALICIOUS_HASHES)
        self._cache: dict[str, tuple[list[IOCMatch], float]] = {}
        self._cache_ttl = cache_ttl

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, text: str) -> list[IOCMatch]:
        """Run all IOC detectors against *text* and return matches."""
        cached = self._cache.get(text)
        if cached and (time.time() - cached[1]) < self._cache_ttl:
            return cached[0]

        matches: list[IOCMatch] = []
        matches.extend(self._detect_ips(text))
        matches.extend(self._detect_domains(text))
        matches.extend(self._detect_hashes(text))
        matches.extend(self._detect_urls(text))
        matches.extend(self._detect_emails(text))

        self._cache[text] = (matches, time.time())
        return matches

    def add_malicious_ip(self, ip: str) -> None:
        self._malicious_ips.add(ip)

    def add_malicious_domain(self, domain: str) -> None:
        self._malicious_domains.add(domain.lower())

    def add_malicious_hash(self, hash_val: str) -> None:
        self._malicious_hashes.add(hash_val.lower())

    # ------------------------------------------------------------------
    # Internal detectors
    # ------------------------------------------------------------------

    def _detect_ips(self, text: str) -> list[IOCMatch]:
        matches = []
        for ip in set(_IP_RE.findall(text)):
            if ip in self._malicious_ips:
                matches.append(
                    IOCMatch(
                        ioc_type="ip",
                        value=ip,
                        confidence=0.95,
                        source="blocklist",
                        details={"matched_list": "malicious_ips"},
                    )
                )
            elif self._is_suspicious_ip(ip):
                matches.append(
                    IOCMatch(
                        ioc_type="ip",
                        value=ip,
                        confidence=0.4,
                        source="heuristic",
                    )
                )
        return matches

    def _is_suspicious_ip(self, ip: str) -> bool:
        """Heuristic: flag IPs in suspicious ranges (simplified)."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first = int(parts[0])
        # RFC 5737 documentation ranges, commonly abused
        return first in (192, 198, 203)

    def _detect_domains(self, text: str) -> list[IOCMatch]:
        matches = []
        for domain in set(_DOMAIN_RE.findall(text)):
            lower = domain.lower()
            if lower in self._malicious_domains:
                matches.append(
                    IOCMatch(
                        ioc_type="domain",
                        value=lower,
                        confidence=0.95,
                        source="blocklist",
                    )
                )
        return matches

    def _detect_hashes(self, text: str) -> list[IOCMatch]:
        matches = []
        for sha256 in set(_SHA256_RE.findall(text)):
            h = sha256.lower()
            if h in self._malicious_hashes:
                matches.append(IOCMatch(ioc_type="sha256", value=h, confidence=0.99, source="blocklist"))

        for sha1 in set(_SHA1_RE.findall(text)):
            h = sha1.lower()
            if h in self._malicious_hashes:
                matches.append(IOCMatch(ioc_type="sha1", value=h, confidence=0.99, source="blocklist"))

        for md5 in set(_MD5_RE.findall(text)):
            h = md5.lower()
            if h in self._malicious_hashes:
                matches.append(IOCMatch(ioc_type="md5", value=h, confidence=0.99, source="blocklist"))
        return matches

    def _detect_urls(self, text: str) -> list[IOCMatch]:
        matches = []
        for url in set(_URL_RE.findall(text)):
            domain_match = _DOMAIN_RE.search(url)
            if domain_match:
                domain = domain_match.group(0).lower()
                if domain in self._malicious_domains:
                    matches.append(
                        IOCMatch(
                            ioc_type="url",
                            value=url,
                            confidence=0.90,
                            source="blocklist",
                            details={"matched_domain": domain},
                        )
                    )
        return matches

    def _detect_emails(self, text: str) -> list[IOCMatch]:
        matches = []
        for email in set(_EMAIL_RE.findall(text)):
            domain = email.split("@")[-1].lower()
            if domain in self._malicious_domains:
                matches.append(
                    IOCMatch(
                        ioc_type="email",
                        value=email,
                        confidence=0.80,
                        source="blocklist",
                        details={"matched_domain": domain},
                    )
                )
        return matches
