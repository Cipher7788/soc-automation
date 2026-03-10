"""Input validation and sanitization utilities."""

import ipaddress
import re
from typing import Any, Optional

_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
_URL_RE = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def is_valid_ip(value: str) -> bool:
    """Return True if *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_valid_domain(value: str) -> bool:
    """Return True if *value* looks like a valid domain name."""
    return bool(_DOMAIN_RE.match(value)) and len(value) <= 253


def is_valid_url(value: str) -> bool:
    """Return True if *value* is a valid HTTP/HTTPS URL."""
    return bool(_URL_RE.match(value))


def is_valid_email(value: str) -> bool:
    """Return True if *value* is a valid email address."""
    return bool(_EMAIL_RE.match(value))


def is_valid_md5(value: str) -> bool:
    return bool(_MD5_RE.match(value))


def is_valid_sha1(value: str) -> bool:
    return bool(_SHA1_RE.match(value))


def is_valid_sha256(value: str) -> bool:
    return bool(_SHA256_RE.match(value))


def sanitize_string(value: Any, max_length: int = 1000) -> str:
    """Convert *value* to a string and strip dangerous characters."""
    s = str(value)
    # Remove null bytes and control characters
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    return s[:max_length]


def validate_severity(severity: str) -> str:
    """Validate and normalize a severity string."""
    normalized = severity.lower().strip()
    valid = {"low", "medium", "high", "critical", "informational"}
    if normalized not in valid:
        raise ValueError(f"Invalid severity '{severity}'. Must be one of {valid}")
    return normalized


def validate_ioc_type(ioc_type: str) -> str:
    """Validate an IOC type string."""
    normalized = ioc_type.lower().strip()
    valid = {"ip", "domain", "url", "email", "md5", "sha1", "sha256", "hash"}
    if normalized not in valid:
        raise ValueError(f"Invalid IOC type '{ioc_type}'. Must be one of {valid}")
    return normalized
