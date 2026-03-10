"""Common utility functions for SOC Automation."""

import hashlib
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def epoch_now() -> float:
    """Return the current Unix timestamp."""
    return time.time()


def sha256_of(data: str) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data.encode()).hexdigest()


def flatten_dict(d: dict[str, Any], prefix: str = "", sep: str = ".") -> dict[str, Any]:
    """Recursively flatten a nested dictionary.

    >>> flatten_dict({"a": {"b": 1}})
    {'a.b': 1}
    """
    items: dict[str, Any] = {}
    for key, value in d.items():
        new_key = f"{prefix}{sep}{key}" if prefix else key
        if isinstance(value, dict):
            items.update(flatten_dict(value, new_key, sep))
        else:
            items[new_key] = value
    return items


def chunk_list(lst: list[Any], size: int) -> list[list[Any]]:
    """Split *lst* into chunks of *size*."""
    return [lst[i: i + size] for i in range(0, len(lst), size)]


def safe_get(obj: Any, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dicts/objects."""
    current = obj
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        elif hasattr(current, key):
            current = getattr(current, key, default)
        else:
            return default
    return current


def truncate(text: str, max_length: int = 500, suffix: str = "...") -> str:
    """Truncate *text* to *max_length* characters."""
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def severity_to_int(severity: str) -> int:
    """Convert a severity string to a numeric value (1–4)."""
    mapping = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return mapping.get(severity.lower(), 1)


def int_to_severity(level: int) -> str:
    """Convert a numeric severity level to a string."""
    mapping = {1: "low", 2: "medium", 3: "high", 4: "critical"}
    return mapping.get(level, "low")
