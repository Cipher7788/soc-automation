"""IOC Database — local repository for storing and managing known malicious indicators."""

import csv
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = "data/ioc_database.json"

_EMPTY_DB: dict[str, Any] = {
    "malicious_ips": [],
    "malicious_domains": [],
    "malware_hashes": [],
    "malicious_urls": [],
    "malicious_emails": [],
    "metadata": {
        "last_updated": "",
        "total_indicators": 0,
        "sources": [],
    },
}


@dataclass
class IOCEntry:
    """Metadata record for a single indicator of compromise."""

    value: str
    type: str  # ip | domain | md5 | sha1 | sha256 | url | email
    source: str = ""
    confidence: float = 0.0  # 0–100
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)


class IOCDatabase:
    """Local IOC repository backed by a JSON file.

    Supports CRUD operations, bulk import from threat feeds, export to JSON/CSV,
    and integration with the IOCDetector for real-time lookups.
    """

    _TYPE_KEY_MAP = {
        "ip": "malicious_ips",
        "domain": "malicious_domains",
        "md5": "malware_hashes",
        "sha1": "malware_hashes",
        "sha256": "malware_hashes",
        "url": "malicious_urls",
        "email": "malicious_emails",
    }

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self._db_path = db_path
        self._db: dict[str, Any] = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if os.path.exists(self._db_path):
            try:
                with open(self._db_path, "r", encoding="utf-8") as fh:
                    self._db = json.load(fh)
                logger.info("IOC database loaded from %s", self._db_path)
            except Exception as exc:
                logger.error("Failed to load IOC database: %s — using empty DB", exc)
                self._db = json.loads(json.dumps(_EMPTY_DB))
        else:
            self._db = json.loads(json.dumps(_EMPTY_DB))
            self._save()

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        self._db["metadata"]["total_indicators"] = sum(
            len(self._db.get(k, [])) for k in self._TYPE_KEY_MAP.values()
        )
        self._db["metadata"]["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            with open(self._db_path, "w", encoding="utf-8") as fh:
                json.dump(self._db, fh, indent=2)
        except Exception as exc:
            logger.error("Failed to save IOC database: %s", exc)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def add_ioc(self, entry: IOCEntry) -> bool:
        """Add an IOC entry. Returns False if the IOC already exists."""
        if self.exists(entry.value, entry.type):
            return False
        key = self._TYPE_KEY_MAP.get(entry.type)
        if not key:
            logger.warning("Unknown IOC type: %s", entry.type)
            return False
        self._db.setdefault(key, []).append(asdict(entry))
        self._save()
        return True

    def remove_ioc(self, value: str, ioc_type: str) -> bool:
        """Remove an IOC by value and type. Returns True if removed."""
        key = self._TYPE_KEY_MAP.get(ioc_type)
        if not key:
            return False
        before = len(self._db.get(key, []))
        self._db[key] = [
            e for e in self._db.get(key, []) if e.get("value") != value
        ]
        removed = len(self._db[key]) < before
        if removed:
            self._save()
        return removed

    def exists(self, value: str, ioc_type: Optional[str] = None) -> bool:
        """Check whether an indicator exists in the database."""
        if ioc_type:
            key = self._TYPE_KEY_MAP.get(ioc_type)
            if not key:
                return False
            return any(e.get("value") == value for e in self._db.get(key, []))
        return any(
            any(e.get("value") == value for e in self._db.get(k, []))
            for k in set(self._TYPE_KEY_MAP.values())
        )

    def search(self, query: str, ioc_type: Optional[str] = None) -> list[IOCEntry]:
        """Search indicators by partial value match."""
        results: list[IOCEntry] = []
        if ioc_type and ioc_type in self._TYPE_KEY_MAP:
            keys = [self._TYPE_KEY_MAP[ioc_type]]
        else:
            keys = list(set(self._TYPE_KEY_MAP.values()))
        seen_values: set[str] = set()
        for key in keys:
            for entry_dict in self._db.get(key, []):
                val = entry_dict.get("value", "")
                if query.lower() in val.lower() and val not in seen_values:
                    seen_values.add(val)
                    try:
                        results.append(IOCEntry(**{k: v for k, v in entry_dict.items() if k in IOCEntry.__dataclass_fields__}))
                    except Exception:
                        pass
        return results

    def get_all(self, ioc_type: Optional[str] = None) -> list[IOCEntry]:
        """Retrieve all indicators, optionally filtered by type."""
        return self.search("", ioc_type)

    # ------------------------------------------------------------------
    # Bulk import / export
    # ------------------------------------------------------------------

    def import_from_list(
        self,
        values: list[str],
        ioc_type: str,
        source: str = "manual",
        confidence: float = 80.0,
        tags: Optional[list[str]] = None,
    ) -> int:
        """Bulk import a list of indicator values. Returns number added."""
        added = 0
        for value in values:
            entry = IOCEntry(
                value=value.strip(),
                type=ioc_type,
                source=source,
                confidence=confidence,
                tags=tags or [],
            )
            if self.add_ioc(entry):
                added += 1
        return added

    def update_from_feed(self, feed_url: str, ioc_type: str = "ip", timeout: int = 15) -> int:
        """Download a plain-text threat feed and import each line as an IOC."""
        try:
            resp = requests.get(feed_url, timeout=timeout)
            resp.raise_for_status()
            lines = [line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")]
            return self.import_from_list(lines, ioc_type, source=feed_url)
        except Exception as exc:
            logger.error("Failed to update from feed %s: %s", feed_url, exc)
            return 0

    def export(self, fmt: str = "json") -> str:
        """Export the full database in 'json' or 'csv' format."""
        if fmt == "json":
            return json.dumps(self._db, indent=2)
        if fmt == "csv":
            import io
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["value", "type", "source", "confidence", "first_seen", "last_seen", "tags"])
            for key, ioc_type in [("malicious_ips", "ip"), ("malicious_domains", "domain"),
                                   ("malware_hashes", "hash"), ("malicious_urls", "url"),
                                   ("malicious_emails", "email")]:
                for entry in self._db.get(key, []):
                    writer.writerow([
                        entry.get("value", ""),
                        ioc_type,
                        entry.get("source", ""),
                        entry.get("confidence", 0),
                        entry.get("first_seen", ""),
                        entry.get("last_seen", ""),
                        ",".join(entry.get("tags", [])),
                    ])
            return buf.getvalue()
        raise ValueError(f"Unsupported export format: {fmt}")

    # ------------------------------------------------------------------
    # Integration helpers
    # ------------------------------------------------------------------

    def get_malicious_ips(self) -> set[str]:
        return {e.get("value", "") for e in self._db.get("malicious_ips", [])}

    def get_malicious_domains(self) -> set[str]:
        return {e.get("value", "") for e in self._db.get("malicious_domains", [])}

    def get_malware_hashes(self) -> set[str]:
        return {e.get("value", "") for e in self._db.get("malware_hashes", [])}
