"""Multi-source log collector with async support."""

import asyncio
import logging
import time
from collections import deque
from typing import Any, Callable

from src.ingestion.wazuh_client import WazuhClient

logger = logging.getLogger(__name__)


class LogCollector:
    """Orchestrates log collection from multiple sources.

    Supports configurable polling intervals and in-memory buffering
    with configurable batch sizes.  Async collection is implemented
    via asyncio.
    """

    def __init__(
        self,
        wazuh_client: WazuhClient,
        poll_interval: int = 60,
        batch_size: int = 1000,
        time_range: int = 60,
    ) -> None:
        self._wazuh = wazuh_client
        self._poll_interval = poll_interval
        self._batch_size = batch_size
        self._time_range = time_range
        self._buffer: deque[dict[str, Any]] = deque()
        self._seen: dict[tuple[str, str] | str, float] = {}
        self._running = False
        self._callbacks: list[Callable[[list[dict[str, Any]]], None]] = []

    def register_callback(self, cb: Callable[[list[dict[str, Any]]], None]) -> None:
        """Register a callback to receive collected log batches."""
        self._callbacks.append(cb)

    def _collect_wazuh(self) -> list[dict[str, Any]]:
        try:
            alerts = self._wazuh.get_alerts(time_range=self._time_range)
            logger.info("Collected %d alerts from Wazuh", len(alerts))
            return alerts
        except Exception as exc:
            logger.error("Failed to collect Wazuh alerts: %s", exc)
            return []

    def _dispatch(self, logs: list[dict[str, Any]]) -> None:
        for cb in self._callbacks:
            try:
                cb(logs)
            except Exception as exc:
                logger.error("Callback error: %s", exc)

    def collect_once(self) -> list[dict[str, Any]]:
        """Return the next batch, fetching alerts when the queue is empty."""
        if not self._buffer:
            now = time.monotonic()
            self._seen = {key: expiry for key, expiry in self._seen.items() if expiry > now}
            expiry = now + self._time_range * 60 + self._poll_interval
            for log in self._collect_wazuh():
                key = log.get("_wazuh_document_id") or log.get("id")
                if key:
                    already_seen = key in self._seen
                    self._seen[key] = expiry
                    if already_seen:
                        continue
                self._buffer.append({**log, "_source": "wazuh"})

        batch = [self._buffer.popleft() for _ in range(min(len(self._buffer), self._batch_size))]
        if batch:
            self._dispatch(batch)
        return batch

    def flush_buffer(self) -> list[dict[str, Any]]:
        """Return and clear the current buffer."""
        items = list(self._buffer)
        self._buffer.clear()
        return items

    async def collect_loop(self) -> None:
        """Async event loop for continuous log collection."""
        self._running = True
        logger.info(
            "Starting log collection loop (interval=%ds)", self._poll_interval
        )
        while self._running:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.collect_once)
            await asyncio.sleep(self._poll_interval)

    def stop(self) -> None:
        """Signal the collection loop to stop."""
        self._running = False
