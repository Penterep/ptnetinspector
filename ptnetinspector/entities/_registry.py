"""In-memory dedup registry for entity persistence during a scan."""
from __future__ import annotations

import threading


class EntityRegistry:
    """Thread-safe process-local set tracking already-persisted records."""

    def __init__(self) -> None:
        self._sets: dict[str, set[tuple]] = {}
        self._lock = threading.Lock()

    def seen(self, entity_type: str, key: tuple) -> bool:
        with self._lock:
            bucket = self._sets.setdefault(entity_type, set())
            if key in bucket:
                return True
            bucket.add(key)
            return False

    def clear(self) -> None:
        with self._lock:
            self._sets.clear()


registry = EntityRegistry()
