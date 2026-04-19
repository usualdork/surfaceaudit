"""File-based enrichment cache: {cache_dir}/{provider}/{key}.json"""

from __future__ import annotations

import json
import logging
import os
import time

logger = logging.getLogger(__name__)


class EnrichmentCache:
    """File-based cache for enrichment API responses.

    Cache files are stored as ``{cache_dir}/{provider}/{key}.json`` with the
    structure ``{"timestamp": <unix_ts>, "data": <provider_data>}``.
    """

    def __init__(self, cache_dir: str, ttl_hours: int = 24) -> None:
        self._cache_dir = cache_dir
        self._ttl_seconds = ttl_hours * 3600
        os.makedirs(cache_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, provider: str, key: str) -> dict | None:
        """Return cached data if it exists and has not expired, else *None*."""
        path = self._path(provider, key)
        if not os.path.isfile(path):
            return None

        try:
            with open(path, "r", encoding="utf-8") as fh:
                entry = json.load(fh)
        except (json.JSONDecodeError, OSError):
            # Corrupt or unreadable file → treat as cache miss.
            logger.debug("Corrupt cache file %s – treating as miss", path)
            return None

        timestamp = entry.get("timestamp", 0)
        if time.time() - timestamp > self._ttl_seconds:
            return None

        return entry.get("data")

    def set(self, provider: str, key: str, data: dict) -> None:
        """Write *data* to the cache with the current timestamp."""
        provider_dir = os.path.join(self._cache_dir, provider)
        os.makedirs(provider_dir, exist_ok=True)

        path = self._path(provider, key)
        entry = {"timestamp": time.time(), "data": data}

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(entry, fh)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _path(self, provider: str, key: str) -> str:
        return os.path.join(self._cache_dir, provider, f"{key}.json")
