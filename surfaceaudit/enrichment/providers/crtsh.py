"""crt.sh enrichment provider – discovers subdomains via Certificate Transparency logs."""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error

from surfaceaudit.enrichment.base import BaseEnrichmentProvider

logger = logging.getLogger(__name__)

# Rate limit: 1 request per second
_MIN_REQUEST_INTERVAL = 1.0


class CrtshProvider(BaseEnrichmentProvider):
    """Query crt.sh for subdomains associated with a domain.

    Returns ``{"subdomains": [...]}``.  Does **not** require an API key.
    """

    def __init__(self) -> None:
        self._last_request_time: float = 0.0

    # ------------------------------------------------------------------
    # BaseEnrichmentProvider interface
    # ------------------------------------------------------------------

    def name(self) -> str:
        return "crtsh"

    def requires_api_key(self) -> bool:
        return False

    def enrich_ip(self, ip: str) -> dict:
        """crt.sh does not support IP lookups – return empty."""
        return {}

    def enrich_domain(self, domain: str) -> dict:
        """Query crt.sh for subdomains of *domain*."""
        self._rate_limit()
        url = f"https://crt.sh/?q={domain}&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SurfaceAudit"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError) as exc:
            logger.warning("crt.sh query failed for '%s': %s", domain, exc)
            return {}
        except Exception:
            logger.exception("Unexpected error querying crt.sh for '%s'", domain)
            return {}

        subdomains = self._parse_subdomains(data)
        return {"subdomains": subdomains}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _rate_limit(self) -> None:
        """Enforce minimum interval between requests."""
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < _MIN_REQUEST_INTERVAL:
            time.sleep(_MIN_REQUEST_INTERVAL - elapsed)
        self._last_request_time = time.monotonic()

    @staticmethod
    def _parse_subdomains(entries: list[dict]) -> list[str]:
        """Extract and deduplicate subdomains from crt.sh JSON response."""
        seen: set[str] = set()
        result: list[str] = []
        for entry in entries:
            name_value = entry.get("name_value", "")
            # crt.sh may return newline-separated names in a single entry
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and name not in seen:
                    seen.add(name)
                    result.append(name)
        return result
