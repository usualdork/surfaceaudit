"""VirusTotal enrichment provider – IP reputation and malware detection."""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error

from surfaceaudit.enrichment.base import BaseEnrichmentProvider

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.virustotal.com/api/v3"
# Rate limit: 4 requests per minute → 15 seconds between requests
_MIN_REQUEST_INTERVAL = 15.0
_MAX_RETRIES = 3


class VirusTotalProvider(BaseEnrichmentProvider):
    """Query VirusTotal API v3 for IP address reputation.

    Returns ``{"malicious_count": int, "reputation": int,
    "last_analysis_stats": dict}``.
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._last_request_time: float = 0.0
        self._disabled = False

    # ------------------------------------------------------------------
    # BaseEnrichmentProvider interface
    # ------------------------------------------------------------------

    def name(self) -> str:
        return "virustotal"

    def requires_api_key(self) -> bool:
        return True

    def enrich_ip(self, ip: str) -> dict:
        """Query VirusTotal for *ip* reputation."""
        if self._disabled:
            return {}

        url = f"{_BASE_URL}/ip_addresses/{ip}"
        headers = {
            "x-apikey": self._api_key,
            "User-Agent": "SurfaceAudit",
        }

        data = self._request_with_retry(url, headers)
        if data is None:
            return {}

        return self._extract_fields(data)

    def enrich_domain(self, domain: str) -> dict:
        """VirusTotal domain enrichment is not implemented – return empty."""
        return {}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _request_with_retry(
        self, url: str, headers: dict[str, str]
    ) -> dict | None:
        """Make an HTTP GET request with rate limiting and exponential backoff."""
        for attempt in range(_MAX_RETRIES + 1):
            self._rate_limit()
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code == 401 or exc.code == 403:
                    logger.error(
                        "VirusTotal auth error (HTTP %d) – disabling provider",
                        exc.code,
                    )
                    self._disabled = True
                    return None
                if exc.code == 429:
                    if attempt < _MAX_RETRIES:
                        wait = 2 ** (attempt + 1)
                        logger.warning(
                            "VirusTotal rate limited – retrying in %ds (attempt %d/%d)",
                            wait, attempt + 1, _MAX_RETRIES,
                        )
                        time.sleep(wait)
                        continue
                    logger.warning("VirusTotal rate limit exhausted after %d retries", _MAX_RETRIES)
                    return None
                logger.warning("VirusTotal HTTP error %d for %s", exc.code, url)
                return None
            except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
                logger.warning("VirusTotal request failed: %s", exc)
                return None
            except Exception:
                logger.exception("Unexpected error querying VirusTotal")
                return None
        return None

    def _rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < _MIN_REQUEST_INTERVAL:
            time.sleep(_MIN_REQUEST_INTERVAL - elapsed)
        self._last_request_time = time.monotonic()

    @staticmethod
    def _extract_fields(response: dict) -> dict:
        """Extract relevant fields from the VirusTotal API response."""
        attributes = response.get("data", {}).get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        malicious_count = last_analysis_stats.get("malicious", 0)
        reputation = attributes.get("reputation", 0)
        return {
            "malicious_count": malicious_count,
            "reputation": reputation,
            "last_analysis_stats": last_analysis_stats,
        }
