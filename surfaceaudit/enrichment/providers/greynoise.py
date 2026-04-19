"""GreyNoise enrichment provider – IP classification and noise detection."""

from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error

from surfaceaudit.enrichment.base import BaseEnrichmentProvider

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.greynoise.io/v3/community"
_MAX_RETRIES = 3


class GreyNoiseProvider(BaseEnrichmentProvider):
    """Query GreyNoise Community API v3 for IP classification.

    Returns ``{"classification": str, "noise": bool, "riot": bool}``.
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._disabled = False

    # ------------------------------------------------------------------
    # BaseEnrichmentProvider interface
    # ------------------------------------------------------------------

    def name(self) -> str:
        return "greynoise"

    def requires_api_key(self) -> bool:
        return True

    def enrich_ip(self, ip: str) -> dict:
        """Query GreyNoise for *ip* classification."""
        if self._disabled:
            return {}

        url = f"{_BASE_URL}/{ip}"
        headers = {
            "key": self._api_key,
            "User-Agent": "SurfaceAudit",
        }

        data = self._request_with_retry(url, headers)
        if data is None:
            return {}

        return self._extract_fields(data)

    def enrich_domain(self, domain: str) -> dict:
        """GreyNoise does not support domain lookups – return empty."""
        return {}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _request_with_retry(
        self, url: str, headers: dict[str, str]
    ) -> dict | None:
        """Make an HTTP GET request with exponential backoff on rate limit."""
        for attempt in range(_MAX_RETRIES + 1):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code == 401 or exc.code == 403:
                    logger.error(
                        "GreyNoise auth error (HTTP %d) – disabling provider",
                        exc.code,
                    )
                    self._disabled = True
                    return None
                if exc.code == 404:
                    # 404 = IP not found in GreyNoise dataset (valid response)
                    try:
                        body = json.loads(exc.read().decode("utf-8"))
                        return body
                    except Exception:
                        return {"noise": False, "riot": False, "classification": "unknown"}
                if exc.code == 429:
                    if attempt < _MAX_RETRIES:
                        wait = 2 ** (attempt + 1)
                        logger.warning(
                            "GreyNoise rate limited – retrying in %ds (attempt %d/%d)",
                            wait, attempt + 1, _MAX_RETRIES,
                        )
                        time.sleep(wait)
                        continue
                    logger.warning("GreyNoise rate limit exhausted after %d retries", _MAX_RETRIES)
                    return None
                logger.warning("GreyNoise HTTP error %d for %s", exc.code, url)
                return None
            except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
                logger.warning("GreyNoise request failed: %s", exc)
                return None
            except Exception:
                logger.exception("Unexpected error querying GreyNoise")
                return None
        return None

    @staticmethod
    def _extract_fields(response: dict) -> dict:
        """Extract relevant fields from the GreyNoise API response."""
        return {
            "classification": response.get("classification", "unknown"),
            "noise": response.get("noise", False),
            "riot": response.get("riot", False),
        }
