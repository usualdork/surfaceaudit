"""AbuseIPDB enrichment provider – IP abuse reports and confidence scoring."""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error

from surfaceaudit.enrichment.base import BaseEnrichmentProvider

logger = logging.getLogger(__name__)

_BASE_URL = "https://api.abuseipdb.com/api/v2"
# Rate limit: 1000 requests per day (tracked externally; provider trusts caller)


class AbuseIPDBProvider(BaseEnrichmentProvider):
    """Query AbuseIPDB API v2 for IP abuse reports.

    Returns ``{"abuse_confidence_score": int, "total_reports": int,
    "country_code": str}``.
    """

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._disabled = False

    # ------------------------------------------------------------------
    # BaseEnrichmentProvider interface
    # ------------------------------------------------------------------

    def name(self) -> str:
        return "abuseipdb"

    def requires_api_key(self) -> bool:
        return True

    def enrich_ip(self, ip: str) -> dict:
        """Query AbuseIPDB for *ip* abuse data."""
        if self._disabled:
            return {}

        url = f"{_BASE_URL}/check?ipAddress={ip}"
        headers = {
            "Key": self._api_key,
            "Accept": "application/json",
            "User-Agent": "SurfaceAudit",
        }

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401 or exc.code == 403:
                logger.error(
                    "AbuseIPDB auth error (HTTP %d) – disabling provider",
                    exc.code,
                )
                self._disabled = True
                return {}
            logger.warning("AbuseIPDB HTTP error %d for %s", exc.code, url)
            return {}
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
            logger.warning("AbuseIPDB request failed: %s", exc)
            return {}
        except Exception:
            logger.exception("Unexpected error querying AbuseIPDB")
            return {}

        return self._extract_fields(data)

    def enrich_domain(self, domain: str) -> dict:
        """AbuseIPDB does not support domain lookups – return empty."""
        return {}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_fields(response: dict) -> dict:
        """Extract relevant fields from the AbuseIPDB API response."""
        report_data = response.get("data", {})
        return {
            "abuse_confidence_score": report_data.get("abuseConfidenceScore", 0),
            "total_reports": report_data.get("totalReports", 0),
            "country_code": report_data.get("countryCode", ""),
        }
