"""Shodan data source provider for SurfaceAudit."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

import shodan

from surfaceaudit.errors import APIError, AuthenticationError, RetryHandler
from surfaceaudit.models import RawAsset
from surfaceaudit.providers import ProviderRegistry
from surfaceaudit.providers.base import BaseProvider

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class ShodanProvider(BaseProvider):
    """Provider backed by the Shodan search engine.

    Consolidates authentication, credit management, and asset discovery
    into a single provider that implements the :class:`BaseProvider` ABC.
    """

    def __init__(
        self,
        rate_limit_delay: float = 1.0,
        retry_handler: RetryHandler | None = None,
        warning_threshold: int = 10,
    ) -> None:
        self._client: shodan.Shodan | None = None
        self._rate_limit_delay = rate_limit_delay
        self._retry_handler = retry_handler or RetryHandler()
        self._warning_threshold = warning_threshold

    # ------------------------------------------------------------------
    # BaseProvider interface
    # ------------------------------------------------------------------

    def name(self) -> str:
        return "shodan"

    def authenticate(self, api_key: str) -> None:
        """Validate *api_key* against the Shodan API.

        On success the internal client is stored for subsequent calls.

        Raises:
            AuthenticationError: If the key is invalid or the API rejects it.
        """
        logger.info("Validating Shodan API key (key=***)")
        client = shodan.Shodan(api_key)
        try:
            client.info()
        except shodan.APIError as exc:
            logger.error("API key validation failed (key=***): %s", exc)
            raise AuthenticationError(
                f"Invalid Shodan API key: {exc}"
            ) from exc
        except Exception as exc:
            logger.error(
                "Unexpected error during API key validation (key=***): %s", exc
            )
            raise AuthenticationError(
                f"Failed to validate Shodan API key: {exc}"
            ) from exc

        logger.info("Shodan API key validated successfully (key=***)")
        self._client = client

    def get_credits(self) -> int:
        """Return the number of scan credits available on the account.

        Raises:
            APIError: If the Shodan API call fails.
        """
        client = self._require_client()
        try:
            info = client.info()
        except shodan.APIError as exc:
            raise APIError(f"Failed to retrieve API info: {exc}") from exc

        credits = int(info.get("scan_credits", 0))
        if credits < self._warning_threshold:
            logger.warning(
                "Low Shodan API credits: %d remaining (threshold: %d)",
                credits,
                self._warning_threshold,
            )
        return credits

    def discover(self, targets: list[str]) -> list[RawAsset]:
        """Query Shodan for every target and return aggregated raw assets.

        Errors on individual targets are logged and skipped so that the
        remaining targets are still processed.  Rate limiting is applied
        between consecutive queries.
        """
        client = self._require_client()
        all_assets: list[RawAsset] = []

        for idx, target in enumerate(targets):
            try:
                assets = self._query_target(client, target)
                all_assets.extend(assets)
            except Exception:
                logger.error(
                    "Failed to query target '%s', skipping.",
                    target,
                    exc_info=True,
                )

            # Rate-limit between queries (not after the last one)
            if idx < len(targets) - 1:
                self._apply_rate_limit()

        return all_assets

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_client(self) -> shodan.Shodan:
        """Return the authenticated client or raise."""
        if self._client is None:
            raise AuthenticationError(
                "ShodanProvider has not been authenticated. "
                "Call authenticate() first."
            )
        return self._client

    def _query_target(
        self, client: shodan.Shodan, target: str
    ) -> list[RawAsset]:
        """Query a single target with retry and return raw assets."""
        result = self._retry_handler.execute_with_retry(client.search, target)

        matches: list[dict] = result.get("matches", [])

        # Group matches by IP address
        ip_groups: dict[str, list[dict]] = {}
        for match in matches:
            ip = match.get("ip_str", "")
            ip_groups.setdefault(ip, []).append(match)

        assets: list[RawAsset] = []
        for ip, group in ip_groups.items():
            ports = sorted({m.get("port", 0) for m in group})
            hostnames: list[str] = []
            for m in group:
                hostnames.extend(m.get("hostnames", []))
            hostname = hostnames[0] if hostnames else None

            assets.append(
                RawAsset(
                    ip=ip,
                    hostname=hostname,
                    ports=ports,
                    data=group,
                )
            )

        return assets

    def _apply_rate_limit(self) -> None:
        """Sleep for the configured delay to respect API rate limits."""
        if self._rate_limit_delay > 0:
            time.sleep(self._rate_limit_delay)


# Auto-register the provider when this module is imported.
ProviderRegistry.register("shodan", ShodanProvider)
