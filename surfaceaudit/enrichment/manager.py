"""Enrichment manager – orchestrates providers, caching, and scoring."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from surfaceaudit.enrichment.base import BaseEnrichmentProvider
from surfaceaudit.enrichment.cache import EnrichmentCache
from surfaceaudit.enrichment.score import CorrelationScoreCalculator
from surfaceaudit.models import AssessedAsset

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lightweight config dataclasses (replaced by Pydantic models in Task 8.2)
# ---------------------------------------------------------------------------


@dataclass
class EnrichmentProviderConfig:
    """Per-provider configuration."""

    enabled: bool = True
    api_key: str | None = None


@dataclass
class EnrichmentConfig:
    """Top-level enrichment configuration."""

    enabled: bool = False
    providers: dict[str, EnrichmentProviderConfig] = field(default_factory=dict)
    cache_dir: str = ".surfaceaudit/cache"
    cache_ttl_hours: int = 24


# ---------------------------------------------------------------------------
# Placeholder result model (replaced by EnrichedAsset in Task 8.1)
# ---------------------------------------------------------------------------


@dataclass
class EnrichedAssetResult:
    """Minimal enriched-asset container until ``EnrichedAsset`` lands."""

    ip: str
    hostname: str | None
    enrichment_data: dict[str, dict]
    correlation_risk_score: int
    discovered_subdomains: list[str]
    original_asset: AssessedAsset


# ---------------------------------------------------------------------------
# EnrichmentManager
# ---------------------------------------------------------------------------


class EnrichmentManager:
    """Orchestrates enrichment across all enabled providers.

    For each asset the manager:

    1. Iterates registered providers.
    2. Skips providers that are disabled or missing a required API key.
    3. Checks the cache before making an API call.
    4. On cache miss, calls the provider and stores the result.
    5. Logs and skips providers that raise unrecoverable errors.
    6. Computes a correlation risk score via ``CorrelationScoreCalculator``.
    7. Returns a list of ``EnrichedAssetResult`` objects.
    """

    def __init__(
        self,
        config: EnrichmentConfig,
        cache: EnrichmentCache,
    ) -> None:
        self._config = config
        self._cache = cache
        self._providers: list[BaseEnrichmentProvider] = []
        self._score_calculator = CorrelationScoreCalculator()

    # ------------------------------------------------------------------
    # Provider registration
    # ------------------------------------------------------------------

    def register_provider(self, provider: BaseEnrichmentProvider) -> None:
        """Add a provider to the enrichment pipeline."""
        self._providers.append(provider)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich(
        self, assets: list[AssessedAsset]
    ) -> list[EnrichedAssetResult]:
        """Enrich each asset with data from all enabled providers."""
        if not self._config.enabled:
            return [
                EnrichedAssetResult(
                    ip=a.ip,
                    hostname=a.hostname,
                    enrichment_data={},
                    correlation_risk_score=0,
                    discovered_subdomains=[],
                    original_asset=a,
                )
                for a in assets
            ]

        results: list[EnrichedAssetResult] = []
        for asset in assets:
            enrichment_data: dict[str, dict] = {}
            discovered_subdomains: list[str] = []

            for provider in self._providers:
                prov_name = provider.name()

                if not self._is_provider_enabled(provider):
                    continue

                try:
                    data = self._enrich_asset_with_provider(
                        provider, asset
                    )
                except Exception:
                    logger.exception(
                        "Unrecoverable error from provider '%s' for "
                        "asset %s – skipping",
                        prov_name,
                        asset.ip,
                    )
                    continue

                if data:
                    enrichment_data[prov_name] = data
                    # Collect subdomains from crt.sh-style providers
                    if "subdomains" in data:
                        discovered_subdomains.extend(data["subdomains"])

            score = self._score_calculator.calculate(enrichment_data)

            results.append(
                EnrichedAssetResult(
                    ip=asset.ip,
                    hostname=asset.hostname,
                    enrichment_data=enrichment_data,
                    correlation_risk_score=score,
                    discovered_subdomains=discovered_subdomains,
                    original_asset=asset,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _is_provider_enabled(
        self, provider: BaseEnrichmentProvider
    ) -> bool:
        """Return *True* if the provider should run."""
        prov_name = provider.name()
        prov_cfg = self._config.providers.get(prov_name)

        # No explicit config → treat as disabled
        if prov_cfg is None:
            return False

        if not prov_cfg.enabled:
            logger.debug("Provider '%s' is disabled – skipping", prov_name)
            return False

        if provider.requires_api_key() and not prov_cfg.api_key:
            logger.debug(
                "Provider '%s' requires an API key but none configured "
                "– skipping",
                prov_name,
            )
            return False

        return True

    def _enrich_asset_with_provider(
        self,
        provider: BaseEnrichmentProvider,
        asset: AssessedAsset,
    ) -> dict:
        """Fetch enrichment data for *asset* from *provider*, using cache."""
        prov_name = provider.name()
        cache_key = asset.ip

        # 1. Check cache
        cached = self._cache.get(prov_name, cache_key)
        if cached is not None:
            logger.debug(
                "Cache hit for provider '%s', key '%s'",
                prov_name,
                cache_key,
            )
            return cached

        # 2. Call provider
        data = provider.enrich_ip(asset.ip)

        # Also enrich by domain if hostname is available
        if asset.hostname:
            domain_data = provider.enrich_domain(asset.hostname)
            if domain_data:
                data = {**data, **domain_data}

        # 3. Store in cache
        if data:
            self._cache.set(prov_name, cache_key, data)

        return data
