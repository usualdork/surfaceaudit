"""Asset classification module for SurfaceAudit.

Classifies raw assets by type, extracts OS, services, and geolocation.
Delegates type determination to the YAML rule engine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from surfaceaudit.models import (
    AssetType,
    ClassifiedAsset,
    GeoLocation,
    RawAsset,
    Service,
)
from surfaceaudit.rules import RuleEngine

if TYPE_CHECKING:
    from surfaceaudit.rules.v2.engine import RuleEngineV2


class AssetClassifier:
    """Classifies raw assets into typed, enriched assets.

    Uses a :class:`RuleEngine` to determine the asset type.  If no engine
    is supplied, a default one is created that loads rules from the bundled
    rules directory.

    An optional *engine_v2* (:class:`RuleEngineV2`) can be provided.  When
    present it is used for classification instead of the v1 engine, while
    the v1 engine remains the default for backward compatibility.
    """

    def __init__(
        self,
        rule_engine: RuleEngine | None = None,
        engine_v2: RuleEngineV2 | None = None,
    ) -> None:
        if rule_engine is None:
            rule_engine = RuleEngine()
            rule_engine.load()
        self._rule_engine = rule_engine
        self._engine_v2 = engine_v2

    def classify(self, raw_asset: RawAsset) -> ClassifiedAsset:
        """Produce a ClassifiedAsset from a RawAsset.

        Determines asset type via the rule engine, then extracts OS,
        services, and geolocation from the raw data.
        """
        return ClassifiedAsset(
            ip=raw_asset.ip,
            hostname=raw_asset.hostname,
            asset_type=self._determine_type(raw_asset),
            os=self._extract_os(raw_asset),
            services=self._extract_services(raw_asset),
            geolocation=self._extract_geolocation(raw_asset),
            ports=list(raw_asset.ports),
            raw_data=raw_asset.data[0] if raw_asset.data else {},
        )

    def _determine_type(self, raw_asset: RawAsset) -> AssetType:
        """Classify the asset type by delegating to the rule engine.

        Uses the v2 engine when available, otherwise falls back to v1.
        """
        ports = list(raw_asset.ports)
        banner_text = self._collect_banner_text(raw_asset)
        services = [
            m.get("product", "")
            for m in raw_asset.data
            if m.get("product")
        ]
        engine = self._engine_v2 if self._engine_v2 is not None else self._rule_engine
        return engine.classify(ports, banner_text, services)

    def _extract_os(self, raw_asset: RawAsset) -> str | None:
        """Extract the operating system from banner data.

        Returns the first non-None, non-empty 'os' value found across
        all match dicts, or None if unavailable.
        """
        for match in raw_asset.data:
            os_value = match.get("os")
            if os_value:
                return os_value
        return None

    def _extract_services(self, raw_asset: RawAsset) -> list[Service]:
        """Extract services from each match dict in raw_asset.data.

        Maps fields: port, transport → protocol, product → name,
        version, data → banner.
        """
        services: list[Service] = []
        for match in raw_asset.data:
            port = match.get("port")
            if port is None:
                continue
            services.append(
                Service(
                    port=int(port),
                    protocol=match.get("transport", "tcp"),
                    name=match.get("product"),
                    version=match.get("version"),
                    banner=match.get("data"),
                )
            )
        return services

    def _extract_geolocation(self, raw_asset: RawAsset) -> GeoLocation | None:
        """Extract geolocation from the first match dict's 'location' key.

        Returns a GeoLocation if location data is present, None otherwise.
        """
        if not raw_asset.data:
            return None

        location = raw_asset.data[0].get("location")
        if not location or not isinstance(location, dict):
            return None

        country = location.get("country_name")
        city = location.get("city")
        latitude = location.get("latitude")
        longitude = location.get("longitude")

        if any(v is not None for v in (country, city, latitude, longitude)):
            return GeoLocation(
                country=country,
                city=city,
                latitude=latitude,
                longitude=longitude,
            )
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_banner_text(raw_asset: RawAsset) -> str:
        """Concatenate all banner data into a single lowered string."""
        parts: list[str] = []
        for match in raw_asset.data:
            banner = match.get("data", "")
            if banner:
                parts.append(banner.lower())
        return " ".join(parts)
