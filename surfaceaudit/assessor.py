"""Vulnerability assessment module for SurfaceAudit.

Analyzes classified assets for potential security vulnerabilities
by delegating to the YAML rule engine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from surfaceaudit.models import (
    AssessedAsset,
    ClassifiedAsset,
    RiskLevel,
    VulnerabilityIndicator,
)
from surfaceaudit.rules import RuleEngine

if TYPE_CHECKING:
    from surfaceaudit.rules.v2.engine import RuleEngineV2


class VulnerabilityAssessor:
    """Assesses classified assets for potential security vulnerabilities.

    Uses a :class:`RuleEngine` to evaluate assessment rules.  If no engine
    is supplied, a default one is created that loads rules from the bundled
    rules directory.

    An optional *engine_v2* (:class:`RuleEngineV2`) can be provided.  When
    present it is used for assessment instead of the v1 engine, while the
    v1 engine remains the default for backward compatibility.
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

    def assess(self, asset: ClassifiedAsset) -> AssessedAsset:
        """Produce an AssessedAsset from a ClassifiedAsset.

        1. Extracts ports, banner text, and service names from the asset.
        2. Delegates to ``rule_engine.assess()`` to collect vulnerability
           indicators.
        3. Determines the overall risk level from the indicators.
        4. Returns an :class:`AssessedAsset`.
        """
        ports = list(asset.ports)
        banner_text = self._collect_banner_text(asset)
        services = self._collect_service_names(asset)

        engine = self._engine_v2 if self._engine_v2 is not None else self._rule_engine
        indicators = engine.assess(ports, banner_text, services)
        risk_level = self._calculate_risk_level(indicators)

        return AssessedAsset(
            ip=asset.ip,
            hostname=asset.hostname,
            asset_type=asset.asset_type,
            os=asset.os,
            services=list(asset.services),
            geolocation=asset.geolocation,
            ports=ports,
            vulnerabilities=indicators,
            risk_level=risk_level,
        )

    @staticmethod
    def _calculate_risk_level(
        indicators: list[VulnerabilityIndicator],
    ) -> RiskLevel:
        """Calculate overall risk level from vulnerability indicators.

        - HIGH if any indicator has severity HIGH
        - MEDIUM if any indicator has severity MEDIUM
        - LOW if no indicators or all are LOW
        """
        if not indicators:
            return RiskLevel.LOW
        for indicator in indicators:
            if indicator.severity == RiskLevel.HIGH:
                return RiskLevel.HIGH
        for indicator in indicators:
            if indicator.severity == RiskLevel.MEDIUM:
                return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _collect_banner_text(asset: ClassifiedAsset) -> str:
        """Concatenate service names, versions, and banners into a single string."""
        parts: list[str] = []
        for service in asset.services:
            if service.name:
                parts.append(service.name.lower())
            if service.version:
                parts.append(service.version.lower())
            if service.banner:
                parts.append(service.banner.lower())
        return " ".join(parts)

    @staticmethod
    def _collect_service_names(asset: ClassifiedAsset) -> list[str]:
        """Extract non-None service names from the asset."""
        return [s.name for s in asset.services if s.name]
