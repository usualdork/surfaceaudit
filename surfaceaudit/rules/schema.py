"""Rule schema dataclasses for the YAML rule engine."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MatchCondition:
    """Defines conditions for matching assets against rules.

    At least one of ``ports``, ``banners``, or ``services`` must be provided.
    """

    ports: list[int] | None = None
    banners: list[str] | None = None      # substring match, case-insensitive
    services: list[str] | None = None     # substring match on service name

    def __post_init__(self) -> None:
        if self.ports is None and self.banners is None and self.services is None:
            raise ValueError(
                "MatchCondition requires at least one of 'ports', 'banners', or 'services'"
            )


@dataclass
class ClassificationRule:
    """A rule that maps asset attributes to an asset type."""

    id: str
    name: str
    match: MatchCondition
    asset_type: str  # maps to AssetType enum value


@dataclass
class AssessmentRule:
    """A rule that maps asset attributes to a vulnerability indicator."""

    id: str
    name: str
    match: MatchCondition
    severity: str       # "high", "medium", "low"
    description: str
    category: str       # "vulnerable_version", "risky_port", "admin_interface"
    details_template: dict | None = None
