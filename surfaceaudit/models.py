"""Data models and serialization helpers for SurfaceAudit."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class AssetType(Enum):
    """Classification type for discovered assets."""

    WEB_SERVER = "web_server"
    DATABASE = "database"
    IOT_DEVICE = "iot_device"
    NETWORK_DEVICE = "network_device"
    OTHER = "other"


class RiskLevel(Enum):
    """Risk severity level assigned to assessed assets."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class GeoLocation:
    """Geographic location information for an asset."""

    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None


@dataclass
class Service:
    """A network service running on an asset."""

    port: int
    protocol: str
    name: str | None = None
    version: str | None = None
    banner: str | None = None


@dataclass
class RawAsset:
    """An unprocessed asset as returned from a data source provider."""

    ip: str
    hostname: str | None = None
    ports: list[int] = field(default_factory=list)
    data: list[dict] = field(default_factory=list)


@dataclass
class ClassifiedAsset:
    """An asset that has been classified by type with extracted metadata."""

    ip: str
    hostname: str | None
    asset_type: AssetType
    os: str | None
    services: list[Service]
    geolocation: GeoLocation | None
    ports: list[int]
    raw_data: dict


@dataclass
class VulnerabilityIndicator:
    """A potential security issue identified on an asset."""

    category: str  # "vulnerable_version", "risky_port", "admin_interface"
    description: str
    severity: RiskLevel
    details: dict = field(default_factory=dict)


@dataclass
class AssessedAsset:
    """An asset with vulnerability assessment and risk level."""

    ip: str
    hostname: str | None
    asset_type: AssetType
    os: str | None
    services: list[Service]
    geolocation: GeoLocation | None
    ports: list[int]
    vulnerabilities: list[VulnerabilityIndicator]
    risk_level: RiskLevel


@dataclass
class ScanMetadata:
    """Metadata about a scan execution."""

    timestamp: datetime
    query_parameters: list[str]
    api_credits_used: int
    scan_duration_seconds: float


@dataclass
class ReportSummary:
    """Summary statistics for a scan report."""

    total_assets: int
    assets_by_type: dict[str, int]
    assets_by_risk: dict[str, int]


@dataclass
class ScanReport:
    """Complete scan report with metadata, summary, and assessed assets."""

    metadata: ScanMetadata
    summary: ReportSummary
    assets: list[AssessedAsset]


@dataclass
class EnrichedAsset(AssessedAsset):
    """An assessed asset enriched with external threat intelligence data."""

    correlation_risk_score: int = 0
    enrichment_data: dict[str, dict] = field(default_factory=dict)
    discovered_subdomains: list[str] = field(default_factory=list)


@dataclass
class ScanDiff:
    """Differences between two scan reports."""

    new_assets: list[AssessedAsset]
    removed_assets: list[AssessedAsset]
    changed_assets: list[tuple[AssessedAsset, AssessedAsset]]  # (old, new)
    risk_increase_assets: list[tuple[AssessedAsset, AssessedAsset]] = field(
        default_factory=list
    )  # (old, new) where new risk > old risk


@dataclass
class CreditUsage:
    """API credit consumption tracking."""

    credits_before: int
    credits_after: int
    credits_consumed: int
    warning: str | None = None


# ---------------------------------------------------------------------------
# JSON Serialization Helpers
# ---------------------------------------------------------------------------

class ScannerJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles datetime and Enum types."""

    def default(self, o: Any) -> Any:
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, Enum):
            return o.value
        return super().default(o)


def _serialize_value(obj: Any) -> Any:
    """Recursively convert datetime and Enum instances for JSON compatibility."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _serialize_value(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize_value(item) for item in obj]
    return obj


def to_serializable_dict(obj: Any) -> dict:
    """Convert a dataclass instance to a JSON-serializable dict.

    Handles nested dataclasses, datetime objects, and Enum values.
    """
    raw = asdict(obj)
    return _serialize_value(raw)


def to_json(obj: Any, **kwargs: Any) -> str:
    """Serialize a dataclass instance to a JSON string.

    Args:
        obj: A dataclass instance to serialize.
        **kwargs: Additional keyword arguments passed to ``json.dumps``
                  (e.g. ``indent``).

    Returns:
        A JSON string representation of the dataclass.
    """
    return json.dumps(to_serializable_dict(obj), **kwargs)
