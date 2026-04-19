"""Scan history management for SurfaceAudit."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

_UTC = timezone.utc

from surfaceaudit.models import (
    AssessedAsset,
    AssetType,
    GeoLocation,
    RiskLevel,
    ReportSummary,
    ScanDiff,
    ScanMetadata,
    ScanReport,
    Service,
    VulnerabilityIndicator,
    to_serializable_dict,
)


class ScanHistoryManager:
    """Persists scan reports and compares them over time."""

    def __init__(self, storage_dir: str) -> None:
        self._storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save(self, report: ScanReport) -> str:
        """Serialize *report* to a timestamped JSON file.

        The file is written with owner-only permissions (``0o600``).
        Returns the absolute path of the saved file.
        """
        timestamp = datetime.now(tz=_UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{timestamp}.json"
        path = os.path.join(self._storage_dir, filename)

        data = to_serializable_dict(report)
        content = json.dumps(data, indent=2)

        # Write with restricted permissions: create file with 0o600
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)

        return path

    def load(self, path: str) -> ScanReport:
        """Deserialize a ``ScanReport`` from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return _dict_to_scan_report(data)

    def compare(self, report_a: ScanReport, report_b: ScanReport) -> ScanDiff:
        """Produce a ``ScanDiff`` between two reports.

        * **new_assets** – assets in *report_b* whose IPs are not in *report_a*.
        * **removed_assets** – assets in *report_a* whose IPs are not in *report_b*.
        * **changed_assets** – assets present in both (by IP) but with
          different port lists or service configurations.
        """
        ips_a = {asset.ip: asset for asset in report_a.assets}
        ips_b = {asset.ip: asset for asset in report_b.assets}

        new_assets = [ips_b[ip] for ip in ips_b if ip not in ips_a]
        removed_assets = [ips_a[ip] for ip in ips_a if ip not in ips_b]

        changed_assets: list[tuple[AssessedAsset, AssessedAsset]] = []
        for ip in ips_a:
            if ip in ips_b:
                old, new = ips_a[ip], ips_b[ip]
                if _asset_changed(old, new):
                    changed_assets.append((old, new))

        return ScanDiff(
            new_assets=new_assets,
            removed_assets=removed_assets,
            changed_assets=changed_assets,
        )


# ---------------------------------------------------------------------------
# Deserialization helpers
# ---------------------------------------------------------------------------

def _dict_to_scan_report(d: dict) -> ScanReport:
    """Reconstruct a ``ScanReport`` from a plain dict."""
    return ScanReport(
        metadata=_dict_to_metadata(d["metadata"]),
        summary=_dict_to_summary(d["summary"]),
        assets=[_dict_to_assessed_asset(a) for a in d["assets"]],
    )


def _dict_to_metadata(d: dict) -> ScanMetadata:
    return ScanMetadata(
        timestamp=datetime.fromisoformat(d["timestamp"]),
        query_parameters=d["query_parameters"],
        api_credits_used=d["api_credits_used"],
        scan_duration_seconds=d["scan_duration_seconds"],
    )


def _dict_to_summary(d: dict) -> ReportSummary:
    return ReportSummary(
        total_assets=d["total_assets"],
        assets_by_type=d["assets_by_type"],
        assets_by_risk=d["assets_by_risk"],
    )


def _dict_to_assessed_asset(d: dict) -> AssessedAsset:
    return AssessedAsset(
        ip=d["ip"],
        hostname=d.get("hostname"),
        asset_type=AssetType(d["asset_type"]),
        os=d.get("os"),
        services=[_dict_to_service(s) for s in d.get("services", [])],
        geolocation=_dict_to_geolocation(d.get("geolocation")) if d.get("geolocation") else None,
        ports=d.get("ports", []),
        vulnerabilities=[_dict_to_vulnerability(v) for v in d.get("vulnerabilities", [])],
        risk_level=RiskLevel(d["risk_level"]),
    )


def _dict_to_service(d: dict) -> Service:
    return Service(
        port=d["port"],
        protocol=d["protocol"],
        name=d.get("name"),
        version=d.get("version"),
        banner=d.get("banner"),
    )


def _dict_to_geolocation(d: dict | None) -> GeoLocation | None:
    if d is None:
        return None
    return GeoLocation(
        country=d.get("country"),
        city=d.get("city"),
        latitude=d.get("latitude"),
        longitude=d.get("longitude"),
    )


def _dict_to_vulnerability(d: dict) -> VulnerabilityIndicator:
    return VulnerabilityIndicator(
        category=d["category"],
        description=d["description"],
        severity=RiskLevel(d["severity"]),
        details=d.get("details", {}),
    )


# ---------------------------------------------------------------------------
# Change detection helper
# ---------------------------------------------------------------------------

def _asset_changed(old: AssessedAsset, new: AssessedAsset) -> bool:
    """Return ``True`` if the two assets differ in ports or services."""
    if sorted(old.ports) != sorted(new.ports):
        return True
    # Compare services by their key attributes
    old_services = sorted(
        [(s.port, s.protocol, s.name, s.version) for s in old.services]
    )
    new_services = sorted(
        [(s.port, s.protocol, s.name, s.version) for s in new.services]
    )
    return old_services != new_services
