"""Unit tests for the ScanHistoryManager."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from datetime import datetime

import pytest

from surfaceaudit.history import ScanHistoryManager
from surfaceaudit.models import (
    AssessedAsset,
    AssetType,
    GeoLocation,
    ReportSummary,
    RiskLevel,
    ScanDiff,
    ScanMetadata,
    ScanReport,
    Service,
    VulnerabilityIndicator,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_metadata() -> ScanMetadata:
    return ScanMetadata(
        timestamp=datetime(2024, 6, 15, 12, 30, 0),
        query_parameters=["example.com"],
        api_credits_used=5,
        scan_duration_seconds=12.5,
    )


def _make_asset(
    ip: str = "1.2.3.4",
    hostname: str | None = "host.example.com",
    ports: list[int] | None = None,
    risk: RiskLevel = RiskLevel.LOW,
    services: list[Service] | None = None,
    vulns: list[VulnerabilityIndicator] | None = None,
    geo: GeoLocation | None = None,
) -> AssessedAsset:
    return AssessedAsset(
        ip=ip,
        hostname=hostname,
        asset_type=AssetType.WEB_SERVER,
        os="Linux",
        services=services or [Service(port=80, protocol="tcp", name="http")],
        geolocation=geo or GeoLocation(country="US", city="NYC", latitude=40.7, longitude=-74.0),
        ports=ports or [80],
        vulnerabilities=vulns or [],
        risk_level=risk,
    )


def _make_report(assets: list[AssessedAsset] | None = None) -> ScanReport:
    assets = assets or [_make_asset()]
    return ScanReport(
        metadata=_make_metadata(),
        summary=ReportSummary(
            total_assets=len(assets),
            assets_by_type={"web_server": len(assets)},
            assets_by_risk={"low": len(assets)},
        ),
        assets=assets,
    )


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


# ---------------------------------------------------------------------------
# Tests: __init__
# ---------------------------------------------------------------------------

class TestInit:
    def test_creates_storage_dir(self, tmp_dir: str):
        sub = os.path.join(tmp_dir, "new_sub")
        ScanHistoryManager(sub)
        assert os.path.isdir(sub)


# ---------------------------------------------------------------------------
# Tests: save / load round-trip
# ---------------------------------------------------------------------------

class TestSaveLoad:
    def test_save_returns_path_with_timestamp(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        path = mgr.save(_make_report())
        assert path.startswith(tmp_dir)
        assert os.path.basename(path).startswith("scan_")
        assert path.endswith(".json")

    def test_saved_file_is_valid_json(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        path = mgr.save(_make_report())
        with open(path) as f:
            data = json.load(f)
        assert "metadata" in data
        assert "assets" in data

    def test_file_permissions_owner_only(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        path = mgr.save(_make_report())
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600

    def test_round_trip_preserves_metadata(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        original = _make_report()
        path = mgr.save(original)
        loaded = mgr.load(path)

        assert loaded.metadata.timestamp == original.metadata.timestamp
        assert loaded.metadata.query_parameters == original.metadata.query_parameters
        assert loaded.metadata.api_credits_used == original.metadata.api_credits_used
        assert loaded.metadata.scan_duration_seconds == original.metadata.scan_duration_seconds

    def test_round_trip_preserves_summary(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        original = _make_report()
        path = mgr.save(original)
        loaded = mgr.load(path)

        assert loaded.summary.total_assets == original.summary.total_assets
        assert loaded.summary.assets_by_type == original.summary.assets_by_type
        assert loaded.summary.assets_by_risk == original.summary.assets_by_risk

    def test_round_trip_preserves_assets(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        asset = _make_asset(
            ip="5.6.7.8",
            hostname="db.example.com",
            ports=[3306, 5432],
            risk=RiskLevel.HIGH,
            services=[
                Service(port=3306, protocol="tcp", name="mysql", version="8.0"),
                Service(port=5432, protocol="tcp", name="postgres"),
            ],
            vulns=[
                VulnerabilityIndicator(
                    category="vulnerable_version",
                    description="Outdated MySQL",
                    severity=RiskLevel.HIGH,
                    details={"cve": "CVE-2024-0001"},
                )
            ],
            geo=GeoLocation(country="DE", city="Berlin", latitude=52.5, longitude=13.4),
        )
        original = _make_report([asset])
        path = mgr.save(original)
        loaded = mgr.load(path)

        la = loaded.assets[0]
        assert la.ip == "5.6.7.8"
        assert la.hostname == "db.example.com"
        assert la.asset_type == AssetType.WEB_SERVER
        assert la.os == "Linux"
        assert la.risk_level == RiskLevel.HIGH
        assert la.ports == [3306, 5432]
        assert len(la.services) == 2
        assert la.services[0].name == "mysql"
        assert la.services[0].version == "8.0"
        assert la.geolocation is not None
        assert la.geolocation.country == "DE"
        assert len(la.vulnerabilities) == 1
        assert la.vulnerabilities[0].category == "vulnerable_version"
        assert la.vulnerabilities[0].severity == RiskLevel.HIGH
        assert la.vulnerabilities[0].details == {"cve": "CVE-2024-0001"}

    def test_round_trip_none_geolocation(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        asset = _make_asset(geo=None)
        # Force None geolocation
        asset.geolocation = None
        original = _make_report([asset])
        path = mgr.save(original)
        loaded = mgr.load(path)
        assert loaded.assets[0].geolocation is None


# ---------------------------------------------------------------------------
# Tests: compare
# ---------------------------------------------------------------------------

class TestCompare:
    def test_new_assets(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        a = _make_report([_make_asset(ip="1.1.1.1")])
        b = _make_report([_make_asset(ip="1.1.1.1"), _make_asset(ip="2.2.2.2")])
        diff = mgr.compare(a, b)
        assert len(diff.new_assets) == 1
        assert diff.new_assets[0].ip == "2.2.2.2"

    def test_removed_assets(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        a = _make_report([_make_asset(ip="1.1.1.1"), _make_asset(ip="2.2.2.2")])
        b = _make_report([_make_asset(ip="1.1.1.1")])
        diff = mgr.compare(a, b)
        assert len(diff.removed_assets) == 1
        assert diff.removed_assets[0].ip == "2.2.2.2"

    def test_changed_assets_ports(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        a = _make_report([_make_asset(ip="1.1.1.1", ports=[80])])
        b = _make_report([_make_asset(ip="1.1.1.1", ports=[80, 443])])
        diff = mgr.compare(a, b)
        assert len(diff.changed_assets) == 1
        old, new = diff.changed_assets[0]
        assert old.ports == [80]
        assert new.ports == [80, 443]

    def test_changed_assets_services(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        svc_old = [Service(port=80, protocol="tcp", name="http", version="1.0")]
        svc_new = [Service(port=80, protocol="tcp", name="http", version="2.0")]
        a = _make_report([_make_asset(ip="1.1.1.1", services=svc_old)])
        b = _make_report([_make_asset(ip="1.1.1.1", services=svc_new)])
        diff = mgr.compare(a, b)
        assert len(diff.changed_assets) == 1

    def test_unchanged_assets_not_in_diff(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        asset = _make_asset(ip="1.1.1.1")
        a = _make_report([asset])
        b = _make_report([asset])
        diff = mgr.compare(a, b)
        assert len(diff.new_assets) == 0
        assert len(diff.removed_assets) == 0
        assert len(diff.changed_assets) == 0

    def test_empty_reports(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        a = _make_report([])
        b = _make_report([])
        diff = mgr.compare(a, b)
        assert diff.new_assets == []
        assert diff.removed_assets == []
        assert diff.changed_assets == []
