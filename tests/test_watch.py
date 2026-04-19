"""Unit tests for WatchMode and diff computation."""

from __future__ import annotations

import json
import os
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
from surfaceaudit.watch import (
    RISK_LEVEL_ORDER,
    WatchMode,
    _NullDispatcher,
    compute_diff,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_asset(
    ip: str = "1.2.3.4",
    hostname: str | None = "host.example.com",
    ports: list[int] | None = None,
    risk: RiskLevel = RiskLevel.LOW,
    services: list[Service] | None = None,
) -> AssessedAsset:
    return AssessedAsset(
        ip=ip,
        hostname=hostname,
        asset_type=AssetType.WEB_SERVER,
        os="Linux",
        services=services or [Service(port=80, protocol="tcp", name="http")],
        geolocation=GeoLocation(country="US", city="NYC", latitude=40.7, longitude=-74.0),
        ports=ports or [80],
        vulnerabilities=[],
        risk_level=risk,
    )


def _make_report(assets: list[AssessedAsset] | None = None) -> ScanReport:
    assets = assets or [_make_asset()]
    return ScanReport(
        metadata=ScanMetadata(
            timestamp=datetime(2024, 6, 15, 12, 30, 0),
            query_parameters=["example.com"],
            api_credits_used=5,
            scan_duration_seconds=12.5,
        ),
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
# Tests: compute_diff — new / removed
# ---------------------------------------------------------------------------

class TestComputeDiffNewRemoved:
    def test_new_asset(self):
        prev = [_make_asset(ip="1.1.1.1")]
        curr = [_make_asset(ip="1.1.1.1"), _make_asset(ip="2.2.2.2")]
        diff = compute_diff(prev, curr)
        assert len(diff.new_assets) == 1
        assert diff.new_assets[0].ip == "2.2.2.2"

    def test_removed_asset(self):
        prev = [_make_asset(ip="1.1.1.1"), _make_asset(ip="2.2.2.2")]
        curr = [_make_asset(ip="1.1.1.1")]
        diff = compute_diff(prev, curr)
        assert len(diff.removed_assets) == 1
        assert diff.removed_assets[0].ip == "2.2.2.2"

    def test_no_previous_all_new(self):
        curr = [_make_asset(ip="1.1.1.1"), _make_asset(ip="2.2.2.2")]
        diff = compute_diff([], curr)
        assert len(diff.new_assets) == 2
        assert len(diff.removed_assets) == 0

    def test_empty_both(self):
        diff = compute_diff([], [])
        assert diff.new_assets == []
        assert diff.removed_assets == []
        assert diff.changed_assets == []
        assert diff.risk_increase_assets == []


# ---------------------------------------------------------------------------
# Tests: compute_diff — risk increase
# ---------------------------------------------------------------------------

class TestComputeDiffRiskIncrease:
    def test_low_to_medium(self):
        prev = [_make_asset(ip="1.1.1.1", risk=RiskLevel.LOW)]
        curr = [_make_asset(ip="1.1.1.1", risk=RiskLevel.MEDIUM)]
        diff = compute_diff(prev, curr)
        assert len(diff.risk_increase_assets) == 1
        old, new = diff.risk_increase_assets[0]
        assert old.risk_level == RiskLevel.LOW
        assert new.risk_level == RiskLevel.MEDIUM

    def test_low_to_high(self):
        prev = [_make_asset(ip="1.1.1.1", risk=RiskLevel.LOW)]
        curr = [_make_asset(ip="1.1.1.1", risk=RiskLevel.HIGH)]
        diff = compute_diff(prev, curr)
        assert len(diff.risk_increase_assets) == 1

    def test_medium_to_high(self):
        prev = [_make_asset(ip="1.1.1.1", risk=RiskLevel.MEDIUM)]
        curr = [_make_asset(ip="1.1.1.1", risk=RiskLevel.HIGH)]
        diff = compute_diff(prev, curr)
        assert len(diff.risk_increase_assets) == 1

    def test_no_increase_same_risk(self):
        prev = [_make_asset(ip="1.1.1.1", risk=RiskLevel.MEDIUM)]
        curr = [_make_asset(ip="1.1.1.1", risk=RiskLevel.MEDIUM)]
        diff = compute_diff(prev, curr)
        assert len(diff.risk_increase_assets) == 0

    def test_risk_decrease_not_flagged(self):
        prev = [_make_asset(ip="1.1.1.1", risk=RiskLevel.HIGH)]
        curr = [_make_asset(ip="1.1.1.1", risk=RiskLevel.LOW)]
        diff = compute_diff(prev, curr)
        assert len(diff.risk_increase_assets) == 0


# ---------------------------------------------------------------------------
# Tests: compute_diff — changed assets
# ---------------------------------------------------------------------------

class TestComputeDiffChanged:
    def test_port_change(self):
        prev = [_make_asset(ip="1.1.1.1", ports=[80])]
        curr = [_make_asset(ip="1.1.1.1", ports=[80, 443])]
        diff = compute_diff(prev, curr)
        assert len(diff.changed_assets) == 1
        old, new = diff.changed_assets[0]
        assert old.ports == [80]
        assert new.ports == [80, 443]

    def test_service_change(self):
        svc_old = [Service(port=80, protocol="tcp", name="http", version="1.0")]
        svc_new = [Service(port=80, protocol="tcp", name="http", version="2.0")]
        prev = [_make_asset(ip="1.1.1.1", services=svc_old)]
        curr = [_make_asset(ip="1.1.1.1", services=svc_new)]
        diff = compute_diff(prev, curr)
        assert len(diff.changed_assets) == 1

    def test_unchanged_not_in_diff(self):
        asset = _make_asset(ip="1.1.1.1")
        diff = compute_diff([asset], [asset])
        assert len(diff.changed_assets) == 0
        assert len(diff.risk_increase_assets) == 0

    def test_risk_increase_not_in_changed(self):
        """Risk increase should be in risk_increase_assets, not changed_assets."""
        prev = [_make_asset(ip="1.1.1.1", risk=RiskLevel.LOW)]
        curr = [_make_asset(ip="1.1.1.1", risk=RiskLevel.HIGH)]
        diff = compute_diff(prev, curr)
        assert len(diff.risk_increase_assets) == 1
        assert len(diff.changed_assets) == 0


# ---------------------------------------------------------------------------
# Tests: RISK_LEVEL_ORDER
# ---------------------------------------------------------------------------

class TestRiskLevelOrder:
    def test_ordering(self):
        assert RISK_LEVEL_ORDER[RiskLevel.LOW] < RISK_LEVEL_ORDER[RiskLevel.MEDIUM]
        assert RISK_LEVEL_ORDER[RiskLevel.MEDIUM] < RISK_LEVEL_ORDER[RiskLevel.HIGH]


# ---------------------------------------------------------------------------
# Tests: WatchMode
# ---------------------------------------------------------------------------

class TestWatchMode:
    def test_run_no_previous_scan(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        wm = WatchMode(config=object(), history_manager=mgr)
        report = _make_report([_make_asset(ip="1.1.1.1")])
        diff = wm.run(current_report=report)
        assert len(diff.new_assets) == 1
        assert diff.new_assets[0].ip == "1.1.1.1"
        assert len(diff.removed_assets) == 0

    def test_run_with_previous_scan(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        # Save a previous scan
        prev_report = _make_report([_make_asset(ip="1.1.1.1")])
        mgr.save(prev_report)

        wm = WatchMode(config=object(), history_manager=mgr)
        curr_report = _make_report([
            _make_asset(ip="1.1.1.1"),
            _make_asset(ip="2.2.2.2"),
        ])
        diff = wm.run(current_report=curr_report)
        assert len(diff.new_assets) == 1
        assert diff.new_assets[0].ip == "2.2.2.2"

    def test_run_saves_current_report(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        wm = WatchMode(config=object(), history_manager=mgr)
        report = _make_report([_make_asset(ip="1.1.1.1")])
        wm.run(current_report=report)

        scan_files = [f for f in os.listdir(tmp_dir) if f.startswith("scan_")]
        assert len(scan_files) == 1

    def test_run_saves_diff_json(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        wm = WatchMode(config=object(), history_manager=mgr)
        report = _make_report([_make_asset(ip="1.1.1.1")])
        wm.run(current_report=report)

        diff_files = [f for f in os.listdir(tmp_dir) if f.startswith("diff_")]
        assert len(diff_files) == 1
        path = os.path.join(tmp_dir, diff_files[0])
        with open(path) as f:
            data = json.load(f)
        assert "new_assets" in data
        assert "removed_assets" in data

    def test_run_dispatches_notifications(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        dispatched: list[tuple] = []

        class FakeDispatcher:
            def dispatch(self, diff, config_path, diff_report_path):
                dispatched.append((diff, config_path, diff_report_path))

        wm = WatchMode(
            config=object(),
            history_manager=mgr,
            dispatcher=FakeDispatcher(),
        )
        report = _make_report([_make_asset(ip="1.1.1.1")])
        wm.run(current_report=report)
        assert len(dispatched) == 1

    def test_creates_history_dir(self):
        with tempfile.TemporaryDirectory() as parent:
            sub = os.path.join(parent, "nested", "history")
            mgr = ScanHistoryManager(sub)
            wm = WatchMode(config=object(), history_manager=mgr)
            assert os.path.isdir(sub)

    def test_run_requires_report(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        wm = WatchMode(config=object(), history_manager=mgr)
        with pytest.raises(ValueError, match="current_report must be provided"):
            wm.run()

    def test_load_latest_scan_returns_none_empty_dir(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        wm = WatchMode(config=object(), history_manager=mgr)
        assert wm._load_latest_scan() is None

    def test_load_latest_scan_picks_most_recent(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        # Save two reports
        r1 = _make_report([_make_asset(ip="1.1.1.1")])
        mgr.save(r1)
        r2 = _make_report([_make_asset(ip="2.2.2.2")])
        mgr.save(r2)

        wm = WatchMode(config=object(), history_manager=mgr)
        latest = wm._load_latest_scan()
        assert latest is not None
        assert latest.assets[0].ip == "2.2.2.2"

    def test_diff_json_contains_risk_increase(self, tmp_dir: str):
        mgr = ScanHistoryManager(tmp_dir)
        prev = _make_report([_make_asset(ip="1.1.1.1", risk=RiskLevel.LOW)])
        mgr.save(prev)

        wm = WatchMode(config=object(), history_manager=mgr)
        curr = _make_report([_make_asset(ip="1.1.1.1", risk=RiskLevel.HIGH)])
        wm.run(current_report=curr)

        diff_files = [f for f in os.listdir(tmp_dir) if f.startswith("diff_")]
        assert len(diff_files) == 1
        path = os.path.join(tmp_dir, diff_files[0])
        with open(path) as f:
            data = json.load(f)
        assert "risk_increase_assets" in data
        assert len(data["risk_increase_assets"]) == 1
