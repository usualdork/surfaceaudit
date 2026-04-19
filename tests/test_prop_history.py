# Feature: shodan-infrastructure-scanner, Property 14: Scan report persistence round-trip
# Feature: shodan-infrastructure-scanner, Property 13: Report diff correctness
"""Property-based tests for scan history persistence and diff comparison.

**Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5**
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from surfaceaudit.history import ScanHistoryManager
from surfaceaudit.models import (
    AssessedAsset,
    AssetType,
    GeoLocation,
    ReportSummary,
    RiskLevel,
    ScanMetadata,
    ScanReport,
    Service,
    VulnerabilityIndicator,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_asset_type_strategy = st.sampled_from(list(AssetType))
_risk_level_strategy = st.sampled_from(list(RiskLevel))
_port_strategy = st.integers(min_value=1, max_value=65535)
_protocol_strategy = st.sampled_from(["tcp", "udp"])

_public_ip_octet = st.integers(min_value=1, max_value=254)
_public_ip_strategy = st.tuples(
    st.integers(min_value=11, max_value=99),
    _public_ip_octet,
    _public_ip_octet,
    _public_ip_octet,
).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}")


@st.composite
def _service_strategy(draw: st.DrawFn) -> Service:
    port = draw(_port_strategy)
    protocol = draw(_protocol_strategy)
    name = draw(st.one_of(st.none(), st.sampled_from(["http", "ssh", "ftp", "smtp"])))
    version = draw(st.one_of(st.none(), st.sampled_from(["1.0", "2.0", "3.1"])))
    return Service(port=port, protocol=protocol, name=name, version=version)


@st.composite
def _vuln_indicator_strategy(draw: st.DrawFn) -> VulnerabilityIndicator:
    category = draw(st.sampled_from(["vulnerable_version", "risky_port", "admin_interface"]))
    severity = draw(_risk_level_strategy)
    return VulnerabilityIndicator(
        category=category,
        description=f"Test {category}",
        severity=severity,
    )


@st.composite
def _geolocation_strategy(draw: st.DrawFn) -> GeoLocation | None:
    if draw(st.booleans()):
        return None
    return GeoLocation(
        country=draw(st.one_of(st.none(), st.sampled_from(["US", "DE", "JP"]))),
        city=draw(st.one_of(st.none(), st.sampled_from(["NYC", "Berlin", "Tokyo"]))),
        latitude=draw(st.one_of(st.none(), st.floats(min_value=-90, max_value=90, allow_nan=False, allow_infinity=False))),
        longitude=draw(st.one_of(st.none(), st.floats(min_value=-180, max_value=180, allow_nan=False, allow_infinity=False))),
    )


@st.composite
def _assessed_asset_strategy(draw: st.DrawFn, ip_strat=None) -> AssessedAsset:
    ip = draw(ip_strat if ip_strat is not None else _public_ip_strategy)
    hostname = draw(st.one_of(st.none(), st.sampled_from(["host.example.com", "db.example.com"])))
    asset_type = draw(_asset_type_strategy)
    os_val = draw(st.one_of(st.none(), st.sampled_from(["Linux", "Windows"])))
    services = draw(st.lists(_service_strategy(), min_size=0, max_size=3))
    geo = draw(_geolocation_strategy())
    ports = draw(st.lists(_port_strategy, min_size=0, max_size=5))
    vulns = draw(st.lists(_vuln_indicator_strategy(), min_size=0, max_size=3))
    risk_level = draw(_risk_level_strategy)
    return AssessedAsset(
        ip=ip,
        hostname=hostname,
        asset_type=asset_type,
        os=os_val,
        services=services,
        geolocation=geo,
        ports=ports,
        vulnerabilities=vulns,
        risk_level=risk_level,
    )


@st.composite
def _scan_metadata_strategy(draw: st.DrawFn) -> ScanMetadata:
    ts = draw(st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2030, 1, 1),
        timezones=st.just(timezone.utc),
    ))
    queries = draw(st.lists(
        st.sampled_from(["example.com", "test.org", "192.0.2.0/24"]),
        min_size=1,
        max_size=3,
    ))
    credits = draw(st.integers(min_value=0, max_value=1000))
    duration = draw(st.floats(min_value=0.0, max_value=3600.0, allow_nan=False, allow_infinity=False))
    return ScanMetadata(
        timestamp=ts,
        query_parameters=queries,
        api_credits_used=credits,
        scan_duration_seconds=duration,
    )


@st.composite
def _scan_report_strategy(draw: st.DrawFn, asset_strat=None) -> ScanReport:
    assets = draw(st.lists(asset_strat or _assessed_asset_strategy(), min_size=0, max_size=5))
    metadata = draw(_scan_metadata_strategy())
    # Build a consistent summary from the assets
    by_type: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    for a in assets:
        by_type[a.asset_type.value] = by_type.get(a.asset_type.value, 0) + 1
        by_risk[a.risk_level.value] = by_risk.get(a.risk_level.value, 0) + 1
    summary = ReportSummary(
        total_assets=len(assets),
        assets_by_type=by_type,
        assets_by_risk=by_risk,
    )
    return ScanReport(metadata=metadata, summary=summary, assets=assets)


# ---------------------------------------------------------------------------
# Property 14: Scan report persistence round-trip
# **Validates: Requirements 7.1**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(report=_scan_report_strategy())
def test_scan_report_persistence_roundtrip(report: ScanReport) -> None:
    # Feature: shodan-infrastructure-scanner, Property 14: Scan report persistence round-trip
    """For any ScanReport, saving via the history manager and loading back
    should produce an equivalent ScanReport.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        mgr = ScanHistoryManager(tmp_dir)
        path = mgr.save(report)
        loaded = mgr.load(path)

        # Metadata
        assert loaded.metadata.timestamp == report.metadata.timestamp
        assert loaded.metadata.query_parameters == report.metadata.query_parameters
        assert loaded.metadata.api_credits_used == report.metadata.api_credits_used
        assert loaded.metadata.scan_duration_seconds == report.metadata.scan_duration_seconds

        # Summary
        assert loaded.summary.total_assets == report.summary.total_assets
        assert loaded.summary.assets_by_type == report.summary.assets_by_type
        assert loaded.summary.assets_by_risk == report.summary.assets_by_risk

        # Assets count
        assert len(loaded.assets) == len(report.assets)

        # Each asset field-by-field
        for orig, ld in zip(report.assets, loaded.assets):
            assert ld.ip == orig.ip
            assert ld.hostname == orig.hostname
            assert ld.asset_type == orig.asset_type
            assert ld.os == orig.os
            assert sorted(ld.ports) == sorted(orig.ports)
            assert ld.risk_level == orig.risk_level

            # Services
            assert len(ld.services) == len(orig.services)
            for os_svc, ls_svc in zip(orig.services, ld.services):
                assert ls_svc.port == os_svc.port
                assert ls_svc.protocol == os_svc.protocol
                assert ls_svc.name == os_svc.name
                assert ls_svc.version == os_svc.version

            # Geolocation
            if orig.geolocation is None:
                assert ld.geolocation is None
            else:
                assert ld.geolocation is not None
                assert ld.geolocation.country == orig.geolocation.country
                assert ld.geolocation.city == orig.geolocation.city
                assert ld.geolocation.latitude == orig.geolocation.latitude
                assert ld.geolocation.longitude == orig.geolocation.longitude

            # Vulnerabilities
            assert len(ld.vulnerabilities) == len(orig.vulnerabilities)
            for ov, lv in zip(orig.vulnerabilities, ld.vulnerabilities):
                assert lv.category == ov.category
                assert lv.description == ov.description
                assert lv.severity == ov.severity
                assert lv.details == ov.details


# ---------------------------------------------------------------------------
# Property 13: Report diff correctness
# **Validates: Requirements 7.2, 7.3, 7.4, 7.5**
# ---------------------------------------------------------------------------

# Strategy that generates a fixed IP pool so we can create overlapping reports
_ip_pool = [f"44.{i}.{j}.1" for i in range(1, 11) for j in range(1, 6)]


@st.composite
def _two_reports_with_overlap(draw: st.DrawFn):
    """Generate two ScanReports with some overlapping IPs.

    We pick IPs from a shared pool, then for overlapping IPs we may
    vary ports/services to produce changed assets.
    """
    pool = list(_ip_pool)
    ips_a = draw(st.lists(
        st.sampled_from(pool), min_size=0, max_size=8, unique=True,
    ))
    ips_b = draw(st.lists(
        st.sampled_from(pool), min_size=0, max_size=8, unique=True,
    ))

    def _build_asset(ip: str) -> AssessedAsset:
        return draw(_assessed_asset_strategy(ip_strat=st.just(ip)))

    assets_a = [_build_asset(ip) for ip in ips_a]
    assets_b = [_build_asset(ip) for ip in ips_b]

    meta_a = draw(_scan_metadata_strategy())
    meta_b = draw(_scan_metadata_strategy())

    def _make_report(assets, meta):
        by_type: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        for a in assets:
            by_type[a.asset_type.value] = by_type.get(a.asset_type.value, 0) + 1
            by_risk[a.risk_level.value] = by_risk.get(a.risk_level.value, 0) + 1
        summary = ReportSummary(
            total_assets=len(assets),
            assets_by_type=by_type,
            assets_by_risk=by_risk,
        )
        return ScanReport(metadata=meta, summary=summary, assets=assets)

    return _make_report(assets_a, meta_a), _make_report(assets_b, meta_b)


@settings(max_examples=100)
@given(reports=_two_reports_with_overlap())
def test_report_diff_correctness(reports: tuple[ScanReport, ScanReport]) -> None:
    # Feature: shodan-infrastructure-scanner, Property 13: Report diff correctness
    """For any two ScanReports A and B, the diff should satisfy:
    (a) new_assets contains exactly those assets in B whose IPs are not in A,
    (b) removed_assets contains exactly those assets in A whose IPs are not in B,
    (c) changed_assets contains exactly those assets present in both but with
        different port lists or service configurations.
    """
    report_a, report_b = reports

    mgr = ScanHistoryManager(tempfile.mkdtemp())
    diff = mgr.compare(report_a, report_b)

    ips_a = {a.ip for a in report_a.assets}
    ips_b = {b.ip for b in report_b.assets}

    # (a) new_assets: IPs in B but not in A
    new_ips = {a.ip for a in diff.new_assets}
    expected_new = ips_b - ips_a
    assert new_ips == expected_new, f"new: got {new_ips}, expected {expected_new}"

    # (b) removed_assets: IPs in A but not in B
    removed_ips = {a.ip for a in diff.removed_assets}
    expected_removed = ips_a - ips_b
    assert removed_ips == expected_removed, f"removed: got {removed_ips}, expected {expected_removed}"

    # (c) changed_assets: IPs in both with different ports or services
    changed_ips = {old.ip for old, new in diff.changed_assets}
    common_ips = ips_a & ips_b

    # Build lookup for assets by IP
    a_by_ip = {a.ip: a for a in report_a.assets}
    b_by_ip = {b.ip: b for b in report_b.assets}

    for ip in common_ips:
        old_asset = a_by_ip[ip]
        new_asset = b_by_ip[ip]

        ports_differ = sorted(old_asset.ports) != sorted(new_asset.ports)
        old_svcs = sorted(
            [(s.port, s.protocol, s.name, s.version) for s in old_asset.services]
        )
        new_svcs = sorted(
            [(s.port, s.protocol, s.name, s.version) for s in new_asset.services]
        )
        services_differ = old_svcs != new_svcs

        if ports_differ or services_differ:
            assert ip in changed_ips, f"IP {ip} should be in changed_assets"
        else:
            assert ip not in changed_ips, f"IP {ip} should NOT be in changed_assets"

    # All changed IPs must be in the common set
    assert changed_ips <= common_ips
