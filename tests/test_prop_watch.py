# Feature: v2-engine-correlation-monitoring, Property 32: Watch mode diff — new and removed assets
# Feature: v2-engine-correlation-monitoring, Property 33: Watch mode diff — risk increase detection
# Feature: v2-engine-correlation-monitoring, Property 34: Watch mode diff — changed assets
# Feature: v2-engine-correlation-monitoring, Property 40: No previous scan treats all assets as new
"""Property-based tests for watch mode diff computation.

**Validates: Requirements 21.4, 22.1, 22.2, 22.3, 22.4**
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from surfaceaudit.models import (
    AssessedAsset,
    AssetType,
    GeoLocation,
    RiskLevel,
    Service,
)
from surfaceaudit.watch import RISK_LEVEL_ORDER, compute_diff


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_ip_octet = st.integers(min_value=1, max_value=254)

_ip_strategy = st.tuples(_ip_octet, _ip_octet, _ip_octet, _ip_octet).map(
    lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"
)

_risk_level_strategy = st.sampled_from(list(RiskLevel))

_port_strategy = st.integers(min_value=1, max_value=65535)

_protocol_strategy = st.sampled_from(["tcp", "udp"])

_service_name_strategy = st.sampled_from(
    ["http", "ssh", "ftp", "smtp", "https", "dns", "mysql", "redis"]
)

_version_strategy = st.one_of(
    st.none(),
    st.from_regex(r"[0-9]{1,2}\.[0-9]{1,2}(\.[0-9]{1,2})?", fullmatch=True),
)


@st.composite
def _service_strategy(draw: st.DrawFn) -> Service:
    """Generate a random Service."""
    return Service(
        port=draw(_port_strategy),
        protocol=draw(_protocol_strategy),
        name=draw(st.one_of(st.none(), _service_name_strategy)),
        version=draw(_version_strategy),
        banner=draw(st.one_of(st.none(), st.text(min_size=0, max_size=30))),
    )


@st.composite
def _assessed_asset(draw: st.DrawFn, ip: str | None = None) -> AssessedAsset:
    """Generate a random AssessedAsset with an optional fixed IP."""
    asset_ip = ip if ip is not None else draw(_ip_strategy)
    services = draw(st.lists(_service_strategy(), min_size=0, max_size=4))
    ports = sorted({s.port for s in services}) if services else draw(
        st.lists(_port_strategy, min_size=0, max_size=5)
    )
    return AssessedAsset(
        ip=asset_ip,
        hostname=draw(st.one_of(st.none(), st.just("host.example.com"))),
        asset_type=draw(st.sampled_from(list(AssetType))),
        os=draw(st.one_of(st.none(), st.sampled_from(["Linux", "Windows"]))),
        services=services,
        geolocation=draw(st.one_of(st.none(), st.just(GeoLocation(country="US")))),
        ports=list(ports),
        vulnerabilities=[],
        risk_level=draw(_risk_level_strategy),
    )


@st.composite
def _unique_ip_asset_list(draw: st.DrawFn, min_size: int = 0, max_size: int = 8) -> list[AssessedAsset]:
    """Generate a list of AssessedAssets with unique IPs."""
    ips = draw(st.lists(_ip_strategy, min_size=min_size, max_size=max_size, unique=True))
    assets = []
    for ip in ips:
        assets.append(draw(_assessed_asset(ip=ip)))
    return assets


# ---------------------------------------------------------------------------
# Property 32: Watch mode diff — new and removed assets
# **Validates: Requirements 22.1, 22.2**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    previous=_unique_ip_asset_list(min_size=0, max_size=8),
    current=_unique_ip_asset_list(min_size=0, max_size=8),
)
def test_watch_diff_new_and_removed_assets(
    previous: list[AssessedAsset],
    current: list[AssessedAsset],
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 32: Watch mode diff — new and removed assets
    """For any two scan reports, the diff SHALL classify an asset as "new"
    iff its IP is in the current scan but not the previous scan, and as
    "removed" iff its IP is in the previous scan but not the current scan."""
    diff = compute_diff(previous, current)

    prev_ips = {a.ip for a in previous}
    curr_ips = {a.ip for a in current}

    expected_new_ips = curr_ips - prev_ips
    expected_removed_ips = prev_ips - curr_ips

    actual_new_ips = {a.ip for a in diff.new_assets}
    actual_removed_ips = {a.ip for a in diff.removed_assets}

    assert actual_new_ips == expected_new_ips, (
        f"New assets mismatch: expected {expected_new_ips}, got {actual_new_ips}"
    )
    assert actual_removed_ips == expected_removed_ips, (
        f"Removed assets mismatch: expected {expected_removed_ips}, got {actual_removed_ips}"
    )


# ---------------------------------------------------------------------------
# Property 33: Watch mode diff — risk increase detection
# **Validates: Requirements 22.3**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    previous=_unique_ip_asset_list(min_size=1, max_size=6),
    current=_unique_ip_asset_list(min_size=1, max_size=6),
)
def test_watch_diff_risk_increase_detection(
    previous: list[AssessedAsset],
    current: list[AssessedAsset],
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 33: Watch mode diff — risk increase detection
    """For any two scan reports where an asset's IP appears in both, the diff
    SHALL classify the asset as "risk_increase" iff the current risk level is
    strictly higher than the previous risk level (LOW < MEDIUM < HIGH)."""
    diff = compute_diff(previous, current)

    prev_map = {a.ip: a for a in previous}
    curr_map = {a.ip: a for a in current}
    common_ips = set(prev_map) & set(curr_map)

    # Compute expected risk-increase IPs
    expected_risk_increase_ips: set[str] = set()
    for ip in common_ips:
        old_rank = RISK_LEVEL_ORDER.get(prev_map[ip].risk_level, 0)
        new_rank = RISK_LEVEL_ORDER.get(curr_map[ip].risk_level, 0)
        if new_rank > old_rank:
            expected_risk_increase_ips.add(ip)

    actual_risk_increase_ips = {new.ip for _, new in diff.risk_increase_assets}

    assert actual_risk_increase_ips == expected_risk_increase_ips, (
        f"Risk increase mismatch: expected {expected_risk_increase_ips}, "
        f"got {actual_risk_increase_ips}"
    )


# ---------------------------------------------------------------------------
# Property 34: Watch mode diff — changed assets
# **Validates: Requirements 22.4**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    previous=_unique_ip_asset_list(min_size=1, max_size=6),
    current=_unique_ip_asset_list(min_size=1, max_size=6),
)
def test_watch_diff_changed_assets(
    previous: list[AssessedAsset],
    current: list[AssessedAsset],
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 34: Watch mode diff — changed assets
    """For any two scan reports where an asset's IP appears in both, the diff
    SHALL classify the asset as "changed" iff the open port list or service
    configuration differs between the two scans (and it's not already a
    risk_increase)."""
    diff = compute_diff(previous, current)

    prev_map = {a.ip: a for a in previous}
    curr_map = {a.ip: a for a in current}
    common_ips = set(prev_map) & set(curr_map)

    # Determine which common IPs are risk_increase
    risk_increase_ips: set[str] = set()
    for ip in common_ips:
        old_rank = RISK_LEVEL_ORDER.get(prev_map[ip].risk_level, 0)
        new_rank = RISK_LEVEL_ORDER.get(curr_map[ip].risk_level, 0)
        if new_rank > old_rank:
            risk_increase_ips.add(ip)

    # Determine which common IPs have changed ports or services
    expected_changed_ips: set[str] = set()
    for ip in common_ips:
        if ip in risk_increase_ips:
            continue
        old, new = prev_map[ip], curr_map[ip]
        ports_differ = sorted(old.ports) != sorted(new.ports)
        old_svcs = sorted(
            [(s.port, s.protocol, s.name, s.version) for s in old.services]
        )
        new_svcs = sorted(
            [(s.port, s.protocol, s.name, s.version) for s in new.services]
        )
        services_differ = old_svcs != new_svcs
        if ports_differ or services_differ:
            expected_changed_ips.add(ip)

    actual_changed_ips = {new.ip for _, new in diff.changed_assets}

    assert actual_changed_ips == expected_changed_ips, (
        f"Changed assets mismatch: expected {expected_changed_ips}, "
        f"got {actual_changed_ips}"
    )


# ---------------------------------------------------------------------------
# Property 40: No previous scan treats all assets as new
# **Validates: Requirements 21.4**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(current=_unique_ip_asset_list(min_size=0, max_size=10))
def test_no_previous_scan_all_assets_new(
    current: list[AssessedAsset],
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 40: No previous scan treats all assets as new
    """For any scan result when no previous scan exists, the Watch_Mode SHALL
    produce a diff where new_assets contains all current assets and
    removed_assets is empty."""
    diff = compute_diff([], current)

    assert len(diff.new_assets) == len(current), (
        f"Expected {len(current)} new assets, got {len(diff.new_assets)}"
    )
    actual_new_ips = {a.ip for a in diff.new_assets}
    expected_ips = {a.ip for a in current}
    assert actual_new_ips == expected_ips, (
        f"New asset IPs mismatch: expected {expected_ips}, got {actual_new_ips}"
    )
    assert len(diff.removed_assets) == 0, (
        f"Expected 0 removed assets, got {len(diff.removed_assets)}"
    )
    assert len(diff.changed_assets) == 0, (
        f"Expected 0 changed assets, got {len(diff.changed_assets)}"
    )
    assert len(diff.risk_increase_assets) == 0, (
        f"Expected 0 risk_increase assets, got {len(diff.risk_increase_assets)}"
    )


# Feature: v2-engine-correlation-monitoring, Property 35: Notification event filtering
# Feature: v2-engine-correlation-monitoring, Property 36: Notification payload completeness
# Feature: v2-engine-correlation-monitoring, Property 37: Notification payload JSON round-trip

import json
from surfaceaudit.notifications.providers import BaseNotificationProvider
from surfaceaudit.notifications.dispatcher import (
    EVENT_NEW_ASSETS,
    EVENT_REMOVED_ASSETS,
    EVENT_RISK_INCREASE,
    NotificationDispatcher,
)
from surfaceaudit.models import ScanDiff


# ---------------------------------------------------------------------------
# Recording provider for property tests
# ---------------------------------------------------------------------------


class _RecordingProvider(BaseNotificationProvider):
    """Test double that records sent payloads."""

    def __init__(self, provider_name: str = "test") -> None:
        self._name = provider_name
        self.sent: list[dict] = []

    def name(self) -> str:
        return self._name

    def send(self, payload: dict) -> None:
        self.sent.append(payload)


# ---------------------------------------------------------------------------
# Strategies for notification tests
# ---------------------------------------------------------------------------

_event_type_strategy = st.sampled_from([EVENT_NEW_ASSETS, EVENT_REMOVED_ASSETS, EVENT_RISK_INCREASE])

_on_list_strategy = st.lists(
    _event_type_strategy, min_size=1, max_size=3, unique=True
)


@st.composite
def _scan_diff_with_events(draw: st.DrawFn) -> ScanDiff:
    """Generate a ScanDiff that may have assets in any category."""
    new = draw(_unique_ip_asset_list(min_size=0, max_size=4))
    removed = draw(_unique_ip_asset_list(min_size=0, max_size=4))
    # For risk_increase, generate pairs
    risk_ips = draw(
        st.lists(_ip_strategy, min_size=0, max_size=3, unique=True)
    )
    risk_pairs = []
    for ip in risk_ips:
        old = draw(_assessed_asset(ip=ip))
        new_a = draw(_assessed_asset(ip=ip))
        risk_pairs.append((old, new_a))
    return ScanDiff(
        new_assets=new,
        removed_assets=removed,
        changed_assets=[],
        risk_increase_assets=risk_pairs,
    )


# ---------------------------------------------------------------------------
# Property 35: Notification event filtering
# **Validates: Requirements 26.2**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    on_list=_on_list_strategy,
    event=_event_type_strategy,
)
def test_notification_event_filtering(on_list: list[str], event: str) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 35: Notification event filtering
    """For any provider with a non-empty on list and any event type, the
    dispatcher SHALL send iff the event type is in the provider's on list."""
    provider = _RecordingProvider()
    dispatcher = NotificationDispatcher([(provider, on_list)])

    # Build a diff that contains exactly the given event type
    asset = AssessedAsset(
        ip="10.0.0.1",
        hostname="test.example.com",
        asset_type=AssetType.WEB_SERVER,
        os="Linux",
        services=[Service(port=80, protocol="tcp", name="http")],
        geolocation=None,
        ports=[80],
        vulnerabilities=[],
        risk_level=RiskLevel.HIGH,
    )

    if event == EVENT_NEW_ASSETS:
        diff = ScanDiff(new_assets=[asset], removed_assets=[], changed_assets=[], risk_increase_assets=[])
    elif event == EVENT_REMOVED_ASSETS:
        diff = ScanDiff(new_assets=[], removed_assets=[asset], changed_assets=[], risk_increase_assets=[])
    else:  # EVENT_RISK_INCREASE
        diff = ScanDiff(new_assets=[], removed_assets=[], changed_assets=[], risk_increase_assets=[(asset, asset)])

    dispatcher.dispatch(diff, "/cfg.yaml", "/diff.json")

    if event in on_list:
        assert len(provider.sent) == 1, (
            f"Expected 1 notification for event={event} with on={on_list}, got {len(provider.sent)}"
        )
    else:
        assert len(provider.sent) == 0, (
            f"Expected 0 notifications for event={event} with on={on_list}, got {len(provider.sent)}"
        )


# ---------------------------------------------------------------------------
# Property 36: Notification payload completeness
# **Validates: Requirements 28.1**
# ---------------------------------------------------------------------------

_REQUIRED_PAYLOAD_FIELDS = {"tool", "timestamp", "event", "summary", "details", "scan_config", "diff_report_path"}


@settings(max_examples=100)
@given(diff=_scan_diff_with_events())
def test_notification_payload_completeness(diff: ScanDiff) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 36: Notification payload completeness
    """For any valid ScanDiff and configuration, the notification payload
    SHALL contain all required fields."""
    provider = _RecordingProvider()
    dispatcher = NotificationDispatcher([(provider, [])])  # empty on → all events
    dispatcher.dispatch(diff, "/config.yaml", "/diff_report.json")

    for payload in provider.sent:
        missing = _REQUIRED_PAYLOAD_FIELDS - set(payload.keys())
        assert not missing, f"Payload missing fields: {missing}"
        assert payload["tool"] == "SurfaceAudit"
        assert isinstance(payload["details"], list)
        for detail in payload["details"]:
            assert "ip" in detail
            assert "hostname" in detail
            assert "ports" in detail
            assert "risk" in detail


# ---------------------------------------------------------------------------
# Property 37: Notification payload JSON round-trip
# **Validates: Requirements 28.3**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(diff=_scan_diff_with_events())
def test_notification_payload_json_round_trip(diff: ScanDiff) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 37: Notification payload JSON round-trip
    """For any valid ScanDiff, serializing the notification payload to JSON
    and deserializing back SHALL produce an equivalent payload."""
    provider = _RecordingProvider()
    dispatcher = NotificationDispatcher([(provider, [])])
    dispatcher.dispatch(diff, "/config.yaml", "/diff_report.json")

    for payload in provider.sent:
        serialized = json.dumps(payload)
        deserialized = json.loads(serialized)
        assert deserialized == payload, (
            f"Round-trip mismatch:\nOriginal: {payload}\nDeserialized: {deserialized}"
        )
