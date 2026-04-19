# Feature: shodan-infrastructure-scanner, Property 5: Vulnerability detection completeness
# Feature: shodan-infrastructure-scanner, Property 6: Risk level validity and monotonicity
"""Property-based tests for the VulnerabilityAssessor.

**Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5**
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from surfaceaudit.assessor import VulnerabilityAssessor
from surfaceaudit.models import (
    AssetType,
    ClassifiedAsset,
    GeoLocation,
    RiskLevel,
    Service,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_ip_octet = st.integers(min_value=1, max_value=254)

_ip_strategy = st.tuples(_ip_octet, _ip_octet, _ip_octet, _ip_octet).map(
    lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"
)

_asset_type_strategy = st.sampled_from(list(AssetType))

_safe_port_strategy = st.sampled_from([80, 443, 8080, 8443, 53, 25, 110, 143, 993])

_risky_port_strategy = st.sampled_from([21, 23, 445, 3389, 5900])

_admin_port_strategy = st.sampled_from([9200, 5601])

_admin_keyword_strategy = st.sampled_from(["admin", "phpmyadmin", "webmin"])

_port_strategy = st.integers(min_value=1, max_value=65535)

_protocol_strategy = st.sampled_from(["tcp", "udp"])


@st.composite
def _service_strategy(draw: st.DrawFn) -> Service:
    """Generate a random Service with optional name/version/banner."""
    port = draw(_port_strategy)
    protocol = draw(_protocol_strategy)
    name = draw(st.one_of(st.none(), st.sampled_from(["http", "ssh", "ftp", "smtp"])))
    version = draw(st.one_of(
        st.none(),
        st.from_regex(r"[0-9]{1,2}\.[0-9]{1,2}(\.[0-9]{1,2})?", fullmatch=True),
    ))
    banner = draw(st.one_of(st.none(), st.text(min_size=0, max_size=30)))
    return Service(port=port, protocol=protocol, name=name, version=version, banner=banner)


def _make_classified_asset(
    ip: str = "1.2.3.4",
    ports: list[int] | None = None,
    services: list[Service] | None = None,
) -> ClassifiedAsset:
    return ClassifiedAsset(
        ip=ip,
        hostname="test.example.com",
        asset_type=AssetType.WEB_SERVER,
        os="Linux",
        services=services or [],
        geolocation=GeoLocation(country="US"),
        ports=ports or [],
        raw_data={},
    )


@st.composite
def classified_asset_strategy(draw: st.DrawFn) -> ClassifiedAsset:
    """Generate a random ClassifiedAsset with varying ports and services."""
    ip = draw(_ip_strategy)
    asset_type = draw(_asset_type_strategy)
    ports = draw(st.lists(_port_strategy, min_size=0, max_size=8))
    services = draw(st.lists(_service_strategy(), min_size=0, max_size=5))
    hostname = draw(st.one_of(st.none(), st.just("host.example.com")))
    os_val = draw(st.one_of(st.none(), st.sampled_from(["Linux", "Windows"])))
    geo = draw(st.one_of(
        st.none(),
        st.just(GeoLocation(country="US", city="NYC")),
    ))
    return ClassifiedAsset(
        ip=ip,
        hostname=hostname,
        asset_type=asset_type,
        os=os_val,
        services=services,
        geolocation=geo,
        ports=ports,
        raw_data={},
    )


# ---------------------------------------------------------------------------
# Property 5: Vulnerability detection completeness
# **Validates: Requirements 4.1, 4.2, 4.3, 4.4**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(risky_port=_risky_port_strategy)
def test_risky_port_detected(risky_port: int) -> None:
    # Feature: shodan-infrastructure-scanner, Property 5: Vulnerability detection completeness
    """For any ClassifiedAsset containing a risky port configuration,
    the assessor should produce at least one VulnerabilityIndicator with
    category 'risky_port'.
    """
    asset = _make_classified_asset(ports=[risky_port])

    assessor = VulnerabilityAssessor()
    result = assessor.assess(asset)

    risky_port_indicators = [
        v for v in result.vulnerabilities if v.category == "risky_port"
    ]
    assert len(risky_port_indicators) >= 1, (
        f"Expected at least one 'risky_port' indicator for port {risky_port}, "
        f"got {len(risky_port_indicators)}"
    )


@settings(max_examples=100)
@given(admin_port=_admin_port_strategy)
def test_admin_interface_detected_by_port(admin_port: int) -> None:
    # Feature: shodan-infrastructure-scanner, Property 5: Vulnerability detection completeness
    """For any ClassifiedAsset with an exposed admin interface port (9200, 5601),
    the assessor should produce at least one VulnerabilityIndicator with
    category 'admin_interface'.
    """
    asset = _make_classified_asset(ports=[admin_port])

    assessor = VulnerabilityAssessor()
    result = assessor.assess(asset)

    admin_indicators = [
        v for v in result.vulnerabilities if v.category == "admin_interface"
    ]
    assert len(admin_indicators) >= 1, (
        f"Expected at least one 'admin_interface' indicator for port {admin_port}, "
        f"got {len(admin_indicators)}"
    )


@settings(max_examples=100)
@given(keyword=_admin_keyword_strategy, use_banner=st.booleans())
def test_admin_interface_detected_by_keyword(keyword: str, use_banner: bool) -> None:
    # Feature: shodan-infrastructure-scanner, Property 5: Vulnerability detection completeness
    """For any ClassifiedAsset with a service whose name or banner contains
    an admin keyword ('admin', 'phpmyadmin', 'webmin'), the assessor should
    produce at least one VulnerabilityIndicator with category 'admin_interface'.
    """
    # Use a non-admin, non-risky port to isolate keyword detection
    port = 12345
    if use_banner:
        service = Service(
            port=port, protocol="tcp", name="http",
            banner=f"Welcome to {keyword} panel",
        )
    else:
        service = Service(
            port=port, protocol="tcp", name=keyword, version="1.0",
        )
    asset = _make_classified_asset(ports=[port], services=[service])

    assessor = VulnerabilityAssessor()
    result = assessor.assess(asset)

    admin_indicators = [
        v for v in result.vulnerabilities if v.category == "admin_interface"
    ]
    assert len(admin_indicators) >= 1, (
        f"Expected at least one 'admin_interface' indicator for keyword "
        f"'{keyword}' (banner={use_banner}), got {len(admin_indicators)}"
    )


# ---------------------------------------------------------------------------
# Property 6: Risk level validity and monotonicity
# **Validates: Requirements 4.5**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(asset=classified_asset_strategy())
def test_risk_level_validity(asset: ClassifiedAsset) -> None:
    # Feature: shodan-infrastructure-scanner, Property 6: Risk level validity and monotonicity
    """For any AssessedAsset, the assigned risk level must be a valid RiskLevel
    (HIGH, MEDIUM, or LOW).
    """
    assessor = VulnerabilityAssessor()
    result = assessor.assess(asset)

    assert isinstance(result.risk_level, RiskLevel)
    assert result.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW)


@settings(max_examples=100)
@given(asset=classified_asset_strategy())
def test_high_severity_implies_high_risk(asset: ClassifiedAsset) -> None:
    # Feature: shodan-infrastructure-scanner, Property 6: Risk level validity and monotonicity
    """If any vulnerability indicator has severity HIGH, the overall risk_level
    must be HIGH.
    """
    assessor = VulnerabilityAssessor()
    result = assessor.assess(asset)

    has_high = any(v.severity == RiskLevel.HIGH for v in result.vulnerabilities)
    if has_high:
        assert result.risk_level == RiskLevel.HIGH, (
            f"Asset has HIGH-severity indicator but risk_level is {result.risk_level}"
        )


@settings(max_examples=100)
@given(asset=classified_asset_strategy())
def test_no_indicators_implies_low_risk(asset: ClassifiedAsset) -> None:
    # Feature: shodan-infrastructure-scanner, Property 6: Risk level validity and monotonicity
    """If an asset has no vulnerability indicators, the risk_level must be LOW."""
    assessor = VulnerabilityAssessor()
    result = assessor.assess(asset)

    if len(result.vulnerabilities) == 0:
        assert result.risk_level == RiskLevel.LOW, (
            f"Asset has no indicators but risk_level is {result.risk_level}"
        )
