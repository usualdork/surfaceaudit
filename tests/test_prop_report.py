# Feature: shodan-infrastructure-scanner, Property 7: Report completeness and summary consistency
# Feature: shodan-infrastructure-scanner, Property 8: JSON report round-trip
# Feature: shodan-infrastructure-scanner, Property 19: Report redaction
# Feature: shodan-infrastructure-scanner, Property 20: Report encryption round-trip
"""Property-based tests for report generation, formatting, redaction, and encryption.

**Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 10.3, 10.5**
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

from surfaceaudit.config import ScanConfig
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
from surfaceaudit.report import ReportEncryptor, ReportFormatter, ReportGenerator

# ---------------------------------------------------------------------------
# RFC 1918 pattern (mirrors the one in report.py)
# ---------------------------------------------------------------------------
_RFC1918_PATTERN = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"|(172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})"
    r"|(192\.168\.\d{1,3}\.\d{1,3})\b"
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_asset_type_strategy = st.sampled_from(list(AssetType))
_risk_level_strategy = st.sampled_from(list(RiskLevel))
_port_strategy = st.integers(min_value=1, max_value=65535)
_protocol_strategy = st.sampled_from(["tcp", "udp"])

# Public IPs only (avoid RFC 1918 ranges)
_public_ip_octet = st.integers(min_value=1, max_value=254)
_public_ip_strategy = st.tuples(
    st.integers(min_value=11, max_value=99),
    _public_ip_octet,
    _public_ip_octet,
    _public_ip_octet,
).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}")

# RFC 1918 private IPs
_rfc1918_ip_strategy = st.one_of(
    # 10.x.x.x
    st.tuples(
        st.just(10),
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(1, 254),
    ).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"),
    # 172.16-31.x.x
    st.tuples(
        st.just(172),
        st.integers(16, 31),
        st.integers(0, 255),
        st.integers(1, 254),
    ).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"),
    # 192.168.x.x
    st.tuples(
        st.just(192),
        st.just(168),
        st.integers(0, 255),
        st.integers(1, 254),
    ).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"),
)


@st.composite
def _service_strategy(draw: st.DrawFn) -> Service:
    port = draw(_port_strategy)
    protocol = draw(_protocol_strategy)
    name = draw(st.one_of(st.none(), st.sampled_from(["http", "ssh", "ftp", "smtp"])))
    version = draw(st.one_of(st.none(), st.just("1.0")))
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
def assessed_asset_strategy(draw: st.DrawFn, ip_strat=None) -> AssessedAsset:
    """Generate a random AssessedAsset."""
    ip = draw(ip_strat or _public_ip_strategy)
    hostname = draw(st.one_of(st.none(), st.just("host.example.com")))
    asset_type = draw(_asset_type_strategy)
    os_val = draw(st.one_of(st.none(), st.sampled_from(["Linux", "Windows"])))
    services = draw(st.lists(_service_strategy(), min_size=0, max_size=3))
    geo = draw(st.one_of(st.none(), st.just(GeoLocation(country="US"))))
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
def scan_metadata_strategy(draw: st.DrawFn) -> ScanMetadata:
    ts = draw(st.datetimes(
        min_value=datetime(2020, 1, 1),
        max_value=datetime(2030, 1, 1),
        timezones=st.just(timezone.utc),
    ))
    queries = draw(st.lists(st.sampled_from(["example.com", "test.org", "192.0.2.0/24"]), min_size=1, max_size=3))
    credits = draw(st.integers(min_value=0, max_value=1000))
    duration = draw(st.floats(min_value=0.0, max_value=3600.0, allow_nan=False, allow_infinity=False))
    return ScanMetadata(
        timestamp=ts,
        query_parameters=queries,
        api_credits_used=credits,
        scan_duration_seconds=duration,
    )


def _make_config(**overrides) -> ScanConfig:
    defaults = {"api_key": "test-key", "targets": ["example.com"]}
    defaults.update(overrides)
    return ScanConfig(**defaults)


# ---------------------------------------------------------------------------
# Property 7: Report completeness and summary consistency
# **Validates: Requirements 5.1, 5.2, 5.3, 5.5**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    assets=st.lists(assessed_asset_strategy(), min_size=0, max_size=10),
    metadata=scan_metadata_strategy(),
)
def test_report_completeness_and_summary_consistency(
    assets: list[AssessedAsset],
    metadata: ScanMetadata,
) -> None:
    # Feature: shodan-infrastructure-scanner, Property 7: Report completeness and summary consistency
    """For any list of AssessedAssets and valid ScanMetadata, the generated
    ScanReport should: (a) contain all input assets, (b) have
    summary.total_assets == len(assets), (c) sum of assets_by_type values ==
    total_assets, (d) sum of assets_by_risk values == total_assets, and
    (e) include metadata with timestamp, query parameters, and credits used.
    """
    gen = ReportGenerator()
    config = _make_config()
    report = gen.generate(assets, metadata, config)

    # (a) All input assets present
    assert len(report.assets) == len(assets)

    # (b) total_assets matches
    assert report.summary.total_assets == len(assets)

    # (c) sum of assets_by_type == total_assets
    assert sum(report.summary.assets_by_type.values()) == report.summary.total_assets

    # (d) sum of assets_by_risk == total_assets
    assert sum(report.summary.assets_by_risk.values()) == report.summary.total_assets

    # (e) metadata preserved
    assert report.metadata.timestamp == metadata.timestamp
    assert report.metadata.query_parameters == metadata.query_parameters
    assert report.metadata.api_credits_used == metadata.api_credits_used


# ---------------------------------------------------------------------------
# Property 8: JSON report round-trip
# **Validates: Requirements 5.4**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    assets=st.lists(assessed_asset_strategy(), min_size=0, max_size=5),
    metadata=scan_metadata_strategy(),
)
def test_json_report_roundtrip(
    assets: list[AssessedAsset],
    metadata: ScanMetadata,
) -> None:
    # Feature: shodan-infrastructure-scanner, Property 8: JSON report round-trip
    """For any valid ScanReport, serializing to JSON and deserializing back
    should produce an equivalent ScanReport (at the dict level).
    """
    from surfaceaudit.models import to_serializable_dict

    gen = ReportGenerator()
    config = _make_config()
    report = gen.generate(assets, metadata, config)

    formatter = ReportFormatter()
    json_str = formatter.to_json(report)

    # Deserialize back
    parsed = json.loads(json_str)

    # Compare at the dict level
    original_dict = to_serializable_dict(report)
    assert parsed == original_dict


# ---------------------------------------------------------------------------
# Property 19: Report redaction
# **Validates: Requirements 10.3**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    private_ips=st.lists(_rfc1918_ip_strategy, min_size=1, max_size=5, unique=True),
    metadata=scan_metadata_strategy(),
)
def test_report_redaction_no_internal_ips(
    private_ips: list[str],
    metadata: ScanMetadata,
) -> None:
    # Feature: shodan-infrastructure-scanner, Property 19: Report redaction
    """For any ScanReport with redaction enabled, the output should not
    contain any internal IP addresses (RFC 1918 ranges) or original
    hostnames that were marked for redaction.
    """
    # Build assets with RFC 1918 IPs and hostnames
    assets = []
    hostnames = []
    for ip in private_ips:
        hostname = f"internal-{ip.replace('.', '-')}.local"
        hostnames.append(hostname)
        assets.append(
            AssessedAsset(
                ip=ip,
                hostname=hostname,
                asset_type=AssetType.WEB_SERVER,
                os=None,
                services=[],
                geolocation=None,
                ports=[80],
                vulnerabilities=[],
                risk_level=RiskLevel.LOW,
            )
        )

    gen = ReportGenerator()
    config = _make_config(redact_sensitive=True)
    report = gen.generate(assets, metadata, config)

    # Serialize to JSON to check the full output
    formatter = ReportFormatter()
    json_output = formatter.to_json(report)

    # No RFC 1918 IP should appear in the output
    for ip in private_ips:
        assert ip not in json_output, f"Internal IP {ip} found in redacted output"

    # No original hostname should appear in the output
    for hostname in hostnames:
        assert hostname not in json_output, (
            f"Original hostname {hostname} found in redacted output"
        )


# ---------------------------------------------------------------------------
# Property 20: Report encryption round-trip
# **Validates: Requirements 10.5**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    content=st.binary(min_size=0, max_size=1024),
    password=st.text(
        alphabet=st.characters(whitelist_categories=("L", "N", "P")),
        min_size=1,
        max_size=50,
    ),
)
def test_encryption_roundtrip(content: bytes, password: str) -> None:
    # Feature: shodan-infrastructure-scanner, Property 20: Report encryption round-trip
    """For any report content and encryption password, encrypting then
    decrypting should produce the original content.
    """
    encryptor = ReportEncryptor()
    encrypted = encryptor.encrypt(content, password)
    decrypted = encryptor.decrypt(encrypted, password)
    assert decrypted == content
