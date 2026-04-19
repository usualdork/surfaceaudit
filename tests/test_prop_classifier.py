# Feature: shodan-infrastructure-scanner, Property 4: Classifier assigns valid type and extracts available metadata
"""Property-based tests for the asset classifier.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4**
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from surfaceaudit.classifier import AssetClassifier
from surfaceaudit.models import AssetType, GeoLocation, RawAsset, Service


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_ip_octet = st.integers(min_value=1, max_value=254)

_ip_strategy = st.tuples(_ip_octet, _ip_octet, _ip_octet, _ip_octet).map(
    lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"
)

_hostname_strategy = st.one_of(
    st.none(),
    st.from_regex(r"[a-z]{3,10}\.[a-z]{2,5}", fullmatch=True),
)

_port_strategy = st.integers(min_value=1, max_value=65535)

_os_strategy = st.one_of(
    st.none(),
    st.sampled_from(["Linux", "Windows", "FreeBSD", "Ubuntu 22.04", "CentOS 7"]),
)

_product_strategy = st.one_of(
    st.none(),
    st.sampled_from(["nginx", "Apache", "OpenSSH", "MySQL", "Redis"]),
)

_version_strategy = st.one_of(
    st.none(),
    st.from_regex(r"[0-9]{1,2}\.[0-9]{1,2}(\.[0-9]{1,2})?", fullmatch=True),
)

_transport_strategy = st.one_of(
    st.none(),
    st.sampled_from(["tcp", "udp"]),
)

_location_strategy = st.one_of(
    st.none(),
    st.fixed_dictionaries({}, optional={
        "country_name": st.one_of(st.none(), st.sampled_from(["US", "Germany", "Japan"])),
        "city": st.one_of(st.none(), st.sampled_from(["NYC", "Berlin", "Tokyo"])),
        "latitude": st.one_of(st.none(), st.floats(min_value=-90, max_value=90, allow_nan=False)),
        "longitude": st.one_of(st.none(), st.floats(min_value=-180, max_value=180, allow_nan=False)),
    }),
)


@st.composite
def match_dict(draw: st.DrawFn) -> dict:
    """Generate a Shodan-like match dict with optional fields."""
    match: dict = {}

    # Port is optional — entries without port are skipped for services
    if draw(st.booleans()):
        match["port"] = draw(_port_strategy)

    os_val = draw(_os_strategy)
    if os_val is not None:
        match["os"] = os_val

    product = draw(_product_strategy)
    if product is not None:
        match["product"] = product

    version = draw(_version_strategy)
    if version is not None:
        match["version"] = version

    transport = draw(_transport_strategy)
    if transport is not None:
        match["transport"] = transport

    location = draw(_location_strategy)
    if location is not None:
        match["location"] = location

    # Optional banner data
    if draw(st.booleans()):
        match["data"] = draw(st.text(min_size=0, max_size=50))

    return match


@st.composite
def raw_asset_strategy(draw: st.DrawFn) -> RawAsset:
    """Generate a random RawAsset with varying ports and match dicts."""
    ip = draw(_ip_strategy)
    hostname = draw(_hostname_strategy)
    ports = draw(st.lists(_port_strategy, min_size=0, max_size=10))
    data = draw(st.lists(match_dict(), min_size=0, max_size=5))
    return RawAsset(ip=ip, hostname=hostname, ports=ports, data=data)


# ---------------------------------------------------------------------------
# Property 4: Classifier assigns valid type and extracts available metadata
# **Validates: Requirements 3.1, 3.2, 3.3, 3.4**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(raw=raw_asset_strategy())
def test_classifier_output(raw: RawAsset) -> None:
    # Feature: shodan-infrastructure-scanner, Property 4: Classifier assigns valid type and extracts available metadata
    """For any RawAsset the classifier must produce a ClassifiedAsset with:
    (a) exactly one valid AssetType,
    (b) OS extracted when present in data (None otherwise),
    (c) services list has one entry per match dict that has a port,
    (d) geolocation extracted when location data is present (None otherwise).
    """
    classifier = AssetClassifier()
    result = classifier.classify(raw)

    # (a) asset_type is a valid AssetType enum member
    assert isinstance(result.asset_type, AssetType)
    assert result.asset_type in AssetType

    # (b) OS extraction: present when any match dict has a truthy 'os', None otherwise
    os_values = [m.get("os") for m in raw.data if m.get("os")]
    if os_values:
        assert result.os is not None
        assert result.os == os_values[0]  # first truthy os
    else:
        assert result.os is None

    # (c) Services: one entry per match dict that has a 'port' key
    matches_with_port = [m for m in raw.data if m.get("port") is not None]
    assert len(result.services) == len(matches_with_port)

    for svc, match in zip(result.services, matches_with_port):
        assert isinstance(svc, Service)
        assert svc.port == int(match["port"])
        assert svc.protocol == match.get("transport", "tcp")
        assert svc.name == match.get("product")
        assert svc.version == match.get("version")

    # (d) Geolocation: extracted when first match dict has location data, None otherwise
    if raw.data:
        first_loc = raw.data[0].get("location")
        if (
            first_loc
            and isinstance(first_loc, dict)
            and any(
                first_loc.get(k) is not None
                for k in ("country_name", "city", "latitude", "longitude")
            )
        ):
            assert result.geolocation is not None
            assert isinstance(result.geolocation, GeoLocation)
            assert result.geolocation.country == first_loc.get("country_name")
            assert result.geolocation.city == first_loc.get("city")
            assert result.geolocation.latitude == first_loc.get("latitude")
            assert result.geolocation.longitude == first_loc.get("longitude")
        else:
            assert result.geolocation is None
    else:
        assert result.geolocation is None
