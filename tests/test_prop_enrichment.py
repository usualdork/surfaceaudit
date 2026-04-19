# Feature: v2-engine-correlation-monitoring, Property 27: Enrichment cache round-trip with TTL
# Feature: v2-engine-correlation-monitoring, Property 28: Enrichment provider independence
# Feature: v2-engine-correlation-monitoring, Property 29: Correlation risk score computation
"""Property-based tests for enrichment infrastructure: cache, provider
independence, and correlation risk score computation.

**Validates: Requirements 16.1, 16.2, 16.3, 17.1, 17.3, 18.1–18.7**
"""

from __future__ import annotations

import json
import math
import os
import tempfile
import time
from unittest.mock import patch

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from surfaceaudit.config import EnrichmentProviderConfig as PydanticEnrichmentProviderConfig
from surfaceaudit.enrichment.cache import EnrichmentCache
from surfaceaudit.enrichment.base import BaseEnrichmentProvider
from surfaceaudit.enrichment.manager import (
    EnrichmentConfig,
    EnrichmentManager,
    EnrichmentProviderConfig,
)
from surfaceaudit.enrichment.score import CorrelationScoreCalculator
from surfaceaudit.models import (
    AssessedAsset,
    AssetType,
    EnrichedAsset,
    GeoLocation,
    RiskLevel,
    Service,
    VulnerabilityIndicator,
    to_serializable_dict,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Provider names: simple alphanumeric identifiers
_provider_name = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=20,
)

# Cache keys: simple alphanumeric (like IP addresses or domain names)
_cache_key = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "Pd")),
    min_size=1,
    max_size=30,
)

# JSON-serializable data dicts for cache storage
_json_value = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-10000, max_value=10000),
        st.floats(allow_nan=False, allow_infinity=False, min_value=-1e6, max_value=1e6),
        st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "Zs")),
            min_size=0,
            max_size=20,
        ),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(
            st.text(
                alphabet=st.characters(whitelist_categories=("L", "N")),
                min_size=1,
                max_size=10,
            ),
            children,
            max_size=5,
        ),
    ),
    max_leaves=15,
)

_data_dict = st.dictionaries(
    st.text(
        alphabet=st.characters(whitelist_categories=("L", "N")),
        min_size=1,
        max_size=10,
    ),
    _json_value,
    min_size=1,
    max_size=5,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_asset(ip: str = "1.2.3.4", hostname: str | None = "example.com") -> AssessedAsset:
    return AssessedAsset(
        ip=ip,
        hostname=hostname,
        asset_type=AssetType.WEB_SERVER,
        os=None,
        services=[Service(port=80, protocol="tcp", name="http")],
        geolocation=None,
        ports=[80],
        vulnerabilities=[],
        risk_level=RiskLevel.LOW,
    )


class StubProvider(BaseEnrichmentProvider):
    """A controllable stub provider for property tests."""

    def __init__(
        self,
        prov_name: str,
        needs_key: bool = False,
        ip_data: dict | None = None,
        raise_on_call: bool = False,
    ) -> None:
        self._name = prov_name
        self._needs_key = needs_key
        self._ip_data = ip_data or {}
        self._raise_on_call = raise_on_call
        self.called = False

    def name(self) -> str:
        return self._name

    def requires_api_key(self) -> bool:
        return self._needs_key

    def enrich_ip(self, ip: str) -> dict:
        if self._raise_on_call:
            raise RuntimeError("provider error")
        self.called = True
        return dict(self._ip_data)

    def enrich_domain(self, domain: str) -> dict:
        return {}


# ---------------------------------------------------------------------------
# Property 27: Enrichment cache round-trip with TTL
# **Validates: Requirements 16.1, 16.2, 16.3**
# ---------------------------------------------------------------------------


@settings(max_examples=100)
@given(
    provider=_provider_name,
    key=_cache_key,
    data=_data_dict,
)
def test_enrichment_cache_round_trip_with_ttl(
    provider: str, key: str, data: dict,
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 27: Enrichment cache round-trip with TTL
    """For any provider name, cache key, and data dict, storing the data in
    the cache and then retrieving it within the TTL SHALL return the original
    data. Retrieving it after the TTL has expired SHALL return None."""
    cache_dir = tempfile.mkdtemp()
    cache = EnrichmentCache(cache_dir, ttl_hours=1)

    # Store data
    cache.set(provider, key, data)

    # Retrieve within TTL — should return original data
    result = cache.get(provider, key)
    assert result == data, (
        f"Cache round-trip failed: stored {data!r}, got {result!r}"
    )

    # Simulate TTL expiry by patching time.time to return a future timestamp
    future_time = time.time() + 3601  # 1 hour + 1 second past TTL
    with patch("surfaceaudit.enrichment.cache.time.time", return_value=future_time):
        expired_result = cache.get(provider, key)

    assert expired_result is None, (
        f"Cache should return None after TTL expiry, got {expired_result!r}"
    )


# ---------------------------------------------------------------------------
# Property 28: Enrichment provider independence
# **Validates: Requirements 17.1, 17.3**
# ---------------------------------------------------------------------------

# Strategy for provider configurations: each provider can be disabled,
# missing an API key, or set to raise errors.
_provider_state = st.sampled_from(["enabled", "disabled", "missing_key", "error"])


@st.composite
def _provider_set(draw: st.DrawFn) -> tuple[
    list[tuple[str, str, dict | None]],  # (name, state, ip_data)
    list[str],  # names of providers expected to execute
]:
    """Generate a set of 2-5 providers with random states.

    Returns (provider_specs, expected_executed_names).
    """
    n = draw(st.integers(min_value=2, max_value=5))
    specs: list[tuple[str, str, dict | None]] = []
    expected_executed: list[str] = []

    for i in range(n):
        name = f"prov{i}"
        state = draw(_provider_state)
        ip_data = {f"key{i}": i}
        specs.append((name, state, ip_data))

        if state == "enabled":
            expected_executed.append(name)

    return specs, expected_executed


@settings(max_examples=100)
@given(data=_provider_set())
def test_enrichment_provider_independence(
    data: tuple,
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 28: Enrichment provider independence
    """For any set of enrichment providers where some are disabled, missing
    API keys, or encounter errors, all remaining enabled providers SHALL
    still execute for each asset."""
    specs, expected_executed = data

    cache_dir = tempfile.mkdtemp()
    cache = EnrichmentCache(cache_dir)
    providers_config: dict[str, EnrichmentProviderConfig] = {}
    stub_providers: list[StubProvider] = []

    for name, state, ip_data in specs:
        if state == "enabled":
            providers_config[name] = EnrichmentProviderConfig(
                enabled=True, api_key="test-key"
            )
            stub_providers.append(
                StubProvider(prov_name=name, needs_key=True, ip_data=ip_data)
            )
        elif state == "disabled":
            providers_config[name] = EnrichmentProviderConfig(
                enabled=False, api_key="test-key"
            )
            stub_providers.append(
                StubProvider(prov_name=name, needs_key=True, ip_data=ip_data)
            )
        elif state == "missing_key":
            providers_config[name] = EnrichmentProviderConfig(
                enabled=True, api_key=None
            )
            stub_providers.append(
                StubProvider(prov_name=name, needs_key=True, ip_data=ip_data)
            )
        elif state == "error":
            providers_config[name] = EnrichmentProviderConfig(
                enabled=True, api_key="test-key"
            )
            stub_providers.append(
                StubProvider(
                    prov_name=name, needs_key=True, raise_on_call=True
                )
            )

    config = EnrichmentConfig(enabled=True, providers=providers_config)
    mgr = EnrichmentManager(config, cache)
    for p in stub_providers:
        mgr.register_provider(p)

    asset = _make_asset()
    results = mgr.enrich([asset])

    assert len(results) == 1
    enrichment_data = results[0].enrichment_data

    # All enabled providers (not disabled, not missing key, not erroring)
    # should have their data in the result
    for name in expected_executed:
        assert name in enrichment_data, (
            f"Enabled provider '{name}' should have executed but its data "
            f"is missing from enrichment_data: {list(enrichment_data.keys())}"
        )

    # Disabled, missing-key, and erroring providers should NOT be in results
    for name, state, _ in specs:
        if state in ("disabled", "missing_key", "error"):
            assert name not in enrichment_data, (
                f"Provider '{name}' (state={state}) should NOT be in "
                f"enrichment_data but was found"
            )


# ---------------------------------------------------------------------------
# Property 29: Correlation risk score computation
# **Validates: Requirements 18.1, 18.2, 18.3, 18.4, 18.5, 18.7**
# ---------------------------------------------------------------------------

# Strategy for enrichment data with controlled provider signals
@st.composite
def _enrichment_data(draw: st.DrawFn) -> dict[str, dict]:
    """Generate enrichment data dicts with realistic provider signals."""
    data: dict[str, dict] = {}

    include_vt = draw(st.booleans())
    include_abuseipdb = draw(st.booleans())
    include_greynoise = draw(st.booleans())

    if include_vt:
        malicious_count = draw(st.integers(min_value=0, max_value=100))
        data["virustotal"] = {"malicious_count": malicious_count}

    if include_abuseipdb:
        confidence = draw(st.integers(min_value=0, max_value=100))
        data["abuseipdb"] = {"abuse_confidence_score": confidence}

    if include_greynoise:
        classification = draw(
            st.sampled_from(["malicious", "benign", "unknown"])
        )
        data["greynoise"] = {"classification": classification}

    return data


@settings(max_examples=100)
@given(enrichment_data=_enrichment_data())
def test_correlation_risk_score_computation(
    enrichment_data: dict[str, dict],
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 29: Correlation risk score computation
    """For any enrichment data dict, the correlation risk score SHALL equal:
    min(100, floor(base_sum * multiplier)) where base_sum = (30 if VT
    malicious > 0) + (25 if AbuseIPDB confidence > 50) + (20 if GreyNoise
    classification == "malicious"), and multiplier = 1.5 if >=2 sources flag
    malicious, else 1.0. The score SHALL always be in [0, 100]."""
    calc = CorrelationScoreCalculator()
    score = calc.calculate(enrichment_data)

    # Reference implementation
    base_sum = 0
    malicious_count = 0

    vt = enrichment_data.get("virustotal")
    if vt and vt.get("malicious_count", 0) > 0:
        base_sum += 30
        malicious_count += 1

    abuseipdb = enrichment_data.get("abuseipdb")
    if abuseipdb and abuseipdb.get("abuse_confidence_score", 0) > 50:
        base_sum += 25
        malicious_count += 1

    greynoise = enrichment_data.get("greynoise")
    if greynoise and greynoise.get("classification") == "malicious":
        base_sum += 20
        malicious_count += 1

    multiplier = 1.5 if malicious_count >= 2 else 1.0
    expected = min(100, int(math.floor(base_sum * multiplier)))

    assert score == expected, (
        f"Score mismatch: got {score}, expected {expected} "
        f"(base_sum={base_sum}, multiplier={multiplier}, data={enrichment_data})"
    )

    # Score must always be in [0, 100]
    assert 0 <= score <= 100, f"Score {score} out of range [0, 100]"


# ---------------------------------------------------------------------------
# Strategies for enrichment provider property tests
# ---------------------------------------------------------------------------

# Subdomain-like strings for crt.sh tests
_subdomain = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters=".-"),
    min_size=3,
    max_size=30,
).filter(lambda s: s.strip() and not s.startswith(".") and not s.endswith("."))


@st.composite
def _crtsh_entries_with_duplicates(draw: st.DrawFn) -> list[dict]:
    """Generate a crt.sh JSON response list that may contain duplicate
    subdomain entries.  Each entry has a ``name_value`` field that can
    contain newline-separated names (as the real API does)."""
    unique_names = draw(
        st.lists(_subdomain, min_size=1, max_size=10, unique=True)
    )
    entries: list[dict] = []
    for name in unique_names:
        # Each unique name appears 1-3 times (simulating duplicate certs)
        repeats = draw(st.integers(min_value=1, max_value=3))
        for _ in range(repeats):
            entries.append({"name_value": name})

    # Optionally add multi-name entries (newline-separated)
    if draw(st.booleans()):
        combo = "\n".join(draw(st.lists(
            st.sampled_from(unique_names), min_size=1, max_size=4
        )))
        entries.append({"name_value": combo})

    return entries


# VirusTotal API response strategy
@st.composite
def _virustotal_response(draw: st.DrawFn) -> dict:
    """Generate a realistic VirusTotal API v3 response dict."""
    malicious = draw(st.integers(min_value=0, max_value=100))
    harmless = draw(st.integers(min_value=0, max_value=100))
    suspicious = draw(st.integers(min_value=0, max_value=50))
    undetected = draw(st.integers(min_value=0, max_value=100))
    reputation = draw(st.integers(min_value=-100, max_value=100))

    last_analysis_stats = {
        "malicious": malicious,
        "harmless": harmless,
        "suspicious": suspicious,
        "undetected": undetected,
    }

    return {
        "data": {
            "attributes": {
                "last_analysis_stats": last_analysis_stats,
                "reputation": reputation,
            }
        }
    }


# GreyNoise API response strategy
@st.composite
def _greynoise_response(draw: st.DrawFn) -> dict:
    """Generate a realistic GreyNoise Community API response dict."""
    classification = draw(
        st.sampled_from(["benign", "malicious", "unknown"])
    )
    noise = draw(st.booleans())
    riot = draw(st.booleans())
    return {
        "classification": classification,
        "noise": noise,
        "riot": riot,
    }


# AbuseIPDB API response strategy
@st.composite
def _abuseipdb_response(draw: st.DrawFn) -> dict:
    """Generate a realistic AbuseIPDB API v2 response dict."""
    confidence = draw(st.integers(min_value=0, max_value=100))
    total_reports = draw(st.integers(min_value=0, max_value=10000))
    country_code = draw(st.text(
        alphabet=st.characters(whitelist_categories=("Lu",)),
        min_size=2,
        max_size=2,
    ))
    return {
        "data": {
            "abuseConfidenceScore": confidence,
            "totalReports": total_reports,
            "countryCode": country_code,
        }
    }


# ---------------------------------------------------------------------------
# Property 23: crt.sh subdomain deduplication
# **Validates: Requirements 12.2**
# ---------------------------------------------------------------------------

from surfaceaudit.enrichment.providers.crtsh import CrtshProvider


@settings(max_examples=100)
@given(entries=_crtsh_entries_with_duplicates())
def test_crtsh_subdomain_deduplication(entries: list[dict]) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 23: crt.sh subdomain deduplication
    """For any crt.sh JSON response containing duplicate subdomain entries,
    the provider SHALL return a list with no duplicate subdomains."""
    result = CrtshProvider._parse_subdomains(entries)

    # No duplicates in the result
    assert len(result) == len(set(result)), (
        f"Duplicate subdomains found in result: {result}"
    )

    # Every subdomain in the result should originate from the input entries
    all_input_names: set[str] = set()
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            stripped = name.strip().lower()
            if stripped:
                all_input_names.add(stripped)

    for subdomain in result:
        assert subdomain in all_input_names, (
            f"Subdomain '{subdomain}' in result but not in input entries"
        )

    # All unique input names should appear in the result
    for name in all_input_names:
        assert name in result, (
            f"Input subdomain '{name}' missing from deduplicated result"
        )


# ---------------------------------------------------------------------------
# Property 24: Enrichment provider field extraction (VirusTotal)
# **Validates: Requirements 13.2**
# ---------------------------------------------------------------------------

from surfaceaudit.enrichment.providers.virustotal import VirusTotalProvider


@settings(max_examples=100)
@given(response=_virustotal_response())
def test_virustotal_field_extraction(response: dict) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 24: Enrichment provider field extraction (VirusTotal)
    """For any valid VirusTotal API response dict, the provider SHALL extract
    malicious_count, reputation, and last_analysis_stats fields correctly."""
    result = VirusTotalProvider._extract_fields(response)

    attributes = response["data"]["attributes"]
    expected_stats = attributes["last_analysis_stats"]
    expected_malicious = expected_stats["malicious"]
    expected_reputation = attributes["reputation"]

    assert result["malicious_count"] == expected_malicious, (
        f"malicious_count: expected {expected_malicious}, got {result['malicious_count']}"
    )
    assert result["reputation"] == expected_reputation, (
        f"reputation: expected {expected_reputation}, got {result['reputation']}"
    )
    assert result["last_analysis_stats"] == expected_stats, (
        f"last_analysis_stats: expected {expected_stats}, got {result['last_analysis_stats']}"
    )

    # Result should contain exactly these three keys
    assert set(result.keys()) == {"malicious_count", "reputation", "last_analysis_stats"}


# ---------------------------------------------------------------------------
# Property 25: Enrichment provider field extraction (GreyNoise)
# **Validates: Requirements 14.2**
# ---------------------------------------------------------------------------

from surfaceaudit.enrichment.providers.greynoise import GreyNoiseProvider


@settings(max_examples=100)
@given(response=_greynoise_response())
def test_greynoise_field_extraction(response: dict) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 25: Enrichment provider field extraction (GreyNoise)
    """For any valid GreyNoise API response dict, the provider SHALL extract
    classification, noise, and riot fields correctly."""
    result = GreyNoiseProvider._extract_fields(response)

    assert result["classification"] == response["classification"], (
        f"classification: expected {response['classification']!r}, got {result['classification']!r}"
    )
    assert result["noise"] == response["noise"], (
        f"noise: expected {response['noise']}, got {result['noise']}"
    )
    assert result["riot"] == response["riot"], (
        f"riot: expected {response['riot']}, got {result['riot']}"
    )

    # Result should contain exactly these three keys
    assert set(result.keys()) == {"classification", "noise", "riot"}


# ---------------------------------------------------------------------------
# Property 26: Enrichment provider field extraction (AbuseIPDB)
# **Validates: Requirements 15.2**
# ---------------------------------------------------------------------------

from surfaceaudit.enrichment.providers.abuseipdb import AbuseIPDBProvider


@settings(max_examples=100)
@given(response=_abuseipdb_response())
def test_abuseipdb_field_extraction(response: dict) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 26: Enrichment provider field extraction (AbuseIPDB)
    """For any valid AbuseIPDB API response dict, the provider SHALL extract
    abuse_confidence_score, total_reports, and country_code fields correctly."""
    result = AbuseIPDBProvider._extract_fields(response)

    report_data = response["data"]
    expected_confidence = report_data["abuseConfidenceScore"]
    expected_reports = report_data["totalReports"]
    expected_country = report_data["countryCode"]

    assert result["abuse_confidence_score"] == expected_confidence, (
        f"abuse_confidence_score: expected {expected_confidence}, got {result['abuse_confidence_score']}"
    )
    assert result["total_reports"] == expected_reports, (
        f"total_reports: expected {expected_reports}, got {result['total_reports']}"
    )
    assert result["country_code"] == expected_country, (
        f"country_code: expected {expected_country!r}, got {result['country_code']!r}"
    )

    # Result should contain exactly these three keys
    assert set(result.keys()) == {"abuse_confidence_score", "total_reports", "country_code"}


# ---------------------------------------------------------------------------
# Property 30: EnrichedAsset JSON serialization round-trip
# **Validates: Requirements 19.2**
# ---------------------------------------------------------------------------

# Strategy for generating random EnrichedAsset objects
@st.composite
def _enriched_asset(draw: st.DrawFn) -> EnrichedAsset:
    """Generate a random EnrichedAsset with varied field values."""
    ip_parts = [draw(st.integers(min_value=0, max_value=255)) for _ in range(4)]
    ip = ".".join(str(p) for p in ip_parts)

    hostname = draw(st.one_of(
        st.none(),
        st.text(
            alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters=".-"),
            min_size=3,
            max_size=30,
        ).filter(lambda s: s.strip() and not s.startswith(".") and not s.endswith(".")),
    ))

    asset_type = draw(st.sampled_from(list(AssetType)))
    os_val = draw(st.one_of(st.none(), st.text(min_size=1, max_size=20, alphabet="abcdefghijklmnopqrstuvwxyz ")))

    num_services = draw(st.integers(min_value=0, max_value=3))
    services = []
    for _ in range(num_services):
        svc = Service(
            port=draw(st.integers(min_value=1, max_value=65535)),
            protocol=draw(st.sampled_from(["tcp", "udp"])),
            name=draw(st.one_of(st.none(), st.sampled_from(["http", "ssh", "ftp", "https", "smtp"]))),
            version=draw(st.one_of(st.none(), st.text(min_size=1, max_size=10, alphabet="0123456789."))),
            banner=draw(st.one_of(st.none(), st.text(min_size=0, max_size=50, alphabet="abcdefghijklmnopqrstuvwxyz0123456789 /."))),
        )
        services.append(svc)

    geolocation = draw(st.one_of(
        st.none(),
        st.builds(
            GeoLocation,
            country=st.one_of(st.none(), st.text(min_size=2, max_size=2, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ")),
            city=st.one_of(st.none(), st.text(min_size=1, max_size=20, alphabet="abcdefghijklmnopqrstuvwxyz ")),
            latitude=st.one_of(st.none(), st.floats(min_value=-90, max_value=90, allow_nan=False, allow_infinity=False)),
            longitude=st.one_of(st.none(), st.floats(min_value=-180, max_value=180, allow_nan=False, allow_infinity=False)),
        ),
    ))

    ports = [svc.port for svc in services] if services else draw(st.lists(st.integers(min_value=1, max_value=65535), max_size=5))

    num_vulns = draw(st.integers(min_value=0, max_value=3))
    vulns = []
    for _ in range(num_vulns):
        vuln = VulnerabilityIndicator(
            category=draw(st.sampled_from(["vulnerable_version", "risky_port", "admin_interface"])),
            description=draw(st.text(min_size=1, max_size=50, alphabet="abcdefghijklmnopqrstuvwxyz0123456789 ")),
            severity=draw(st.sampled_from(list(RiskLevel))),
        )
        vulns.append(vuln)

    risk_level = draw(st.sampled_from(list(RiskLevel)))
    correlation_risk_score = draw(st.integers(min_value=0, max_value=100))

    # Enrichment data: dict of provider name → dict of simple values
    enrichment_data = draw(st.dictionaries(
        st.sampled_from(["virustotal", "abuseipdb", "greynoise", "crtsh"]),
        st.dictionaries(
            st.text(min_size=1, max_size=15, alphabet="abcdefghijklmnopqrstuvwxyz_"),
            st.one_of(
                st.integers(min_value=-1000, max_value=1000),
                st.text(min_size=0, max_size=20, alphabet="abcdefghijklmnopqrstuvwxyz"),
                st.booleans(),
            ),
            min_size=0,
            max_size=4,
        ),
        max_size=4,
    ))

    discovered_subdomains = draw(st.lists(
        st.text(
            alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters=".-"),
            min_size=3,
            max_size=30,
        ).filter(lambda s: s.strip() and not s.startswith(".") and not s.endswith(".")),
        max_size=5,
    ))

    return EnrichedAsset(
        ip=ip,
        hostname=hostname,
        asset_type=asset_type,
        os=os_val,
        services=services,
        geolocation=geolocation,
        ports=ports,
        vulnerabilities=vulns,
        risk_level=risk_level,
        correlation_risk_score=correlation_risk_score,
        enrichment_data=enrichment_data,
        discovered_subdomains=discovered_subdomains,
    )


@settings(max_examples=100)
@given(asset=_enriched_asset())
def test_enriched_asset_json_serialization_round_trip(asset: EnrichedAsset) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 30: EnrichedAsset JSON serialization round-trip
    """For any valid EnrichedAsset object, calling to_serializable_dict()
    SHALL produce a JSON-serializable dict, and serializing to JSON then
    deserializing SHALL preserve all field values."""
    serialized = to_serializable_dict(asset)

    # Must be JSON-serializable without errors
    json_str = json.dumps(serialized)

    # Round-trip: deserialize back
    deserialized = json.loads(json_str)

    # The deserialized dict must equal the serialized dict
    assert deserialized == serialized, (
        f"JSON round-trip mismatch:\n"
        f"  serialized:   {serialized}\n"
        f"  deserialized: {deserialized}"
    )

    # Verify key enrichment fields are preserved
    assert deserialized["correlation_risk_score"] == asset.correlation_risk_score
    assert deserialized["enrichment_data"] == asset.enrichment_data
    assert deserialized["discovered_subdomains"] == asset.discovered_subdomains
    assert deserialized["ip"] == asset.ip
    assert deserialized["risk_level"] == asset.risk_level.value
    assert deserialized["asset_type"] == asset.asset_type.value


# ---------------------------------------------------------------------------
# Property 31: Environment variable resolution in API keys
# **Validates: Requirements 20.3**
# ---------------------------------------------------------------------------

# Strategy for env var names: simple uppercase alphanumeric identifiers
_env_var_name = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "N"), whitelist_characters="_"),
    min_size=1,
    max_size=20,
).filter(lambda s: s[0].isalpha())

# Strategy for env var values: printable strings
_env_var_value = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "Zs", "P")),
    min_size=1,
    max_size=50,
)


@settings(max_examples=100)
@given(var_name=_env_var_name, var_value=_env_var_value)
def test_env_var_resolution_in_api_keys(var_name: str, var_value: str) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 31: Environment variable resolution in API keys
    """For any API key string containing ${VAR_NAME} where the environment
    variable VAR_NAME is set, the resolved value SHALL equal the environment
    variable's value."""
    api_key_template = f"${{{var_name}}}"

    with patch.dict(os.environ, {var_name: var_value}):
        config = PydanticEnrichmentProviderConfig(
            enabled=True, api_key=api_key_template
        )

    assert config.api_key == var_value, (
        f"Expected resolved API key to be {var_value!r}, "
        f"got {config.api_key!r} (template was {api_key_template!r})"
    )
