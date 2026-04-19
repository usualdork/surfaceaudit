"""Unit tests for EnrichmentManager."""

from __future__ import annotations

import logging

import pytest

from surfaceaudit.enrichment.base import BaseEnrichmentProvider
from surfaceaudit.enrichment.cache import EnrichmentCache
from surfaceaudit.enrichment.manager import (
    EnrichmentConfig,
    EnrichmentManager,
    EnrichmentProviderConfig,
)
from surfaceaudit.models import (
    AssessedAsset,
    AssetType,
    RiskLevel,
    Service,
    VulnerabilityIndicator,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_asset(
    ip: str = "1.2.3.4",
    hostname: str | None = "example.com",
) -> AssessedAsset:
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


class FakeProvider(BaseEnrichmentProvider):
    """Controllable fake provider for testing."""

    def __init__(
        self,
        prov_name: str = "fake",
        needs_key: bool = False,
        ip_data: dict | None = None,
        domain_data: dict | None = None,
        raise_on_ip: bool = False,
    ) -> None:
        self._name = prov_name
        self._needs_key = needs_key
        self._ip_data = ip_data or {}
        self._domain_data = domain_data or {}
        self._raise_on_ip = raise_on_ip

    def name(self) -> str:
        return self._name

    def requires_api_key(self) -> bool:
        return self._needs_key

    def enrich_ip(self, ip: str) -> dict:
        if self._raise_on_ip:
            raise RuntimeError("boom")
        return dict(self._ip_data)

    def enrich_domain(self, domain: str) -> dict:
        return dict(self._domain_data)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEnrichmentManagerDisabled:
    """When enrichment is disabled, assets pass through with score 0."""

    def test_returns_all_assets_with_zero_score(self, tmp_path):
        cache = EnrichmentCache(str(tmp_path / "cache"))
        config = EnrichmentConfig(enabled=False)
        mgr = EnrichmentManager(config, cache)

        assets = [_make_asset("10.0.0.1"), _make_asset("10.0.0.2")]
        results = mgr.enrich(assets)

        assert len(results) == 2
        for r in results:
            assert r.correlation_risk_score == 0
            assert r.enrichment_data == {}


class TestEnrichmentManagerCaching:
    """Cache is checked before calling the provider."""

    def test_uses_cache_on_hit(self, tmp_path):
        cache = EnrichmentCache(str(tmp_path / "cache"))
        # Pre-populate cache
        cache.set("fake", "1.2.3.4", {"cached": True})

        config = EnrichmentConfig(
            enabled=True,
            providers={"fake": EnrichmentProviderConfig(enabled=True)},
        )
        mgr = EnrichmentManager(config, cache)
        provider = FakeProvider(ip_data={"cached": False})
        mgr.register_provider(provider)

        results = mgr.enrich([_make_asset()])
        # Should get cached data, not provider data
        assert results[0].enrichment_data["fake"]["cached"] is True

    def test_stores_in_cache_on_miss(self, tmp_path):
        cache = EnrichmentCache(str(tmp_path / "cache"))
        config = EnrichmentConfig(
            enabled=True,
            providers={"fake": EnrichmentProviderConfig(enabled=True)},
        )
        mgr = EnrichmentManager(config, cache)
        provider = FakeProvider(ip_data={"fresh": True})
        mgr.register_provider(provider)

        mgr.enrich([_make_asset()])
        # Verify it was cached
        assert cache.get("fake", "1.2.3.4") == {"fresh": True}


class TestEnrichmentManagerProviderSkipping:
    """Disabled providers and providers missing API keys are skipped."""

    def test_skips_disabled_provider(self, tmp_path):
        cache = EnrichmentCache(str(tmp_path / "cache"))
        config = EnrichmentConfig(
            enabled=True,
            providers={"fake": EnrichmentProviderConfig(enabled=False)},
        )
        mgr = EnrichmentManager(config, cache)
        mgr.register_provider(FakeProvider(ip_data={"data": 1}))

        results = mgr.enrich([_make_asset()])
        assert results[0].enrichment_data == {}

    def test_skips_provider_missing_api_key(self, tmp_path):
        cache = EnrichmentCache(str(tmp_path / "cache"))
        config = EnrichmentConfig(
            enabled=True,
            providers={
                "fake": EnrichmentProviderConfig(enabled=True, api_key=None)
            },
        )
        mgr = EnrichmentManager(config, cache)
        mgr.register_provider(
            FakeProvider(needs_key=True, ip_data={"data": 1})
        )

        results = mgr.enrich([_make_asset()])
        assert results[0].enrichment_data == {}

    def test_skips_provider_not_in_config(self, tmp_path):
        cache = EnrichmentCache(str(tmp_path / "cache"))
        config = EnrichmentConfig(enabled=True, providers={})
        mgr = EnrichmentManager(config, cache)
        mgr.register_provider(FakeProvider(ip_data={"data": 1}))

        results = mgr.enrich([_make_asset()])
        assert results[0].enrichment_data == {}


class TestEnrichmentManagerErrorHandling:
    """Providers that raise are logged and skipped."""

    def test_logs_and_skips_failing_provider(self, tmp_path, caplog):
        cache = EnrichmentCache(str(tmp_path / "cache"))
        config = EnrichmentConfig(
            enabled=True,
            providers={
                "failing": EnrichmentProviderConfig(enabled=True),
                "ok": EnrichmentProviderConfig(enabled=True),
            },
        )
        mgr = EnrichmentManager(config, cache)
        mgr.register_provider(
            FakeProvider(prov_name="failing", raise_on_ip=True)
        )
        mgr.register_provider(
            FakeProvider(prov_name="ok", ip_data={"ok": True})
        )

        with caplog.at_level(logging.ERROR):
            results = mgr.enrich([_make_asset()])

        # The "ok" provider still ran
        assert "ok" in results[0].enrichment_data
        # The "failing" provider was skipped
        assert "failing" not in results[0].enrichment_data
        assert "Unrecoverable error" in caplog.text


class TestEnrichmentManagerScoring:
    """Correlation risk score is computed from enrichment data."""

    def test_score_computed_from_enrichment(self, tmp_path):
        cache = EnrichmentCache(str(tmp_path / "cache"))
        config = EnrichmentConfig(
            enabled=True,
            providers={
                "virustotal": EnrichmentProviderConfig(
                    enabled=True, api_key="key"
                ),
            },
        )
        mgr = EnrichmentManager(config, cache)
        mgr.register_provider(
            FakeProvider(
                prov_name="virustotal",
                needs_key=True,
                ip_data={"malicious_count": 5},
            )
        )

        results = mgr.enrich([_make_asset()])
        # VT malicious > 0 → 30 points
        assert results[0].correlation_risk_score == 30

    def test_multi_source_multiplier(self, tmp_path):
        cache = EnrichmentCache(str(tmp_path / "cache"))
        config = EnrichmentConfig(
            enabled=True,
            providers={
                "virustotal": EnrichmentProviderConfig(
                    enabled=True, api_key="k"
                ),
                "greynoise": EnrichmentProviderConfig(
                    enabled=True, api_key="k"
                ),
            },
        )
        mgr = EnrichmentManager(config, cache)
        mgr.register_provider(
            FakeProvider(
                prov_name="virustotal",
                needs_key=True,
                ip_data={"malicious_count": 3},
            )
        )
        mgr.register_provider(
            FakeProvider(
                prov_name="greynoise",
                needs_key=True,
                ip_data={"classification": "malicious"},
            )
        )

        results = mgr.enrich([_make_asset()])
        # (30 + 20) * 1.5 = 75
        assert results[0].correlation_risk_score == 75


class TestEnrichmentManagerSubdomains:
    """Subdomains from crt.sh-style providers are collected."""

    def test_collects_subdomains(self, tmp_path):
        cache = EnrichmentCache(str(tmp_path / "cache"))
        config = EnrichmentConfig(
            enabled=True,
            providers={"crtsh": EnrichmentProviderConfig(enabled=True)},
        )
        mgr = EnrichmentManager(config, cache)
        mgr.register_provider(
            FakeProvider(
                prov_name="crtsh",
                ip_data={"subdomains": ["a.example.com", "b.example.com"]},
            )
        )

        results = mgr.enrich([_make_asset()])
        assert results[0].discovered_subdomains == [
            "a.example.com",
            "b.example.com",
        ]


class TestEnrichmentManagerDomainEnrichment:
    """Domain enrichment is called when hostname is available."""

    def test_merges_domain_data(self, tmp_path):
        cache = EnrichmentCache(str(tmp_path / "cache"))
        config = EnrichmentConfig(
            enabled=True,
            providers={"fake": EnrichmentProviderConfig(enabled=True)},
        )
        mgr = EnrichmentManager(config, cache)
        mgr.register_provider(
            FakeProvider(
                ip_data={"ip_field": 1},
                domain_data={"domain_field": 2},
            )
        )

        results = mgr.enrich([_make_asset(hostname="example.com")])
        data = results[0].enrichment_data["fake"]
        assert data["ip_field"] == 1
        assert data["domain_field"] == 2

    def test_no_domain_call_when_no_hostname(self, tmp_path):
        cache = EnrichmentCache(str(tmp_path / "cache"))
        config = EnrichmentConfig(
            enabled=True,
            providers={"fake": EnrichmentProviderConfig(enabled=True)},
        )
        mgr = EnrichmentManager(config, cache)
        mgr.register_provider(
            FakeProvider(
                ip_data={"ip_field": 1},
                domain_data={"domain_field": 2},
            )
        )

        results = mgr.enrich([_make_asset(hostname=None)])
        data = results[0].enrichment_data["fake"]
        assert data["ip_field"] == 1
        # domain_field should NOT be present since hostname is None
        assert "domain_field" not in data
