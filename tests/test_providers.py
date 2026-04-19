"""Unit tests for the provider abstraction layer.

Tests cover:
- ProviderRegistry: register, get, available, ConfigurationError on unknown
- ShodanProvider: authenticate, get_credits, discover (success + error cases)
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
import shodan

from surfaceaudit.errors import APIError, AuthenticationError, ConfigurationError, RetryHandler
from surfaceaudit.models import RawAsset
from surfaceaudit.providers import ProviderRegistry
from surfaceaudit.providers.base import BaseProvider
from surfaceaudit.providers.shodan import ShodanProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_shodan_client(
    info_return: dict | None = None,
    info_side_effect: Exception | None = None,
    search_return: dict | None = None,
    search_side_effect=None,
) -> MagicMock:
    """Return a mock ``shodan.Shodan`` client."""
    client = MagicMock(spec=shodan.Shodan)
    if info_side_effect is not None:
        client.info.side_effect = info_side_effect
    else:
        client.info.return_value = info_return if info_return is not None else {"scan_credits": 100}
    if search_side_effect is not None:
        client.search.side_effect = search_side_effect
    elif search_return is not None:
        client.search.return_value = search_return
    else:
        client.search.return_value = {"matches": [], "total": 0}
    return client


def _make_match(ip: str, port: int, hostnames: list[str] | None = None) -> dict:
    """Build a minimal Shodan match dict."""
    return {
        "ip_str": ip,
        "port": port,
        "hostnames": hostnames or [],
        "data": f"banner on {port}",
    }


def _authenticated_provider(
    mock_client: MagicMock,
    rate_limit_delay: float = 0,
) -> ShodanProvider:
    """Return a ShodanProvider with the mock client injected."""
    provider = ShodanProvider(rate_limit_delay=rate_limit_delay, retry_handler=RetryHandler(max_retries=0, base_delay=0))
    provider._client = mock_client
    return provider


# ===========================================================================
# ProviderRegistry
# ===========================================================================

class TestProviderRegistry:
    """Tests for ProviderRegistry.register(), get(), and available()."""

    def test_get_raises_configuration_error_for_unknown_provider(self) -> None:
        """Requesting an unregistered provider must raise ConfigurationError."""
        with pytest.raises(ConfigurationError, match="Unknown provider"):
            ProviderRegistry.get("nonexistent_provider_xyz")

    def test_register_and_get(self) -> None:
        """A registered provider class can be retrieved by name."""
        # Use a unique name to avoid polluting other tests
        class _DummyProvider(BaseProvider):
            def name(self) -> str:
                return "dummy"

            def authenticate(self, api_key: str) -> None:
                pass

            def get_credits(self) -> int:
                return 0

            def discover(self, targets: list[str]) -> list[RawAsset]:
                return []

        ProviderRegistry.register("_test_dummy", _DummyProvider)
        assert ProviderRegistry.get("_test_dummy") is _DummyProvider

    def test_available_includes_registered_providers(self) -> None:
        """available() returns names of all registered providers."""
        available = ProviderRegistry.available()
        # shodan is auto-registered when shodan.py is imported
        assert "shodan" in available

    def test_shodan_auto_registered(self) -> None:
        """ShodanProvider is auto-registered under the name 'shodan'."""
        cls = ProviderRegistry.get("shodan")
        assert cls is ShodanProvider


# ===========================================================================
# ShodanProvider — authenticate
# ===========================================================================

class TestShodanProviderAuthenticate:
    """Tests for ShodanProvider.authenticate()."""

    @patch("surfaceaudit.providers.shodan.shodan.Shodan")
    def test_authenticate_success(self, mock_shodan_cls: MagicMock) -> None:
        """Valid API key stores the client for later use."""
        mock_instance = MagicMock()
        mock_instance.info.return_value = {"scan_credits": 50}
        mock_shodan_cls.return_value = mock_instance

        provider = ShodanProvider()
        provider.authenticate("valid-key")

        mock_shodan_cls.assert_called_once_with("valid-key")
        mock_instance.info.assert_called_once()
        assert provider._client is mock_instance

    @patch("surfaceaudit.providers.shodan.shodan.Shodan")
    def test_authenticate_invalid_key_raises(self, mock_shodan_cls: MagicMock) -> None:
        """Invalid API key raises AuthenticationError."""
        mock_instance = MagicMock()
        mock_instance.info.side_effect = shodan.APIError("Access denied")
        mock_shodan_cls.return_value = mock_instance

        provider = ShodanProvider()
        with pytest.raises(AuthenticationError, match="Invalid Shodan API key"):
            provider.authenticate("bad-key")

    @patch("surfaceaudit.providers.shodan.shodan.Shodan")
    def test_authenticate_unexpected_error_raises(self, mock_shodan_cls: MagicMock) -> None:
        """Unexpected errors during authentication raise AuthenticationError."""
        mock_instance = MagicMock()
        mock_instance.info.side_effect = ConnectionError("network down")
        mock_shodan_cls.return_value = mock_instance

        provider = ShodanProvider()
        with pytest.raises(AuthenticationError, match="Failed to validate"):
            provider.authenticate("some-key")


# ===========================================================================
# ShodanProvider — get_credits
# ===========================================================================

class TestShodanProviderGetCredits:
    """Tests for ShodanProvider.get_credits()."""

    def test_returns_scan_credits(self) -> None:
        mock_client = _make_shodan_client(info_return={"scan_credits": 42})
        provider = _authenticated_provider(mock_client)
        assert provider.get_credits() == 42

    def test_defaults_to_zero_when_key_missing(self) -> None:
        mock_client = _make_shodan_client(info_return={})
        provider = _authenticated_provider(mock_client)
        assert provider.get_credits() == 0

    def test_raises_api_error_on_failure(self) -> None:
        mock_client = _make_shodan_client(info_side_effect=shodan.APIError("Forbidden"))
        provider = _authenticated_provider(mock_client)
        with pytest.raises(APIError, match="Failed to retrieve API info"):
            provider.get_credits()

    def test_raises_authentication_error_when_not_authenticated(self) -> None:
        provider = ShodanProvider()
        with pytest.raises(AuthenticationError, match="not been authenticated"):
            provider.get_credits()

    def test_low_credits_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        mock_client = _make_shodan_client(info_return={"scan_credits": 3})
        provider = ShodanProvider(warning_threshold=10)
        provider._client = mock_client
        with caplog.at_level(logging.WARNING):
            credits = provider.get_credits()
        assert credits == 3
        assert "Low Shodan API credits" in caplog.text


# ===========================================================================
# ShodanProvider — discover
# ===========================================================================

class TestShodanProviderDiscover:
    """Tests for ShodanProvider.discover()."""

    def test_discover_empty_targets(self) -> None:
        mock_client = _make_shodan_client()
        provider = _authenticated_provider(mock_client)
        result = provider.discover([])
        assert result == []

    def test_discover_single_target(self) -> None:
        mock_client = _make_shodan_client(search_return={
            "matches": [_make_match("1.2.3.4", 80, ["example.com"])],
            "total": 1,
        })
        provider = _authenticated_provider(mock_client)
        assets = provider.discover(["example.com"])

        assert len(assets) == 1
        assert assets[0].ip == "1.2.3.4"
        assert assets[0].hostname == "example.com"
        assert assets[0].ports == [80]

    def test_discover_groups_by_ip(self) -> None:
        mock_client = _make_shodan_client(search_return={
            "matches": [
                _make_match("1.2.3.4", 80, ["a.com"]),
                _make_match("1.2.3.4", 443, ["a.com"]),
                _make_match("5.6.7.8", 22),
            ],
            "total": 3,
        })
        provider = _authenticated_provider(mock_client)
        assets = provider.discover(["org:test"])

        ips = {a.ip for a in assets}
        assert ips == {"1.2.3.4", "5.6.7.8"}

        asset_a = next(a for a in assets if a.ip == "1.2.3.4")
        assert sorted(asset_a.ports) == [80, 443]

    def test_discover_continues_on_error(self) -> None:
        """A failing target should not prevent other targets from being queried."""
        call_results = [
            RuntimeError("API error"),
            {"matches": [_make_match("1.1.1.1", 443)], "total": 1},
        ]

        def search_side_effect(target):
            result = call_results.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

        mock_client = _make_shodan_client(search_side_effect=search_side_effect)
        provider = _authenticated_provider(mock_client)
        assets = provider.discover(["bad_target", "good_target"])

        assert len(assets) == 1
        assert assets[0].ip == "1.1.1.1"

    def test_discover_raises_when_not_authenticated(self) -> None:
        provider = ShodanProvider()
        with pytest.raises(AuthenticationError, match="not been authenticated"):
            provider.discover(["example.com"])

    def test_name_returns_shodan(self) -> None:
        provider = ShodanProvider()
        assert provider.name() == "shodan"
