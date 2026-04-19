"""Unit tests for enrichment providers – mock HTTP responses and verify field extraction."""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock
from io import BytesIO
import urllib.error

import pytest

from surfaceaudit.enrichment.providers.crtsh import CrtshProvider
from surfaceaudit.enrichment.providers.virustotal import VirusTotalProvider
from surfaceaudit.enrichment.providers.greynoise import GreyNoiseProvider
from surfaceaudit.enrichment.providers.abuseipdb import AbuseIPDBProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_urlopen(response_data: dict | list, status: int = 200):
    """Create a mock for urllib.request.urlopen that returns JSON data."""
    body = json.dumps(response_data).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _mock_http_error(code: int):
    """Create a urllib.error.HTTPError with the given status code."""
    return urllib.error.HTTPError(
        url="https://example.com",
        code=code,
        msg=f"HTTP {code}",
        hdrs=None,  # type: ignore[arg-type]
        fp=BytesIO(b""),
    )


# ===================================================================
# crt.sh Provider
# ===================================================================


class TestCrtshProvider:
    """Tests for the crt.sh enrichment provider."""

    def test_name(self):
        p = CrtshProvider()
        assert p.name() == "crtsh"

    def test_requires_api_key(self):
        p = CrtshProvider()
        assert p.requires_api_key() is False

    def test_enrich_ip_returns_empty(self):
        p = CrtshProvider()
        assert p.enrich_ip("1.2.3.4") == {}

    @patch("surfaceaudit.enrichment.providers.crtsh.urllib.request.urlopen")
    def test_enrich_domain_parses_subdomains(self, mock_urlopen_fn):
        crtsh_response = [
            {"name_value": "sub1.example.com"},
            {"name_value": "sub2.example.com\nsub3.example.com"},
            {"name_value": "sub1.example.com"},  # duplicate
        ]
        mock_urlopen_fn.return_value = _mock_urlopen(crtsh_response)

        p = CrtshProvider()
        result = p.enrich_domain("example.com")

        assert "subdomains" in result
        subs = result["subdomains"]
        assert "sub1.example.com" in subs
        assert "sub2.example.com" in subs
        assert "sub3.example.com" in subs
        # No duplicates
        assert len(subs) == len(set(subs))

    @patch("surfaceaudit.enrichment.providers.crtsh.urllib.request.urlopen")
    def test_enrich_domain_deduplicates(self, mock_urlopen_fn):
        crtsh_response = [
            {"name_value": "a.example.com"},
            {"name_value": "A.EXAMPLE.COM"},  # case-insensitive duplicate
            {"name_value": "b.example.com"},
        ]
        mock_urlopen_fn.return_value = _mock_urlopen(crtsh_response)

        p = CrtshProvider()
        result = p.enrich_domain("example.com")

        assert len(result["subdomains"]) == 2

    @patch("surfaceaudit.enrichment.providers.crtsh.urllib.request.urlopen")
    def test_enrich_domain_returns_empty_on_error(self, mock_urlopen_fn):
        mock_urlopen_fn.side_effect = urllib.error.URLError("timeout")

        p = CrtshProvider()
        result = p.enrich_domain("example.com")

        assert result == {}

    @patch("surfaceaudit.enrichment.providers.crtsh.urllib.request.urlopen")
    def test_enrich_domain_returns_empty_on_http_error(self, mock_urlopen_fn):
        mock_urlopen_fn.side_effect = _mock_http_error(503)

        p = CrtshProvider()
        result = p.enrich_domain("example.com")

        assert result == {}


# ===================================================================
# VirusTotal Provider
# ===================================================================


class TestVirusTotalProvider:
    """Tests for the VirusTotal enrichment provider."""

    def test_name(self):
        p = VirusTotalProvider(api_key="test-key")
        assert p.name() == "virustotal"

    def test_requires_api_key(self):
        p = VirusTotalProvider(api_key="test-key")
        assert p.requires_api_key() is True

    @patch("surfaceaudit.enrichment.providers.virustotal.urllib.request.urlopen")
    def test_enrich_ip_extracts_fields(self, mock_urlopen_fn):
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 1,
                        "harmless": 60,
                        "undetected": 10,
                    },
                    "reputation": -15,
                }
            }
        }
        mock_urlopen_fn.return_value = _mock_urlopen(vt_response)

        p = VirusTotalProvider(api_key="test-key")
        result = p.enrich_ip("1.2.3.4")

        assert result["malicious_count"] == 5
        assert result["reputation"] == -15
        assert result["last_analysis_stats"]["malicious"] == 5
        assert result["last_analysis_stats"]["suspicious"] == 1

    @patch("surfaceaudit.enrichment.providers.virustotal.urllib.request.urlopen")
    def test_enrich_ip_handles_missing_attributes(self, mock_urlopen_fn):
        vt_response = {"data": {"attributes": {}}}
        mock_urlopen_fn.return_value = _mock_urlopen(vt_response)

        p = VirusTotalProvider(api_key="test-key")
        result = p.enrich_ip("1.2.3.4")

        assert result["malicious_count"] == 0
        assert result["reputation"] == 0
        assert result["last_analysis_stats"] == {}

    @patch("surfaceaudit.enrichment.providers.virustotal.urllib.request.urlopen")
    def test_enrich_ip_disables_on_auth_error(self, mock_urlopen_fn):
        mock_urlopen_fn.side_effect = _mock_http_error(401)

        p = VirusTotalProvider(api_key="bad-key")
        result = p.enrich_ip("1.2.3.4")

        assert result == {}
        assert p._disabled is True

        # Subsequent calls should return empty without making requests
        mock_urlopen_fn.reset_mock()
        result2 = p.enrich_ip("5.6.7.8")
        assert result2 == {}
        mock_urlopen_fn.assert_not_called()

    @patch("surfaceaudit.enrichment.providers.virustotal.time.sleep")
    @patch("surfaceaudit.enrichment.providers.virustotal.urllib.request.urlopen")
    def test_enrich_ip_retries_on_rate_limit(self, mock_urlopen_fn, mock_sleep):
        # First call: rate limited, second call: success
        vt_response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2},
                    "reputation": 0,
                }
            }
        }
        mock_urlopen_fn.side_effect = [
            _mock_http_error(429),
            _mock_urlopen(vt_response),
        ]

        p = VirusTotalProvider(api_key="test-key")
        result = p.enrich_ip("1.2.3.4")

        assert result["malicious_count"] == 2

    def test_enrich_domain_returns_empty(self):
        p = VirusTotalProvider(api_key="test-key")
        assert p.enrich_domain("example.com") == {}


# ===================================================================
# GreyNoise Provider
# ===================================================================


class TestGreyNoiseProvider:
    """Tests for the GreyNoise enrichment provider."""

    def test_name(self):
        p = GreyNoiseProvider(api_key="test-key")
        assert p.name() == "greynoise"

    def test_requires_api_key(self):
        p = GreyNoiseProvider(api_key="test-key")
        assert p.requires_api_key() is True

    @patch("surfaceaudit.enrichment.providers.greynoise.urllib.request.urlopen")
    def test_enrich_ip_extracts_fields(self, mock_urlopen_fn):
        gn_response = {
            "classification": "malicious",
            "noise": True,
            "riot": False,
            "ip": "1.2.3.4",
            "name": "Some Scanner",
        }
        mock_urlopen_fn.return_value = _mock_urlopen(gn_response)

        p = GreyNoiseProvider(api_key="test-key")
        result = p.enrich_ip("1.2.3.4")

        assert result["classification"] == "malicious"
        assert result["noise"] is True
        assert result["riot"] is False
        # Extra fields should not leak through
        assert "ip" not in result
        assert "name" not in result

    @patch("surfaceaudit.enrichment.providers.greynoise.urllib.request.urlopen")
    def test_enrich_ip_handles_missing_fields(self, mock_urlopen_fn):
        gn_response = {}
        mock_urlopen_fn.return_value = _mock_urlopen(gn_response)

        p = GreyNoiseProvider(api_key="test-key")
        result = p.enrich_ip("1.2.3.4")

        assert result["classification"] == "unknown"
        assert result["noise"] is False
        assert result["riot"] is False

    @patch("surfaceaudit.enrichment.providers.greynoise.urllib.request.urlopen")
    def test_enrich_ip_disables_on_auth_error(self, mock_urlopen_fn):
        mock_urlopen_fn.side_effect = _mock_http_error(403)

        p = GreyNoiseProvider(api_key="bad-key")
        result = p.enrich_ip("1.2.3.4")

        assert result == {}
        assert p._disabled is True

    @patch("surfaceaudit.enrichment.providers.greynoise.time.sleep")
    @patch("surfaceaudit.enrichment.providers.greynoise.urllib.request.urlopen")
    def test_enrich_ip_retries_on_rate_limit(self, mock_urlopen_fn, mock_sleep):
        gn_response = {
            "classification": "benign",
            "noise": False,
            "riot": True,
        }
        mock_urlopen_fn.side_effect = [
            _mock_http_error(429),
            _mock_urlopen(gn_response),
        ]

        p = GreyNoiseProvider(api_key="test-key")
        result = p.enrich_ip("1.2.3.4")

        assert result["classification"] == "benign"
        assert result["riot"] is True

    def test_enrich_domain_returns_empty(self):
        p = GreyNoiseProvider(api_key="test-key")
        assert p.enrich_domain("example.com") == {}


# ===================================================================
# AbuseIPDB Provider
# ===================================================================


class TestAbuseIPDBProvider:
    """Tests for the AbuseIPDB enrichment provider."""

    def test_name(self):
        p = AbuseIPDBProvider(api_key="test-key")
        assert p.name() == "abuseipdb"

    def test_requires_api_key(self):
        p = AbuseIPDBProvider(api_key="test-key")
        assert p.requires_api_key() is True

    @patch("surfaceaudit.enrichment.providers.abuseipdb.urllib.request.urlopen")
    def test_enrich_ip_extracts_fields(self, mock_urlopen_fn):
        abuse_response = {
            "data": {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 85,
                "totalReports": 42,
                "countryCode": "US",
                "isPublic": True,
            }
        }
        mock_urlopen_fn.return_value = _mock_urlopen(abuse_response)

        p = AbuseIPDBProvider(api_key="test-key")
        result = p.enrich_ip("1.2.3.4")

        assert result["abuse_confidence_score"] == 85
        assert result["total_reports"] == 42
        assert result["country_code"] == "US"
        # Extra fields should not leak through
        assert "ipAddress" not in result
        assert "isPublic" not in result

    @patch("surfaceaudit.enrichment.providers.abuseipdb.urllib.request.urlopen")
    def test_enrich_ip_handles_missing_data(self, mock_urlopen_fn):
        abuse_response = {"data": {}}
        mock_urlopen_fn.return_value = _mock_urlopen(abuse_response)

        p = AbuseIPDBProvider(api_key="test-key")
        result = p.enrich_ip("1.2.3.4")

        assert result["abuse_confidence_score"] == 0
        assert result["total_reports"] == 0
        assert result["country_code"] == ""

    @patch("surfaceaudit.enrichment.providers.abuseipdb.urllib.request.urlopen")
    def test_enrich_ip_disables_on_auth_error(self, mock_urlopen_fn):
        mock_urlopen_fn.side_effect = _mock_http_error(401)

        p = AbuseIPDBProvider(api_key="bad-key")
        result = p.enrich_ip("1.2.3.4")

        assert result == {}
        assert p._disabled is True

        # Subsequent calls return empty without HTTP requests
        mock_urlopen_fn.reset_mock()
        result2 = p.enrich_ip("5.6.7.8")
        assert result2 == {}
        mock_urlopen_fn.assert_not_called()

    @patch("surfaceaudit.enrichment.providers.abuseipdb.urllib.request.urlopen")
    def test_enrich_ip_returns_empty_on_network_error(self, mock_urlopen_fn):
        mock_urlopen_fn.side_effect = urllib.error.URLError("connection refused")

        p = AbuseIPDBProvider(api_key="test-key")
        result = p.enrich_ip("1.2.3.4")

        assert result == {}

    def test_enrich_domain_returns_empty(self):
        p = AbuseIPDBProvider(api_key="test-key")
        assert p.enrich_domain("example.com") == {}
