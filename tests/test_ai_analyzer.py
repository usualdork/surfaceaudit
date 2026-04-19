"""Unit tests for the AI analyzer module."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from surfaceaudit.ai.analyzer import AIAnalyzer
from surfaceaudit.models import (
    AssessedAsset,
    AssetType,
    ReportSummary,
    RiskLevel,
    ScanDiff,
    ScanMetadata,
    ScanReport,
    Service,
    VulnerabilityIndicator,
)


def _make_asset(
    ip: str = "1.2.3.4",
    risk: RiskLevel = RiskLevel.HIGH,
    vulns: list[VulnerabilityIndicator] | None = None,
) -> AssessedAsset:
    return AssessedAsset(
        ip=ip,
        hostname="example.com",
        asset_type=AssetType.WEB_SERVER,
        os="Linux",
        services=[Service(port=443, protocol="tcp", name="https")],
        geolocation=None,
        ports=[443],
        vulnerabilities=vulns or [
            VulnerabilityIndicator(
                category="risky_port",
                description="HTTPS on port 443",
                severity=RiskLevel.MEDIUM,
            )
        ],
        risk_level=risk,
    )


def _make_report() -> ScanReport:
    return ScanReport(
        metadata=ScanMetadata(
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            query_parameters=["example.com"],
            api_credits_used=1,
            scan_duration_seconds=5.0,
        ),
        summary=ReportSummary(
            total_assets=2,
            assets_by_type={"web_server": 2},
            assets_by_risk={"high": 1, "medium": 1},
        ),
        assets=[
            _make_asset("1.2.3.4", RiskLevel.HIGH),
            _make_asset("5.6.7.8", RiskLevel.MEDIUM),
        ],
    )


class TestAIAnalyzerContextBuilders:
    """Test the context builder methods without hitting the API."""

    def test_build_scan_context(self):
        analyzer = AIAnalyzer(api_key="fake")
        report = _make_report()
        ctx = analyzer._build_scan_context(report)
        assert "Total assets: 2" in ctx
        assert "1.2.3.4" in ctx
        assert "web_server" in ctx

    def test_build_vuln_context(self):
        analyzer = AIAnalyzer(api_key="fake")
        assets = [_make_asset()]
        ctx = analyzer._build_vuln_context(assets)
        assert "risky_port" in ctx
        assert "HTTPS on port 443" in ctx

    def test_build_vuln_context_deduplicates(self):
        analyzer = AIAnalyzer(api_key="fake")
        assets = [_make_asset("1.1.1.1"), _make_asset("2.2.2.2")]
        ctx = analyzer._build_vuln_context(assets)
        # Same vuln on two assets should appear only once
        assert ctx.count("risky_port") == 1

    def test_build_vuln_context_empty(self):
        analyzer = AIAnalyzer(api_key="fake")
        asset = AssessedAsset(
            ip="1.2.3.4", hostname="example.com",
            asset_type=AssetType.WEB_SERVER, os=None,
            services=[], geolocation=None, ports=[],
            vulnerabilities=[], risk_level=RiskLevel.LOW,
        )
        ctx = analyzer._build_vuln_context([asset])
        assert ctx == ""

    def test_build_diff_context_new_assets(self):
        analyzer = AIAnalyzer(api_key="fake")
        diff = ScanDiff(
            new_assets=[_make_asset("10.0.0.1")],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[],
        )
        ctx = analyzer._build_diff_context(diff)
        assert "NEW ASSETS" in ctx
        assert "10.0.0.1" in ctx

    def test_build_diff_context_empty(self):
        analyzer = AIAnalyzer(api_key="fake")
        diff = ScanDiff(
            new_assets=[],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[],
        )
        ctx = analyzer._build_diff_context(diff)
        assert ctx == ""


class TestAIAnalyzerGenerate:
    """Test the generate method with mocked API."""

    @patch("surfaceaudit.ai.analyzer.AIAnalyzer._get_client")
    def test_summarize_scan_calls_api(self, mock_get_client):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "This is an AI summary."
        mock_client.models.generate_content.return_value = mock_response
        mock_get_client.return_value = mock_client

        analyzer = AIAnalyzer(api_key="fake")
        result = analyzer.summarize_scan(_make_report())

        assert result == "This is an AI summary."
        mock_client.models.generate_content.assert_called_once()

    @patch("surfaceaudit.ai.analyzer.AIAnalyzer._get_client")
    def test_recommend_remediations_calls_api(self, mock_get_client):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "1. Fix the port."
        mock_client.models.generate_content.return_value = mock_response
        mock_get_client.return_value = mock_client

        analyzer = AIAnalyzer(api_key="fake")
        result = analyzer.recommend_remediations([_make_asset()])

        assert "Fix the port" in result

    def test_recommend_remediations_no_vulns(self):
        analyzer = AIAnalyzer(api_key="fake")
        asset = AssessedAsset(
            ip="1.2.3.4", hostname="example.com",
            asset_type=AssetType.WEB_SERVER, os=None,
            services=[], geolocation=None, ports=[],
            vulnerabilities=[], risk_level=RiskLevel.LOW,
        )
        result = analyzer.recommend_remediations([asset])
        assert "No vulnerabilities" in result

    @patch("surfaceaudit.ai.analyzer.AIAnalyzer._get_client")
    def test_explain_changes_calls_api(self, mock_get_client):
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "New assets detected."
        mock_client.models.generate_content.return_value = mock_response
        mock_get_client.return_value = mock_client

        analyzer = AIAnalyzer(api_key="fake")
        diff = ScanDiff(
            new_assets=[_make_asset()],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[],
        )
        result = analyzer.explain_changes(diff)
        assert "New assets" in result

    def test_explain_changes_empty_diff(self):
        analyzer = AIAnalyzer(api_key="fake")
        diff = ScanDiff(
            new_assets=[],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[],
        )
        result = analyzer.explain_changes(diff)
        assert "No changes" in result

    @patch("surfaceaudit.ai.analyzer.AIAnalyzer._get_client")
    def test_generate_handles_api_error(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = RuntimeError("API down")
        mock_get_client.return_value = mock_client

        analyzer = AIAnalyzer(api_key="fake")
        result = analyzer.summarize_scan(_make_report())
        assert result == ""
