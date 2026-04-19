"""Unit tests for the SurfaceAudit CLI commands."""
from __future__ import annotations
import json, os, tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest, yaml
from click.testing import CliRunner
from surfaceaudit.cli import main
from surfaceaudit.config import ScanConfig
from surfaceaudit.models import (
    AssessedAsset, AssetType, RawAsset, ReportSummary, RiskLevel,
    ScanDiff, ScanMetadata, ScanReport, Service, VulnerabilityIndicator,
    to_serializable_dict,
)

def _make_raw_asset(ip="1.2.3.4", port=80):
    return RawAsset(ip=ip, hostname="example.com", ports=[port],
        data=[{"port": port, "transport": "tcp", "product": "nginx", "data": "HTTP/1.1"}])

def _make_scan_report():
    asset = AssessedAsset(ip="1.2.3.4", hostname="example.com",
        asset_type=AssetType.WEB_SERVER, os=None,
        services=[Service(port=80, protocol="tcp", name="nginx")],
        geolocation=None, ports=[80],
        vulnerabilities=[VulnerabilityIndicator(category="risky_port",
            description="Risky port 80 open", severity=RiskLevel.MEDIUM)],
        risk_level=RiskLevel.MEDIUM)
    return ScanReport(
        metadata=ScanMetadata(timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            query_parameters=["example.com"], api_credits_used=1, scan_duration_seconds=2.5),
        summary=ReportSummary(total_assets=1, assets_by_type={"web_server": 1},
            assets_by_risk={"medium": 1}),
        assets=[asset])

def _write_report_file(path, report):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_serializable_dict(report), f, indent=2)

def _create_mock_provider():
    p = MagicMock()
    p.name.return_value = "shodan"
    p.authenticate.return_value = None
    p.get_credits.return_value = 100
    p.discover.return_value = [_make_raw_asset()]
    return p

def _mock_setup(mock_registry, mock_history_cls):
    mp = _create_mock_provider()
    mock_registry.get.return_value = lambda: mp
    mh = MagicMock()
    mh.save.return_value = "/tmp/s.json"
    mock_history_cls.return_value = mh
    return mp, mh


class TestScanCommand:
    @patch("surfaceaudit.cli.ScanHistoryManager")
    @patch("surfaceaudit.cli.ProviderRegistry")
    def test_scan_executes_pipeline(self, mock_registry, mock_history_cls):
        mp, mh = _mock_setup(mock_registry, mock_history_cls)
        r = CliRunner().invoke(main, ["scan", "--api-key", "k", "--targets", "example.com"])
        assert r.exit_code == 0, r.output
        mp.authenticate.assert_called_once_with("k")
        mp.discover.assert_called_once()
        mh.save.assert_called_once()

    @patch("surfaceaudit.cli.ScanHistoryManager")
    @patch("surfaceaudit.cli.ProviderRegistry")
    def test_scan_with_provider_option(self, mock_registry, mock_history_cls):
        _mock_setup(mock_registry, mock_history_cls)
        r = CliRunner().invoke(main, ["scan", "--api-key", "k", "--targets", "example.com", "--provider", "shodan"])
        assert r.exit_code == 0, r.output

    @patch("surfaceaudit.cli.ScanHistoryManager")
    @patch("surfaceaudit.cli.ProviderRegistry")
    def test_scan_sarif_output_format(self, mock_registry, mock_history_cls):
        _mock_setup(mock_registry, mock_history_cls)
        r = CliRunner().invoke(main, ["scan", "--api-key", "k", "--targets", "example.com", "--output-format", "sarif"])
        assert r.exit_code == 0, r.output
        assert "sarif" in r.output.lower() or "$schema" in r.output

    @patch("surfaceaudit.cli.ScanHistoryManager")
    @patch("surfaceaudit.cli.ProviderRegistry")
    def test_scan_writes_output_file(self, mock_registry, mock_history_cls):
        _mock_setup(mock_registry, mock_history_cls)
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "report.json")
            r = CliRunner().invoke(main, ["scan", "--api-key", "k", "--targets", "example.com", "--output-file", out])
            assert r.exit_code == 0, r.output
            assert os.path.exists(out)

    def test_scan_missing_api_key(self):
        r = CliRunner().invoke(main, ["scan", "--targets", "example.com"], env={"SHODAN_API_KEY": ""})
        assert r.exit_code != 0


class TestScanV2Options:
    @patch("surfaceaudit.cli.ScanHistoryManager")
    @patch("surfaceaudit.cli.ProviderRegistry")
    def test_scan_with_exclude_rules(self, mock_registry, mock_history_cls):
        _mock_setup(mock_registry, mock_history_cls)
        with patch("surfaceaudit.rules.v2.engine.RuleEngineV2") as mock_v2_cls:
            mock_v2 = MagicMock()
            mock_v2.classify.return_value = AssetType.WEB_SERVER
            mock_v2.assess.return_value = []
            mock_v2_cls.return_value = mock_v2
            r = CliRunner().invoke(main, ["scan", "--api-key", "k", "--targets", "example.com", "--exclude-rules", "rule-1,rule-2"])
            assert r.exit_code == 0, r.output
            mock_v2.load.assert_called_once()
            assert mock_v2.load.call_args[1]["exclude_ids"] == ["rule-1", "rule-2"]

    @patch("surfaceaudit.cli.ScanHistoryManager")
    @patch("surfaceaudit.cli.ProviderRegistry")
    def test_scan_with_tags_filter(self, mock_registry, mock_history_cls):
        _mock_setup(mock_registry, mock_history_cls)
        with patch("surfaceaudit.rules.v2.engine.RuleEngineV2") as mock_v2_cls:
            mock_v2 = MagicMock()
            mock_v2.classify.return_value = AssetType.WEB_SERVER
            mock_v2.assess.return_value = []
            mock_v2_cls.return_value = mock_v2
            r = CliRunner().invoke(main, ["scan", "--api-key", "k", "--targets", "example.com", "--tags", "web,database"])
            assert r.exit_code == 0, r.output
            mock_v2.load.assert_called_once()
            assert mock_v2.load.call_args[1]["tags"] == ["web", "database"]

    @patch("surfaceaudit.cli.ScanHistoryManager")
    @patch("surfaceaudit.cli.ProviderRegistry")
    def test_scan_with_min_severity(self, mock_registry, mock_history_cls):
        _mock_setup(mock_registry, mock_history_cls)
        with patch("surfaceaudit.rules.v2.engine.RuleEngineV2") as mock_v2_cls:
            mock_v2 = MagicMock()
            mock_v2.classify.return_value = AssetType.WEB_SERVER
            mock_v2.assess.return_value = []
            mock_v2_cls.return_value = mock_v2
            r = CliRunner().invoke(main, ["scan", "--api-key", "k", "--targets", "example.com", "--min-severity", "high"])
            assert r.exit_code == 0, r.output
            mock_v2.load.assert_called_once()
            assert mock_v2.load.call_args[1]["min_severity"] == "high"

    @patch("surfaceaudit.cli.ScanHistoryManager")
    @patch("surfaceaudit.cli.ProviderRegistry")
    def test_scan_without_v2_options_uses_v1(self, mock_registry, mock_history_cls):
        _mock_setup(mock_registry, mock_history_cls)
        with patch("surfaceaudit.cli.RuleEngine") as mock_v1_cls:
            mock_v1 = MagicMock()
            mock_v1.classify.return_value = AssetType.WEB_SERVER
            mock_v1.assess.return_value = []
            mock_v1_cls.return_value = mock_v1
            r = CliRunner().invoke(main, ["scan", "--api-key", "k", "--targets", "example.com"])
            assert r.exit_code == 0, r.output
            mock_v1.load.assert_called_once()

    @patch("surfaceaudit.cli._run_enrichment")
    @patch("surfaceaudit.cli.ScanHistoryManager")
    @patch("surfaceaudit.cli.ProviderRegistry")
    def test_scan_with_enrich_flag(self, mock_registry, mock_history_cls, mock_enrich):
        _mock_setup(mock_registry, mock_history_cls)
        mock_enrich.side_effect = lambda cfg, assets: assets
        r = CliRunner().invoke(main, ["scan", "--api-key", "k", "--targets", "example.com", "--enrich"])
        assert r.exit_code == 0, r.output
        mock_enrich.assert_called_once()

    @patch("surfaceaudit.cli.ScanHistoryManager")
    @patch("surfaceaudit.cli.ProviderRegistry")
    def test_scan_without_enrich_skips_enrichment(self, mock_registry, mock_history_cls):
        _mock_setup(mock_registry, mock_history_cls)
        with patch("surfaceaudit.cli._run_enrichment") as mock_enrich:
            r = CliRunner().invoke(main, ["scan", "--api-key", "k", "--targets", "example.com"])
            assert r.exit_code == 0, r.output
            mock_enrich.assert_not_called()


class TestWatchCommand:
    def test_watch_requires_config(self):
        r = CliRunner().invoke(main, ["watch"])
        assert r.exit_code != 0
        assert "Missing option" in r.output or "required" in r.output.lower()

    def test_watch_config_file_not_found(self):
        r = CliRunner().invoke(main, ["watch", "--config", "/nonexistent/config.yaml"])
        assert r.exit_code != 0

    @patch("surfaceaudit.watch.WatchMode")
    @patch("surfaceaudit.cli.ProviderRegistry")
    def test_watch_invocation(self, mock_registry, mock_watch_cls):
        _mock_setup(mock_registry, MagicMock())
        mock_watch = MagicMock()
        mock_watch.run.return_value = ScanDiff(new_assets=[], removed_assets=[], changed_assets=[], risk_increase_assets=[])
        mock_watch_cls.return_value = mock_watch
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                yaml.dump({"api_key": "k", "targets": ["example.com"], "watch": {"history_dir": os.path.join(tmpdir, "h"), "notifications": []}}, f)
            r = CliRunner().invoke(main, ["watch", "--config", cfg_path])
            assert r.exit_code == 0, r.output
            mock_watch.run.assert_called_once()


class TestConfigLoading:
    def test_config_with_enrichment_section(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                yaml.dump({"api_key": "k", "targets": ["example.com"], "enrichment": {"enabled": True, "providers": {"virustotal": {"enabled": True, "api_key": "vt-123"}}, "cache_dir": "/tmp/cache", "cache_ttl_hours": 12}}, f)
            cfg = ScanConfig.from_file(cfg_path)
            assert cfg.enrichment.enabled is True
            assert "virustotal" in cfg.enrichment.providers
            assert cfg.enrichment.providers["virustotal"].api_key == "vt-123"
            assert cfg.enrichment.cache_dir == "/tmp/cache"
            assert cfg.enrichment.cache_ttl_hours == 12

    def test_config_with_watch_section(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                yaml.dump({"api_key": "k", "targets": ["example.com"], "watch": {"history_dir": "/tmp/history", "notifications": [{"type": "slack", "webhook_url": "https://hooks.slack.com/t", "on": ["new_assets"]}, {"type": "discord", "webhook_url": "https://discord.com/wh", "on": []}, {"type": "webhook", "url": "https://example.com/wh", "on": ["removed_assets"]}]}}, f)
            cfg = ScanConfig.from_file(cfg_path)
            assert cfg.watch.history_dir == "/tmp/history"
            assert len(cfg.watch.notifications) == 3
            assert cfg.watch.notifications[0].type == "slack"
            assert cfg.watch.notifications[1].type == "discord"
            assert cfg.watch.notifications[2].type == "webhook"

    def test_config_defaults_for_enrichment_and_watch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "config.yaml")
            with open(cfg_path, "w") as f:
                yaml.dump({"api_key": "k", "targets": ["example.com"]}, f)
            cfg = ScanConfig.from_file(cfg_path)
            assert cfg.enrichment.enabled is False
            assert cfg.watch.history_dir == ".surfaceaudit/history"
            assert cfg.watch.notifications == []


class TestCompareCommand:
    def test_compare_two_reports(self):
        ra = _make_scan_report()
        rb = _make_scan_report()
        rb.assets[0].ip = "5.6.7.8"
        with tempfile.TemporaryDirectory() as tmpdir:
            pa = os.path.join(tmpdir, "a.json")
            pb = os.path.join(tmpdir, "b.json")
            _write_report_file(pa, ra)
            _write_report_file(pb, rb)
            r = CliRunner().invoke(main, ["compare", pa, pb])
            assert r.exit_code == 0, r.output

    def test_compare_identical_reports(self):
        rpt = _make_scan_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            pa = os.path.join(tmpdir, "a.json")
            pb = os.path.join(tmpdir, "b.json")
            _write_report_file(pa, rpt)
            _write_report_file(pb, rpt)
            r = CliRunner().invoke(main, ["compare", pa, pb])
            assert r.exit_code == 0, r.output

    def test_compare_nonexistent_file(self):
        r = CliRunner().invoke(main, ["compare", "/nonexistent/a.json", "/nonexistent/b.json"])
        assert r.exit_code != 0
