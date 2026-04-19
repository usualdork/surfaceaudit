"""Unit tests for the ReportGenerator and ReportFormatter."""

import csv
import io
import json
from datetime import datetime, timezone

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
from surfaceaudit.report import ReportFormatter, ReportGenerator


def _make_config(**overrides) -> ScanConfig:
    defaults = {"api_key": "test-key", "targets": ["example.com"]}
    defaults.update(overrides)
    return ScanConfig(**defaults)


def _make_metadata() -> ScanMetadata:
    return ScanMetadata(
        timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        query_parameters=["example.com"],
        api_credits_used=5,
        scan_duration_seconds=10.0,
    )


def _make_asset(
    ip: str = "203.0.113.1",
    hostname: str | None = "web.example.com",
    asset_type: AssetType = AssetType.WEB_SERVER,
    risk_level: RiskLevel = RiskLevel.LOW,
) -> AssessedAsset:
    return AssessedAsset(
        ip=ip,
        hostname=hostname,
        asset_type=asset_type,
        os=None,
        services=[Service(port=80, protocol="tcp", name="http")],
        geolocation=None,
        ports=[80],
        vulnerabilities=[],
        risk_level=risk_level,
    )


class TestReportGenerator:
    def test_generate_basic_report(self):
        gen = ReportGenerator()
        assets = [_make_asset()]
        report = gen.generate(assets, _make_metadata(), _make_config())

        assert isinstance(report, ScanReport)
        assert len(report.assets) == 1
        assert report.summary.total_assets == 1
        assert report.metadata.api_credits_used == 5

    def test_generate_empty_assets(self):
        gen = ReportGenerator()
        report = gen.generate([], _make_metadata(), _make_config())

        assert report.summary.total_assets == 0
        assert report.summary.assets_by_type == {}
        assert report.summary.assets_by_risk == {}

    def test_summary_counts_by_type(self):
        gen = ReportGenerator()
        assets = [
            _make_asset(ip="1.1.1.1", asset_type=AssetType.WEB_SERVER),
            _make_asset(ip="2.2.2.2", asset_type=AssetType.WEB_SERVER),
            _make_asset(ip="3.3.3.3", asset_type=AssetType.DATABASE),
        ]
        report = gen.generate(assets, _make_metadata(), _make_config())

        assert report.summary.assets_by_type == {"web_server": 2, "database": 1}

    def test_summary_counts_by_risk(self):
        gen = ReportGenerator()
        assets = [
            _make_asset(ip="1.1.1.1", risk_level=RiskLevel.HIGH),
            _make_asset(ip="2.2.2.2", risk_level=RiskLevel.LOW),
            _make_asset(ip="3.3.3.3", risk_level=RiskLevel.LOW),
        ]
        report = gen.generate(assets, _make_metadata(), _make_config())

        assert report.summary.assets_by_risk == {"high": 1, "low": 2}

    def test_redact_internal_ip_10(self):
        gen = ReportGenerator()
        assets = [_make_asset(ip="10.0.0.1", hostname="internal.local")]
        config = _make_config(redact_sensitive=True)
        report = gen.generate(assets, _make_metadata(), config)

        assert report.assets[0].ip == "[REDACTED]"
        assert report.assets[0].hostname == "[REDACTED]"

    def test_redact_internal_ip_172(self):
        gen = ReportGenerator()
        assets = [_make_asset(ip="172.16.0.1", hostname="priv.local")]
        config = _make_config(redact_sensitive=True)
        report = gen.generate(assets, _make_metadata(), config)

        assert report.assets[0].ip == "[REDACTED]"
        assert report.assets[0].hostname == "[REDACTED]"

    def test_redact_internal_ip_192(self):
        gen = ReportGenerator()
        assets = [_make_asset(ip="192.168.1.100", hostname="home.local")]
        config = _make_config(redact_sensitive=True)
        report = gen.generate(assets, _make_metadata(), config)

        assert report.assets[0].ip == "[REDACTED]"
        assert report.assets[0].hostname == "[REDACTED]"

    def test_redact_preserves_public_ip(self):
        gen = ReportGenerator()
        assets = [_make_asset(ip="8.8.8.8", hostname="dns.google")]
        config = _make_config(redact_sensitive=True)
        report = gen.generate(assets, _make_metadata(), config)

        assert report.assets[0].ip == "8.8.8.8"
        assert report.assets[0].hostname == "dns.google"

    def test_redact_does_not_mutate_original(self):
        gen = ReportGenerator()
        original_asset = _make_asset(ip="10.0.0.1", hostname="internal.local")
        assets = [original_asset]
        config = _make_config(redact_sensitive=True)
        report = gen.generate(assets, _make_metadata(), config)

        # Original asset should be unchanged
        assert original_asset.ip == "10.0.0.1"
        assert original_asset.hostname == "internal.local"
        # Report asset should be redacted
        assert report.assets[0].ip == "[REDACTED]"

    def test_no_redaction_when_disabled(self):
        gen = ReportGenerator()
        assets = [_make_asset(ip="10.0.0.1", hostname="internal.local")]
        config = _make_config(redact_sensitive=False)
        report = gen.generate(assets, _make_metadata(), config)

        assert report.assets[0].ip == "10.0.0.1"
        assert report.assets[0].hostname == "internal.local"

    def test_redact_172_31_boundary(self):
        """172.31.x.x is private, 172.32.x.x is not."""
        gen = ReportGenerator()
        config = _make_config(redact_sensitive=True)

        # 172.31 is private
        assets_priv = [_make_asset(ip="172.31.255.255")]
        report_priv = gen.generate(assets_priv, _make_metadata(), config)
        assert report_priv.assets[0].ip == "[REDACTED]"

        # 172.32 is public
        assets_pub = [_make_asset(ip="172.32.0.1")]
        report_pub = gen.generate(assets_pub, _make_metadata(), config)
        assert report_pub.assets[0].ip == "172.32.0.1"


class TestReportFormatter:
    """Tests for ReportFormatter (to_json, to_csv, to_html)."""

    def _make_report(self) -> ScanReport:
        assets = [
            _make_asset(ip="1.2.3.4", hostname="web.example.com"),
            _make_asset(
                ip="5.6.7.8",
                hostname="db.example.com",
                asset_type=AssetType.DATABASE,
                risk_level=RiskLevel.HIGH,
            ),
        ]
        return ScanReport(
            metadata=_make_metadata(),
            summary=ReportSummary(
                total_assets=2,
                assets_by_type={"web_server": 1, "database": 1},
                assets_by_risk={"low": 1, "high": 1},
            ),
            assets=assets,
        )

    # -- JSON ---------------------------------------------------------------

    def test_to_json_returns_valid_json(self):
        fmt = ReportFormatter()
        result = fmt.to_json(self._make_report())
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_to_json_contains_metadata(self):
        fmt = ReportFormatter()
        parsed = json.loads(fmt.to_json(self._make_report()))
        assert "metadata" in parsed
        assert parsed["metadata"]["api_credits_used"] == 5

    def test_to_json_contains_assets(self):
        fmt = ReportFormatter()
        parsed = json.loads(fmt.to_json(self._make_report()))
        assert len(parsed["assets"]) == 2
        assert parsed["assets"][0]["ip"] == "1.2.3.4"

    def test_to_json_serializes_enums_as_values(self):
        fmt = ReportFormatter()
        parsed = json.loads(fmt.to_json(self._make_report()))
        assert parsed["assets"][0]["asset_type"] == "web_server"
        assert parsed["assets"][0]["risk_level"] == "low"

    def test_to_json_serializes_datetime_as_iso(self):
        fmt = ReportFormatter()
        parsed = json.loads(fmt.to_json(self._make_report()))
        # Should be a valid ISO timestamp string
        datetime.fromisoformat(parsed["metadata"]["timestamp"])

    def test_to_json_pretty_printed(self):
        fmt = ReportFormatter()
        result = fmt.to_json(self._make_report())
        # indent=2 means lines should have leading spaces
        assert "\n" in result
        assert "  " in result

    # -- CSV ----------------------------------------------------------------

    def test_to_csv_has_header(self):
        fmt = ReportFormatter()
        result = fmt.to_csv(self._make_report())
        reader = csv.reader(io.StringIO(result))
        header = next(reader)
        assert "ip" in header
        assert "hostname" in header
        assert "asset_type" in header
        assert "risk_level" in header
        assert "ports" in header
        assert "services_count" in header
        assert "vulnerabilities_count" in header

    def test_to_csv_row_count(self):
        fmt = ReportFormatter()
        result = fmt.to_csv(self._make_report())
        reader = csv.reader(io.StringIO(result))
        rows = list(reader)
        # 1 header + 2 data rows
        assert len(rows) == 3

    def test_to_csv_asset_values(self):
        fmt = ReportFormatter()
        result = fmt.to_csv(self._make_report())
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        assert rows[0]["ip"] == "1.2.3.4"
        assert rows[0]["asset_type"] == "web_server"
        assert rows[0]["risk_level"] == "low"
        assert rows[0]["ports"] == "80"
        assert rows[0]["services_count"] == "1"

    def test_to_csv_empty_report(self):
        fmt = ReportFormatter()
        report = ScanReport(
            metadata=_make_metadata(),
            summary=ReportSummary(
                total_assets=0, assets_by_type={}, assets_by_risk={}
            ),
            assets=[],
        )
        result = fmt.to_csv(report)
        reader = csv.reader(io.StringIO(result))
        rows = list(reader)
        # header only
        assert len(rows) == 1

    # -- HTML ---------------------------------------------------------------

    def test_to_html_returns_html(self):
        fmt = ReportFormatter()
        result = fmt.to_html(self._make_report())
        assert "<html" in result
        assert "</html>" in result

    def test_to_html_contains_metadata(self):
        fmt = ReportFormatter()
        result = fmt.to_html(self._make_report())
        assert "example.com" in result
        assert "5" in result  # api_credits_used

    def test_to_html_contains_asset_ips(self):
        fmt = ReportFormatter()
        result = fmt.to_html(self._make_report())
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result

    def test_to_html_contains_summary(self):
        fmt = ReportFormatter()
        result = fmt.to_html(self._make_report())
        assert "Total Assets" in result


class TestReportEncryptor:
    """Tests for ReportEncryptor (encrypt / decrypt)."""

    def test_encrypt_decrypt_roundtrip(self):
        from surfaceaudit.report import ReportEncryptor

        enc = ReportEncryptor()
        plaintext = b"hello world"
        password = "s3cret"
        ciphertext = enc.encrypt(plaintext, password)
        assert enc.decrypt(ciphertext, password) == plaintext

    def test_encrypted_output_differs_from_plaintext(self):
        from surfaceaudit.report import ReportEncryptor

        enc = ReportEncryptor()
        plaintext = b"sensitive report data"
        ciphertext = enc.encrypt(plaintext, "pw")
        assert ciphertext != plaintext

    def test_decrypt_with_wrong_password_fails(self):
        import pytest
        from surfaceaudit.report import ReportEncryptor

        enc = ReportEncryptor()
        ciphertext = enc.encrypt(b"data", "correct")
        with pytest.raises(Exception):
            enc.decrypt(ciphertext, "wrong")

    def test_salt_prepended_to_output(self):
        from surfaceaudit.report import ReportEncryptor

        enc = ReportEncryptor()
        ciphertext = enc.encrypt(b"test", "pw")
        # Output must be at least 16 bytes (salt) + some encrypted data
        assert len(ciphertext) > 16

    def test_different_encryptions_produce_different_output(self):
        from surfaceaudit.report import ReportEncryptor

        enc = ReportEncryptor()
        c1 = enc.encrypt(b"same", "pw")
        c2 = enc.encrypt(b"same", "pw")
        # Different random salts → different ciphertext
        assert c1 != c2

    def test_empty_content_roundtrip(self):
        from surfaceaudit.report import ReportEncryptor

        enc = ReportEncryptor()
        ciphertext = enc.encrypt(b"", "pw")
        assert enc.decrypt(ciphertext, "pw") == b""
