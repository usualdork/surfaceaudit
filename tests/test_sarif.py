"""Unit tests for the SARIFFormatter."""

import json
from datetime import datetime, timezone

from surfaceaudit import __version__
from surfaceaudit.models import (
    AssessedAsset,
    AssetType,
    ReportSummary,
    RiskLevel,
    ScanMetadata,
    ScanReport,
    Service,
    VulnerabilityIndicator,
)
from surfaceaudit.output.sarif import SARIFFormatter


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
    risk_level: RiskLevel = RiskLevel.LOW,
    vulnerabilities: list[VulnerabilityIndicator] | None = None,
) -> AssessedAsset:
    return AssessedAsset(
        ip=ip,
        hostname=hostname,
        asset_type=AssetType.WEB_SERVER,
        os=None,
        services=[Service(port=80, protocol="tcp", name="http")],
        geolocation=None,
        ports=[80],
        vulnerabilities=vulnerabilities or [],
        risk_level=risk_level,
    )


def _make_report(assets: list[AssessedAsset] | None = None) -> ScanReport:
    assets = assets or []
    return ScanReport(
        metadata=_make_metadata(),
        summary=ReportSummary(
            total_assets=len(assets),
            assets_by_type={},
            assets_by_risk={},
        ),
        assets=assets,
    )


class TestSARIFFormatterRequiredFields:
    """Output contains required SARIF fields ($schema, version, runs)."""

    def test_contains_schema_field(self):
        fmt = SARIFFormatter()
        report = _make_report()
        parsed = json.loads(fmt.format(report, __version__))
        assert "$schema" in parsed
        assert parsed["$schema"] == SARIFFormatter.SCHEMA_URI

    def test_contains_version_field(self):
        fmt = SARIFFormatter()
        report = _make_report()
        parsed = json.loads(fmt.format(report, __version__))
        assert parsed["version"] == "2.1.0"

    def test_contains_runs_field(self):
        fmt = SARIFFormatter()
        report = _make_report()
        parsed = json.loads(fmt.format(report, __version__))
        assert "runs" in parsed
        assert isinstance(parsed["runs"], list)
        assert len(parsed["runs"]) == 1


class TestSARIFFormatterSeverityMapping:
    """Severity mapping: HIGH→error, MEDIUM→warning, LOW→note."""

    def test_high_maps_to_error(self):
        assert SARIFFormatter._map_severity(RiskLevel.HIGH) == "error"

    def test_medium_maps_to_warning(self):
        assert SARIFFormatter._map_severity(RiskLevel.MEDIUM) == "warning"

    def test_low_maps_to_note(self):
        assert SARIFFormatter._map_severity(RiskLevel.LOW) == "note"

    def test_severity_in_results(self):
        fmt = SARIFFormatter()
        vuln = VulnerabilityIndicator(
            category="risky_port",
            description="Port 21 open",
            severity=RiskLevel.HIGH,
        )
        report = _make_report([_make_asset(vulnerabilities=[vuln])])
        parsed = json.loads(fmt.format(report, __version__))
        results = parsed["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["level"] == "error"


class TestSARIFFormatterRoundTrip:
    """Round-trip: serialize to SARIF, parse JSON, verify structure."""

    def test_roundtrip_empty_report(self):
        fmt = SARIFFormatter()
        report = _make_report()
        sarif_str = fmt.format(report, __version__)
        parsed = json.loads(sarif_str)
        assert parsed["$schema"] == SARIFFormatter.SCHEMA_URI
        assert parsed["version"] == "2.1.0"
        assert parsed["runs"][0]["results"] == []

    def test_roundtrip_with_vulnerabilities(self):
        fmt = SARIFFormatter()
        vulns = [
            VulnerabilityIndicator(
                category="risky_port",
                description="FTP exposed",
                severity=RiskLevel.MEDIUM,
            ),
            VulnerabilityIndicator(
                category="admin_interface",
                description="Admin panel found",
                severity=RiskLevel.HIGH,
            ),
        ]
        asset = _make_asset(ip="10.0.0.1", vulnerabilities=vulns)
        report = _make_report([asset])
        sarif_str = fmt.format(report, __version__)
        parsed = json.loads(sarif_str)

        results = parsed["runs"][0]["results"]
        assert len(results) == 2
        assert results[0]["ruleId"] == "risky_port"
        assert results[0]["message"]["text"] == "FTP exposed"
        assert results[0]["level"] == "warning"
        assert results[1]["ruleId"] == "admin_interface"
        assert results[1]["level"] == "error"

    def test_roundtrip_locations_contain_ip(self):
        fmt = SARIFFormatter()
        vuln = VulnerabilityIndicator(
            category="vuln", description="test", severity=RiskLevel.LOW,
        )
        asset = _make_asset(ip="192.168.1.1", vulnerabilities=[vuln])
        report = _make_report([asset])
        parsed = json.loads(fmt.format(report, __version__))
        loc = parsed["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "192.168.1.1"


class TestSARIFFormatterToolInfo:
    """Tool name is 'SurfaceAudit' and version matches."""

    def test_tool_name_is_surfaceaudit(self):
        fmt = SARIFFormatter()
        report = _make_report()
        parsed = json.loads(fmt.format(report, __version__))
        driver = parsed["runs"][0]["tool"]["driver"]
        assert driver["name"] == "SurfaceAudit"

    def test_tool_version_matches(self):
        fmt = SARIFFormatter()
        report = _make_report()
        parsed = json.loads(fmt.format(report, "1.2.3"))
        driver = parsed["runs"][0]["tool"]["driver"]
        assert driver["version"] == "1.2.3"

    def test_tool_version_uses_package_version(self):
        fmt = SARIFFormatter()
        report = _make_report()
        parsed = json.loads(fmt.format(report, __version__))
        driver = parsed["runs"][0]["tool"]["driver"]
        assert driver["version"] == __version__

    def test_rules_populated_from_vulnerabilities(self):
        fmt = SARIFFormatter()
        vuln = VulnerabilityIndicator(
            category="risky_port",
            description="Port open",
            severity=RiskLevel.LOW,
        )
        report = _make_report([_make_asset(vulnerabilities=[vuln])])
        parsed = json.loads(fmt.format(report, __version__))
        rules = parsed["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "risky_port"
