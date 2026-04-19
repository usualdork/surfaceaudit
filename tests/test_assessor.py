"""Unit tests for the VulnerabilityAssessor.

The assessor now delegates vulnerability detection to the YAML RuleEngine.
Tests exercise the public assess() API and the _calculate_risk_level helper.
"""

from surfaceaudit.assessor import VulnerabilityAssessor
from surfaceaudit.models import (
    AssetType,
    ClassifiedAsset,
    GeoLocation,
    RiskLevel,
    Service,
    VulnerabilityIndicator,
)


def _make_asset(
    ports: list[int] | None = None,
    services: list[Service] | None = None,
    ip: str = "1.2.3.4",
) -> ClassifiedAsset:
    """Helper to build a ClassifiedAsset with sensible defaults."""
    return ClassifiedAsset(
        ip=ip,
        hostname="example.com",
        asset_type=AssetType.WEB_SERVER,
        os="Linux",
        services=services or [],
        geolocation=GeoLocation(country="US"),
        ports=ports or [],
        raw_data={},
    )


class TestCalculateRiskLevel:
    def setup_method(self):
        self.assessor = VulnerabilityAssessor()

    def test_no_indicators_is_low(self):
        assert self.assessor._calculate_risk_level([]) == RiskLevel.LOW

    def test_high_severity_gives_high(self):
        indicators = [
            VulnerabilityIndicator(
                category="vulnerable_version",
                description="old ssh",
                severity=RiskLevel.HIGH,
            )
        ]
        assert self.assessor._calculate_risk_level(indicators) == RiskLevel.HIGH

    def test_medium_severity_gives_medium(self):
        indicators = [
            VulnerabilityIndicator(
                category="risky_port",
                description="ftp open",
                severity=RiskLevel.MEDIUM,
            )
        ]
        assert self.assessor._calculate_risk_level(indicators) == RiskLevel.MEDIUM

    def test_low_severity_gives_low(self):
        indicators = [
            VulnerabilityIndicator(
                category="info",
                description="informational",
                severity=RiskLevel.LOW,
            )
        ]
        assert self.assessor._calculate_risk_level(indicators) == RiskLevel.LOW

    def test_mixed_high_wins(self):
        indicators = [
            VulnerabilityIndicator(
                category="risky_port",
                description="ftp",
                severity=RiskLevel.MEDIUM,
            ),
            VulnerabilityIndicator(
                category="vulnerable_version",
                description="old ssh",
                severity=RiskLevel.HIGH,
            ),
        ]
        assert self.assessor._calculate_risk_level(indicators) == RiskLevel.HIGH


class TestAssess:
    """Tests for the public assess() method using the default RuleEngine."""

    def setup_method(self):
        self.assessor = VulnerabilityAssessor()

    def test_clean_asset_low_risk(self):
        asset = _make_asset(ports=[80, 443])
        result = self.assessor.assess(asset)
        assert result.risk_level == RiskLevel.LOW
        assert result.vulnerabilities == []
        assert result.ip == asset.ip
        assert result.hostname == asset.hostname

    def test_asset_with_risky_port(self):
        asset = _make_asset(ports=[23])
        result = self.assessor.assess(asset)
        assert result.risk_level == RiskLevel.MEDIUM
        assert len(result.vulnerabilities) >= 1
        assert any(v.category == "risky_port" for v in result.vulnerabilities)

    def test_asset_with_admin_port(self):
        asset = _make_asset(ports=[9200])
        result = self.assessor.assess(asset)
        assert any(v.category == "admin_interface" for v in result.vulnerabilities)

    def test_asset_with_admin_keyword_in_banner(self):
        asset = _make_asset(
            ports=[12345],
            services=[
                Service(
                    port=12345,
                    protocol="tcp",
                    name="http",
                    banner="phpMyAdmin login page",
                )
            ],
        )
        result = self.assessor.assess(asset)
        assert any(v.category == "admin_interface" for v in result.vulnerabilities)

    def test_all_fields_carried_over(self):
        geo = GeoLocation(country="US", city="NYC", latitude=40.7, longitude=-74.0)
        asset = ClassifiedAsset(
            ip="10.0.0.1",
            hostname="host.local",
            asset_type=AssetType.DATABASE,
            os="Ubuntu",
            services=[Service(port=3306, protocol="tcp", name="MySQL", version="5.7")],
            geolocation=geo,
            ports=[3306],
            raw_data={"key": "value"},
        )
        result = self.assessor.assess(asset)
        assert result.ip == "10.0.0.1"
        assert result.hostname == "host.local"
        assert result.asset_type == AssetType.DATABASE
        assert result.os == "Ubuntu"
        assert result.geolocation == geo
        assert result.ports == [3306]
