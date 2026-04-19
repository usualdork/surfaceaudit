"""Unit tests for the RichUI terminal component."""

from io import StringIO

from rich.console import Console

from surfaceaudit.models import (
    AssessedAsset,
    AssetType,
    ClassifiedAsset,
    GeoLocation,
    ReportSummary,
    RiskLevel,
    ScanDiff,
    Service,
    VulnerabilityIndicator,
)
from surfaceaudit.ui.rich_ui import RichUI


def _capture_console() -> tuple[Console, StringIO]:
    """Create a Console that writes to a StringIO buffer."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=True)
    return console, buf


def _make_classified(
    ip: str = "1.2.3.4",
    hostname: str | None = "example.com",
    asset_type: AssetType = AssetType.WEB_SERVER,
    ports: list[int] | None = None,
    os_name: str | None = "Linux",
) -> ClassifiedAsset:
    return ClassifiedAsset(
        ip=ip,
        hostname=hostname,
        asset_type=asset_type,
        os=os_name,
        services=[],
        geolocation=GeoLocation(country="US"),
        ports=ports or [80, 443],
        raw_data={},
    )


def _make_assessed(
    ip: str = "1.2.3.4",
    hostname: str | None = "example.com",
    risk_level: RiskLevel = RiskLevel.HIGH,
    vuln_count: int = 2,
    ports: list[int] | None = None,
) -> AssessedAsset:
    vulns = [
        VulnerabilityIndicator(
            category="risky_port",
            description=f"Vuln {i}",
            severity=risk_level,
        )
        for i in range(vuln_count)
    ]
    return AssessedAsset(
        ip=ip,
        hostname=hostname,
        asset_type=AssetType.WEB_SERVER,
        os="Linux",
        services=[],
        geolocation=GeoLocation(country="US"),
        ports=ports or [80],
        vulnerabilities=vulns,
        risk_level=risk_level,
    )


# --- risk_color tests ---


class TestRiskColor:
    def test_high_returns_red(self):
        assert RichUI.risk_color(RiskLevel.HIGH) == "red"

    def test_medium_returns_yellow(self):
        assert RichUI.risk_color(RiskLevel.MEDIUM) == "yellow"

    def test_low_returns_green(self):
        assert RichUI.risk_color(RiskLevel.LOW) == "green"


# --- display_classified_assets tests ---


class TestDisplayClassifiedAssets:
    def test_output_contains_column_headers_and_data(self):
        console, buf = _capture_console()
        ui = RichUI(console=console)

        assets = [
            _make_classified(ip="10.0.0.1", hostname="web.local", ports=[80, 443]),
        ]
        ui.display_classified_assets(assets)

        output = buf.getvalue()
        assert "Classified Assets" in output
        assert "IP" in output
        assert "Hostname" in output
        assert "Asset Type" in output
        assert "Ports" in output
        assert "OS" in output
        assert "10.0.0.1" in output
        assert "web.local" in output
        assert "web_server" in output
        assert "80" in output
        assert "Linux" in output


# --- display_assessed_assets tests ---


class TestDisplayAssessedAssets:
    def test_output_contains_assessed_data(self):
        console, buf = _capture_console()
        ui = RichUI(console=console)

        assets = [
            _make_assessed(ip="10.0.0.2", hostname="db.local", risk_level=RiskLevel.HIGH, vuln_count=3),
        ]
        ui.display_assessed_assets(assets)

        output = buf.getvalue()
        assert "Assessed Assets" in output
        assert "10.0.0.2" in output
        assert "db.local" in output
        assert "HIGH" in output
        assert "3" in output


# --- display_summary tests ---


class TestDisplaySummary:
    def test_output_contains_totals(self):
        console, buf = _capture_console()
        ui = RichUI(console=console)

        summary = ReportSummary(
            total_assets=5,
            assets_by_type={"web_server": 3, "database": 2},
            assets_by_risk={"high": 1, "medium": 2, "low": 2},
        )
        ui.display_summary(summary)

        output = buf.getvalue()
        assert "Scan Summary" in output
        assert "5" in output
        assert "web_server" in output
        assert "database" in output
        assert "HIGH" in output
        assert "MEDIUM" in output
        assert "LOW" in output


# --- display_diff tests ---


class TestDisplayDiff:
    def test_output_contains_new_removed_changed_markers(self):
        console, buf = _capture_console()
        ui = RichUI(console=console)

        new_asset = _make_assessed(ip="10.0.0.10", risk_level=RiskLevel.LOW)
        removed_asset = _make_assessed(ip="10.0.0.20", risk_level=RiskLevel.MEDIUM)
        old_changed = _make_assessed(ip="10.0.0.30", risk_level=RiskLevel.LOW)
        new_changed = _make_assessed(ip="10.0.0.30", risk_level=RiskLevel.HIGH)

        diff = ScanDiff(
            new_assets=[new_asset],
            removed_assets=[removed_asset],
            changed_assets=[(old_changed, new_changed)],
        )
        ui.display_diff(diff)

        output = buf.getvalue()
        assert "Scan Diff" in output
        assert "NEW" in output
        assert "REMOVED" in output
        assert "CHANGED" in output
        assert "10.0.0.10" in output
        assert "10.0.0.20" in output
        assert "10.0.0.30" in output
