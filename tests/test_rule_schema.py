"""Unit tests for surfaceaudit.rules.schema dataclasses."""

import pytest

from surfaceaudit.rules.schema import (
    AssessmentRule,
    ClassificationRule,
    MatchCondition,
)


class TestMatchCondition:
    """Tests for MatchCondition validation and construction."""

    def test_ports_only(self):
        mc = MatchCondition(ports=[80, 443])
        assert mc.ports == [80, 443]
        assert mc.banners is None
        assert mc.services is None

    def test_banners_only(self):
        mc = MatchCondition(banners=["nginx"])
        assert mc.banners == ["nginx"]
        assert mc.ports is None

    def test_services_only(self):
        mc = MatchCondition(services=["http"])
        assert mc.services == ["http"]

    def test_all_fields(self):
        mc = MatchCondition(ports=[80], banners=["http"], services=["web"])
        assert mc.ports == [80]
        assert mc.banners == ["http"]
        assert mc.services == ["web"]

    def test_no_fields_raises_value_error(self):
        with pytest.raises(ValueError, match="at least one"):
            MatchCondition()

    def test_all_none_raises_value_error(self):
        with pytest.raises(ValueError, match="at least one"):
            MatchCondition(ports=None, banners=None, services=None)

    def test_empty_list_is_valid(self):
        """An empty list is not None, so it satisfies the constraint."""
        mc = MatchCondition(ports=[])
        assert mc.ports == []


class TestClassificationRule:
    """Tests for ClassificationRule construction."""

    def test_basic_construction(self):
        match = MatchCondition(ports=[80, 443])
        rule = ClassificationRule(
            id="cls-web",
            name="Web Server",
            match=match,
            asset_type="web_server",
        )
        assert rule.id == "cls-web"
        assert rule.name == "Web Server"
        assert rule.match.ports == [80, 443]
        assert rule.asset_type == "web_server"


class TestAssessmentRule:
    """Tests for AssessmentRule construction."""

    def test_basic_construction(self):
        match = MatchCondition(ports=[21])
        rule = AssessmentRule(
            id="assess-ftp",
            name="FTP Exposed",
            match=match,
            severity="medium",
            description="Risky port 21 (FTP) is open",
            category="risky_port",
        )
        assert rule.id == "assess-ftp"
        assert rule.severity == "medium"
        assert rule.description == "Risky port 21 (FTP) is open"
        assert rule.category == "risky_port"
        assert rule.details_template is None

    def test_with_details_template(self):
        match = MatchCondition(banners=["apache/2.2"])
        rule = AssessmentRule(
            id="assess-vuln",
            name="Vulnerable Apache",
            match=match,
            severity="high",
            description="Outdated Apache version",
            category="vulnerable_version",
            details_template={"version_pattern": "apache/2.2"},
        )
        assert rule.details_template == {"version_pattern": "apache/2.2"}
