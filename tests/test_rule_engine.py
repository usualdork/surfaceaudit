"""Unit tests for surfaceaudit.rules.RuleEngine."""

import os
import textwrap

import pytest

from surfaceaudit.errors import ConfigurationError
from surfaceaudit.models import AssetType, RiskLevel
from surfaceaudit.rules import RuleEngine
from surfaceaudit.rules.schema import MatchCondition


@pytest.fixture()
def rules_dir(tmp_path):
    """Create a temporary rules directory with classification/ and assessment/ subdirs."""
    cls_dir = tmp_path / "classification"
    cls_dir.mkdir()
    assess_dir = tmp_path / "assessment"
    assess_dir.mkdir()
    return tmp_path


@pytest.fixture()
def write_classification_yaml(rules_dir):
    """Helper to write a classification YAML file."""
    def _write(filename: str, content: str):
        path = rules_dir / "classification" / filename
        path.write_text(textwrap.dedent(content))
        return path
    return _write


@pytest.fixture()
def write_assessment_yaml(rules_dir):
    """Helper to write an assessment YAML file."""
    def _write(filename: str, content: str):
        path = rules_dir / "assessment" / filename
        path.write_text(textwrap.dedent(content))
        return path
    return _write


class TestRuleEngineLoad:
    """Tests for loading YAML rule files."""

    def test_load_empty_directories(self, rules_dir):
        engine = RuleEngine(str(rules_dir))
        engine.load()
        assert engine.classify([], "", []) == AssetType.OTHER
        assert engine.assess([], "", []) == []

    def test_load_classification_rules(self, rules_dir, write_classification_yaml):
        write_classification_yaml("default.yaml", """\
            rules:
              - id: cls-web
                name: Web Server
                match:
                  ports: [80, 443]
                asset_type: web_server
        """)
        engine = RuleEngine(str(rules_dir))
        engine.load()
        assert engine.classify([80], "", []) == AssetType.WEB_SERVER

    def test_load_assessment_rules(self, rules_dir, write_assessment_yaml):
        write_assessment_yaml("default.yaml", """\
            rules:
              - id: assess-ftp
                name: FTP Exposed
                match:
                  ports: [21]
                severity: medium
                description: "Risky port 21 (FTP) is open"
                category: risky_port
        """)
        engine = RuleEngine(str(rules_dir))
        engine.load()
        indicators = engine.assess([21], "", [])
        assert len(indicators) == 1
        assert indicators[0].severity == RiskLevel.MEDIUM

    def test_invalid_yaml_raises_configuration_error(self, rules_dir, write_classification_yaml):
        write_classification_yaml("bad.yaml", """\
            rules:
              - id: cls-web
                name: Web Server
                match: [invalid: yaml: here
        """)
        engine = RuleEngine(str(rules_dir))
        with pytest.raises(ConfigurationError, match="bad.yaml"):
            engine.load()

    def test_missing_required_classification_field(self, rules_dir, write_classification_yaml):
        write_classification_yaml("missing.yaml", """\
            rules:
              - id: cls-web
                name: Web Server
                match:
                  ports: [80]
        """)
        engine = RuleEngine(str(rules_dir))
        with pytest.raises(ConfigurationError, match="asset_type"):
            engine.load()

    def test_missing_required_assessment_field(self, rules_dir, write_assessment_yaml):
        write_assessment_yaml("missing.yaml", """\
            rules:
              - id: assess-ftp
                name: FTP Exposed
                match:
                  ports: [21]
        """)
        engine = RuleEngine(str(rules_dir))
        with pytest.raises(ConfigurationError, match="severity"):
            engine.load()

    def test_no_subdirectories_returns_empty(self, tmp_path):
        """When classification/ and assessment/ dirs don't exist, load succeeds with no rules."""
        engine = RuleEngine(str(tmp_path))
        engine.load()
        assert engine.classify([80], "", []) == AssetType.OTHER
        assert engine.assess([80], "", []) == []


class TestRuleEngineClassify:
    """Tests for classification rule evaluation."""

    def test_first_match_wins(self, rules_dir, write_classification_yaml):
        write_classification_yaml("default.yaml", """\
            rules:
              - id: cls-web
                name: Web Server
                match:
                  ports: [80, 443]
                asset_type: web_server
              - id: cls-db
                name: Database
                match:
                  ports: [80, 3306]
                asset_type: database
        """)
        engine = RuleEngine(str(rules_dir))
        engine.load()
        # Port 80 matches both, but first rule wins
        assert engine.classify([80], "", []) == AssetType.WEB_SERVER

    def test_fallback_to_other(self, rules_dir, write_classification_yaml):
        write_classification_yaml("default.yaml", """\
            rules:
              - id: cls-web
                name: Web Server
                match:
                  ports: [80, 443]
                asset_type: web_server
        """)
        engine = RuleEngine(str(rules_dir))
        engine.load()
        assert engine.classify([9999], "", []) == AssetType.OTHER

    def test_banner_match(self, rules_dir, write_classification_yaml):
        write_classification_yaml("default.yaml", """\
            rules:
              - id: cls-web
                name: Web Server
                match:
                  banners: ["nginx", "apache"]
                asset_type: web_server
        """)
        engine = RuleEngine(str(rules_dir))
        engine.load()
        assert engine.classify([], "Running NGINX/1.18", []) == AssetType.WEB_SERVER

    def test_service_match(self, rules_dir, write_classification_yaml):
        write_classification_yaml("default.yaml", """\
            rules:
              - id: cls-db
                name: Database
                match:
                  services: ["mysql", "postgresql"]
                asset_type: database
        """)
        engine = RuleEngine(str(rules_dir))
        engine.load()
        assert engine.classify([], "", ["MySQL Server"]) == AssetType.DATABASE


class TestRuleEngineAssess:
    """Tests for assessment rule evaluation."""

    def test_all_matching_rules_collected(self, rules_dir, write_assessment_yaml):
        write_assessment_yaml("default.yaml", """\
            rules:
              - id: assess-ftp
                name: FTP Exposed
                match:
                  ports: [21]
                severity: medium
                description: "FTP is open"
                category: risky_port
              - id: assess-telnet
                name: Telnet Exposed
                match:
                  ports: [23]
                severity: medium
                description: "Telnet is open"
                category: risky_port
        """)
        engine = RuleEngine(str(rules_dir))
        engine.load()
        indicators = engine.assess([21, 23], "", [])
        assert len(indicators) == 2
        descriptions = {i.description for i in indicators}
        assert "FTP is open" in descriptions
        assert "Telnet is open" in descriptions

    def test_no_match_returns_empty(self, rules_dir, write_assessment_yaml):
        write_assessment_yaml("default.yaml", """\
            rules:
              - id: assess-ftp
                name: FTP Exposed
                match:
                  ports: [21]
                severity: medium
                description: "FTP is open"
                category: risky_port
        """)
        engine = RuleEngine(str(rules_dir))
        engine.load()
        assert engine.assess([80], "", []) == []

    def test_severity_mapping(self, rules_dir, write_assessment_yaml):
        write_assessment_yaml("default.yaml", """\
            rules:
              - id: assess-admin
                name: Admin Interface
                match:
                  ports: [9200]
                severity: high
                description: "Elasticsearch exposed"
                category: admin_interface
        """)
        engine = RuleEngine(str(rules_dir))
        engine.load()
        indicators = engine.assess([9200], "", [])
        assert indicators[0].severity == RiskLevel.HIGH


class TestMatches:
    """Tests for the _matches() internal method."""

    def test_port_match(self):
        engine = RuleEngine()
        cond = MatchCondition(ports=[80, 443])
        assert engine._matches(cond, [80], "", []) is True
        assert engine._matches(cond, [22], "", []) is False

    def test_banner_match_case_insensitive(self):
        engine = RuleEngine()
        cond = MatchCondition(banners=["nginx"])
        assert engine._matches(cond, [], "Running NGINX/1.18", []) is True
        assert engine._matches(cond, [], "apache server", []) is False

    def test_service_match_case_insensitive(self):
        engine = RuleEngine()
        cond = MatchCondition(services=["mysql"])
        assert engine._matches(cond, [], "", ["MySQL Server"]) is True
        assert engine._matches(cond, [], "", ["PostgreSQL"]) is False

    def test_any_field_triggers_match(self):
        engine = RuleEngine()
        cond = MatchCondition(ports=[9999], banners=["nginx"])
        # Port doesn't match but banner does — should still match
        assert engine._matches(cond, [80], "nginx/1.18", []) is True

    def test_no_match_when_all_fields_miss(self):
        engine = RuleEngine()
        cond = MatchCondition(ports=[80], banners=["nginx"], services=["http"])
        assert engine._matches(cond, [22], "ssh server", ["sshd"]) is False
