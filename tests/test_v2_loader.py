"""Unit tests for the V2 RuleLoader."""

from __future__ import annotations

import os
import textwrap

import pytest
import yaml

from surfaceaudit.errors import ConfigurationError
from surfaceaudit.rules.v2.loader import RuleLoader, _default_rules_dir
from surfaceaudit.rules.v2.schema import (
    SEVERITY_ORDER,
    AssessBlock,
    InfoBlock,
    MatchConditionV2,
    MatcherV2,
    RuleV2,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_yaml(path: str, data: dict | list) -> None:
    """Write a YAML file."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False)


def _make_v2_rule_yaml(
    rule_id: str = "test-rule-1",
    name: str = "Test Rule",
    severity: str = "high",
    tags: list[str] | None = None,
    matcher_type: str = "word",
    **matcher_kwargs,
) -> dict:
    """Build a minimal valid v2 rule dict."""
    matcher = {"type": matcher_type, **matcher_kwargs}
    if matcher_type == "word" and "field" not in matcher_kwargs:
        matcher["field"] = "banner"
        matcher["words"] = ["test"]
    return {
        "id": rule_id,
        "info": {
            "name": name,
            "author": "tester",
            "severity": severity,
            "tags": tags or ["test"],
            "description": f"Description for {name}",
        },
        "match": {
            "condition": "and",
            "matchers": [matcher],
        },
        "assess": {
            "category": "test_category",
            "severity": severity,
            "description": f"Assessment for {name}",
        },
    }


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

class TestDetectFormat:
    """Tests for RuleLoader._detect_format."""

    def test_v1_with_rules_key_and_match_ports(self):
        loader = RuleLoader()
        data = {"rules": [{"id": "r1", "match": {"ports": [80]}}]}
        assert loader._detect_format(data) == "v1"

    def test_v1_with_rules_key_and_match_banners(self):
        loader = RuleLoader()
        data = {"rules": [{"id": "r1", "match": {"banners": ["http"]}}]}
        assert loader._detect_format(data) == "v1"

    def test_v1_with_rules_key_and_match_services(self):
        loader = RuleLoader()
        data = {"rules": [{"id": "r1", "match": {"services": ["http"]}}]}
        assert loader._detect_format(data) == "v1"

    def test_v1_empty_rules_list(self):
        loader = RuleLoader()
        data = {"rules": []}
        assert loader._detect_format(data) == "v1"

    def test_v2_with_id_and_info(self):
        loader = RuleLoader()
        data = {"id": "rule-1", "info": {}, "match": {"matchers": []}, "assess": {}}
        assert loader._detect_format(data) == "v2"

    def test_v2_no_rules_key(self):
        loader = RuleLoader()
        data = {"id": "rule-1"}
        assert loader._detect_format(data) == "v2"


# ---------------------------------------------------------------------------
# V1 to V2 conversion
# ---------------------------------------------------------------------------

class TestConvertV1ToV2:
    """Tests for RuleLoader._convert_v1_to_v2."""

    def test_converts_banners_to_word_matcher(self):
        loader = RuleLoader()
        v1 = {
            "id": "assess-vuln-nginx",
            "name": "Vulnerable Nginx",
            "match": {"banners": ["nginx"]},
            "severity": "high",
            "category": "vulnerable_version",
            "description": "Nginx may be vulnerable",
        }
        rule = loader._convert_v1_to_v2(v1, "assessment/default.yaml")
        word_matchers = [m for m in rule.match.matchers if m.type == "word" and m.field == "banner"]
        assert len(word_matchers) == 1
        assert word_matchers[0].words == ["nginx"]

    def test_converts_ports_to_port_matcher(self):
        loader = RuleLoader()
        v1 = {
            "id": "assess-risky-ftp",
            "name": "FTP Exposed",
            "match": {"ports": [21]},
            "severity": "medium",
            "category": "risky_port",
            "description": "FTP is open",
        }
        rule = loader._convert_v1_to_v2(v1, "assessment/default.yaml")
        port_matchers = [m for m in rule.match.matchers if m.type == "port"]
        assert len(port_matchers) == 1
        assert port_matchers[0].ports == [21]

    def test_converts_services_to_word_matcher_on_service_name(self):
        loader = RuleLoader()
        v1 = {
            "id": "test-svc",
            "name": "Service Match",
            "match": {"services": ["http", "ftp"]},
            "severity": "low",
            "category": "general",
            "description": "Service match",
        }
        rule = loader._convert_v1_to_v2(v1, "test.yaml")
        svc_matchers = [m for m in rule.match.matchers if m.type == "word" and m.field == "service_name"]
        assert len(svc_matchers) == 1
        assert svc_matchers[0].words == ["http", "ftp"]

    def test_v1_condition_is_or(self):
        loader = RuleLoader()
        v1 = {
            "id": "test-or",
            "name": "OR Rule",
            "match": {"ports": [80], "banners": ["http"]},
            "severity": "medium",
            "category": "test",
            "description": "Test",
        }
        rule = loader._convert_v1_to_v2(v1, "test.yaml")
        assert rule.match.condition == "or"

    def test_preserves_rule_id(self):
        loader = RuleLoader()
        v1 = {"id": "my-custom-id", "name": "Custom", "match": {"ports": [22]},
               "severity": "low", "category": "test", "description": "Test"}
        rule = loader._convert_v1_to_v2(v1, "test.yaml")
        assert rule.id == "my-custom-id"

    def test_synthesizes_id_when_missing(self):
        loader = RuleLoader()
        v1 = {"name": "FTP Exposed", "match": {"ports": [21]},
               "severity": "medium", "category": "test", "description": "Test"}
        rule = loader._convert_v1_to_v2(v1, "test.yaml")
        assert rule.id.startswith("v1-")
        assert "ftp" in rule.id.lower()

    def test_default_severity_when_missing(self):
        loader = RuleLoader()
        v1 = {"id": "no-sev", "name": "No Severity", "match": {"ports": [80]},
               "category": "test", "description": "Test"}
        rule = loader._convert_v1_to_v2(v1, "test.yaml")
        assert rule.info.severity == "info"

    def test_classification_rule_conversion(self):
        loader = RuleLoader()
        v1 = {
            "id": "cls-web-server",
            "name": "Web Server",
            "match": {"ports": [80, 443], "banners": ["http", "nginx"]},
            "asset_type": "web_server",
        }
        rule = loader._convert_v1_to_v2(v1, "classification/default.yaml")
        assert rule.id == "cls-web-server"
        assert "classification" in rule.info.tags


# ---------------------------------------------------------------------------
# V2 file parsing
# ---------------------------------------------------------------------------

class TestParseV2File:
    """Tests for loading v2 format YAML files."""

    def test_loads_single_v2_rule(self, tmp_path):
        rule_data = _make_v2_rule_yaml()
        filepath = str(tmp_path / "rule.yaml")
        _write_yaml(filepath, rule_data)

        loader = RuleLoader()
        rules = loader.load(dirs=[str(tmp_path)])
        assert len(rules) == 1
        assert rules[0].id == "test-rule-1"
        assert rules[0].info.name == "Test Rule"

    def test_loads_multiple_v2_files(self, tmp_path):
        for i in range(3):
            rule_data = _make_v2_rule_yaml(rule_id=f"rule-{i}", name=f"Rule {i}")
            _write_yaml(str(tmp_path / f"rule_{i}.yaml"), rule_data)

        loader = RuleLoader()
        rules = loader.load(dirs=[str(tmp_path)])
        assert len(rules) == 3
        ids = {r.id for r in rules}
        assert ids == {"rule-0", "rule-1", "rule-2"}

    def test_loads_from_subdirectories(self, tmp_path):
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        rule_data = _make_v2_rule_yaml(rule_id="sub-rule")
        _write_yaml(str(subdir / "rule.yaml"), rule_data)

        loader = RuleLoader()
        rules = loader.load(dirs=[str(tmp_path)])
        assert len(rules) == 1
        assert rules[0].id == "sub-rule"


# ---------------------------------------------------------------------------
# V1 file loading
# ---------------------------------------------------------------------------

class TestLoadV1Files:
    """Tests for loading v1 format YAML files."""

    def test_loads_v1_assessment_rules(self, tmp_path):
        assess_dir = tmp_path / "assessment"
        assess_dir.mkdir()
        v1_data = {
            "rules": [
                {
                    "id": "assess-risky-ftp",
                    "name": "FTP Exposed",
                    "match": {"ports": [21]},
                    "severity": "medium",
                    "category": "risky_port",
                    "description": "FTP is open",
                },
            ]
        }
        _write_yaml(str(assess_dir / "default.yaml"), v1_data)

        loader = RuleLoader()
        rules = loader.load(dirs=[str(tmp_path)])
        assert len(rules) == 1
        assert rules[0].id == "assess-risky-ftp"

    def test_loads_v1_classification_rules(self, tmp_path):
        cls_dir = tmp_path / "classification"
        cls_dir.mkdir()
        v1_data = {
            "rules": [
                {
                    "id": "cls-web-server",
                    "name": "Web Server",
                    "match": {"ports": [80, 443], "banners": ["http"]},
                    "asset_type": "web_server",
                },
            ]
        }
        _write_yaml(str(cls_dir / "default.yaml"), v1_data)

        loader = RuleLoader()
        rules = loader.load(dirs=[str(tmp_path)])
        assert len(rules) == 1
        assert rules[0].id == "cls-web-server"


# ---------------------------------------------------------------------------
# Mixed v1/v2 loading
# ---------------------------------------------------------------------------

class TestMixedLoading:
    """Tests for loading both v1 and v2 rules together."""

    def test_merges_v1_and_v2_rules(self, tmp_path):
        # V1 file in assessment subdir.
        assess_dir = tmp_path / "assessment"
        assess_dir.mkdir()
        v1_data = {
            "rules": [
                {
                    "id": "v1-rule",
                    "name": "V1 Rule",
                    "match": {"ports": [21]},
                    "severity": "medium",
                    "category": "risky_port",
                    "description": "V1 rule",
                },
            ]
        }
        _write_yaml(str(assess_dir / "default.yaml"), v1_data)

        # V2 file at top level.
        v2_data = _make_v2_rule_yaml(rule_id="v2-rule")
        _write_yaml(str(tmp_path / "v2_rule.yaml"), v2_data)

        loader = RuleLoader()
        rules = loader.load(dirs=[str(tmp_path)])
        ids = {r.id for r in rules}
        assert "v1-rule" in ids
        assert "v2-rule" in ids


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

class TestFiltering:
    """Tests for rule filtering (exclude, tags, min_severity)."""

    def _create_rules_dir(self, tmp_path):
        """Create a directory with several v2 rules for filtering tests."""
        rules = [
            _make_v2_rule_yaml("r-info", "Info Rule", "info", ["network"]),
            _make_v2_rule_yaml("r-low", "Low Rule", "low", ["web"]),
            _make_v2_rule_yaml("r-medium", "Medium Rule", "medium", ["web", "network"]),
            _make_v2_rule_yaml("r-high", "High Rule", "high", ["database"]),
            _make_v2_rule_yaml("r-critical", "Critical Rule", "critical", ["web", "database"]),
        ]
        for rule_data in rules:
            _write_yaml(str(tmp_path / f"{rule_data['id']}.yaml"), rule_data)
        return tmp_path

    def test_exclude_by_id(self, tmp_path):
        self._create_rules_dir(tmp_path)
        loader = RuleLoader()
        rules = loader.load(dirs=[str(tmp_path)], exclude_ids=["r-info", "r-low"])
        ids = {r.id for r in rules}
        assert "r-info" not in ids
        assert "r-low" not in ids
        assert "r-medium" in ids

    def test_filter_by_tags(self, tmp_path):
        self._create_rules_dir(tmp_path)
        loader = RuleLoader()
        rules = loader.load(dirs=[str(tmp_path)], tags=["database"])
        ids = {r.id for r in rules}
        assert ids == {"r-high", "r-critical"}

    def test_filter_by_tags_intersection(self, tmp_path):
        self._create_rules_dir(tmp_path)
        loader = RuleLoader()
        rules = loader.load(dirs=[str(tmp_path)], tags=["web"])
        ids = {r.id for r in rules}
        assert ids == {"r-low", "r-medium", "r-critical"}

    def test_filter_by_min_severity(self, tmp_path):
        self._create_rules_dir(tmp_path)
        loader = RuleLoader()
        rules = loader.load(dirs=[str(tmp_path)], min_severity="high")
        ids = {r.id for r in rules}
        assert ids == {"r-high", "r-critical"}

    def test_filter_by_min_severity_info_includes_all(self, tmp_path):
        self._create_rules_dir(tmp_path)
        loader = RuleLoader()
        rules = loader.load(dirs=[str(tmp_path)], min_severity="info")
        assert len(rules) == 5

    def test_combined_filters(self, tmp_path):
        self._create_rules_dir(tmp_path)
        loader = RuleLoader()
        rules = loader.load(
            dirs=[str(tmp_path)],
            tags=["web"],
            min_severity="medium",
            exclude_ids=["r-critical"],
        )
        ids = {r.id for r in rules}
        assert ids == {"r-medium"}

    def test_exclude_empty_list_no_effect(self, tmp_path):
        self._create_rules_dir(tmp_path)
        loader = RuleLoader()
        rules = loader.load(dirs=[str(tmp_path)], exclude_ids=[])
        assert len(rules) == 5


# ---------------------------------------------------------------------------
# Multiple directories
# ---------------------------------------------------------------------------

class TestMultipleDirectories:
    """Tests for loading from multiple directories."""

    def test_merge_from_two_directories(self, tmp_path):
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()

        _write_yaml(str(dir1 / "rule1.yaml"), _make_v2_rule_yaml("rule-a"))
        _write_yaml(str(dir2 / "rule2.yaml"), _make_v2_rule_yaml("rule-b"))

        loader = RuleLoader()
        rules = loader.load(dirs=[str(dir1), str(dir2)])
        ids = {r.id for r in rules}
        assert ids == {"rule-a", "rule-b"}

    def test_nonexistent_directory_is_skipped(self, tmp_path):
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        _write_yaml(str(real_dir / "rule.yaml"), _make_v2_rule_yaml("rule-ok"))

        loader = RuleLoader()
        rules = loader.load(dirs=[str(real_dir), str(tmp_path / "nonexistent")])
        assert len(rules) == 1
        assert rules[0].id == "rule-ok"


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    """Tests for error conditions."""

    def test_invalid_yaml_raises_configuration_error(self, tmp_path):
        filepath = tmp_path / "bad.yaml"
        filepath.write_text("{{invalid yaml")

        loader = RuleLoader()
        with pytest.raises(ConfigurationError, match="Invalid YAML"):
            loader.load(dirs=[str(tmp_path)])

    def test_duplicate_ids_raises_configuration_error(self, tmp_path):
        _write_yaml(str(tmp_path / "rule1.yaml"), _make_v2_rule_yaml("dup-id"))
        _write_yaml(str(tmp_path / "rule2.yaml"), _make_v2_rule_yaml("dup-id"))

        loader = RuleLoader()
        with pytest.raises(ConfigurationError, match="Duplicate rule ID"):
            loader.load(dirs=[str(tmp_path)])

    def test_validation_errors_raised_as_batch(self, tmp_path):
        # Rule with invalid severity.
        bad_rule = _make_v2_rule_yaml("bad-rule", severity="invalid_sev")
        _write_yaml(str(tmp_path / "bad.yaml"), bad_rule)

        loader = RuleLoader()
        with pytest.raises(ConfigurationError, match="invalid severity"):
            loader.load(dirs=[str(tmp_path)])


# ---------------------------------------------------------------------------
# Default rules directory
# ---------------------------------------------------------------------------

class TestDefaultRulesDir:
    """Tests for loading from the bundled default rules directory."""

    def test_default_rules_dir_exists(self):
        assert os.path.isdir(_default_rules_dir())

    def test_loads_bundled_v1_rules(self):
        loader = RuleLoader()
        rules = loader.load()
        # The bundled rules directory has assessment and classification rules.
        assert len(rules) > 0
        ids = {r.id for r in rules}
        # Check a few known v1 rule IDs.
        assert "assess-risky-ftp" in ids
        assert "cls-web-server" in ids
