"""Unit tests for V2 rule schema YAML serialization round-trip."""

from __future__ import annotations

import yaml

from surfaceaudit.rules.v2.loader import RuleLoader
from surfaceaudit.rules.v2.schema import (
    AssessBlock,
    InfoBlock,
    MatchConditionV2,
    MatcherV2,
    RuleV2,
    rule_to_yaml,
)


def _make_rule(**overrides) -> RuleV2:
    """Build a minimal valid RuleV2 for testing."""
    defaults = dict(
        id="test-rule-1",
        info=InfoBlock(
            name="Test Rule",
            author="tester",
            severity="high",
            tags=["web", "test"],
            description="A test rule",
            references=["https://example.com"],
            created="2024-01-01",
        ),
        match=MatchConditionV2(
            condition="and",
            matchers=[
                MatcherV2(type="word", field="banner", words=["nginx"]),
            ],
        ),
        assess=AssessBlock(
            category="vulnerability",
            severity="high",
            description="Assessment description",
        ),
    )
    defaults.update(overrides)
    return RuleV2(**defaults)


class TestRuleToYaml:
    """Tests for rule_to_yaml serialization."""

    def test_produces_valid_yaml(self):
        rule = _make_rule()
        yaml_str = rule_to_yaml(rule)
        data = yaml.safe_load(yaml_str)
        assert isinstance(data, dict)
        assert data["id"] == "test-rule-1"

    def test_round_trip_word_matcher(self):
        rule = _make_rule()
        yaml_str = rule_to_yaml(rule)
        data = yaml.safe_load(yaml_str)

        loader = RuleLoader()
        restored = loader._parse_v2_rule(data, "<test>")

        assert restored.id == rule.id
        assert restored.info.name == rule.info.name
        assert restored.info.author == rule.info.author
        assert restored.info.severity == rule.info.severity
        assert restored.info.tags == rule.info.tags
        assert restored.info.description == rule.info.description
        assert restored.info.references == rule.info.references
        assert restored.info.created == rule.info.created
        assert restored.match.condition == rule.match.condition
        assert len(restored.match.matchers) == 1
        assert restored.match.matchers[0].type == "word"
        assert restored.match.matchers[0].field == "banner"
        assert restored.match.matchers[0].words == ["nginx"]
        assert restored.assess.category == rule.assess.category
        assert restored.assess.severity == rule.assess.severity
        assert restored.assess.description == rule.assess.description

    def test_round_trip_regex_matcher(self):
        rule = _make_rule(
            match=MatchConditionV2(
                condition="or",
                matchers=[
                    MatcherV2(type="regex", field="banner", regex=r"nginx/\d+"),
                ],
            ),
        )
        yaml_str = rule_to_yaml(rule)
        data = yaml.safe_load(yaml_str)
        loader = RuleLoader()
        restored = loader._parse_v2_rule(data, "<test>")

        assert restored.match.condition == "or"
        assert restored.match.matchers[0].type == "regex"
        assert restored.match.matchers[0].regex == r"nginx/\d+"

    def test_round_trip_port_matcher(self):
        rule = _make_rule(
            match=MatchConditionV2(
                condition="and",
                matchers=[MatcherV2(type="port", ports=[80, 443, 8080])],
            ),
        )
        yaml_str = rule_to_yaml(rule)
        data = yaml.safe_load(yaml_str)
        loader = RuleLoader()
        restored = loader._parse_v2_rule(data, "<test>")

        assert restored.match.matchers[0].type == "port"
        assert restored.match.matchers[0].ports == [80, 443, 8080]

    def test_round_trip_version_compare_matcher(self):
        rule = _make_rule(
            match=MatchConditionV2(
                condition="and",
                matchers=[
                    MatcherV2(
                        type="version_compare",
                        field="service_version",
                        operator="lt",
                        version="2.4.50",
                        skip_if_null=False,
                    ),
                ],
            ),
        )
        yaml_str = rule_to_yaml(rule)
        data = yaml.safe_load(yaml_str)
        loader = RuleLoader()
        restored = loader._parse_v2_rule(data, "<test>")

        m = restored.match.matchers[0]
        assert m.type == "version_compare"
        assert m.field == "service_version"
        assert m.operator == "lt"
        assert m.version == "2.4.50"
        assert m.skip_if_null is False

    def test_round_trip_dsl_matcher(self):
        rule = _make_rule(
            match=MatchConditionV2(
                condition="and",
                matchers=[
                    MatcherV2(type="dsl", expression="port == 9200 and banner contains 'elastic'"),
                ],
            ),
        )
        yaml_str = rule_to_yaml(rule)
        data = yaml.safe_load(yaml_str)
        loader = RuleLoader()
        restored = loader._parse_v2_rule(data, "<test>")

        assert restored.match.matchers[0].type == "dsl"
        assert restored.match.matchers[0].expression == "port == 9200 and banner contains 'elastic'"

    def test_round_trip_multiple_matchers(self):
        rule = _make_rule(
            match=MatchConditionV2(
                condition="and",
                matchers=[
                    MatcherV2(type="word", field="banner", words=["nginx"]),
                    MatcherV2(type="port", ports=[80, 443]),
                    MatcherV2(type="version_compare", field="service_version", operator="lt", version="1.20.0"),
                ],
            ),
        )
        yaml_str = rule_to_yaml(rule)
        data = yaml.safe_load(yaml_str)
        loader = RuleLoader()
        restored = loader._parse_v2_rule(data, "<test>")

        assert len(restored.match.matchers) == 3
        assert restored.match.matchers[0].type == "word"
        assert restored.match.matchers[1].type == "port"
        assert restored.match.matchers[2].type == "version_compare"

    def test_round_trip_empty_optional_fields(self):
        rule = _make_rule(
            info=InfoBlock(
                name="Minimal",
                author="tester",
                severity="info",
                tags=["test"],
                description="Minimal rule",
                references=[],
                created=None,
            ),
        )
        yaml_str = rule_to_yaml(rule)
        data = yaml.safe_load(yaml_str)
        loader = RuleLoader()
        restored = loader._parse_v2_rule(data, "<test>")

        assert restored.info.references == []
        assert restored.info.created is None

    def test_round_trip_empty_matchers_list(self):
        rule = _make_rule(
            match=MatchConditionV2(condition="and", matchers=[]),
        )
        yaml_str = rule_to_yaml(rule)
        data = yaml.safe_load(yaml_str)
        loader = RuleLoader()
        restored = loader._parse_v2_rule(data, "<test>")

        assert restored.match.matchers == []

    def test_skip_if_null_default_true_omitted_from_yaml(self):
        """When skip_if_null is True (default), it should be omitted from YAML for cleanliness."""
        rule = _make_rule(
            match=MatchConditionV2(
                condition="and",
                matchers=[
                    MatcherV2(type="version_compare", field="service_version",
                              operator="lt", version="1.0", skip_if_null=True),
                ],
            ),
        )
        yaml_str = rule_to_yaml(rule)
        assert "skip_if_null" not in yaml_str

        # Round-trip still works — parser defaults to True
        data = yaml.safe_load(yaml_str)
        loader = RuleLoader()
        restored = loader._parse_v2_rule(data, "<test>")
        assert restored.match.matchers[0].skip_if_null is True
