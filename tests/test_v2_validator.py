"""Unit tests for RuleValidator."""

from __future__ import annotations

from surfaceaudit.rules.v2.schema import (
    AssessBlock,
    InfoBlock,
    MatchConditionV2,
    MatcherV2,
    RuleV2,
)
from surfaceaudit.rules.v2.validator import RuleValidator


def _make_rule(
    rule_id: str = "test-001",
    severity: str = "high",
    condition: str = "and",
    matchers: list[MatcherV2] | None = None,
    **overrides,
) -> RuleV2:
    """Helper to build a valid RuleV2 with sensible defaults."""
    if matchers is None:
        matchers = [MatcherV2(type="word", field="banner", words=["nginx"])]
    info = InfoBlock(
        name=overrides.get("name", "Test Rule"),
        author=overrides.get("author", "tester"),
        severity=severity,
        tags=overrides.get("tags", ["test"]),
        description=overrides.get("description", "A test rule"),
    )
    match = MatchConditionV2(condition=condition, matchers=matchers)
    assess = AssessBlock(
        category=overrides.get("category", "vulnerability"),
        severity=overrides.get("assess_severity", severity),
        description=overrides.get("assess_description", "Found issue"),
    )
    return RuleV2(id=rule_id, info=info, match=match, assess=assess)


class TestRuleValidatorValid:
    """Tests that valid rules pass validation."""

    def test_valid_rule_no_errors(self):
        v = RuleValidator()
        rule = _make_rule()
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert errors == []

    def test_valid_rule_with_optional_fields(self):
        """Optional fields (references, created) should not cause rejection."""
        v = RuleValidator()
        rule = _make_rule()
        rule.info.references = ["https://example.com"]
        rule.info.created = "2024-01-01"
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert errors == []

    def test_all_severity_values_accepted(self):
        v = RuleValidator()
        for sev in ("critical", "high", "medium", "low", "info"):
            rule = _make_rule(severity=sev)
            errors = v.validate([rule], {"test-001": "rules/test.yaml"})
            assert errors == [], f"Severity '{sev}' should be valid"


class TestRequiredFields:
    """Tests for missing required fields."""

    def test_missing_id(self):
        v = RuleValidator()
        rule = _make_rule(rule_id="")
        errors = v.validate([rule], {"": "rules/test.yaml"})
        assert any("'id'" in e for e in errors)

    def test_missing_info_name(self):
        v = RuleValidator()
        rule = _make_rule(name="")
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("'info.name'" in e for e in errors)

    def test_missing_info_author(self):
        v = RuleValidator()
        rule = _make_rule(author="")
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("'info.author'" in e for e in errors)

    def test_missing_info_tags(self):
        v = RuleValidator()
        rule = _make_rule(tags=[])
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("'info.tags'" in e for e in errors)

    def test_missing_info_description(self):
        v = RuleValidator()
        rule = _make_rule(description="")
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("'info.description'" in e for e in errors)

    def test_missing_matchers(self):
        v = RuleValidator()
        rule = _make_rule(matchers=[])
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("'match'" in e for e in errors)


class TestSeverityValidation:
    def test_invalid_severity_rejected(self):
        v = RuleValidator()
        rule = _make_rule(severity="extreme")
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("severity" in e and "extreme" in e for e in errors)


class TestRegexValidation:
    def test_valid_regex_accepted(self):
        v = RuleValidator()
        rule = _make_rule(
            matchers=[MatcherV2(type="regex", field="banner", regex=r"nginx/\d+")]
        )
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert errors == []

    def test_invalid_regex_rejected(self):
        v = RuleValidator()
        rule = _make_rule(
            matchers=[MatcherV2(type="regex", field="banner", regex=r"[invalid")]
        )
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("regex" in e.lower() for e in errors)


class TestVersionValidation:
    def test_valid_version_accepted(self):
        v = RuleValidator()
        rule = _make_rule(
            matchers=[
                MatcherV2(
                    type="version_compare",
                    field="service_version",
                    operator="lt",
                    version="2.4.50",
                )
            ]
        )
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert errors == []

    def test_invalid_version_rejected(self):
        v = RuleValidator()
        rule = _make_rule(
            matchers=[
                MatcherV2(
                    type="version_compare",
                    field="service_version",
                    operator="lt",
                    version="abc",
                )
            ]
        )
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("version" in e.lower() for e in errors)

    def test_invalid_operator_rejected(self):
        v = RuleValidator()
        rule = _make_rule(
            matchers=[
                MatcherV2(
                    type="version_compare",
                    field="service_version",
                    operator="neq",
                    version="1.0",
                )
            ]
        )
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("operator" in e.lower() for e in errors)


class TestPortValidation:
    def test_valid_ports_accepted(self):
        v = RuleValidator()
        rule = _make_rule(
            matchers=[MatcherV2(type="port", ports=[80, 443, 8080])]
        )
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert errors == []

    def test_port_zero_rejected(self):
        v = RuleValidator()
        rule = _make_rule(matchers=[MatcherV2(type="port", ports=[0])])
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("port" in e.lower() for e in errors)

    def test_port_too_high_rejected(self):
        v = RuleValidator()
        rule = _make_rule(matchers=[MatcherV2(type="port", ports=[70000])])
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("port" in e.lower() for e in errors)

    def test_negative_port_rejected(self):
        v = RuleValidator()
        rule = _make_rule(matchers=[MatcherV2(type="port", ports=[-1])])
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("port" in e.lower() for e in errors)


class TestConditionValidation:
    def test_valid_conditions_accepted(self):
        v = RuleValidator()
        for cond in ("and", "or"):
            rule = _make_rule(condition=cond)
            errors = v.validate([rule], {"test-001": "rules/test.yaml"})
            assert errors == [], f"Condition '{cond}' should be valid"

    def test_invalid_condition_rejected(self):
        v = RuleValidator()
        rule = _make_rule(condition="xor")
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("condition" in e.lower() for e in errors)


class TestDSLValidation:
    def test_valid_dsl_accepted(self):
        v = RuleValidator()
        rule = _make_rule(
            matchers=[
                MatcherV2(type="dsl", expression="port == 80 and banner contains 'nginx'")
            ]
        )
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert errors == []

    def test_invalid_dsl_rejected(self):
        v = RuleValidator()
        rule = _make_rule(
            matchers=[MatcherV2(type="dsl", expression="((( bad")]
        )
        errors = v.validate([rule], {"test-001": "rules/test.yaml"})
        assert any("dsl" in e.lower() for e in errors)


class TestDuplicateIDs:
    def test_duplicate_ids_detected(self):
        v = RuleValidator()
        r1 = _make_rule(rule_id="dup-001")
        r2 = _make_rule(rule_id="dup-001")
        errors = v.validate(
            [r1, r2],
            {"dup-001": "rules/a.yaml"},
        )
        assert any("Duplicate" in e and "dup-001" in e for e in errors)

    def test_unique_ids_no_error(self):
        v = RuleValidator()
        r1 = _make_rule(rule_id="rule-001")
        r2 = _make_rule(rule_id="rule-002")
        errors = v.validate(
            [r1, r2],
            {"rule-001": "rules/a.yaml", "rule-002": "rules/b.yaml"},
        )
        assert errors == []


class TestBatchErrorReporting:
    def test_multiple_errors_collected(self):
        """Multiple invalid rules should each produce errors (batch reporting)."""
        v = RuleValidator()
        r1 = _make_rule(rule_id="bad-1", severity="extreme")
        r2 = _make_rule(rule_id="bad-2", severity="ultra")
        errors = v.validate(
            [r1, r2],
            {"bad-1": "rules/a.yaml", "bad-2": "rules/b.yaml"},
        )
        # At least one error per invalid rule
        assert len(errors) >= 2
        assert any("bad-1" in e for e in errors)
        assert any("bad-2" in e for e in errors)
