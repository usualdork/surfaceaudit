"""Unit tests for the v2 DSL evaluator."""

from __future__ import annotations

import pytest

from surfaceaudit.rules.v2.dsl import DSLEvaluator, DSLMatcher, DSLSyntaxError, validate_dsl_syntax
from surfaceaudit.rules.v2.schema import AssetContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ctx(**kwargs) -> AssetContext:
    return AssetContext(**kwargs)


def _eval(expr: str, **kwargs) -> bool:
    return DSLEvaluator(_ctx(**kwargs)).evaluate(expr)


# ---------------------------------------------------------------------------
# Basic comparisons
# ---------------------------------------------------------------------------

class TestEquality:
    def test_field_eq_number(self):
        assert _eval("port == 80", port=80) is True

    def test_field_neq_number(self):
        assert _eval("port != 80", port=443) is True

    def test_field_eq_string(self):
        assert _eval("service_name == 'nginx'", service_name="nginx") is True

    def test_field_neq_string(self):
        assert _eval("service_name != 'apache'", service_name="nginx") is True

    def test_field_eq_string_mismatch(self):
        assert _eval("service_name == 'nginx'", service_name="apache") is False


class TestNumericComparisons:
    def test_gt(self):
        assert _eval("port > 80", port=443) is True

    def test_gt_false(self):
        assert _eval("port > 443", port=80) is False

    def test_lt(self):
        assert _eval("port < 443", port=80) is True

    def test_gte_equal(self):
        assert _eval("port >= 80", port=80) is True

    def test_gte_greater(self):
        assert _eval("port >= 80", port=443) is True

    def test_lte_equal(self):
        assert _eval("port <= 443", port=443) is True

    def test_lte_less(self):
        assert _eval("port <= 443", port=80) is True


class TestContains:
    def test_contains_match(self):
        assert _eval("banner contains 'nginx'", banner="Server: nginx/1.20") is True

    def test_contains_case_insensitive(self):
        assert _eval("banner contains 'NGINX'", banner="Server: nginx/1.20") is True

    def test_contains_no_match(self):
        assert _eval("banner contains 'apache'", banner="Server: nginx/1.20") is False


# ---------------------------------------------------------------------------
# Boolean logic
# ---------------------------------------------------------------------------

class TestAndOr:
    def test_and_both_true(self):
        assert _eval("port == 80 and service_name == 'nginx'", port=80, service_name="nginx") is True

    def test_and_one_false(self):
        assert _eval("port == 80 and service_name == 'apache'", port=80, service_name="nginx") is False

    def test_or_one_true(self):
        assert _eval("port == 80 or port == 443", port=443) is True

    def test_or_both_false(self):
        assert _eval("port == 80 or port == 443", port=8080) is False

    def test_and_or_precedence(self):
        # and binds tighter than or: "a or (b and c)"
        # port==80 is True, service_name=='apache' is False, banner contains 'x' is False
        # => True or (False and False) => True
        assert _eval(
            "port == 80 or service_name == 'apache' and banner contains 'x'",
            port=80, service_name="nginx", banner="hello",
        ) is True

    def test_parenthesised_or(self):
        # (port==80 or port==443) and service_name=='nginx'
        assert _eval(
            "(port == 80 or port == 443) and service_name == 'nginx'",
            port=443, service_name="nginx",
        ) is True

    def test_parenthesised_or_fails(self):
        assert _eval(
            "(port == 80 or port == 443) and service_name == 'nginx'",
            port=8080, service_name="nginx",
        ) is False


# ---------------------------------------------------------------------------
# Null / missing field handling
# ---------------------------------------------------------------------------

class TestNullFields:
    def test_null_string_becomes_empty(self):
        # service_name is None → "" for string ops
        assert _eval("service_name == ''") is True

    def test_null_numeric_becomes_zero(self):
        # port is None → 0 for numeric ops
        assert _eval("port == 0") is True

    def test_null_contains(self):
        # banner is None → "" → contains anything is False
        assert _eval("banner contains 'nginx'") is False

    def test_null_gt(self):
        # port is None → 0 > 80 is False
        assert _eval("port > 80") is False


# ---------------------------------------------------------------------------
# DSLMatcher dataclass
# ---------------------------------------------------------------------------

class TestDSLMatcher:
    def test_matches_true(self):
        matcher = DSLMatcher(expression="port == 9200")
        ctx = _ctx(port=9200)
        assert matcher.matches(ctx) is True

    def test_matches_false(self):
        matcher = DSLMatcher(expression="port == 9200")
        ctx = _ctx(port=80)
        assert matcher.matches(ctx) is False

    def test_complex_expression(self):
        matcher = DSLMatcher(
            expression="port == 9200 and banner contains 'elasticsearch'"
        )
        ctx = _ctx(port=9200, banner="Elasticsearch 7.10.2")
        assert matcher.matches(ctx) is True


# ---------------------------------------------------------------------------
# Syntax validation
# ---------------------------------------------------------------------------

class TestValidation:
    def test_valid_expression(self):
        validate_dsl_syntax("port == 80 and banner contains 'nginx'")

    def test_unbalanced_parens(self):
        with pytest.raises(DSLSyntaxError):
            validate_dsl_syntax("(port == 80")

    def test_unknown_char(self):
        with pytest.raises(DSLSyntaxError):
            validate_dsl_syntax("port @ 80")

    def test_empty_expression(self):
        with pytest.raises(DSLSyntaxError):
            validate_dsl_syntax("")

    def test_trailing_operator(self):
        with pytest.raises(DSLSyntaxError):
            validate_dsl_syntax("port ==")

    def test_double_operator(self):
        with pytest.raises(DSLSyntaxError):
            validate_dsl_syntax("port == == 80")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_string_with_spaces(self):
        assert _eval("banner contains 'hello world'", banner="say hello world!") is True

    def test_float_number(self):
        assert _eval("port > 79.5", port=80) is True

    def test_nested_parens(self):
        assert _eval("((port == 80))", port=80) is True

    def test_multiple_and(self):
        assert _eval(
            "port == 80 and service_name == 'nginx' and banner contains 'server'",
            port=80, service_name="nginx", banner="Server: nginx",
        ) is True

    def test_multiple_or(self):
        assert _eval(
            "port == 80 or port == 443 or port == 8080",
            port=8080,
        ) is True
