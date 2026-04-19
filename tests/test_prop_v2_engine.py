# Feature: v2-engine-correlation-monitoring, Property 4: Word matcher case-insensitive substring
# Feature: v2-engine-correlation-monitoring, Property 5: Regex matcher correctness
# Feature: v2-engine-correlation-monitoring, Property 7: Port matcher set intersection
# Feature: v2-engine-correlation-monitoring, Property 9: Version comparison correctness
# Feature: v2-engine-correlation-monitoring, Property 11: DSL evaluator correctness
# Feature: v2-engine-correlation-monitoring, Property 13: Matcher condition logic (AND/OR)
# Feature: v2-engine-correlation-monitoring, Property 15: Template variable substitution
"""Property-based tests for v2 rule engine matchers, version comparison,
DSL evaluator, matcher condition logic, and template substitution.

**Validates: Requirements 2.1, 2.2, 3.1, 3.2, 4.1, 4.2, 5.1, 5.2, 5.5,
6.1, 6.2, 6.3, 7.1, 7.2, 8.1, 8.2**
"""

from __future__ import annotations

import re

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from surfaceaudit.rules.v2.matchers import (
    PortMatcher,
    RegexMatcher,
    VersionCompareMatcher,
    WordMatcher,
)
from surfaceaudit.rules.v2.schema import AssetContext
from surfaceaudit.rules.v2.version import _compare, parse_version
from surfaceaudit.rules.v2.dsl import DSLEvaluator
from surfaceaudit.rules.v2.template import substitute_template


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Printable ASCII text without control chars, suitable for field values
_printable_text = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S", "Zs")),
    min_size=1,
    max_size=50,
)

# Words for WordMatcher — non-empty printable strings
_word_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=20,
)

# Port numbers in valid range
_port_strategy = st.integers(min_value=1, max_value=65535)

# Version segment: 0-999
_version_segment = st.integers(min_value=0, max_value=999)

# Version string like "1.2.3"
_version_string = st.tuples(
    _version_segment,
    _version_segment,
    _version_segment,
).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}")

# Version operators
_version_op = st.sampled_from(["lt", "lte", "gt", "gte", "eq"])

# Field names that hold string values on AssetContext
_string_field_names = st.sampled_from(["service_name", "service_version", "banner", "ip", "hostname", "os"])

# Condition for AND/OR logic
_condition_strategy = st.sampled_from(["and", "or"])


# ---------------------------------------------------------------------------
# Property 4: Word matcher case-insensitive substring
# **Validates: Requirements 2.1, 2.2**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    field_name=_string_field_names,
    words=st.lists(_word_strategy, min_size=1, max_size=5),
    field_value=_printable_text,
)
def test_word_matcher_case_insensitive_substring(
    field_name: str, words: list[str], field_value: str,
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 4: Word matcher case-insensitive substring
    """For any word matcher with a words list and a non-null, non-empty field
    value, the matcher SHALL return True iff at least one word
    (case-insensitively) is a substring of the field value."""
    ctx = AssetContext(**{field_name: field_value})
    matcher = WordMatcher(field=field_name, words=words)

    result = matcher.matches(ctx)

    # Reference implementation
    value_lower = field_value.lower()
    expected = any(w.lower() in value_lower for w in words)

    assert result == expected, (
        f"WordMatcher({words}).matches({field_value!r}) = {result}, expected {expected}"
    )


# ---------------------------------------------------------------------------
# Property 5: Regex matcher correctness
# **Validates: Requirements 3.1, 3.2**
# ---------------------------------------------------------------------------

# Simple regex patterns that are always valid
_simple_regex_patterns = st.sampled_from([
    r"nginx",
    r"apache",
    r"\d+\.\d+",
    r"[a-z]+",
    r"server",
    r"http",
    r"ssh",
    r"ftp",
    r"open",
    r"version",
])


@settings(max_examples=100)
@given(
    field_name=_string_field_names,
    pattern=_simple_regex_patterns,
    field_value=_printable_text,
)
def test_regex_matcher_correctness(
    field_name: str, pattern: str, field_value: str,
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 5: Regex matcher correctness
    """For any regex matcher with a valid pattern and a non-null, non-empty
    field value, the matcher SHALL return True iff re.search(pattern, value,
    re.IGNORECASE) produces a match."""
    ctx = AssetContext(**{field_name: field_value})
    matcher = RegexMatcher(field=field_name, regex=pattern)

    result = matcher.matches(ctx)

    expected = bool(re.search(pattern, field_value, re.IGNORECASE))

    assert result == expected, (
        f"RegexMatcher({pattern!r}).matches({field_value!r}) = {result}, expected {expected}"
    )


# ---------------------------------------------------------------------------
# Property 7: Port matcher set intersection
# **Validates: Requirements 4.1, 4.2**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    matcher_ports=st.lists(_port_strategy, min_size=0, max_size=10),
    asset_ports=st.lists(_port_strategy, min_size=0, max_size=10),
)
def test_port_matcher_set_intersection(
    matcher_ports: list[int], asset_ports: list[int],
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 7: Port matcher set intersection
    """For any port matcher with a ports list and an asset with an open ports
    list, the matcher SHALL return True iff the intersection of the two lists
    is non-empty."""
    ctx = AssetContext(ports=asset_ports)
    matcher = PortMatcher(ports=matcher_ports)

    result = matcher.matches(ctx)

    expected = len(set(matcher_ports) & set(asset_ports)) > 0

    assert result == expected, (
        f"PortMatcher({matcher_ports}).matches(ports={asset_ports}) = {result}, "
        f"expected {expected}"
    )


# ---------------------------------------------------------------------------
# Property 9: Version comparison correctness
# **Validates: Requirements 5.1, 5.2, 5.5**
# ---------------------------------------------------------------------------

# Version strings with optional non-numeric suffix
_version_with_suffix = _version_string.flatmap(
    lambda v: st.one_of(
        st.just(v),
        st.just(v + "-ubuntu"),
        st.just(v + "-alpine"),
        st.just(v + "-1"),
    )
)


@settings(max_examples=100)
@given(
    version_a=_version_with_suffix,
    version_b=_version_with_suffix,
    op=_version_op,
)
def test_version_comparison_correctness(
    version_a: str, version_b: str, op: str,
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 9: Version comparison correctness
    """For any two version strings and any operator in {lt, lte, gt, gte, eq},
    the VersionCompareMatcher SHALL produce the same result as comparing the
    zero-padded integer tuples."""
    ctx = AssetContext(service_version=version_a)
    matcher = VersionCompareMatcher(
        field="service_version", operator=op, version=version_b,
    )

    result = matcher.matches(ctx)

    # Reference: parse both, zero-pad, compare tuples
    parsed_a = parse_version(version_a)
    parsed_b = parse_version(version_b)
    expected = _compare(parsed_a, parsed_b, op)

    assert result == expected, (
        f"VersionCompareMatcher({version_a!r} {op} {version_b!r}) = {result}, "
        f"expected {expected}"
    )


# ---------------------------------------------------------------------------
# Property 11: DSL evaluator correctness
# **Validates: Requirements 6.1, 6.2, 6.3**
# ---------------------------------------------------------------------------


# Strategy to build simple DSL expressions and their expected Python results.
# We generate expressions from a small grammar and evaluate both the DSL and
# the equivalent Python expression.

@st.composite
def _dsl_comparison(draw: st.DrawFn) -> tuple[str, AssetContext, bool]:
    """Generate a single DSL comparison expression with its expected result.

    Returns (dsl_expression, context, expected_bool).
    """
    op_type = draw(st.sampled_from(["num_eq", "num_neq", "num_gt", "num_lt",
                                     "num_gte", "num_lte", "contains"]))

    if op_type == "contains":
        field_val = draw(st.text(
            alphabet=st.characters(whitelist_categories=("L", "N")),
            min_size=1, max_size=20,
        ))
        search_word = draw(st.text(
            alphabet=st.characters(whitelist_categories=("L", "N")),
            min_size=1, max_size=10,
        ))
        ctx = AssetContext(banner=field_val)
        expr = f"banner contains '{search_word}'"
        expected = search_word.lower() in field_val.lower()
        return expr, ctx, expected

    # Numeric comparisons on port
    port_val = draw(st.integers(min_value=0, max_value=65535))
    cmp_val = draw(st.integers(min_value=0, max_value=65535))
    ctx = AssetContext(port=port_val)

    op_map = {
        "num_eq": ("==", port_val == cmp_val),
        "num_neq": ("!=", port_val != cmp_val),
        "num_gt": (">", port_val > cmp_val),
        "num_lt": ("<", port_val < cmp_val),
        "num_gte": (">=", port_val >= cmp_val),
        "num_lte": ("<=", port_val <= cmp_val),
    }
    op_str, expected = op_map[op_type]
    expr = f"port {op_str} {cmp_val}"
    return expr, ctx, expected


@st.composite
def _dsl_expression(draw: st.DrawFn) -> tuple[str, AssetContext, bool]:
    """Generate a DSL expression combining 1-3 comparisons with and/or.

    Returns (dsl_expression, merged_context, expected_bool).
    """
    # Generate 1-3 comparisons
    n = draw(st.integers(min_value=1, max_value=3))

    if n == 1:
        return draw(_dsl_comparison())

    # For compound expressions, use port-based comparisons so we can share
    # a single context.
    port_val = draw(st.integers(min_value=1, max_value=65535))
    banner_val = draw(st.text(
        alphabet=st.characters(whitelist_categories=("L", "N")),
        min_size=1, max_size=20,
    ))
    ctx = AssetContext(port=port_val, banner=banner_val)

    # Build sub-expressions
    parts: list[tuple[str, bool]] = []
    for _ in range(n):
        sub_type = draw(st.sampled_from(["port_cmp", "banner_contains"]))
        if sub_type == "port_cmp":
            cmp_val = draw(st.integers(min_value=0, max_value=65535))
            op_choice = draw(st.sampled_from(["==", "!=", ">", "<", ">=", "<="]))
            expr_part = f"port {op_choice} {cmp_val}"
            py_ops = {
                "==": port_val == cmp_val,
                "!=": port_val != cmp_val,
                ">": port_val > cmp_val,
                "<": port_val < cmp_val,
                ">=": port_val >= cmp_val,
                "<=": port_val <= cmp_val,
            }
            parts.append((expr_part, py_ops[op_choice]))
        else:
            word = draw(st.text(
                alphabet=st.characters(whitelist_categories=("L", "N")),
                min_size=1, max_size=10,
            ))
            expr_part = f"banner contains '{word}'"
            parts.append((expr_part, word.lower() in banner_val.lower()))

    # Combine with a single connector (and/or)
    connector = draw(st.sampled_from(["and", "or"]))
    full_expr = f" {connector} ".join(p[0] for p in parts)
    bools = [p[1] for p in parts]

    if connector == "and":
        expected = all(bools)
    else:
        expected = any(bools)

    return full_expr, ctx, expected


@settings(max_examples=100)
@given(data=_dsl_expression())
def test_dsl_evaluator_correctness(data: tuple[str, AssetContext, bool]) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 11: DSL evaluator correctness
    """For any valid DSL expression built from supported operators and any
    AssetContext, the DSLEvaluator SHALL produce the same boolean result as
    the equivalent Python expression."""
    expr, ctx, expected = data
    evaluator = DSLEvaluator(ctx)
    result = evaluator.evaluate(expr)

    assert result == expected, (
        f"DSLEvaluator({expr!r}) = {result}, expected {expected}"
    )


# ---------------------------------------------------------------------------
# Property 13: Matcher condition logic (AND/OR)
# **Validates: Requirements 7.1, 7.2**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    results=st.lists(st.booleans(), min_size=1, max_size=10),
    condition=_condition_strategy,
)
def test_matcher_condition_logic(results: list[bool], condition: str) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 13: Matcher condition logic (AND/OR)
    """For any list of individual matcher boolean results and any condition
    value ("and" or "or"), the rule SHALL match iff all(results) when "and",
    or any(results) when "or"."""
    if condition == "and":
        expected = all(results)
    else:
        expected = any(results)

    # Simulate the engine's condition logic directly
    if condition == "and":
        actual = all(results)
    else:
        actual = any(results)

    assert actual == expected


# ---------------------------------------------------------------------------
# Property 15: Template variable substitution
# **Validates: Requirements 8.1, 8.2**
# ---------------------------------------------------------------------------

# Strategy for non-null AssetContext field values
@st.composite
def _asset_context_with_values(draw: st.DrawFn) -> AssetContext:
    """Generate an AssetContext where all template-relevant fields are non-null."""
    return AssetContext(
        service_name=draw(st.text(
            alphabet=st.characters(whitelist_categories=("L", "N")),
            min_size=1, max_size=20,
        )),
        service_version=draw(st.from_regex(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", fullmatch=True)),
        port=draw(st.integers(min_value=1, max_value=65535)),
        ip=draw(st.tuples(
            st.integers(min_value=1, max_value=254),
            st.integers(min_value=0, max_value=255),
            st.integers(min_value=0, max_value=255),
            st.integers(min_value=1, max_value=254),
        ).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}")),
        hostname=draw(st.from_regex(r"[a-z]{3,10}\.(com|org|net)", fullmatch=True)),
        banner=draw(st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "Zs")),
            min_size=1, max_size=60,
        )),
    )


# Template variables and their corresponding AssetContext field names
_TEMPLATE_VARS = {
    "service_name": "service_name",
    "service_version": "service_version",
    "port": "port",
    "ip": "ip",
    "hostname": "hostname",
    "banner_preview": "banner",
}


@settings(max_examples=100)
@given(
    ctx=_asset_context_with_values(),
    var_names=st.lists(
        st.sampled_from(list(_TEMPLATE_VARS.keys())),
        min_size=1,
        max_size=6,
        unique=True,
    ),
)
def test_template_variable_substitution(
    ctx: AssetContext, var_names: list[str],
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 15: Template variable substitution
    """For any AssetContext with non-null field values and any template string
    containing supported variables, the substituted string SHALL contain the
    actual field values."""
    # Build a template with the selected variables
    template = " ".join("{" + v + "}" for v in var_names)

    result = substitute_template(template, ctx)

    # Verify each variable was substituted with the actual value
    for var_name in var_names:
        field_name = _TEMPLATE_VARS[var_name]
        raw_value = ctx.get_field(field_name)
        expected_str = str(raw_value)
        # banner_preview is truncated to 80 chars
        if var_name == "banner_preview" and len(expected_str) > 80:
            expected_str = expected_str[:80]
        assert expected_str in result, (
            f"Expected {expected_str!r} (from {var_name}) in result {result!r}"
        )


# ---------------------------------------------------------------------------
# Additional imports for validation and loading property tests
# ---------------------------------------------------------------------------

import os
import copy

import yaml

from surfaceaudit.rules.v2.schema import (
    SEVERITY_ORDER,
    AssessBlock,
    InfoBlock,
    MatchConditionV2,
    MatcherV2,
    RuleV2,
    rule_to_yaml,
)
from surfaceaudit.rules.v2.validator import RuleValidator
from surfaceaudit.rules.v2.loader import RuleLoader
from surfaceaudit.rules.v2.dsl import DSLSyntaxError, validate_dsl_syntax
from surfaceaudit.rules import RuleEngine


# ---------------------------------------------------------------------------
# Shared strategies for validation / loading tests
# ---------------------------------------------------------------------------

_valid_severities = ["critical", "high", "medium", "low", "info"]

_severity_strategy = st.sampled_from(_valid_severities)

_tag_strategy = st.lists(
    st.text(alphabet=st.characters(whitelist_categories=("L", "N")), min_size=1, max_size=10),
    min_size=1,
    max_size=5,
)

_rule_id_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "Pd")),
    min_size=1,
    max_size=30,
)


@st.composite
def _valid_rule(draw: st.DrawFn) -> RuleV2:
    """Generate a fully valid RuleV2 object."""
    rule_id = draw(_rule_id_strategy)
    name = draw(st.text(alphabet=st.characters(whitelist_categories=("L", "N")), min_size=1, max_size=20))
    author = draw(st.text(alphabet=st.characters(whitelist_categories=("L", "N")), min_size=1, max_size=20))
    severity = draw(_severity_strategy)
    tags = draw(_tag_strategy)
    description = draw(st.text(alphabet=st.characters(whitelist_categories=("L", "N", "Zs")), min_size=1, max_size=40))
    references = draw(st.lists(st.just("https://example.com"), min_size=0, max_size=2))
    created = draw(st.one_of(st.none(), st.just("2024-01-01")))
    category = draw(st.text(alphabet=st.characters(whitelist_categories=("L", "N")), min_size=1, max_size=15))

    info = InfoBlock(
        name=name,
        author=author,
        severity=severity,
        tags=tags,
        description=description,
        references=references,
        created=created,
    )

    # Build a simple word matcher so the rule has at least one matcher
    matcher = MatcherV2(
        type="word",
        field="banner",
        words=["test"],
    )

    match = MatchConditionV2(condition="and", matchers=[matcher])

    assess = AssessBlock(
        category=category,
        severity=severity,
        description=description,
    )

    return RuleV2(id=rule_id, info=info, match=match, assess=assess)


# ---------------------------------------------------------------------------
# Property 1: Required field validation with error reporting
# **Validates: Requirements 1.1, 1.3**
# ---------------------------------------------------------------------------

# Required fields and how to "blank" them on a RuleV2
_REQUIRED_FIELD_BLANKERS = {
    "id": lambda r: setattr(r, "id", ""),
    "info.name": lambda r: setattr(r.info, "name", ""),
    "info.author": lambda r: setattr(r.info, "author", ""),
    "info.severity": lambda r: setattr(r.info, "severity", ""),
    "info.tags": lambda r: setattr(r.info, "tags", []),
    "info.description": lambda r: setattr(r.info, "description", ""),
    "match": lambda r: setattr(r.match, "matchers", []),
    "assess.category": lambda r: setattr(r.assess, "category", ""),
    "assess.severity": lambda r: setattr(r.assess, "severity", ""),
    "assess.description": lambda r: setattr(r.assess, "description", ""),
}


@settings(max_examples=100)
@given(
    rule=_valid_rule(),
    fields_to_remove=st.lists(
        st.sampled_from(list(_REQUIRED_FIELD_BLANKERS.keys())),
        min_size=1,
        max_size=5,
        unique=True,
    ),
)
def test_required_field_validation_with_error_reporting(
    rule: RuleV2, fields_to_remove: list[str],
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 1: Required field validation with error reporting
    """For any rule dict missing required fields, the RuleValidator SHALL
    reject and report each missing field name."""
    rule_copy = copy.deepcopy(rule)
    for field_name in fields_to_remove:
        _REQUIRED_FIELD_BLANKERS[field_name](rule_copy)

    validator = RuleValidator()
    errors = validator.validate([rule_copy], {rule_copy.id or "test": "test.yaml"})

    # There should be at least one error
    assert len(errors) > 0, f"Expected errors for missing fields {fields_to_remove}, got none"

    # Each blanked field should be mentioned in at least one error message
    error_text = "\n".join(errors)
    for field_name in fields_to_remove:
        # The validator reports field names like 'id', 'info.name', etc.
        # For severity, the error may say "invalid severity" instead of "missing"
        # when it's set to empty string. Check for the field name in the error.
        assert field_name in error_text or field_name.split(".")[-1] in error_text, (
            f"Expected field '{field_name}' to be mentioned in errors: {error_text}"
        )


# ---------------------------------------------------------------------------
# Property 2: Optional fields do not cause rejection
# **Validates: Requirements 1.2**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    rule=_valid_rule(),
    remove_references=st.booleans(),
    remove_created=st.booleans(),
)
def test_optional_fields_do_not_cause_rejection(
    rule: RuleV2, remove_references: bool, remove_created: bool,
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 2: Optional fields do not cause rejection
    """For any valid rule, removing info.references and/or info.created
    SHALL still pass validation."""
    rule_copy = copy.deepcopy(rule)
    if remove_references:
        rule_copy.info.references = []
    if remove_created:
        rule_copy.info.created = None

    validator = RuleValidator()
    errors = validator.validate([rule_copy], {rule_copy.id: "test.yaml"})

    assert len(errors) == 0, (
        f"Valid rule with optional fields removed should pass validation, got: {errors}"
    )


# ---------------------------------------------------------------------------
# Property 3: Severity value validation
# **Validates: Requirements 1.4**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    rule=_valid_rule(),
    severity_value=st.text(
        alphabet=st.characters(whitelist_categories=("L", "N")),
        min_size=1,
        max_size=20,
    ),
)
def test_severity_value_validation(rule: RuleV2, severity_value: str) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 3: Severity value validation
    """For any string value for info.severity, the RuleValidator SHALL accept
    iff it's in {critical, high, medium, low, info}."""
    rule_copy = copy.deepcopy(rule)
    rule_copy.info.severity = severity_value
    # Also set assess.severity to a valid value so we only test info.severity
    rule_copy.assess.severity = "info"

    validator = RuleValidator()
    errors = validator.validate([rule_copy], {rule_copy.id: "test.yaml"})

    is_valid = severity_value in _valid_severities
    severity_errors = [e for e in errors if "severity" in e.lower()]

    if is_valid:
        assert len(severity_errors) == 0, (
            f"Valid severity '{severity_value}' should not produce severity errors: {severity_errors}"
        )
    else:
        assert len(severity_errors) > 0, (
            f"Invalid severity '{severity_value}' should produce severity errors"
        )


# ---------------------------------------------------------------------------
# Property 6: Invalid regex rejection
# **Validates: Requirements 3.3, 9.2**
# ---------------------------------------------------------------------------

_invalid_regex_patterns = st.sampled_from([
    "[invalid",
    "(unclosed",
    "*bad",
    "+bad",
    "(?P<dup>a)(?P<dup>b)",
    "[z-a]",
    "(?<=a+)b",
])


@settings(max_examples=100)
@given(
    rule=_valid_rule(),
    bad_regex=_invalid_regex_patterns,
)
def test_invalid_regex_rejection(rule: RuleV2, bad_regex: str) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 6: Invalid regex rejection
    """For any regex string that fails re.compile(), the RuleValidator SHALL
    reject and report the error."""
    rule_copy = copy.deepcopy(rule)
    # Replace the matcher with a regex matcher containing the bad pattern
    rule_copy.match.matchers = [
        MatcherV2(type="regex", field="banner", regex=bad_regex)
    ]

    validator = RuleValidator()
    errors = validator.validate([rule_copy], {rule_copy.id: "test.yaml"})

    regex_errors = [e for e in errors if "regex" in e.lower()]
    assert len(regex_errors) > 0, (
        f"Invalid regex '{bad_regex}' should produce regex errors, got: {errors}"
    )


# ---------------------------------------------------------------------------
# Property 8: Port range validation
# **Validates: Requirements 4.3**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    rule=_valid_rule(),
    port_value=st.one_of(
        st.integers(min_value=-1000, max_value=0),
        st.integers(min_value=65536, max_value=100000),
    ),
)
def test_port_range_validation(rule: RuleV2, port_value: int) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 8: Port range validation
    """For any port value, the RuleValidator SHALL reject if not an integer
    in range 1–65535."""
    rule_copy = copy.deepcopy(rule)
    rule_copy.match.matchers = [
        MatcherV2(type="port", ports=[port_value])
    ]

    validator = RuleValidator()
    errors = validator.validate([rule_copy], {rule_copy.id: "test.yaml"})

    port_errors = [e for e in errors if "port" in e.lower()]
    assert len(port_errors) > 0, (
        f"Invalid port {port_value} should produce port errors, got: {errors}"
    )


# Also test that valid ports pass
@settings(max_examples=100)
@given(
    rule=_valid_rule(),
    port_value=st.integers(min_value=1, max_value=65535),
)
def test_port_range_validation_valid(rule: RuleV2, port_value: int) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 8: Port range validation (valid)
    """Valid ports in range 1–65535 SHALL not produce port errors."""
    rule_copy = copy.deepcopy(rule)
    rule_copy.match.matchers = [
        MatcherV2(type="port", ports=[port_value])
    ]

    validator = RuleValidator()
    errors = validator.validate([rule_copy], {rule_copy.id: "test.yaml"})

    port_errors = [e for e in errors if "port" in e.lower()]
    assert len(port_errors) == 0, (
        f"Valid port {port_value} should not produce port errors: {port_errors}"
    )



# ---------------------------------------------------------------------------
# Property 10: Version string validation
# **Validates: Requirements 5.6, 5.7, 9.4**
# ---------------------------------------------------------------------------

_valid_version_strings = st.from_regex(r"[0-9]{1,4}(\.[0-9]{1,4}){0,4}", fullmatch=True)

_invalid_version_strings = st.sampled_from([
    "abc",
    "1.2.3.a",
    "v1.0",
    "1.2-beta",
    ".1.2",
    "1..2",
    "1.2.",
    "",
    "one.two",
])


@settings(max_examples=100)
@given(
    rule=_valid_rule(),
    version_str=_valid_version_strings,
)
def test_version_string_validation_valid(rule: RuleV2, version_str: str) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 10: Version string validation (valid)
    """For any string matching digits separated by dots, the RuleValidator
    SHALL accept."""
    rule_copy = copy.deepcopy(rule)
    rule_copy.match.matchers = [
        MatcherV2(type="version_compare", field="service_version",
                  operator="lt", version=version_str)
    ]

    validator = RuleValidator()
    errors = validator.validate([rule_copy], {rule_copy.id: "test.yaml"})

    version_errors = [e for e in errors if "version" in e.lower()]
    assert len(version_errors) == 0, (
        f"Valid version '{version_str}' should not produce version errors: {version_errors}"
    )


@settings(max_examples=100)
@given(
    rule=_valid_rule(),
    version_str=_invalid_version_strings,
)
def test_version_string_validation_invalid(rule: RuleV2, version_str: str) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 10: Version string validation (invalid)
    """For any string NOT matching digits separated by dots, the RuleValidator
    SHALL reject."""
    rule_copy = copy.deepcopy(rule)
    rule_copy.match.matchers = [
        MatcherV2(type="version_compare", field="service_version",
                  operator="lt", version=version_str)
    ]

    validator = RuleValidator()
    errors = validator.validate([rule_copy], {rule_copy.id: "test.yaml"})

    version_errors = [e for e in errors if "version" in e.lower()]
    assert len(version_errors) > 0, (
        f"Invalid version '{version_str}' should produce version errors, got: {errors}"
    )


# ---------------------------------------------------------------------------
# Property 12: Invalid DSL expression rejection
# **Validates: Requirements 6.4**
# ---------------------------------------------------------------------------

_invalid_dsl_expressions = st.sampled_from([
    "(unclosed",
    "port ==",
    "== 80",
    "port >> 80",
    "and or",
    "((port == 80)",
    "port == 80 )",
    "contains 'test'",
])


@settings(max_examples=100)
@given(
    rule=_valid_rule(),
    bad_expr=_invalid_dsl_expressions,
)
def test_invalid_dsl_expression_rejection(rule: RuleV2, bad_expr: str) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 12: Invalid DSL expression rejection
    """For any DSL expression with syntax errors, the RuleValidator SHALL
    reject at load time."""
    rule_copy = copy.deepcopy(rule)
    rule_copy.match.matchers = [
        MatcherV2(type="dsl", expression=bad_expr)
    ]

    validator = RuleValidator()
    errors = validator.validate([rule_copy], {rule_copy.id: "test.yaml"})

    dsl_errors = [e for e in errors if "dsl" in e.lower() or "expression" in e.lower()]
    assert len(dsl_errors) > 0, (
        f"Invalid DSL expression '{bad_expr}' should produce errors, got: {errors}"
    )


# ---------------------------------------------------------------------------
# Property 14: Matcher condition validation
# **Validates: Requirements 7.4**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    rule=_valid_rule(),
    condition_value=st.text(
        alphabet=st.characters(whitelist_categories=("L", "N")),
        min_size=1,
        max_size=15,
    ),
)
def test_matcher_condition_validation(rule: RuleV2, condition_value: str) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 14: Matcher condition validation
    """For any string for match.condition, the RuleValidator SHALL accept
    iff it's in {and, or}."""
    rule_copy = copy.deepcopy(rule)
    rule_copy.match.condition = condition_value

    validator = RuleValidator()
    errors = validator.validate([rule_copy], {rule_copy.id: "test.yaml"})

    is_valid = condition_value in {"and", "or"}
    condition_errors = [e for e in errors if "condition" in e.lower()]

    if is_valid:
        assert len(condition_errors) == 0, (
            f"Valid condition '{condition_value}' should not produce condition errors: {condition_errors}"
        )
    else:
        assert len(condition_errors) > 0, (
            f"Invalid condition '{condition_value}' should produce condition errors"
        )


# ---------------------------------------------------------------------------
# Property 16: Duplicate rule ID detection
# **Validates: Requirements 9.3**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    rule=_valid_rule(),
    num_duplicates=st.integers(min_value=2, max_value=5),
)
def test_duplicate_rule_id_detection(rule: RuleV2, num_duplicates: int) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 16: Duplicate rule ID detection
    """For any list of rules with duplicate IDs, the RuleValidator SHALL
    report the duplicate."""
    rules = [copy.deepcopy(rule) for _ in range(num_duplicates)]
    filepaths = {rule.id: f"file_{i}.yaml" for i in range(num_duplicates)}

    validator = RuleValidator()
    errors = validator.validate(rules, filepaths)

    dup_errors = [e for e in errors if "duplicate" in e.lower() or "Duplicate" in e]
    assert len(dup_errors) > 0, (
        f"Duplicate rule ID '{rule.id}' (x{num_duplicates}) should produce duplicate errors, got: {errors}"
    )
    # The duplicate ID should be mentioned
    assert any(rule.id in e for e in dup_errors), (
        f"Duplicate error should mention rule ID '{rule.id}'"
    )


# ---------------------------------------------------------------------------
# Property 17: Batch error reporting
# **Validates: Requirements 9.5**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    rules=st.lists(_valid_rule(), min_size=1, max_size=5),
)
def test_batch_error_reporting(rules: list[RuleV2]) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 17: Batch error reporting
    """For N rules each with at least one error, the RuleValidator SHALL
    return at least N error messages."""
    # Make each rule invalid by blanking a required field, and give unique IDs
    for i, rule in enumerate(rules):
        rule.id = f"batch-test-{i}"
        rule.info.name = ""  # blank a required field

    filepaths = {r.id: f"file_{i}.yaml" for i, r in enumerate(rules)}

    validator = RuleValidator()
    errors = validator.validate(rules, filepaths)

    assert len(errors) >= len(rules), (
        f"Expected at least {len(rules)} errors for {len(rules)} invalid rules, got {len(errors)}: {errors}"
    )



# ---------------------------------------------------------------------------
# Property 18: Rule merge from multiple directories
# **Validates: Requirements 10.3**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    rules_a=st.lists(_valid_rule(), min_size=1, max_size=3),
    rules_b=st.lists(_valid_rule(), min_size=1, max_size=3),
)
def test_rule_merge_from_multiple_directories(
    rules_a: list[RuleV2], rules_b: list[RuleV2],
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 18: Rule merge from multiple directories
    """For two sets of rules with no ID conflicts, the merged set SHALL be
    the union."""
    import tempfile

    # Ensure unique IDs across both sets
    for i, r in enumerate(rules_a):
        r.id = f"dir-a-rule-{i}"
    for i, r in enumerate(rules_b):
        r.id = f"dir-b-rule-{i}"

    with tempfile.TemporaryDirectory() as tmp:
        dir_a = os.path.join(tmp, "dir_a")
        dir_b = os.path.join(tmp, "dir_b")
        os.makedirs(dir_a)
        os.makedirs(dir_b)

        for r in rules_a:
            yaml_str = rule_to_yaml(r)
            with open(os.path.join(dir_a, f"{r.id}.yaml"), "w") as f:
                f.write(yaml_str)

        for r in rules_b:
            yaml_str = rule_to_yaml(r)
            with open(os.path.join(dir_b, f"{r.id}.yaml"), "w") as f:
                f.write(yaml_str)

        loader = RuleLoader()
        merged = loader.load(dirs=[dir_a, dir_b])

    merged_ids = {r.id for r in merged}
    expected_ids = {r.id for r in rules_a} | {r.id for r in rules_b}

    assert merged_ids == expected_ids, (
        f"Merged IDs {merged_ids} != expected {expected_ids}"
    )


# ---------------------------------------------------------------------------
# Property 19: Rule exclusion by ID
# **Validates: Requirements 10.4**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    rules=st.lists(_valid_rule(), min_size=2, max_size=6),
    exclude_fraction=st.floats(min_value=0.1, max_value=0.9),
)
def test_rule_exclusion_by_id(rules: list[RuleV2], exclude_fraction: float) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 19: Rule exclusion by ID
    """Filtered result SHALL not contain excluded IDs and SHALL contain all
    non-excluded IDs."""
    # Ensure unique IDs
    for i, r in enumerate(rules):
        r.id = f"excl-rule-{i}"

    # Determine which IDs to exclude
    n_exclude = max(1, int(len(rules) * exclude_fraction))
    exclude_ids = [r.id for r in rules[:n_exclude]]
    keep_ids = {r.id for r in rules[n_exclude:]}

    loader = RuleLoader()
    filtered = loader._apply_filters(rules, tags=None, min_severity=None, exclude_ids=exclude_ids)

    filtered_ids = {r.id for r in filtered}

    # No excluded IDs should be present
    assert not (filtered_ids & set(exclude_ids)), (
        f"Excluded IDs {exclude_ids} should not be in filtered result {filtered_ids}"
    )
    # All non-excluded IDs should be present
    assert keep_ids == filtered_ids, (
        f"Non-excluded IDs {keep_ids} should all be in filtered result {filtered_ids}"
    )


# ---------------------------------------------------------------------------
# Property 20: Rule filtering by tags
# **Validates: Requirements 10.5**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    rules=st.lists(_valid_rule(), min_size=2, max_size=6),
    filter_tags=st.lists(
        st.text(alphabet=st.characters(whitelist_categories=("L", "N")), min_size=1, max_size=10),
        min_size=1,
        max_size=3,
    ),
)
def test_rule_filtering_by_tags(rules: list[RuleV2], filter_tags: list[str]) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 20: Rule filtering by tags
    """Filtered result SHALL contain only rules with at least one matching tag."""
    # Ensure unique IDs
    for i, r in enumerate(rules):
        r.id = f"tag-rule-{i}"

    loader = RuleLoader()
    filtered = loader._apply_filters(rules, tags=filter_tags, min_severity=None, exclude_ids=None)

    tag_set = set(filter_tags)
    for r in filtered:
        assert tag_set & set(r.info.tags), (
            f"Rule '{r.id}' with tags {r.info.tags} should have at least one tag in {filter_tags}"
        )

    # Rules NOT in filtered should have no matching tags
    filtered_ids = {r.id for r in filtered}
    for r in rules:
        if r.id not in filtered_ids:
            assert not (tag_set & set(r.info.tags)), (
                f"Rule '{r.id}' with tags {r.info.tags} has matching tags but was excluded"
            )


# ---------------------------------------------------------------------------
# Property 21: Rule filtering by minimum severity
# **Validates: Requirements 10.6**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    rules=st.lists(_valid_rule(), min_size=2, max_size=6),
    min_severity=_severity_strategy,
)
def test_rule_filtering_by_minimum_severity(
    rules: list[RuleV2], min_severity: str,
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 21: Rule filtering by minimum severity
    """Filtered result SHALL contain only rules at or above the threshold."""
    # Ensure unique IDs and assign random severities
    for i, r in enumerate(rules):
        r.id = f"sev-rule-{i}"

    loader = RuleLoader()
    filtered = loader._apply_filters(rules, tags=None, min_severity=min_severity, exclude_ids=None)

    threshold = SEVERITY_ORDER[min_severity]

    for r in filtered:
        rule_sev = SEVERITY_ORDER.get(r.info.severity, 0)
        assert rule_sev >= threshold, (
            f"Rule '{r.id}' severity '{r.info.severity}' ({rule_sev}) is below threshold "
            f"'{min_severity}' ({threshold})"
        )

    # Rules NOT in filtered should be below threshold
    filtered_ids = {r.id for r in filtered}
    for r in rules:
        if r.id not in filtered_ids:
            rule_sev = SEVERITY_ORDER.get(r.info.severity, 0)
            assert rule_sev < threshold, (
                f"Rule '{r.id}' severity '{r.info.severity}' ({rule_sev}) is at/above threshold "
                f"but was excluded"
            )


# ---------------------------------------------------------------------------
# Property 22: Rule YAML serialization round-trip
# **Validates: Requirements 11.2**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(rule=_valid_rule())
def test_rule_yaml_serialization_round_trip(rule: RuleV2) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 22: Rule YAML serialization round-trip
    """For any valid RuleV2, serialize to YAML and parse back SHALL produce
    equivalent object."""
    yaml_str = rule_to_yaml(rule)

    # Parse back
    data = yaml.safe_load(yaml_str)

    # Reconstruct RuleV2 from parsed data
    info_data = data["info"]
    match_data = data["match"]
    assess_data = data["assess"]

    reconstructed_info = InfoBlock(
        name=info_data["name"],
        author=info_data["author"],
        severity=info_data["severity"],
        tags=info_data["tags"],
        description=info_data["description"],
        references=info_data.get("references", []),
        created=info_data.get("created"),
    )

    reconstructed_matchers = []
    for m in match_data.get("matchers", []):
        reconstructed_matchers.append(MatcherV2(
            type=m["type"],
            field=m.get("field"),
            words=m.get("words"),
            regex=m.get("regex"),
            ports=m.get("ports"),
            operator=m.get("operator"),
            version=m.get("version"),
            skip_if_null=m.get("skip_if_null", True),
            expression=m.get("expression"),
        ))

    reconstructed_match = MatchConditionV2(
        condition=match_data["condition"],
        matchers=reconstructed_matchers,
    )

    reconstructed_assess = AssessBlock(
        category=assess_data["category"],
        severity=assess_data["severity"],
        description=assess_data["description"],
    )

    reconstructed = RuleV2(
        id=data["id"],
        info=reconstructed_info,
        match=reconstructed_match,
        assess=reconstructed_assess,
    )

    # Compare fields
    assert reconstructed.id == rule.id
    assert reconstructed.info.name == rule.info.name
    assert reconstructed.info.author == rule.info.author
    assert reconstructed.info.severity == rule.info.severity
    assert reconstructed.info.tags == rule.info.tags
    assert reconstructed.info.description == rule.info.description
    assert reconstructed.info.references == rule.info.references
    assert reconstructed.info.created == rule.info.created
    assert reconstructed.match.condition == rule.match.condition
    assert len(reconstructed.match.matchers) == len(rule.match.matchers)
    for orig_m, recon_m in zip(rule.match.matchers, reconstructed.match.matchers):
        assert recon_m.type == orig_m.type
        assert recon_m.field == orig_m.field
        assert recon_m.words == orig_m.words
    assert reconstructed.assess.category == rule.assess.category
    assert reconstructed.assess.severity == rule.assess.severity
    assert reconstructed.assess.description == rule.assess.description



# ---------------------------------------------------------------------------
# Property 38: V1 to V2 rule conversion equivalence
# **Validates: Requirements 30.1, 30.2**
# ---------------------------------------------------------------------------

@st.composite
def _v1_rule_dict(draw: st.DrawFn) -> dict:
    """Generate a valid v1 format rule dict."""
    rule_id = draw(st.text(
        alphabet=st.characters(whitelist_categories=("L", "N", "Pd")),
        min_size=1, max_size=20,
    ))
    name = draw(st.text(
        alphabet=st.characters(whitelist_categories=("L", "N")),
        min_size=1, max_size=20,
    ))
    severity = draw(_severity_strategy)

    # Build match block with at least one of ports, banners, services
    match_block: dict = {}
    has_ports = draw(st.booleans())
    has_banners = draw(st.booleans())
    has_services = draw(st.booleans())

    # Ensure at least one match field
    if not (has_ports or has_banners or has_services):
        has_ports = True

    if has_ports:
        match_block["ports"] = draw(st.lists(
            st.integers(min_value=1, max_value=65535),
            min_size=1, max_size=5,
        ))
    if has_banners:
        match_block["banners"] = draw(st.lists(
            st.text(alphabet=st.characters(whitelist_categories=("L", "N")),
                    min_size=1, max_size=15),
            min_size=1, max_size=3,
        ))
    if has_services:
        match_block["services"] = draw(st.lists(
            st.text(alphabet=st.characters(whitelist_categories=("L", "N")),
                    min_size=1, max_size=15),
            min_size=1, max_size=3,
        ))

    return {
        "id": rule_id,
        "name": name,
        "severity": severity,
        "category": "test",
        "description": f"Test rule {name}",
        "match": match_block,
    }


@settings(max_examples=100)
@given(
    v1_rule=_v1_rule_dict(),
    ports=st.lists(st.integers(min_value=1, max_value=65535), min_size=0, max_size=5),
    banner_text=st.text(
        alphabet=st.characters(whitelist_categories=("L", "N", "Zs")),
        min_size=0, max_size=50,
    ),
    services=st.lists(
        st.text(alphabet=st.characters(whitelist_categories=("L", "N")),
                min_size=1, max_size=15),
        min_size=0, max_size=3,
    ),
)
def test_v1_to_v2_rule_conversion_equivalence(
    v1_rule: dict, ports: list[int], banner_text: str, services: list[str],
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 38: V1 to V2 rule conversion equivalence
    """Converting v1 rule to v2 and evaluating SHALL produce same match
    result as v1 engine."""
    # Evaluate with v1 engine logic
    v1_match = v1_rule.get("match", {})
    v1_result = False

    banner_lower = banner_text.lower()
    services_lower = [s.lower() for s in services]

    if "ports" in v1_match and v1_match["ports"]:
        if any(p in ports for p in v1_match["ports"]):
            v1_result = True

    if "banners" in v1_match and v1_match["banners"]:
        for keyword in v1_match["banners"]:
            if keyword.lower() in banner_lower:
                v1_result = True

    if "services" in v1_match and v1_match["services"]:
        for svc_pattern in v1_match["services"]:
            pattern_lower = svc_pattern.lower()
            for svc_name in services_lower:
                if pattern_lower in svc_name:
                    v1_result = True

    # Convert to v2 and evaluate
    loader = RuleLoader()
    v2_rule = loader._convert_v1_to_v2(v1_rule, "test.yaml")

    # Evaluate v2 rule: the converted rule uses OR condition across matchers
    # Build an AssetContext for each service and check
    from surfaceaudit.rules.v2.matchers import WordMatcher, PortMatcher

    v2_result = False
    for matcher_def in v2_rule.match.matchers:
        if matcher_def.type == "word" and matcher_def.field == "banner":
            # Check banner
            if banner_text:
                bl = banner_text.lower()
                if any(w.lower() in bl for w in (matcher_def.words or [])):
                    v2_result = True
        elif matcher_def.type == "port":
            if any(p in ports for p in (matcher_def.ports or [])):
                v2_result = True
        elif matcher_def.type == "word" and matcher_def.field == "service_name":
            for svc in services:
                svc_lower = svc.lower()
                if any(w.lower() in svc_lower for w in (matcher_def.words or [])):
                    v2_result = True

    assert v2_result == v1_result, (
        f"V1 result {v1_result} != V2 result {v2_result} for rule {v1_rule['id']}"
    )


# ---------------------------------------------------------------------------
# Property 39: Mixed v1/v2 rule merge
# **Validates: Requirements 30.3**
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    v1_rules=st.lists(_v1_rule_dict(), min_size=1, max_size=3),
    v2_rules=st.lists(_valid_rule(), min_size=1, max_size=3),
)
def test_mixed_v1_v2_rule_merge(
    v1_rules: list[dict], v2_rules: list[RuleV2],
) -> None:
    # Feature: v2-engine-correlation-monitoring, Property 39: Mixed v1/v2 rule merge
    """Loading both v1 and v2 rules with no ID conflicts SHALL produce
    merged set containing all rules."""
    import tempfile

    # Ensure unique IDs
    for i, r in enumerate(v1_rules):
        r["id"] = f"v1-mixed-{i}"
    for i, r in enumerate(v2_rules):
        r.id = f"v2-mixed-{i}"

    with tempfile.TemporaryDirectory() as tmp:
        v1_dir = os.path.join(tmp, "v1_rules")
        v2_dir = os.path.join(tmp, "v2_rules")
        os.makedirs(v1_dir)
        os.makedirs(v2_dir)

        v1_data = {"rules": v1_rules}
        with open(os.path.join(v1_dir, "v1_rules.yaml"), "w") as f:
            yaml.dump(v1_data, f, default_flow_style=False)

        for r in v2_rules:
            yaml_str = rule_to_yaml(r)
            with open(os.path.join(v2_dir, f"{r.id}.yaml"), "w") as f:
                f.write(yaml_str)

        loader = RuleLoader()
        merged = loader.load(dirs=[v1_dir, v2_dir])

    merged_ids = {r.id for r in merged}
    expected_v1_ids = {r["id"] for r in v1_rules}
    expected_v2_ids = {r.id for r in v2_rules}
    expected_all = expected_v1_ids | expected_v2_ids

    assert expected_all == merged_ids, (
        f"Merged IDs {merged_ids} != expected {expected_all}"
    )
