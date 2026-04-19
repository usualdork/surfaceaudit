"""V2 rule validator — validates rules at load time and collects all errors."""

from __future__ import annotations

import re
from collections import Counter

from surfaceaudit.rules.v2.dsl import DSLSyntaxError, validate_dsl_syntax
from surfaceaudit.rules.v2.schema import SEVERITY_ORDER, RuleV2

# Valid sets for enum-like fields.
_VALID_SEVERITIES = frozenset(SEVERITY_ORDER.keys())
_VALID_OPERATORS = frozenset({"lt", "lte", "gt", "gte", "eq"})
_VALID_CONDITIONS = frozenset({"and", "or"})

# Version string pattern: digits separated by dots (e.g. "1.20.0", "8.0").
_VERSION_RE = re.compile(r"^\d+(\.\d+)*$")


class RuleValidator:
    """Validates v2 rules at load time. Collects all errors before raising."""

    def validate(self, rules: list[RuleV2], filepaths: dict[str, str]) -> list[str]:
        """Validate all rules. Returns list of error messages.

        Checks: required fields, severity values, regex compilation,
        duplicate IDs, version string format, DSL syntax, port ranges,
        matcher condition values.
        """
        errors: list[str] = []

        # --- duplicate ID detection ---
        id_counts = Counter(r.id for r in rules)
        for rule_id, count in id_counts.items():
            if count > 1:
                paths = [
                    filepaths.get(r.id, "<unknown>")
                    for r in rules
                    if r.id == rule_id
                ]
                errors.append(
                    f"Duplicate rule ID '{rule_id}' found in: {', '.join(paths)}"
                )

        # --- per-rule validation ---
        for rule in rules:
            filepath = filepaths.get(rule.id, "<unknown>")
            errors.extend(self._validate_rule(rule, filepath))

        return errors

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_rule(self, rule: RuleV2, filepath: str) -> list[str]:
        """Validate a single rule and return any error messages."""
        errors: list[str] = []
        prefix = f"Rule '{rule.id}' ({filepath})"

        # --- required fields ---
        errors.extend(self._check_required_fields(rule, prefix))

        # --- severity ---
        if rule.info.severity not in _VALID_SEVERITIES:
            errors.append(
                f"{prefix}: invalid severity '{rule.info.severity}', "
                f"must be one of {sorted(_VALID_SEVERITIES)}"
            )

        # --- match.condition ---
        if rule.match.condition not in _VALID_CONDITIONS:
            errors.append(
                f"{prefix}: invalid match.condition '{rule.match.condition}', "
                f"must be one of {sorted(_VALID_CONDITIONS)}"
            )

        # --- per-matcher validation ---
        for i, matcher in enumerate(rule.match.matchers):
            m_prefix = f"{prefix} matcher[{i}]"
            errors.extend(self._validate_matcher(matcher, m_prefix))

        return errors

    def _check_required_fields(self, rule: RuleV2, prefix: str) -> list[str]:
        """Check that all required fields are present and non-empty."""
        errors: list[str] = []

        if not rule.id:
            errors.append(f"{prefix}: missing required field 'id'")
        if not rule.info.name:
            errors.append(f"{prefix}: missing required field 'info.name'")
        if not rule.info.author:
            errors.append(f"{prefix}: missing required field 'info.author'")
        if not rule.info.severity:
            errors.append(f"{prefix}: missing required field 'info.severity'")
        if not rule.info.tags:
            errors.append(f"{prefix}: missing required field 'info.tags'")
        if not rule.info.description:
            errors.append(f"{prefix}: missing required field 'info.description'")
        if not rule.match.matchers:
            errors.append(f"{prefix}: missing required field 'match' (no matchers)")
        if not rule.assess.category:
            errors.append(f"{prefix}: missing required field 'assess.category'")
        if not rule.assess.severity:
            errors.append(f"{prefix}: missing required field 'assess.severity'")
        if not rule.assess.description:
            errors.append(f"{prefix}: missing required field 'assess.description'")

        return errors

    def _validate_matcher(self, matcher, prefix: str) -> list[str]:
        """Validate a single MatcherV2 based on its type."""
        from surfaceaudit.rules.v2.schema import MatcherV2

        errors: list[str] = []

        if matcher.type == "regex":
            errors.extend(self._validate_regex_matcher(matcher, prefix))
        elif matcher.type == "version_compare":
            errors.extend(self._validate_version_matcher(matcher, prefix))
        elif matcher.type == "port":
            errors.extend(self._validate_port_matcher(matcher, prefix))
        elif matcher.type == "dsl":
            errors.extend(self._validate_dsl_matcher(matcher, prefix))

        return errors

    def _validate_regex_matcher(self, matcher, prefix: str) -> list[str]:
        """Compile the regex pattern and report errors."""
        errors: list[str] = []
        if matcher.regex is not None:
            try:
                re.compile(matcher.regex)
            except re.error as exc:
                errors.append(f"{prefix}: invalid regex '{matcher.regex}': {exc}")
        return errors

    def _validate_version_matcher(self, matcher, prefix: str) -> list[str]:
        """Validate version string format and operator value."""
        errors: list[str] = []

        if matcher.version is not None and not _VERSION_RE.match(matcher.version):
            errors.append(
                f"{prefix}: invalid version string '{matcher.version}', "
                "must be digits separated by dots (e.g. '1.20.0')"
            )

        if matcher.operator is not None and matcher.operator not in _VALID_OPERATORS:
            errors.append(
                f"{prefix}: invalid operator '{matcher.operator}', "
                f"must be one of {sorted(_VALID_OPERATORS)}"
            )

        return errors

    def _validate_port_matcher(self, matcher, prefix: str) -> list[str]:
        """Validate that all ports are integers in range 1–65535."""
        errors: list[str] = []
        if matcher.ports is not None:
            for port in matcher.ports:
                if not isinstance(port, int) or port < 1 or port > 65535:
                    errors.append(
                        f"{prefix}: invalid port {port}, must be integer in range 1–65535"
                    )
        return errors

    def _validate_dsl_matcher(self, matcher, prefix: str) -> list[str]:
        """Validate DSL expression syntax."""
        errors: list[str] = []
        if matcher.expression is not None:
            try:
                validate_dsl_syntax(matcher.expression)
            except DSLSyntaxError as exc:
                errors.append(
                    f"{prefix}: invalid DSL expression '{matcher.expression}': {exc}"
                )
        return errors
