"""V2 rule engine — loads, validates, and evaluates v2 rules.

Provides the same ``classify()`` / ``assess()`` interface as the v1
:class:`~surfaceaudit.rules.RuleEngine` so it can be used as a drop-in
replacement by :class:`AssetClassifier` and :class:`VulnerabilityAssessor`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from surfaceaudit.models import AssetType, RiskLevel, VulnerabilityIndicator
from surfaceaudit.rules.v2.dsl import DSLMatcher
from surfaceaudit.rules.v2.loader import RuleLoader
from surfaceaudit.rules.v2.matchers import (
    Matcher,
    PortMatcher,
    RegexMatcher,
    VersionCompareMatcher,
    WordMatcher,
)
from surfaceaudit.rules.v2.schema import AssetContext, MatcherV2, RuleV2
from surfaceaudit.rules.v2.template import substitute_template

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def _build_matcher(spec: MatcherV2) -> Matcher:
    """Instantiate the appropriate matcher class from a MatcherV2 spec."""
    if spec.type == "word":
        return WordMatcher(field=spec.field or "banner", words=spec.words or [])
    if spec.type == "regex":
        return RegexMatcher(field=spec.field or "banner", regex=spec.regex or "")
    if spec.type == "port":
        return PortMatcher(ports=spec.ports or [])
    if spec.type == "version_compare":
        return VersionCompareMatcher(
            field=spec.field or "service_version",
            operator=spec.operator or "lt",
            version=spec.version or "0",
            skip_if_null=spec.skip_if_null,
        )
    if spec.type == "dsl":
        return DSLMatcher(expression=spec.expression or "")
    # Fallback — unknown matcher type always returns False
    return _NullMatcher()


class _NullMatcher:
    """Fallback matcher that never matches."""

    def matches(self, context: AssetContext) -> bool:  # noqa: D401
        return False


def _severity_to_risk(severity: str) -> RiskLevel:
    """Map a rule severity string to a :class:`RiskLevel`."""
    mapping = {
        "critical": RiskLevel.HIGH,
        "high": RiskLevel.HIGH,
        "medium": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
        "info": RiskLevel.LOW,
    }
    return mapping.get(severity.lower(), RiskLevel.LOW)


def _build_contexts(
    ports: list[int], banner_text: str, services: list[str],
) -> list[AssetContext]:
    """Build one :class:`AssetContext` per service (or a single fallback).

    For rules that need to evaluate against each service on an asset, the
    engine creates one ``AssetContext`` per service and evaluates the rule
    against each context.  A rule matches the asset if it matches *any*
    service context.
    """
    if not services:
        return [
            AssetContext(
                banner=banner_text,
                ports=list(ports),
            )
        ]

    contexts: list[AssetContext] = []
    for svc in services:
        contexts.append(
            AssetContext(
                service_name=svc,
                banner=banner_text,
                ports=list(ports),
            )
        )
    return contexts


class RuleEngineV2:
    """Loads, validates, and evaluates v2 rules.

    Exposes the same ``classify()`` / ``assess()`` signatures as the v1
    :class:`~surfaceaudit.rules.RuleEngine`.
    """

    def __init__(self) -> None:
        self._rules: list[RuleV2] = []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(
        self,
        rules_dirs: list[str] | None = None,
        tags: list[str] | None = None,
        min_severity: str | None = None,
        exclude_ids: list[str] | None = None,
    ) -> None:
        """Load and validate rules from directories with optional filters."""
        loader = RuleLoader()
        self._rules = loader.load(
            dirs=rules_dirs,
            tags=tags,
            min_severity=min_severity,
            exclude_ids=exclude_ids,
        )

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def classify(
        self, ports: list[int], banner_text: str, services: list[str],
    ) -> AssetType:
        """Evaluate classification rules. Returns first match or OTHER."""
        classification_rules = [
            r for r in self._rules if "classification" in r.info.tags
        ]
        contexts = _build_contexts(ports, banner_text, services)

        for rule in classification_rules:
            for ctx in contexts:
                if self.evaluate_rule(rule, ctx):
                    # Map the assess.category to an AssetType
                    try:
                        return AssetType(rule.assess.category)
                    except ValueError:
                        # Category doesn't map to a known AssetType — skip
                        continue
        return AssetType.OTHER

    # ------------------------------------------------------------------
    # Assessment
    # ------------------------------------------------------------------

    def assess(
        self, ports: list[int], banner_text: str, services: list[str],
    ) -> list[VulnerabilityIndicator]:
        """Evaluate all assessment rules. Returns matching indicators."""
        indicators: list[VulnerabilityIndicator] = []
        contexts = _build_contexts(ports, banner_text, services)

        for rule in self._rules:
            for ctx in contexts:
                if self.evaluate_rule(rule, ctx):
                    description = substitute_template(
                        rule.assess.description, ctx,
                    )
                    severity = _severity_to_risk(rule.assess.severity)
                    indicators.append(
                        VulnerabilityIndicator(
                            category=rule.assess.category,
                            description=description,
                            severity=severity,
                        )
                    )
                    # Only match once per rule (first matching context wins)
                    break

        return indicators

    # ------------------------------------------------------------------
    # Rule evaluation
    # ------------------------------------------------------------------

    def evaluate_rule(self, rule: RuleV2, context: AssetContext) -> bool:
        """Evaluate a single rule against an asset context.

        Builds the appropriate matcher instance for each ``MatcherV2`` in
        the rule, evaluates each against *context*, and applies AND/OR
        condition logic based on ``rule.match.condition``.
        """
        if not rule.match.matchers:
            return False

        results: list[bool] = []
        for spec in rule.match.matchers:
            matcher = _build_matcher(spec)
            results.append(matcher.matches(context))

        condition = rule.match.condition
        if condition == "or":
            return any(results)
        # Default to AND
        return all(results)
