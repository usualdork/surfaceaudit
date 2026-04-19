"""YAML rule engine for classification and assessment."""

from __future__ import annotations

import glob
import os
from typing import Any

import yaml

from surfaceaudit.errors import ConfigurationError
from surfaceaudit.models import AssetType, RiskLevel, VulnerabilityIndicator
from surfaceaudit.rules.schema import AssessmentRule, ClassificationRule, MatchCondition


def _default_rules_dir() -> str:
    """Return the default rules directory (package-relative)."""
    return os.path.dirname(__file__)


class RuleEngine:
    """Loads and evaluates YAML rules for classification and assessment."""

    def __init__(self, rules_dir: str | None = None) -> None:
        self._rules_dir = rules_dir or _default_rules_dir()
        self._classification_rules: list[ClassificationRule] = []
        self._assessment_rules: list[AssessmentRule] = []

    def load(self) -> None:
        """Load all YAML rule files from the rules directory.

        Raises ConfigurationError on invalid YAML or missing required fields.
        """
        self._classification_rules = self._load_classification_rules()
        self._assessment_rules = self._load_assessment_rules()

    def classify(
        self, ports: list[int], banner_text: str, services: list[str]
    ) -> AssetType:
        """Evaluate classification rules in order, return first match or OTHER."""
        for rule in self._classification_rules:
            if self._matches(rule.match, ports, banner_text, services):
                try:
                    return AssetType(rule.asset_type)
                except ValueError:
                    continue
        return AssetType.OTHER

    def assess(
        self, ports: list[int], banner_text: str, services: list[str]
    ) -> list[VulnerabilityIndicator]:
        """Evaluate all assessment rules, return all matching indicators."""
        indicators: list[VulnerabilityIndicator] = []
        for rule in self._assessment_rules:
            if self._matches(rule.match, ports, banner_text, services):
                try:
                    severity = RiskLevel(rule.severity)
                except ValueError:
                    severity = RiskLevel.LOW
                indicators.append(
                    VulnerabilityIndicator(
                        category=rule.category,
                        description=rule.description,
                        severity=severity,
                        details=dict(rule.details_template) if rule.details_template else {},
                    )
                )
        return indicators

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _matches(
        self,
        condition: MatchCondition,
        ports: list[int],
        banner_text: str,
        services: list[str],
    ) -> bool:
        """Check if a MatchCondition is satisfied.

        A condition matches if ANY of its non-None fields match:
        - ports: any port in the condition is in the asset's ports
        - banners: any banner substring (case-insensitive) is in the banner text
        - services: any service substring (case-insensitive) is in the service names
        """
        banner_lower = banner_text.lower()
        services_lower = [s.lower() for s in services]

        if condition.ports is not None:
            if any(p in ports for p in condition.ports):
                return True

        if condition.banners is not None:
            for keyword in condition.banners:
                if keyword.lower() in banner_lower:
                    return True

        if condition.services is not None:
            for svc_pattern in condition.services:
                pattern_lower = svc_pattern.lower()
                for svc_name in services_lower:
                    if pattern_lower in svc_name:
                        return True

        return False

    def _load_classification_rules(self) -> list[ClassificationRule]:
        """Load classification rules from YAML files in classification/ subdir."""
        cls_dir = os.path.join(self._rules_dir, "classification")
        if not os.path.isdir(cls_dir):
            return []

        rules: list[ClassificationRule] = []
        for filepath in sorted(glob.glob(os.path.join(cls_dir, "*.yaml"))):
            data = self._read_yaml(filepath)
            raw_rules = data.get("rules", [])
            for raw in raw_rules:
                self._validate_classification_rule(raw, filepath)
                match = self._parse_match(raw["match"], filepath)
                rules.append(
                    ClassificationRule(
                        id=raw["id"],
                        name=raw["name"],
                        match=match,
                        asset_type=raw["asset_type"],
                    )
                )
        return rules

    def _load_assessment_rules(self) -> list[AssessmentRule]:
        """Load assessment rules from YAML files in assessment/ subdir."""
        assess_dir = os.path.join(self._rules_dir, "assessment")
        if not os.path.isdir(assess_dir):
            return []

        rules: list[AssessmentRule] = []
        for filepath in sorted(glob.glob(os.path.join(assess_dir, "*.yaml"))):
            data = self._read_yaml(filepath)
            raw_rules = data.get("rules", [])
            for raw in raw_rules:
                self._validate_assessment_rule(raw, filepath)
                match = self._parse_match(raw["match"], filepath)
                rules.append(
                    AssessmentRule(
                        id=raw["id"],
                        name=raw["name"],
                        match=match,
                        severity=raw["severity"],
                        description=raw["description"],
                        category=raw.get("category", ""),
                        details_template=raw.get("details_template"),
                    )
                )
        return rules

    def _read_yaml(self, filepath: str) -> dict[str, Any]:
        """Read and parse a YAML file, raising ConfigurationError on failure."""
        try:
            with open(filepath, "r") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise ConfigurationError(
                f"Invalid YAML in {filepath}: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise ConfigurationError(
                f"Invalid YAML in {filepath}: expected a mapping at top level"
            )
        return data

    @staticmethod
    def _validate_classification_rule(raw: Any, filepath: str) -> None:
        """Validate required fields for a classification rule."""
        required = ("id", "name", "match", "asset_type")
        for field_name in required:
            if field_name not in raw:
                raise ConfigurationError(
                    f"Classification rule in {filepath} missing required field '{field_name}'"
                )

    @staticmethod
    def _validate_assessment_rule(raw: Any, filepath: str) -> None:
        """Validate required fields for an assessment rule."""
        required = ("id", "name", "match", "severity", "description")
        for field_name in required:
            if field_name not in raw:
                raise ConfigurationError(
                    f"Assessment rule in {filepath} missing required field '{field_name}'"
                )

    @staticmethod
    def _parse_match(raw_match: Any, filepath: str) -> MatchCondition:
        """Parse a match condition dict into a MatchCondition dataclass."""
        if not isinstance(raw_match, dict):
            raise ConfigurationError(
                f"Rule in {filepath} has invalid 'match' field: expected a mapping"
            )
        try:
            return MatchCondition(
                ports=raw_match.get("ports"),
                banners=raw_match.get("banners"),
                services=raw_match.get("services"),
            )
        except ValueError as exc:
            raise ConfigurationError(
                f"Rule in {filepath} has invalid match condition: {exc}"
            ) from exc
