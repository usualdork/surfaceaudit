"""V2 rule schema dataclasses and constants."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml


# Severity ordering used for filtering and risk-increase detection.
SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class AssetContext:
    """Flat view of an asset for matcher field access."""

    service_name: str | None = None
    service_version: str | None = None
    port: int | None = None
    banner: str | None = None
    ip: str | None = None
    hostname: str | None = None
    ports: list[int] = field(default_factory=list)
    os: str | None = None

    def get_field(self, field_name: str) -> str | int | list | None:
        """Return the value of the named field, or ``None`` if not found."""
        return getattr(self, field_name, None)


@dataclass
class InfoBlock:
    """Structured metadata for a v2 rule."""

    name: str
    author: str
    severity: str  # "critical", "high", "medium", "low", "info"
    tags: list[str]
    description: str
    references: list[str] = field(default_factory=list)
    created: str | None = None


@dataclass
class MatcherV2:
    """A single matcher definition within a v2 rule."""

    type: str  # "word", "regex", "port", "version_compare", "dsl"
    field: str | None = None
    words: list[str] | None = None
    regex: str | None = None
    ports: list[int] | None = None
    operator: str | None = None
    version: str | None = None
    skip_if_null: bool = True
    expression: str | None = None


@dataclass
class MatchConditionV2:
    """Logical grouping of matchers with AND/OR condition."""

    condition: str = "and"  # "and" or "or"
    matchers: list[MatcherV2] = field(default_factory=list)


@dataclass
class AssessBlock:
    """Assessment output metadata for a matched rule."""

    category: str
    severity: str
    description: str


@dataclass
class RuleV2:
    """A complete v2 rule with metadata, match logic, and assessment output."""

    id: str
    info: InfoBlock
    match: MatchConditionV2
    assess: AssessBlock


def _matcher_to_dict(matcher: MatcherV2) -> dict[str, Any]:
    """Convert a MatcherV2 dataclass to a dict, omitting None-valued optional fields."""
    d: dict[str, Any] = {"type": matcher.type}
    if matcher.field is not None:
        d["field"] = matcher.field
    if matcher.words is not None:
        d["words"] = list(matcher.words)
    if matcher.regex is not None:
        d["regex"] = matcher.regex
    if matcher.ports is not None:
        d["ports"] = list(matcher.ports)
    if matcher.operator is not None:
        d["operator"] = matcher.operator
    if matcher.version is not None:
        d["version"] = matcher.version
    if not matcher.skip_if_null:
        d["skip_if_null"] = matcher.skip_if_null
    if matcher.expression is not None:
        d["expression"] = matcher.expression
    return d


def _rule_to_dict(rule: RuleV2) -> dict[str, Any]:
    """Convert a RuleV2 dataclass to a dict matching the v2 YAML format."""
    return {
        "id": rule.id,
        "info": {
            "name": rule.info.name,
            "author": rule.info.author,
            "severity": rule.info.severity,
            "tags": list(rule.info.tags),
            "description": rule.info.description,
            "references": list(rule.info.references),
            "created": rule.info.created,
        },
        "match": {
            "condition": rule.match.condition,
            "matchers": [_matcher_to_dict(m) for m in rule.match.matchers],
        },
        "assess": {
            "category": rule.assess.category,
            "severity": rule.assess.severity,
            "description": rule.assess.description,
        },
    }


def rule_to_yaml(rule: RuleV2) -> str:
    """Serialize a RuleV2 object to a YAML string.

    The output is parseable by RuleLoader._parse_v2_rule() to produce
    an equivalent RuleV2 object (round-trip property).
    """
    return yaml.dump(_rule_to_dict(rule), default_flow_style=False, sort_keys=False)
