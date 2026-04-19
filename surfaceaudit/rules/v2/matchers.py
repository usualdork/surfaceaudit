"""V2 matcher implementations for the rule engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from surfaceaudit.rules.v2.version import _compare, parse_version

if TYPE_CHECKING:
    from surfaceaudit.rules.v2.schema import AssetContext


@runtime_checkable
class Matcher(Protocol):
    """Protocol for all v2 matchers."""

    def matches(self, context: "AssetContext") -> bool:
        """Return True if this matcher matches the given asset context."""
        ...


@dataclass
class WordMatcher:
    """Case-insensitive substring matcher against a named field."""

    field: str
    words: list[str]

    def matches(self, context: "AssetContext") -> bool:
        """Case-insensitive substring match of any word against the field value."""
        value = context.get_field(self.field)
        if not value or not isinstance(value, str):
            return False
        value_lower = value.lower()
        return any(w.lower() in value_lower for w in self.words)


@dataclass
class RegexMatcher:
    """Regex pattern matcher against a named field."""

    field: str
    regex: str
    _compiled: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.regex, re.IGNORECASE)

    def matches(self, context: "AssetContext") -> bool:
        value = context.get_field(self.field)
        if not value or not isinstance(value, str):
            return False
        return bool(self._compiled.search(value))


@dataclass
class PortMatcher:
    """Matches when any port in the matcher's list is in the asset's open ports."""

    ports: list[int]

    def matches(self, context: "AssetContext") -> bool:
        asset_ports = context.ports
        return any(p in asset_ports for p in self.ports)


@dataclass
class VersionCompareMatcher:
    """Semantic version comparison matcher against a named field."""

    field: str
    operator: str  # "lt", "lte", "gt", "gte", "eq"
    version: str
    skip_if_null: bool = True

    def matches(self, context: "AssetContext") -> bool:
        raw = context.get_field(self.field)
        if not raw or not isinstance(raw, str) or not raw.strip():
            return not self.skip_if_null
        parsed = parse_version(raw)
        threshold = parse_version(self.version)
        return _compare(parsed, threshold, self.operator)
