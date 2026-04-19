"""V2 rule loader — discovers, parses, validates, and filters YAML rule files."""

from __future__ import annotations

import glob
import logging
import os
import re
from typing import Any

import yaml

from surfaceaudit.errors import ConfigurationError
from surfaceaudit.rules.v2.schema import (
    SEVERITY_ORDER,
    AssessBlock,
    InfoBlock,
    MatchConditionV2,
    MatcherV2,
    RuleV2,
)
from surfaceaudit.rules.v2.validator import RuleValidator

logger = logging.getLogger(__name__)


def _default_rules_dir() -> str:
    """Return the bundled default rules directory (package-relative)."""
    return os.path.dirname(os.path.dirname(__file__))


class RuleLoader:
    """Discovers, parses, and filters YAML rule files."""

    def __init__(self) -> None:
        self._validator = RuleValidator()

    def load(
        self,
        dirs: list[str] | None = None,
        tags: list[str] | None = None,
        min_severity: str | None = None,
        exclude_ids: list[str] | None = None,
    ) -> list[RuleV2]:
        """Load rules from multiple directories, detect v1/v2 format,
        validate, filter, and return merged rule set."""
        if dirs is None:
            dirs = [_default_rules_dir()]

        rules: list[RuleV2] = []
        filepaths: dict[str, str] = {}

        for directory in dirs:
            loaded, paths = self._load_directory(directory)
            rules.extend(loaded)
            filepaths.update(paths)

        # Validate all rules as a batch.
        errors = self._validator.validate(rules, filepaths)
        if errors:
            raise ConfigurationError(
                "Rule validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
            )

        # Apply filters.
        rules = self._apply_filters(rules, tags, min_severity, exclude_ids)
        return rules

    # ------------------------------------------------------------------
    # Directory discovery
    # ------------------------------------------------------------------

    def _load_directory(
        self, directory: str
    ) -> tuple[list[RuleV2], dict[str, str]]:
        """Load all YAML files from a directory (recursively).

        Returns (rules, filepaths) where filepaths maps rule ID → file path.
        """
        rules: list[RuleV2] = []
        filepaths: dict[str, str] = {}

        if not os.path.isdir(directory):
            logger.warning("Rules directory does not exist: %s", directory)
            return rules, filepaths

        yaml_files = sorted(
            glob.glob(os.path.join(directory, "**", "*.yaml"), recursive=True)
            + glob.glob(os.path.join(directory, "**", "*.yml"), recursive=True)
        )

        for filepath in yaml_files:
            try:
                file_rules = self._load_file(filepath)
                for rule in file_rules:
                    filepaths[rule.id] = filepath
                rules.extend(file_rules)
            except ConfigurationError:
                raise
            except Exception as exc:
                raise ConfigurationError(
                    f"Error loading rule file {filepath}: {exc}"
                ) from exc

        return rules, filepaths

    def _load_file(self, filepath: str) -> list[RuleV2]:
        """Load rules from a single YAML file, auto-detecting v1 vs v2 format."""
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

        fmt = self._detect_format(data)
        if fmt == "v1":
            return self._parse_v1_file(data, filepath)
        return self._parse_v2_file(data, filepath)

    # ------------------------------------------------------------------
    # Format detection
    # ------------------------------------------------------------------

    def _detect_format(self, data: dict) -> str:
        """Return 'v1' if data has flat 'rules' list, 'v2' otherwise.

        V1 format: top-level ``rules`` key containing a list of dicts with
        ``match.ports``, ``match.banners``, or ``match.services`` fields.
        V2 format: top-level ``id``, ``info``, ``match.matchers``, ``assess``.
        """
        if "rules" in data and isinstance(data["rules"], list):
            # Peek at the first rule to confirm v1 structure.
            if data["rules"]:
                first = data["rules"][0]
                if isinstance(first, dict):
                    match_block = first.get("match", {})
                    if isinstance(match_block, dict):
                        v1_keys = {"ports", "banners", "services"}
                        if v1_keys & set(match_block.keys()):
                            return "v1"
            # Empty rules list under 'rules' key — treat as v1.
            return "v1"
        return "v2"

    # ------------------------------------------------------------------
    # V1 parsing and conversion
    # ------------------------------------------------------------------

    def _parse_v1_file(self, data: dict, filepath: str) -> list[RuleV2]:
        """Parse a v1 format YAML file into RuleV2 objects."""
        raw_rules = data.get("rules", [])
        rules: list[RuleV2] = []
        for raw in raw_rules:
            if not isinstance(raw, dict):
                continue
            rules.append(self._convert_v1_to_v2(raw, filepath))
        return rules

    def _convert_v1_to_v2(self, v1_rule: dict, filepath: str) -> RuleV2:
        """Convert a v1 format rule dict to a RuleV2 object.

        V1 match fields are converted to typed matchers:
        - ``match.banners`` → WordMatcher on ``banner`` field
        - ``match.ports`` → PortMatcher
        - ``match.services`` → WordMatcher on ``service_name`` field

        The v1 engine uses OR logic across match fields, so the v2
        condition is set to ``or``.
        """
        rule_id = v1_rule.get("id", self._synthesize_id(v1_rule.get("name", "unknown")))
        name = v1_rule.get("name", "Unnamed Rule")
        severity = v1_rule.get("severity", "info")
        category = v1_rule.get("category", "general")
        description = v1_rule.get("description", "")
        asset_type = v1_rule.get("asset_type", "")

        # Build matchers from v1 match block.
        match_block = v1_rule.get("match", {})
        matchers: list[MatcherV2] = []

        if "banners" in match_block and match_block["banners"]:
            matchers.append(
                MatcherV2(
                    type="word",
                    field="banner",
                    words=list(match_block["banners"]),
                )
            )

        if "ports" in match_block and match_block["ports"]:
            matchers.append(
                MatcherV2(
                    type="port",
                    ports=list(match_block["ports"]),
                )
            )

        if "services" in match_block and match_block["services"]:
            matchers.append(
                MatcherV2(
                    type="word",
                    field="service_name",
                    words=list(match_block["services"]),
                )
            )

        # Determine assess description — use description or build from asset_type.
        assess_description = description or f"Matched v1 rule: {name}"
        assess_severity = severity if severity in SEVERITY_ORDER else "info"

        # Build tags from category and filepath context.
        tags = []
        if category:
            tags.append(category)
        if "classification" in filepath:
            tags.append("classification")
        if "assessment" in filepath:
            tags.append("assessment")
        if not tags:
            tags = ["v1-converted"]

        info = InfoBlock(
            name=name,
            author="v1-auto-converted",
            severity=assess_severity,
            tags=tags,
            description=assess_description,
        )

        match_condition = MatchConditionV2(
            condition="or",
            matchers=matchers,
        )

        assess = AssessBlock(
            category=category or asset_type or "general",
            severity=assess_severity,
            description=assess_description,
        )

        return RuleV2(
            id=rule_id,
            info=info,
            match=match_condition,
            assess=assess,
        )

    @staticmethod
    def _synthesize_id(name: str) -> str:
        """Generate a synthetic rule ID from a rule name.

        Lowercases, replaces non-alphanumeric chars with hyphens, strips
        leading/trailing hyphens.
        """
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        return f"v1-{slug}" if slug else "v1-unknown"

    # ------------------------------------------------------------------
    # V2 parsing
    # ------------------------------------------------------------------

    def _parse_v2_file(self, data: dict, filepath: str) -> list[RuleV2]:
        """Parse a v2 format YAML file into a RuleV2 object.

        A v2 file contains a single rule at the top level.
        """
        try:
            rule = self._parse_v2_rule(data, filepath)
            return [rule]
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"Error parsing v2 rule in {filepath}: {exc}"
            ) from exc

    def _parse_v2_rule(self, data: dict, filepath: str) -> RuleV2:
        """Parse a single v2 rule dict into a RuleV2 dataclass."""
        rule_id = data.get("id", "")
        info_data = data.get("info", {})
        match_data = data.get("match", {})
        assess_data = data.get("assess", {})

        info = InfoBlock(
            name=info_data.get("name", ""),
            author=info_data.get("author", ""),
            severity=info_data.get("severity", ""),
            tags=info_data.get("tags", []),
            description=info_data.get("description", ""),
            references=info_data.get("references", []),
            created=info_data.get("created"),
        )

        # Parse matchers list.
        raw_matchers = match_data.get("matchers", [])
        matchers: list[MatcherV2] = []
        for raw_m in raw_matchers:
            if not isinstance(raw_m, dict):
                continue
            matchers.append(
                MatcherV2(
                    type=raw_m.get("type", ""),
                    field=raw_m.get("field"),
                    words=raw_m.get("words"),
                    regex=raw_m.get("regex"),
                    ports=raw_m.get("ports"),
                    operator=raw_m.get("operator"),
                    version=raw_m.get("version"),
                    skip_if_null=raw_m.get("skip_if_null", True),
                    expression=raw_m.get("expression"),
                )
            )

        match_condition = MatchConditionV2(
            condition=match_data.get("condition", "and"),
            matchers=matchers,
        )

        assess = AssessBlock(
            category=assess_data.get("category", ""),
            severity=assess_data.get("severity", ""),
            description=assess_data.get("description", ""),
        )

        return RuleV2(
            id=rule_id,
            info=info,
            match=match_condition,
            assess=assess,
        )

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def _apply_filters(
        self,
        rules: list[RuleV2],
        tags: list[str] | None,
        min_severity: str | None,
        exclude_ids: list[str] | None,
    ) -> list[RuleV2]:
        """Apply exclusion and inclusion filters to the rule set."""
        # Exclude by ID.
        if exclude_ids:
            exclude_set = set(exclude_ids)
            rules = [r for r in rules if r.id not in exclude_set]

        # Filter by tags (intersection).
        if tags:
            tag_set = set(tags)
            rules = [r for r in rules if tag_set & set(r.info.tags)]

        # Filter by minimum severity.
        if min_severity and min_severity in SEVERITY_ORDER:
            threshold = SEVERITY_ORDER[min_severity]
            rules = [
                r
                for r in rules
                if SEVERITY_ORDER.get(r.info.severity, 0) >= threshold
            ]

        return rules
