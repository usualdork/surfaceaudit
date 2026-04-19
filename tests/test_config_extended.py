"""Unit tests for extended ScanConfig fields (provider, rules_dir, sarif output).

Validates: Requirements 10.1, 10.2, 10.3, 10.6
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from surfaceaudit.config import ScanConfig


# Minimum required fields for a valid ScanConfig
_BASE = dict(api_key="test-key", targets=["example.com"])


class TestProviderDefault:
    """Requirement 10.1 – provider defaults to 'shodan'."""

    def test_provider_defaults_to_shodan(self) -> None:
        cfg = ScanConfig(**_BASE)
        assert cfg.provider == "shodan"

    def test_provider_explicit_shodan(self) -> None:
        cfg = ScanConfig(**_BASE, provider="shodan")
        assert cfg.provider == "shodan"


class TestRulesDirDefault:
    """Requirement 10.2 – rules_dir defaults to None."""

    def test_rules_dir_defaults_to_none(self) -> None:
        cfg = ScanConfig(**_BASE)
        assert cfg.rules_dir is None

    def test_rules_dir_accepts_custom_path(self) -> None:
        cfg = ScanConfig(**_BASE, rules_dir="/tmp/my_rules")
        assert cfg.rules_dir == "/tmp/my_rules"


class TestSarifOutputFormat:
    """Requirement 10.3 – 'sarif' is a valid output_format."""

    def test_sarif_accepted(self) -> None:
        cfg = ScanConfig(**_BASE, output_format="sarif")
        assert cfg.output_format == "sarif"

    def test_other_formats_still_accepted(self) -> None:
        for fmt in ("json", "csv", "html"):
            cfg = ScanConfig(**_BASE, output_format=fmt)
            assert cfg.output_format == fmt


class TestInvalidProvider:
    """Requirement 10.6 – invalid provider raises validation error."""

    def test_unknown_provider_raises(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            ScanConfig(**_BASE, provider="nonexistent_provider")
        errors = exc_info.value.errors()
        assert any("provider" in str(e.get("loc", "")) for e in errors)

    def test_empty_provider_raises(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            ScanConfig(**_BASE, provider="")
        errors = exc_info.value.errors()
        assert any("provider" in str(e.get("loc", "")) for e in errors)
