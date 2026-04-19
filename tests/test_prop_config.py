# Feature: shodan-infrastructure-scanner, Property 10: Configuration validation rejects invalid input
"""Property-based test for ScanConfig validation of invalid input.

**Validates: Requirements 9.4**

For any configuration with missing required fields (empty api_key, empty targets
list) or invalid values (negative rate_limit_delay, output_format not in allowed
set), the validator should reject it with a descriptive error.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from surfaceaudit.config import ScanConfig

# ---------------------------------------------------------------------------
# Helpers – a valid base config to mutate one field at a time
# ---------------------------------------------------------------------------
_VALID_BASE = dict(
    api_key="test-key-123",
    targets=["example.com"],
    output_format="json",
    rate_limit_delay=1.0,
)


# ---------------------------------------------------------------------------
# Strategy: empty / whitespace-only api_key
# ---------------------------------------------------------------------------
_empty_api_keys = st.sampled_from(["", "   ", "\t", "\n"])


@settings(max_examples=100)
@given(bad_key=_empty_api_keys)
def test_rejects_empty_api_key(bad_key: str) -> None:
    """An empty or whitespace-only api_key must be rejected."""
    with pytest.raises(ValidationError) as exc_info:
        ScanConfig(**{**_VALID_BASE, "api_key": bad_key})
    errors = exc_info.value.errors()
    assert any("api_key" in str(e.get("loc", "")) for e in errors)


# ---------------------------------------------------------------------------
# Strategy: empty targets list
# ---------------------------------------------------------------------------
@settings(max_examples=100)
@given(data=st.just([]))
def test_rejects_empty_targets(data: list) -> None:
    """An empty targets list must be rejected."""
    with pytest.raises(ValidationError) as exc_info:
        ScanConfig(**{**_VALID_BASE, "targets": data})
    errors = exc_info.value.errors()
    assert any("targets" in str(e.get("loc", "")) for e in errors)


# ---------------------------------------------------------------------------
# Strategy: negative rate_limit_delay
# ---------------------------------------------------------------------------
_negative_delays = st.floats(max_value=-0.001, allow_nan=False, allow_infinity=False)


@settings(max_examples=100)
@given(bad_delay=_negative_delays)
def test_rejects_negative_rate_limit_delay(bad_delay: float) -> None:
    """A negative rate_limit_delay must be rejected."""
    with pytest.raises(ValidationError) as exc_info:
        ScanConfig(**{**_VALID_BASE, "rate_limit_delay": bad_delay})
    errors = exc_info.value.errors()
    assert any("rate_limit_delay" in str(e.get("loc", "")) for e in errors)


# ---------------------------------------------------------------------------
# Strategy: output_format not in {"json", "csv", "html", "sarif"}
# ---------------------------------------------------------------------------
_invalid_formats = st.text(min_size=1).filter(lambda s: s not in {"json", "csv", "html", "sarif"})


@settings(max_examples=100)
@given(bad_format=_invalid_formats)
def test_rejects_invalid_output_format(bad_format: str) -> None:
    """An output_format outside the allowed set must be rejected."""
    with pytest.raises(ValidationError) as exc_info:
        ScanConfig(**{**_VALID_BASE, "output_format": bad_format})
    errors = exc_info.value.errors()
    assert any("output_format" in str(e.get("loc", "")) for e in errors)


# Feature: shodan-infrastructure-scanner, Property 11: Configuration round-trip
# ---------------------------------------------------------------------------
# Property-based test for ScanConfig round-trip through JSON and YAML files.
#
# **Validates: Requirements 9.1, 9.5**
#
# For any valid ScanConfig, saving to a JSON file and loading from that file
# should produce an equivalent ScanConfig. The same should hold for YAML format.
# ---------------------------------------------------------------------------

import tempfile
import os

# Strategy: generate valid ScanConfig instances
_valid_scan_configs = st.builds(
    ScanConfig,
    api_key=st.text(min_size=1, max_size=50).filter(lambda s: s.strip()),
    targets=st.lists(st.text(min_size=1, max_size=50), min_size=1, max_size=5),
    output_format=st.sampled_from(["json", "csv", "html", "sarif"]),
    output_file=st.one_of(st.none(), st.text(min_size=1, max_size=50)),
    encrypt_reports=st.booleans(),
    redact_sensitive=st.booleans(),
    rate_limit_delay=st.floats(min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
    retry_attempts=st.integers(min_value=0, max_value=100),
    credit_warning_threshold=st.integers(min_value=0, max_value=10000),
)


@settings(max_examples=100)
@given(config=_valid_scan_configs)
def test_config_roundtrip_json(config: ScanConfig) -> None:
    """Saving a ScanConfig to JSON and loading it back produces an equivalent config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "config.json")
        config.save(path)
        loaded = ScanConfig.from_file(path)
        assert loaded == config


@settings(max_examples=100)
@given(config=_valid_scan_configs)
def test_config_roundtrip_yaml(config: ScanConfig) -> None:
    """Saving a ScanConfig to YAML and loading it back produces an equivalent config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "config.yaml")
        config.save(path)
        loaded = ScanConfig.from_file(path)
        assert loaded == config


# Feature: shodan-infrastructure-scanner, Property 12: CLI overrides take precedence
# ---------------------------------------------------------------------------
# Property-based test for CLI override precedence in ScanConfig.merge().
#
# **Validates: Requirements 9.3**
#
# For any file-based configuration and any CLI override for a given field,
# the merged configuration should use the CLI value for that field and the
# file value for all other fields.
# ---------------------------------------------------------------------------

# Overridable fields with strategies that produce valid alternative values
_OVERRIDABLE_FIELDS: dict[str, st.SearchStrategy] = {
    "api_key": st.text(min_size=1, max_size=50).filter(lambda s: s.strip()),
    "targets": st.lists(st.text(min_size=1, max_size=50), min_size=1, max_size=5),
    "output_format": st.sampled_from(["json", "csv", "html", "sarif"]),
    "output_file": st.one_of(st.none(), st.text(min_size=1, max_size=50)),
    "encrypt_reports": st.booleans(),
    "redact_sensitive": st.booleans(),
    "rate_limit_delay": st.floats(min_value=0.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
    "retry_attempts": st.integers(min_value=0, max_value=100),
    "credit_warning_threshold": st.integers(min_value=0, max_value=10000),
}


@st.composite
def _file_config_and_cli_override(draw: st.DrawFn):
    """Draw a valid file config dict and a single-field CLI override."""
    base = draw(_valid_scan_configs)
    file_config = base.model_dump()

    field_name = draw(st.sampled_from(sorted(_OVERRIDABLE_FIELDS.keys())))
    cli_value = draw(_OVERRIDABLE_FIELDS[field_name])

    return file_config, field_name, cli_value


@settings(max_examples=100)
@given(data=_file_config_and_cli_override())
def test_cli_override_precedence(data: tuple) -> None:
    """CLI overrides take precedence over file-based configuration values."""
    file_config, overridden_field, cli_value = data
    cli_overrides = {overridden_field: cli_value}

    merged = ScanConfig.merge(file_config, cli_overrides)

    # The overridden field must use the CLI value
    assert getattr(merged, overridden_field) == cli_value

    # All other fields must retain the file-based value
    for field_name in _OVERRIDABLE_FIELDS:
        if field_name != overridden_field:
            assert getattr(merged, field_name) == file_config[field_name]


# Feature: shodan-infrastructure-scanner, Property 1: Valid targets are accepted by configuration
# ---------------------------------------------------------------------------
# Property-based test for valid target acceptance by ScanConfig.
#
# **Validates: Requirements 2.1**
#
# For any valid target string (well-formed domain name, valid IP range in CIDR
# notation, or non-empty organization name), the configuration validator should
# accept it without error. The ScanConfig targets field accepts any non-empty
# list of non-empty strings — domain/IP/org validation happens at the Shodan
# API level, not at config level.
# ---------------------------------------------------------------------------

# Strategies for realistic target strings
_domain_names = st.from_regex(r"[a-z][a-z0-9]{0,10}\.(com|org|net|io)", fullmatch=True)
_cidr_ranges = st.tuples(
    st.integers(min_value=1, max_value=223),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=0, max_value=255),
    st.integers(min_value=8, max_value=32),
).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}/{t[4]}")
_org_names = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "Zs")),
    min_size=1,
    max_size=50,
).filter(lambda s: s.strip())

_valid_targets = st.one_of(_domain_names, _cidr_ranges, _org_names)


@settings(max_examples=100)
@given(target=_valid_targets)
def test_valid_targets_accepted(target: str) -> None:
    """Any non-empty target string should be accepted by ScanConfig without error."""
    config = ScanConfig(api_key="test-key-123", targets=[target])
    assert config.targets == [target]


@settings(max_examples=100)
@given(targets=st.lists(_valid_targets, min_size=1, max_size=10))
def test_valid_target_lists_accepted(targets: list[str]) -> None:
    """Any non-empty list of non-empty target strings should be accepted."""
    config = ScanConfig(api_key="test-key-123", targets=targets)
    assert config.targets == targets
