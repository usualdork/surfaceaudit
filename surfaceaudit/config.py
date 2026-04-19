"""Configuration management for SurfaceAudit."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from surfaceaudit.errors import ConfigurationError


# Ensure the Shodan provider is registered before any provider validation runs.
import surfaceaudit.providers.shodan  # noqa: F401
from surfaceaudit.providers import ProviderRegistry


# ---------------------------------------------------------------------------
# Environment variable resolution helper
# ---------------------------------------------------------------------------

_ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _resolve_env_vars(value: str | None) -> str | None:
    """Replace ``${VAR_NAME}`` tokens with environment variable values.

    If the referenced variable is not set, the token is replaced with an
    empty string (effectively disabling the provider).
    """
    if value is None:
        return None
    return _ENV_VAR_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)


# ---------------------------------------------------------------------------
# Enrichment configuration models
# ---------------------------------------------------------------------------


class EnrichmentProviderConfig(BaseModel):
    """Configuration for a single enrichment provider."""

    enabled: bool = True
    api_key: str | None = None

    @field_validator("api_key", mode="before")
    @classmethod
    def _resolve_api_key(cls, v: str | None) -> str | None:
        return _resolve_env_vars(v)


class EnrichmentConfig(BaseModel):
    """Top-level enrichment configuration."""

    enabled: bool = False
    providers: dict[str, EnrichmentProviderConfig] = {}
    cache_dir: str = ".surfaceaudit/cache"
    cache_ttl_hours: int = 24


# ---------------------------------------------------------------------------
# Watch / notification configuration models
# ---------------------------------------------------------------------------


class NotificationConfig(BaseModel):
    """Configuration for a single notification channel."""

    type: str  # "slack", "discord", "webhook"
    webhook_url: str | None = None
    url: str | None = None
    on: list[str] = []


class WatchConfig(BaseModel):
    """Watch-mode configuration."""

    history_dir: str = ".surfaceaudit/history"
    notifications: list[NotificationConfig] = []


class AIConfig(BaseModel):
    """AI analysis configuration."""

    enabled: bool = False
    api_key: str | None = None
    model: str = "gemma-4-31b-it"

    @field_validator("api_key", mode="before")
    @classmethod
    def _resolve_api_key(cls, v: str | None) -> str | None:
        return _resolve_env_vars(v)


class ScanConfig(BaseModel):
    """Validated scan configuration with file I/O and merge support."""

    api_key: str
    targets: list[str]
    output_format: str = "json"
    output_file: str | None = None
    encrypt_reports: bool = False
    redact_sensitive: bool = False
    rate_limit_delay: float = Field(default=1.0, ge=0)
    retry_attempts: int = Field(default=3, ge=0)
    credit_warning_threshold: int = Field(default=10, ge=0)
    provider: str = "shodan"
    rules_dir: str | None = None
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig)
    watch: WatchConfig = Field(default_factory=WatchConfig)
    ai: AIConfig = Field(default_factory=AIConfig)

    @field_validator("api_key")
    @classmethod
    def _api_key_non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("api_key must be a non-empty string")
        return v

    @field_validator("targets")
    @classmethod
    def _targets_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("targets must be a non-empty list")
        return v

    @field_validator("output_format")
    @classmethod
    def _output_format_valid(cls, v: str) -> str:
        allowed = {"json", "csv", "html", "sarif"}
        if v not in allowed:
            raise ValueError(f"output_format must be one of {allowed}, got '{v}'")
        return v

    @field_validator("provider")
    @classmethod
    def _provider_valid(cls, v: str) -> str:
        if v not in ProviderRegistry.available():
            raise ValueError(
                f"Unknown provider '{v}'. Available: {ProviderRegistry.available()}"
            )
        return v


    # ------------------------------------------------------------------
    # Factory / persistence helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_file(cls, path: str) -> "ScanConfig":
        """Load configuration from a JSON or YAML file.

        The format is detected by file extension: ``.json`` for JSON,
        ``.yaml`` or ``.yml`` for YAML.

        Raises:
            ConfigurationError: If the file cannot be read, parsed, or
                contains invalid configuration values.
        """
        file_path = Path(path)

        if not file_path.exists():
            raise ConfigurationError(f"Configuration file not found: {path}")

        ext = file_path.suffix.lower()
        try:
            raw_text = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"Cannot read configuration file: {exc}") from exc

        try:
            if ext == ".json":
                data = json.loads(raw_text)
            elif ext in {".yaml", ".yml"}:
                data = yaml.safe_load(raw_text)
            else:
                raise ConfigurationError(
                    f"Unsupported config file extension '{ext}'. Use .json, .yaml, or .yml"
                )
        except (json.JSONDecodeError, yaml.YAMLError) as exc:
            raise ConfigurationError(f"Failed to parse configuration file: {exc}") from exc

        if not isinstance(data, dict):
            raise ConfigurationError("Configuration file must contain a mapping/object")

        try:
            return cls(**data)
        except Exception as exc:
            raise ConfigurationError(f"Invalid configuration: {exc}") from exc

    @classmethod
    def merge(cls, file_config: dict, cli_overrides: dict) -> "ScanConfig":
        """Create a config by merging file values with CLI overrides.

        CLI overrides take precedence: any key present in *cli_overrides*
        replaces the corresponding value from *file_config*.

        Raises:
            ConfigurationError: If the merged result fails validation.
        """
        merged = {**file_config, **cli_overrides}
        try:
            return cls(**merged)
        except Exception as exc:
            raise ConfigurationError(f"Invalid configuration: {exc}") from exc

    def save(self, path: str) -> None:
        """Persist the configuration to a JSON or YAML file.

        The format is detected by file extension.

        Raises:
            ConfigurationError: If the file cannot be written.
        """
        file_path = Path(path)
        ext = file_path.suffix.lower()
        data = self.model_dump()

        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            if ext == ".json":
                file_path.write_text(
                    json.dumps(data, indent=2) + "\n", encoding="utf-8"
                )
            elif ext in {".yaml", ".yml"}:
                file_path.write_text(
                    yaml.dump(data, default_flow_style=False), encoding="utf-8"
                )
            else:
                raise ConfigurationError(
                    f"Unsupported config file extension '{ext}'. Use .json, .yaml, or .yml"
                )
        except OSError as exc:
            raise ConfigurationError(f"Cannot write configuration file: {exc}") from exc
