"""Provider registry for SurfaceAudit data source backends."""

from __future__ import annotations

from surfaceaudit.errors import ConfigurationError
from surfaceaudit.providers.base import BaseProvider


class ProviderRegistry:
    """Maps provider names to BaseProvider subclasses."""

    _providers: dict[str, type[BaseProvider]] = {}

    @classmethod
    def register(cls, name: str, provider_cls: type[BaseProvider]) -> None:
        """Register a provider class under the given name."""
        cls._providers[name] = provider_cls

    @classmethod
    def get(cls, name: str) -> type[BaseProvider]:
        """Return the provider class registered under *name*.

        Raises ``ConfigurationError`` if *name* is not recognised.
        """
        if name not in cls._providers:
            raise ConfigurationError(
                f"Unknown provider '{name}'. Available: {list(cls._providers)}"
            )
        return cls._providers[name]

    @classmethod
    def available(cls) -> list[str]:
        """Return the names of all registered providers."""
        return list(cls._providers.keys())
