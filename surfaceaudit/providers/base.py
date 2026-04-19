"""Abstract base class for all data source providers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from surfaceaudit.models import RawAsset


class BaseProvider(ABC):
    """Abstract base class for all data source providers."""

    @abstractmethod
    def name(self) -> str:
        """Return the provider's registered name (e.g. 'shodan')."""

    @abstractmethod
    def authenticate(self, api_key: str) -> None:
        """Validate credentials. Raises AuthenticationError on failure."""

    @abstractmethod
    def get_credits(self) -> int:
        """Return available API credits/quota."""

    @abstractmethod
    def discover(self, targets: list[str]) -> list[RawAsset]:
        """Query the data source and return raw assets."""
