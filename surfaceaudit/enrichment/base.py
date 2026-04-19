"""Abstract base class for all enrichment providers."""

from __future__ import annotations

from abc import ABC, abstractmethod


class BaseEnrichmentProvider(ABC):
    """Abstract base for enrichment providers.

    Each provider fetches threat intelligence data for IPs or domains
    from an external API (e.g., crt.sh, VirusTotal, GreyNoise, AbuseIPDB).
    """

    @abstractmethod
    def name(self) -> str:
        """Return the provider's registered name (e.g. 'virustotal')."""

    @abstractmethod
    def requires_api_key(self) -> bool:
        """Return True if this provider needs an API key to operate."""

    @abstractmethod
    def enrich_ip(self, ip: str) -> dict:
        """Fetch enrichment data for an IP address.

        Returns a provider-specific dict of enrichment results.
        """

    @abstractmethod
    def enrich_domain(self, domain: str) -> dict:
        """Fetch enrichment data for a domain.

        Returns a provider-specific dict of enrichment results.
        """
