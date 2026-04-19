"""Tests for BaseEnrichmentProvider ABC."""

import pytest

from surfaceaudit.enrichment.base import BaseEnrichmentProvider


class TestBaseEnrichmentProvider:
    """Verify the ABC contract for enrichment providers."""

    def test_cannot_instantiate_directly(self):
        """BaseEnrichmentProvider cannot be instantiated."""
        with pytest.raises(TypeError):
            BaseEnrichmentProvider()  # type: ignore[abstract]

    def test_concrete_subclass_must_implement_all_methods(self):
        """A subclass missing any abstract method cannot be instantiated."""

        class IncompleteProvider(BaseEnrichmentProvider):
            def name(self) -> str:
                return "incomplete"

        with pytest.raises(TypeError):
            IncompleteProvider()  # type: ignore[abstract]

    def test_complete_subclass_works(self):
        """A subclass implementing all abstract methods can be instantiated."""

        class DummyProvider(BaseEnrichmentProvider):
            def name(self) -> str:
                return "dummy"

            def requires_api_key(self) -> bool:
                return False

            def enrich_ip(self, ip: str) -> dict:
                return {"ip": ip}

            def enrich_domain(self, domain: str) -> dict:
                return {"domain": domain}

        provider = DummyProvider()
        assert provider.name() == "dummy"
        assert provider.requires_api_key() is False
        assert provider.enrich_ip("1.2.3.4") == {"ip": "1.2.3.4"}
        assert provider.enrich_domain("example.com") == {"domain": "example.com"}

    def test_is_abstract_base_class(self):
        """BaseEnrichmentProvider is recognized as an ABC."""
        assert issubclass(BaseEnrichmentProvider, BaseEnrichmentProvider)

        class ConcreteProvider(BaseEnrichmentProvider):
            def name(self) -> str:
                return "concrete"

            def requires_api_key(self) -> bool:
                return True

            def enrich_ip(self, ip: str) -> dict:
                return {}

            def enrich_domain(self, domain: str) -> dict:
                return {}

        assert isinstance(ConcreteProvider(), BaseEnrichmentProvider)
