"""Unit tests for EnrichmentCache."""

from __future__ import annotations

import json
import os
import time

import pytest

from surfaceaudit.enrichment.cache import EnrichmentCache


@pytest.fixture()
def cache_dir(tmp_path):
    return str(tmp_path / "cache")


class TestEnrichmentCacheGet:
    """Tests for EnrichmentCache.get()."""

    def test_miss_when_no_file(self, cache_dir):
        cache = EnrichmentCache(cache_dir, ttl_hours=1)
        assert cache.get("vt", "1.2.3.4") is None

    def test_hit_within_ttl(self, cache_dir):
        cache = EnrichmentCache(cache_dir, ttl_hours=1)
        data = {"malicious": 5}
        cache.set("vt", "1.2.3.4", data)
        assert cache.get("vt", "1.2.3.4") == data

    def test_miss_after_ttl_expired(self, cache_dir):
        cache = EnrichmentCache(cache_dir, ttl_hours=1)
        # Write a cache entry with a timestamp far in the past.
        provider_dir = os.path.join(cache_dir, "vt")
        os.makedirs(provider_dir, exist_ok=True)
        path = os.path.join(provider_dir, "1.2.3.4.json")
        entry = {"timestamp": time.time() - 7200, "data": {"old": True}}
        with open(path, "w") as fh:
            json.dump(entry, fh)

        assert cache.get("vt", "1.2.3.4") is None

    def test_corrupt_file_returns_none(self, cache_dir):
        cache = EnrichmentCache(cache_dir, ttl_hours=1)
        provider_dir = os.path.join(cache_dir, "vt")
        os.makedirs(provider_dir, exist_ok=True)
        path = os.path.join(provider_dir, "bad.json")
        with open(path, "w") as fh:
            fh.write("NOT VALID JSON {{{")

        assert cache.get("vt", "bad") is None


class TestEnrichmentCacheSet:
    """Tests for EnrichmentCache.set()."""

    def test_creates_provider_subdirectory(self, cache_dir):
        cache = EnrichmentCache(cache_dir, ttl_hours=1)
        cache.set("greynoise", "8.8.8.8", {"noise": True})
        assert os.path.isdir(os.path.join(cache_dir, "greynoise"))

    def test_written_file_is_valid_json(self, cache_dir):
        cache = EnrichmentCache(cache_dir, ttl_hours=1)
        cache.set("vt", "key1", {"a": 1})
        path = os.path.join(cache_dir, "vt", "key1.json")
        with open(path) as fh:
            entry = json.load(fh)
        assert "timestamp" in entry
        assert entry["data"] == {"a": 1}


class TestEnrichmentCacheInit:
    """Tests for EnrichmentCache.__init__()."""

    def test_creates_cache_dir_if_missing(self, tmp_path):
        new_dir = str(tmp_path / "does" / "not" / "exist")
        EnrichmentCache(new_dir, ttl_hours=1)
        assert os.path.isdir(new_dir)

    def test_default_ttl(self, cache_dir):
        cache = EnrichmentCache(cache_dir)
        assert cache._ttl_seconds == 24 * 3600
