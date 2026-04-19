"""Unit tests for surfaceaudit.rules.v2.matchers."""

import pytest

from surfaceaudit.rules.v2.matchers import (
    Matcher,
    PortMatcher,
    RegexMatcher,
    VersionCompareMatcher,
    WordMatcher,
)
from surfaceaudit.rules.v2.schema import AssetContext


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------

class TestMatcherProtocol:
    def test_word_matcher_is_matcher(self):
        assert isinstance(WordMatcher(field="banner", words=["nginx"]), Matcher)

    def test_regex_matcher_is_matcher(self):
        assert isinstance(RegexMatcher(field="banner", regex="nginx"), Matcher)

    def test_port_matcher_is_matcher(self):
        assert isinstance(PortMatcher(ports=[80]), Matcher)

    def test_version_compare_matcher_is_matcher(self):
        assert isinstance(
            VersionCompareMatcher(field="service_version", operator="lt", version="2.0"),
            Matcher,
        )


# ---------------------------------------------------------------------------
# WordMatcher
# ---------------------------------------------------------------------------

class TestWordMatcher:
    def test_case_insensitive_match(self):
        ctx = AssetContext(banner="Running NGINX/1.18")
        m = WordMatcher(field="banner", words=["nginx"])
        assert m.matches(ctx) is True

    def test_substring_match(self):
        ctx = AssetContext(service_name="Apache HTTP Server")
        m = WordMatcher(field="service_name", words=["apache"])
        assert m.matches(ctx) is True

    def test_no_match(self):
        ctx = AssetContext(banner="OpenSSH 8.9")
        m = WordMatcher(field="banner", words=["nginx", "apache"])
        assert m.matches(ctx) is False

    def test_null_field_returns_false(self):
        ctx = AssetContext(banner=None)
        m = WordMatcher(field="banner", words=["nginx"])
        assert m.matches(ctx) is False

    def test_empty_string_field_returns_false(self):
        ctx = AssetContext(banner="")
        m = WordMatcher(field="banner", words=["nginx"])
        assert m.matches(ctx) is False

    def test_nonexistent_field_returns_false(self):
        ctx = AssetContext()
        m = WordMatcher(field="nonexistent", words=["test"])
        assert m.matches(ctx) is False

    def test_multiple_words_any_matches(self):
        ctx = AssetContext(banner="lighttpd/1.4")
        m = WordMatcher(field="banner", words=["nginx", "lighttpd", "apache"])
        assert m.matches(ctx) is True


# ---------------------------------------------------------------------------
# RegexMatcher
# ---------------------------------------------------------------------------

class TestRegexMatcher:
    def test_basic_regex_match(self):
        ctx = AssetContext(banner="nginx/1.18.0")
        m = RegexMatcher(field="banner", regex=r"nginx/\d+\.\d+")
        assert m.matches(ctx) is True

    def test_case_insensitive(self):
        ctx = AssetContext(banner="NGINX/1.18.0")
        m = RegexMatcher(field="banner", regex=r"nginx/\d+")
        assert m.matches(ctx) is True

    def test_no_match(self):
        ctx = AssetContext(banner="Apache/2.4.58")
        m = RegexMatcher(field="banner", regex=r"nginx/\d+")
        assert m.matches(ctx) is False

    def test_null_field_returns_false(self):
        ctx = AssetContext(banner=None)
        m = RegexMatcher(field="banner", regex=r"nginx")
        assert m.matches(ctx) is False

    def test_empty_string_field_returns_false(self):
        ctx = AssetContext(banner="")
        m = RegexMatcher(field="banner", regex=r"nginx")
        assert m.matches(ctx) is False

    def test_nonexistent_field_returns_false(self):
        ctx = AssetContext()
        m = RegexMatcher(field="nonexistent", regex=r"test")
        assert m.matches(ctx) is False


# ---------------------------------------------------------------------------
# PortMatcher
# ---------------------------------------------------------------------------

class TestPortMatcher:
    def test_single_port_match(self):
        ctx = AssetContext(ports=[80, 443])
        m = PortMatcher(ports=[443])
        assert m.matches(ctx) is True

    def test_no_match(self):
        ctx = AssetContext(ports=[22, 80])
        m = PortMatcher(ports=[443, 8080])
        assert m.matches(ctx) is False

    def test_empty_asset_ports(self):
        ctx = AssetContext(ports=[])
        m = PortMatcher(ports=[80])
        assert m.matches(ctx) is False

    def test_empty_matcher_ports(self):
        ctx = AssetContext(ports=[80, 443])
        m = PortMatcher(ports=[])
        assert m.matches(ctx) is False

    def test_multiple_overlapping_ports(self):
        ctx = AssetContext(ports=[80, 443, 8080])
        m = PortMatcher(ports=[443, 8443])
        assert m.matches(ctx) is True


# ---------------------------------------------------------------------------
# VersionCompareMatcher
# ---------------------------------------------------------------------------

class TestVersionCompareMatcher:
    def test_lt_match(self):
        ctx = AssetContext(service_version="1.18.0")
        m = VersionCompareMatcher(field="service_version", operator="lt", version="2.0.0")
        assert m.matches(ctx) is True

    def test_lt_no_match(self):
        ctx = AssetContext(service_version="2.4.58")
        m = VersionCompareMatcher(field="service_version", operator="lt", version="2.4.0")
        assert m.matches(ctx) is False

    def test_gte_match(self):
        ctx = AssetContext(service_version="2.4.58")
        m = VersionCompareMatcher(field="service_version", operator="gte", version="2.4.0")
        assert m.matches(ctx) is True

    def test_eq_match(self):
        ctx = AssetContext(service_version="1.0.0")
        m = VersionCompareMatcher(field="service_version", operator="eq", version="1.0.0")
        assert m.matches(ctx) is True

    def test_eq_no_match(self):
        ctx = AssetContext(service_version="1.0.1")
        m = VersionCompareMatcher(field="service_version", operator="eq", version="1.0.0")
        assert m.matches(ctx) is False

    def test_version_with_suffix_stripped(self):
        ctx = AssetContext(service_version="1.20.3-ubuntu")
        m = VersionCompareMatcher(field="service_version", operator="lt", version="2.0.0")
        assert m.matches(ctx) is True

    def test_skip_if_null_true_default(self):
        ctx = AssetContext(service_version=None)
        m = VersionCompareMatcher(field="service_version", operator="lt", version="2.0.0")
        assert m.matches(ctx) is False

    def test_skip_if_null_false_matches(self):
        ctx = AssetContext(service_version=None)
        m = VersionCompareMatcher(
            field="service_version", operator="lt", version="2.0.0", skip_if_null=False
        )
        assert m.matches(ctx) is True

    def test_empty_string_with_skip_if_null_true(self):
        ctx = AssetContext(service_version="")
        m = VersionCompareMatcher(field="service_version", operator="lt", version="2.0.0")
        assert m.matches(ctx) is False

    def test_whitespace_only_with_skip_if_null_true(self):
        ctx = AssetContext(service_version="   ")
        m = VersionCompareMatcher(field="service_version", operator="lt", version="2.0.0")
        assert m.matches(ctx) is False

    def test_whitespace_only_with_skip_if_null_false(self):
        ctx = AssetContext(service_version="   ")
        m = VersionCompareMatcher(
            field="service_version", operator="lt", version="2.0.0", skip_if_null=False
        )
        assert m.matches(ctx) is True
