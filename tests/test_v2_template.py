"""Unit tests for surfaceaudit.rules.v2.template."""

import pytest

from surfaceaudit.rules.v2.schema import AssetContext
from surfaceaudit.rules.v2.template import substitute_template


class TestSubstituteTemplate:
    """Tests for substitute_template — Requirements 8.1, 8.2, 8.3."""

    def test_all_variables_substituted(self):
        ctx = AssetContext(
            service_name="nginx",
            service_version="1.18.0",
            port=443,
            ip="10.0.0.1",
            hostname="example.com",
            banner="nginx/1.18.0",
        )
        tpl = (
            "{service_name} {service_version} on port {port} "
            "at {ip} ({hostname}) — {banner_preview}"
        )
        result = substitute_template(tpl, ctx)
        assert result == "nginx 1.18.0 on port 443 at 10.0.0.1 (example.com) — nginx/1.18.0"

    def test_null_values_become_unknown(self):
        ctx = AssetContext()  # all None
        tpl = "{service_name} {service_version} {port} {ip} {hostname} {banner_preview}"
        result = substitute_template(tpl, ctx)
        assert result == "unknown unknown unknown unknown unknown unknown"

    def test_partial_null_values(self):
        ctx = AssetContext(service_name="ssh", port=22)
        tpl = "{service_name} v{service_version} on {port}"
        result = substitute_template(tpl, ctx)
        assert result == "ssh vunknown on 22"

    def test_banner_preview_truncated_at_80(self):
        long_banner = "A" * 120
        ctx = AssetContext(banner=long_banner)
        result = substitute_template("{banner_preview}", ctx)
        assert result == "A" * 80
        assert len(result) == 80

    def test_banner_preview_not_truncated_when_short(self):
        ctx = AssetContext(banner="short banner")
        result = substitute_template("{banner_preview}", ctx)
        assert result == "short banner"

    def test_banner_preview_exactly_80_chars(self):
        ctx = AssetContext(banner="B" * 80)
        result = substitute_template("{banner_preview}", ctx)
        assert result == "B" * 80

    def test_no_template_variables_returns_unchanged(self):
        ctx = AssetContext(service_name="nginx")
        tpl = "No variables here"
        assert substitute_template(tpl, ctx) == "No variables here"

    def test_empty_template_returns_empty(self):
        ctx = AssetContext(service_name="nginx")
        assert substitute_template("", ctx) == ""

    def test_repeated_variable(self):
        ctx = AssetContext(ip="1.2.3.4")
        tpl = "{ip} and {ip}"
        assert substitute_template(tpl, ctx) == "1.2.3.4 and 1.2.3.4"

    def test_port_rendered_as_string(self):
        ctx = AssetContext(port=8080)
        result = substitute_template("port={port}", ctx)
        assert result == "port=8080"

    def test_unknown_placeholder_left_as_is(self):
        ctx = AssetContext()
        tpl = "{service_name} {unknown_var}"
        result = substitute_template(tpl, ctx)
        assert result == "unknown {unknown_var}"
