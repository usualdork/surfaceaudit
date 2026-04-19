"""Unit tests for RuleEngineV2 — end-to-end evaluation, classification,
assessment, template substitution, and matcher condition logic.

**Validates: Requirements 7.1, 7.2, 7.3, 8.1, 8.2, 8.3**
"""

from __future__ import annotations

import pytest

from surfaceaudit.models import AssetType, RiskLevel, VulnerabilityIndicator
from surfaceaudit.rules.v2.engine import (
    RuleEngineV2,
    _build_contexts,
    _build_matcher,
    _severity_to_risk,
)
from surfaceaudit.rules.v2.schema import (
    AssessBlock,
    AssetContext,
    InfoBlock,
    MatchConditionV2,
    MatcherV2,
    RuleV2,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rule(
    rule_id: str = "test-rule",
    tags: list[str] | None = None,
    condition: str = "and",
    matchers: list[MatcherV2] | None = None,
    category: str = "risky_port",
    severity: str = "high",
    description: str = "Test description",
) -> RuleV2:
    """Build a minimal RuleV2 for testing."""
    if tags is None:
        tags = ["assessment"]
    if matchers is None:
        matchers = [MatcherV2(type="port", ports=[22])]
    return RuleV2(
        id=rule_id,
        info=InfoBlock(
            name="Test Rule",
            author="tester",
            severity=severity,
            tags=tags,
            description=description,
        ),
        match=MatchConditionV2(condition=condition, matchers=matchers),
        assess=AssessBlock(
            category=category,
            severity=severity,
            description=description,
        ),
    )


# ---------------------------------------------------------------------------
# evaluate_rule — AND / OR condition logic
# ---------------------------------------------------------------------------

class TestEvaluateRule:
    """Tests for RuleEngineV2.evaluate_rule()."""

    def test_and_all_match(self) -> None:
        """AND condition: all matchers match → True."""
        engine = RuleEngineV2()
        rule = _make_rule(
            condition="and",
            matchers=[
                MatcherV2(type="port", ports=[80]),
                MatcherV2(type="word", field="banner", words=["nginx"]),
            ],
        )
        ctx = AssetContext(banner="nginx/1.18", ports=[80, 443])
        assert engine.evaluate_rule(rule, ctx) is True

    def test_and_one_fails(self) -> None:
        """AND condition: one matcher fails → False."""
        engine = RuleEngineV2()
        rule = _make_rule(
            condition="and",
            matchers=[
                MatcherV2(type="port", ports=[80]),
                MatcherV2(type="word", field="banner", words=["apache"]),
            ],
        )
        ctx = AssetContext(banner="nginx/1.18", ports=[80])
        assert engine.evaluate_rule(rule, ctx) is False

    def test_or_one_matches(self) -> None:
        """OR condition: one matcher matches → True."""
        engine = RuleEngineV2()
        rule = _make_rule(
            condition="or",
            matchers=[
                MatcherV2(type="port", ports=[9999]),
                MatcherV2(type="word", field="banner", words=["nginx"]),
            ],
        )
        ctx = AssetContext(banner="nginx/1.18", ports=[80])
        assert engine.evaluate_rule(rule, ctx) is True

    def test_or_none_match(self) -> None:
        """OR condition: no matchers match → False."""
        engine = RuleEngineV2()
        rule = _make_rule(
            condition="or",
            matchers=[
                MatcherV2(type="port", ports=[9999]),
                MatcherV2(type="word", field="banner", words=["apache"]),
            ],
        )
        ctx = AssetContext(banner="nginx/1.18", ports=[80])
        assert engine.evaluate_rule(rule, ctx) is False

    def test_empty_matchers_returns_false(self) -> None:
        """No matchers → False."""
        engine = RuleEngineV2()
        rule = _make_rule(matchers=[])
        rule.match.matchers = []
        ctx = AssetContext(ports=[80])
        assert engine.evaluate_rule(rule, ctx) is False

    def test_default_condition_is_and(self) -> None:
        """Default condition (and) requires all matchers to match."""
        engine = RuleEngineV2()
        rule = _make_rule(
            condition="and",
            matchers=[
                MatcherV2(type="port", ports=[80]),
                MatcherV2(type="port", ports=[443]),
            ],
        )
        ctx = AssetContext(ports=[80, 443])
        assert engine.evaluate_rule(rule, ctx) is True

    def test_version_compare_matcher(self) -> None:
        """version_compare matcher evaluates correctly."""
        engine = RuleEngineV2()
        rule = _make_rule(
            matchers=[
                MatcherV2(
                    type="version_compare",
                    field="service_version",
                    operator="lt",
                    version="2.4.50",
                ),
            ],
        )
        ctx = AssetContext(service_version="2.4.49", ports=[])
        assert engine.evaluate_rule(rule, ctx) is True

        ctx2 = AssetContext(service_version="2.4.51", ports=[])
        assert engine.evaluate_rule(rule, ctx2) is False

    def test_regex_matcher(self) -> None:
        """regex matcher evaluates correctly."""
        engine = RuleEngineV2()
        rule = _make_rule(
            matchers=[
                MatcherV2(type="regex", field="banner", regex=r"nginx/\d+\.\d+"),
            ],
        )
        ctx = AssetContext(banner="nginx/1.18.0", ports=[])
        assert engine.evaluate_rule(rule, ctx) is True

        ctx2 = AssetContext(banner="apache/2.4", ports=[])
        assert engine.evaluate_rule(rule, ctx2) is False

    def test_dsl_matcher(self) -> None:
        """dsl matcher evaluates correctly."""
        engine = RuleEngineV2()
        rule = _make_rule(
            matchers=[
                MatcherV2(type="dsl", expression="port == 9200"),
            ],
        )
        ctx = AssetContext(port=9200, ports=[9200])
        assert engine.evaluate_rule(rule, ctx) is True

        ctx2 = AssetContext(port=80, ports=[80])
        assert engine.evaluate_rule(rule, ctx2) is False


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------

class TestClassify:
    """Tests for RuleEngineV2.classify()."""

    def test_returns_first_matching_classification(self) -> None:
        engine = RuleEngineV2()
        engine._rules = [
            _make_rule(
                rule_id="cls-web",
                tags=["classification"],
                category="web_server",
                matchers=[MatcherV2(type="word", field="banner", words=["nginx"])],
            ),
            _make_rule(
                rule_id="cls-db",
                tags=["classification"],
                category="database",
                matchers=[MatcherV2(type="port", ports=[3306])],
            ),
        ]
        result = engine.classify([80], "nginx/1.18", ["nginx"])
        assert result == AssetType.WEB_SERVER

    def test_returns_other_when_no_match(self) -> None:
        engine = RuleEngineV2()
        engine._rules = [
            _make_rule(
                rule_id="cls-web",
                tags=["classification"],
                category="web_server",
                matchers=[MatcherV2(type="word", field="banner", words=["nginx"])],
            ),
        ]
        result = engine.classify([22], "openssh", ["ssh"])
        assert result == AssetType.OTHER

    def test_skips_non_classification_rules(self) -> None:
        engine = RuleEngineV2()
        engine._rules = [
            _make_rule(
                rule_id="assess-only",
                tags=["assessment"],
                category="web_server",
                matchers=[MatcherV2(type="word", field="banner", words=["nginx"])],
            ),
        ]
        result = engine.classify([80], "nginx/1.18", ["nginx"])
        assert result == AssetType.OTHER

    def test_skips_invalid_asset_type_category(self) -> None:
        """If category doesn't map to AssetType, skip and try next."""
        engine = RuleEngineV2()
        engine._rules = [
            _make_rule(
                rule_id="cls-bad",
                tags=["classification"],
                category="not_a_real_type",
                matchers=[MatcherV2(type="port", ports=[80])],
            ),
            _make_rule(
                rule_id="cls-good",
                tags=["classification"],
                category="web_server",
                matchers=[MatcherV2(type="port", ports=[80])],
            ),
        ]
        result = engine.classify([80], "", [])
        assert result == AssetType.WEB_SERVER

    def test_classify_with_services(self) -> None:
        """Classification evaluates per-service contexts."""
        engine = RuleEngineV2()
        engine._rules = [
            _make_rule(
                rule_id="cls-mysql",
                tags=["classification"],
                category="database",
                matchers=[
                    MatcherV2(type="word", field="service_name", words=["mysql"]),
                ],
            ),
        ]
        result = engine.classify([3306], "", ["mysql"])
        assert result == AssetType.DATABASE


# ---------------------------------------------------------------------------
# assess
# ---------------------------------------------------------------------------

class TestAssess:
    """Tests for RuleEngineV2.assess()."""

    def test_returns_matching_indicators(self) -> None:
        engine = RuleEngineV2()
        engine._rules = [
            _make_rule(
                rule_id="vuln-ssh",
                category="risky_port",
                severity="high",
                description="SSH exposed on port 22",
                matchers=[MatcherV2(type="port", ports=[22])],
            ),
        ]
        indicators = engine.assess([22, 80], "", [])
        assert len(indicators) == 1
        assert indicators[0].category == "risky_port"
        assert indicators[0].severity == RiskLevel.HIGH
        assert indicators[0].description == "SSH exposed on port 22"

    def test_no_match_returns_empty(self) -> None:
        engine = RuleEngineV2()
        engine._rules = [
            _make_rule(
                matchers=[MatcherV2(type="port", ports=[9999])],
            ),
        ]
        indicators = engine.assess([80], "", [])
        assert indicators == []

    def test_template_substitution_in_description(self) -> None:
        engine = RuleEngineV2()
        engine._rules = [
            _make_rule(
                rule_id="vuln-ver",
                description="Service {service_name} version {service_version} is outdated",
                matchers=[
                    MatcherV2(type="word", field="service_name", words=["nginx"]),
                ],
            ),
        ]
        indicators = engine.assess([80], "", ["nginx"])
        assert len(indicators) == 1
        assert "nginx" in indicators[0].description
        # service_version is None → "unknown"
        assert "unknown" in indicators[0].description

    def test_template_substitution_with_banner_preview(self) -> None:
        engine = RuleEngineV2()
        engine._rules = [
            _make_rule(
                rule_id="vuln-banner",
                description="Banner: {banner_preview}",
                matchers=[
                    MatcherV2(type="word", field="banner", words=["nginx"]),
                ],
            ),
        ]
        indicators = engine.assess([80], "nginx/1.18.0 Ubuntu", [])
        assert len(indicators) == 1
        assert "nginx/1.18.0 Ubuntu" in indicators[0].description

    def test_multiple_rules_match(self) -> None:
        engine = RuleEngineV2()
        engine._rules = [
            _make_rule(
                rule_id="r1",
                matchers=[MatcherV2(type="port", ports=[22])],
            ),
            _make_rule(
                rule_id="r2",
                matchers=[MatcherV2(type="port", ports=[80])],
            ),
        ]
        indicators = engine.assess([22, 80], "", [])
        assert len(indicators) == 2

    def test_rule_matches_only_once_per_rule(self) -> None:
        """A rule should only produce one indicator even with multiple service contexts."""
        engine = RuleEngineV2()
        engine._rules = [
            _make_rule(
                rule_id="r1",
                matchers=[
                    MatcherV2(type="word", field="service_name", words=["http"]),
                ],
            ),
        ]
        # Two services both named "http" — should still only get one indicator
        indicators = engine.assess([], "", ["http", "http-alt"])
        assert len(indicators) == 1

    def test_severity_mapping(self) -> None:
        """Severity strings map to correct RiskLevel."""
        assert _severity_to_risk("critical") == RiskLevel.HIGH
        assert _severity_to_risk("high") == RiskLevel.HIGH
        assert _severity_to_risk("medium") == RiskLevel.MEDIUM
        assert _severity_to_risk("low") == RiskLevel.LOW
        assert _severity_to_risk("info") == RiskLevel.LOW
        assert _severity_to_risk("unknown") == RiskLevel.LOW


# ---------------------------------------------------------------------------
# _build_contexts
# ---------------------------------------------------------------------------

class TestBuildContexts:
    """Tests for _build_contexts helper."""

    def test_no_services_returns_single_context(self) -> None:
        contexts = _build_contexts([80, 443], "nginx", [])
        assert len(contexts) == 1
        assert contexts[0].ports == [80, 443]
        assert contexts[0].banner == "nginx"
        assert contexts[0].service_name is None

    def test_with_services_returns_per_service_context(self) -> None:
        contexts = _build_contexts([80], "banner", ["nginx", "apache"])
        assert len(contexts) == 2
        assert contexts[0].service_name == "nginx"
        assert contexts[1].service_name == "apache"
        assert all(c.banner == "banner" for c in contexts)
        assert all(c.ports == [80] for c in contexts)


# ---------------------------------------------------------------------------
# _build_matcher
# ---------------------------------------------------------------------------

class TestBuildMatcher:
    """Tests for _build_matcher helper."""

    def test_word_matcher(self) -> None:
        spec = MatcherV2(type="word", field="banner", words=["test"])
        m = _build_matcher(spec)
        assert hasattr(m, "matches")

    def test_regex_matcher(self) -> None:
        spec = MatcherV2(type="regex", field="banner", regex="test")
        m = _build_matcher(spec)
        assert hasattr(m, "matches")

    def test_port_matcher(self) -> None:
        spec = MatcherV2(type="port", ports=[80])
        m = _build_matcher(spec)
        assert hasattr(m, "matches")

    def test_version_compare_matcher(self) -> None:
        spec = MatcherV2(
            type="version_compare", field="service_version",
            operator="lt", version="1.0",
        )
        m = _build_matcher(spec)
        assert hasattr(m, "matches")

    def test_dsl_matcher(self) -> None:
        spec = MatcherV2(type="dsl", expression="port == 80")
        m = _build_matcher(spec)
        assert hasattr(m, "matches")

    def test_unknown_type_returns_null_matcher(self) -> None:
        spec = MatcherV2(type="unknown_type")
        m = _build_matcher(spec)
        ctx = AssetContext(ports=[80])
        assert m.matches(ctx) is False


# ---------------------------------------------------------------------------
# End-to-end evaluation with bundled rules (Task 4.4)
# ---------------------------------------------------------------------------

import os

from surfaceaudit.rules import RuleEngine


def _v2_rules_dir() -> str:
    """Return the path to the bundled v2 rules directory."""
    return os.path.join(os.path.dirname(__file__), "..", "surfaceaudit", "rules", "v2")


def _v1_rules_dir() -> str:
    """Return the path to the bundled v1 rules directory."""
    return os.path.join(os.path.dirname(__file__), "..", "surfaceaudit", "rules")


class TestE2EClassificationFromYAML:
    """End-to-end: v2 rules loaded from YAML produce correct classification.

    **Validates: Requirements 7.1, 7.2, 7.3, 30.1**
    """

    @pytest.fixture()
    def engine(self) -> RuleEngineV2:
        e = RuleEngineV2()
        e.load(rules_dirs=[_v2_rules_dir()])
        return e

    def test_nginx_banner_classifies_as_web_server(self, engine: RuleEngineV2) -> None:
        result = engine.classify([80], "nginx/1.18.0", ["nginx"])
        assert result == AssetType.WEB_SERVER

    def test_apache_banner_classifies_as_web_server(self, engine: RuleEngineV2) -> None:
        result = engine.classify([443], "apache/2.4.52", ["apache"])
        assert result == AssetType.WEB_SERVER

    def test_http_port_classifies_as_web_server(self, engine: RuleEngineV2) -> None:
        result = engine.classify([8080], "", [])
        assert result == AssetType.WEB_SERVER

    def test_mysql_port_classifies_as_database(self, engine: RuleEngineV2) -> None:
        result = engine.classify([3306], "", [])
        assert result == AssetType.DATABASE

    def test_postgresql_port_classifies_as_database(self, engine: RuleEngineV2) -> None:
        result = engine.classify([5432], "", [])
        assert result == AssetType.DATABASE

    def test_mysql_banner_classifies_as_database(self, engine: RuleEngineV2) -> None:
        result = engine.classify([], "mysql 8.0.30", ["mysql"])
        assert result == AssetType.DATABASE

    def test_mqtt_port_classifies_as_iot_device(self, engine: RuleEngineV2) -> None:
        result = engine.classify([1883], "", [])
        assert result == AssetType.IOT_DEVICE

    def test_snmp_port_classifies_as_network_device(self, engine: RuleEngineV2) -> None:
        result = engine.classify([161], "", [])
        assert result == AssetType.NETWORK_DEVICE

    def test_unknown_port_classifies_as_other(self, engine: RuleEngineV2) -> None:
        result = engine.classify([12345], "", [])
        assert result == AssetType.OTHER


class TestE2EAssessmentFromYAML:
    """End-to-end: v2 rules loaded from YAML produce correct assessment.

    **Validates: Requirements 7.1, 7.2, 7.3, 8.1, 30.1**
    """

    @pytest.fixture()
    def engine(self) -> RuleEngineV2:
        e = RuleEngineV2()
        e.load(rules_dirs=[_v2_rules_dir()])
        return e

    def test_ftp_port_produces_risky_port_indicator(self, engine: RuleEngineV2) -> None:
        indicators = engine.assess([21], "", [])
        categories = [i.category for i in indicators]
        assert "risky_port" in categories
        ftp_ind = [i for i in indicators if i.category == "risky_port" and "21" in i.description]
        assert len(ftp_ind) >= 1

    def test_telnet_port_produces_risky_port_indicator(self, engine: RuleEngineV2) -> None:
        indicators = engine.assess([23], "", [])
        categories = [i.category for i in indicators]
        assert "risky_port" in categories

    def test_rdp_port_produces_risky_port_indicator(self, engine: RuleEngineV2) -> None:
        indicators = engine.assess([3389], "", [])
        categories = [i.category for i in indicators]
        assert "risky_port" in categories

    def test_outdated_apache_produces_vulnerable_version(self, engine: RuleEngineV2) -> None:
        """Apache 2.4.49 with service_version set triggers vulnerable_version.

        The version_compare matcher requires service_version in the context.
        We simulate this by injecting rules with a context that has the version.
        """
        ctx = AssetContext(
            service_name="apache", service_version="2.4.49",
            banner="apache/2.4.49", ports=[80],
        )
        vuln_rules = [
            r for r in engine._rules
            if r.assess.category == "vulnerable_version" and "apache" in r.info.name.lower()
        ]
        assert len(vuln_rules) >= 1
        assert engine.evaluate_rule(vuln_rules[0], ctx) is True

    def test_current_apache_no_vulnerable_version(self, engine: RuleEngineV2) -> None:
        """Apache 2.4.58 is above 2.4.50 threshold → version_compare does not match."""
        ctx = AssetContext(
            service_name="apache", service_version="2.4.58",
            banner="apache/2.4.58", ports=[80],
        )
        vuln_rules = [
            r for r in engine._rules
            if r.assess.category == "vulnerable_version" and "apache" in r.info.name.lower()
        ]
        assert len(vuln_rules) >= 1
        assert engine.evaluate_rule(vuln_rules[0], ctx) is False

    def test_outdated_nginx_produces_vulnerable_version(self, engine: RuleEngineV2) -> None:
        """Nginx 1.18.0 with service_version set triggers vulnerable_version."""
        ctx = AssetContext(
            service_name="nginx", service_version="1.18.0",
            banner="nginx/1.18.0", ports=[80],
        )
        vuln_rules = [
            r for r in engine._rules
            if r.assess.category == "vulnerable_version" and "nginx" in r.info.name.lower()
        ]
        assert len(vuln_rules) >= 1
        assert engine.evaluate_rule(vuln_rules[0], ctx) is True

    def test_no_match_returns_empty(self, engine: RuleEngineV2) -> None:
        indicators = engine.assess([12345], "", [])
        assert indicators == []

    def test_elasticsearch_port_produces_admin_interface(self, engine: RuleEngineV2) -> None:
        indicators = engine.assess([9200], "", [])
        categories = [i.category for i in indicators]
        assert "admin_interface" in categories


class TestE2EV1RulesThroughV2Engine:
    """End-to-end: v1 rules loaded through v2 engine produce results.

    **Validates: Requirements 30.1, 30.2**
    """

    @pytest.fixture()
    def v2_engine(self) -> RuleEngineV2:
        e = RuleEngineV2()
        e.load(rules_dirs=[_v1_rules_dir()])
        return e

    @pytest.fixture()
    def v1_engine(self) -> RuleEngine:
        e = RuleEngine()
        e.load()
        return e

    def test_v1_rules_load_without_error(self, v2_engine: RuleEngineV2) -> None:
        """V1 rules are loaded and converted — engine has rules."""
        assert len(v2_engine._rules) > 0

    def test_v1_classification_web_server(
        self, v1_engine: RuleEngine, v2_engine: RuleEngineV2,
    ) -> None:
        """V1 rules through v2 engine classify nginx banner as web_server, same as v1."""
        v1_result = v1_engine.classify([80], "nginx/1.18", ["nginx"])
        v2_result = v2_engine.classify([80], "nginx/1.18", ["nginx"])
        assert v1_result == v2_result == AssetType.WEB_SERVER

    def test_v1_classification_database(
        self, v1_engine: RuleEngine, v2_engine: RuleEngineV2,
    ) -> None:
        """V1 rules through v2 engine classify mysql port as database, same as v1."""
        v1_result = v1_engine.classify([3306], "mysql", ["mysql"])
        v2_result = v2_engine.classify([3306], "mysql", ["mysql"])
        assert v1_result == v2_result == AssetType.DATABASE

    def test_v1_classification_other(
        self, v1_engine: RuleEngine, v2_engine: RuleEngineV2,
    ) -> None:
        """Unknown asset classifies as OTHER in both engines."""
        v1_result = v1_engine.classify([12345], "", [])
        v2_result = v2_engine.classify([12345], "", [])
        assert v1_result == v2_result == AssetType.OTHER

    def test_v1_assessment_ftp_port(
        self, v1_engine: RuleEngine, v2_engine: RuleEngineV2,
    ) -> None:
        """V1 FTP rule through v2 engine produces risky_port indicator."""
        v1_indicators = v1_engine.assess([21], "", [])
        v2_indicators = v2_engine.assess([21], "", [])
        v1_cats = {i.category for i in v1_indicators}
        v2_cats = {i.category for i in v2_indicators}
        assert "risky_port" in v1_cats
        assert "risky_port" in v2_cats

    def test_v1_assessment_admin_keyword(
        self, v1_engine: RuleEngine, v2_engine: RuleEngineV2,
    ) -> None:
        """V1 admin keyword rule through v2 engine produces admin_interface indicator."""
        v1_indicators = v1_engine.assess([], "phpmyadmin dashboard", [])
        v2_indicators = v2_engine.assess([], "phpmyadmin dashboard", [])
        v1_cats = {i.category for i in v1_indicators}
        v2_cats = {i.category for i in v2_indicators}
        assert "admin_interface" in v1_cats
        assert "admin_interface" in v2_cats


class TestE2ETemplateSubstitutionFromYAML:
    """End-to-end: template variables in assessment descriptions are substituted.

    **Validates: Requirements 8.1, 30.1**
    """

    @pytest.fixture()
    def engine(self) -> RuleEngineV2:
        e = RuleEngineV2()
        e.load(rules_dirs=[_v2_rules_dir()])
        return e

    def test_apache_version_substituted_in_description(self, engine: RuleEngineV2) -> None:
        """The {service_version} template in the Apache rule is substituted with actual value."""
        # Directly evaluate the Apache vuln rule with a context that has service_version
        from surfaceaudit.rules.v2.template import substitute_template

        vuln_rules = [
            r for r in engine._rules
            if r.assess.category == "vulnerable_version" and "apache" in r.info.name.lower()
        ]
        assert len(vuln_rules) >= 1
        ctx = AssetContext(
            service_name="apache", service_version="2.4.49",
            banner="apache/2.4.49", ports=[80],
        )
        desc = substitute_template(vuln_rules[0].assess.description, ctx)
        assert "2.4.49" in desc

    def test_nginx_version_substituted_in_description(self, engine: RuleEngineV2) -> None:
        """The {service_version} template in the Nginx rule is substituted with actual value."""
        from surfaceaudit.rules.v2.template import substitute_template

        vuln_rules = [
            r for r in engine._rules
            if r.assess.category == "vulnerable_version" and "nginx" in r.info.name.lower()
        ]
        assert len(vuln_rules) >= 1
        ctx = AssetContext(
            service_name="nginx", service_version="1.18.0",
            banner="nginx/1.18.0", ports=[80],
        )
        desc = substitute_template(vuln_rules[0].assess.description, ctx)
        assert "1.18.0" in desc

    def test_banner_preview_substituted(self, engine: RuleEngineV2) -> None:
        """Template substitution replaces {banner_preview} with actual banner text."""
        # Use a synthetic rule to test banner_preview substitution
        engine_custom = RuleEngineV2()
        engine_custom._rules = [
            _make_rule(
                rule_id="test-banner-tpl",
                description="Detected: {banner_preview}",
                matchers=[MatcherV2(type="word", field="banner", words=["nginx"])],
            ),
        ]
        indicators = engine_custom.assess([80], "nginx/1.18.0 Ubuntu", [])
        assert len(indicators) == 1
        assert "nginx/1.18.0 Ubuntu" in indicators[0].description

    def test_null_template_vars_become_unknown(self, engine: RuleEngineV2) -> None:
        """When context fields are None, template vars are replaced with 'unknown'."""
        engine_custom = RuleEngineV2()
        engine_custom._rules = [
            _make_rule(
                rule_id="test-null-tpl",
                description="Host: {hostname}, IP: {ip}, Port: {port}",
                matchers=[MatcherV2(type="port", ports=[80])],
            ),
        ]
        indicators = engine_custom.assess([80], "", [])
        assert len(indicators) == 1
        assert "unknown" in indicators[0].description
