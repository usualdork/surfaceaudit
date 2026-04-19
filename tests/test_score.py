"""Unit tests for CorrelationScoreCalculator."""

from __future__ import annotations

from surfaceaudit.enrichment.score import CorrelationScoreCalculator


class TestCorrelationScoreCalculator:
    """Tests for the correlation risk score computation."""

    def setup_method(self) -> None:
        self.calc = CorrelationScoreCalculator()

    # ------------------------------------------------------------------
    # No enrichment data → 0
    # ------------------------------------------------------------------

    def test_empty_dict_returns_zero(self) -> None:
        assert self.calc.calculate({}) == 0

    def test_none_like_empty_returns_zero(self) -> None:
        # Providers present but with no actionable signals
        assert self.calc.calculate({"virustotal": {"malicious_count": 0}}) == 0

    # ------------------------------------------------------------------
    # Single-source scoring
    # ------------------------------------------------------------------

    def test_vt_malicious_only(self) -> None:
        data = {"virustotal": {"malicious_count": 3}}
        assert self.calc.calculate(data) == 30

    def test_abuseipdb_only(self) -> None:
        data = {"abuseipdb": {"abuse_confidence_score": 80}}
        assert self.calc.calculate(data) == 25

    def test_greynoise_malicious_only(self) -> None:
        data = {"greynoise": {"classification": "malicious"}}
        assert self.calc.calculate(data) == 20

    def test_greynoise_benign_no_points(self) -> None:
        data = {"greynoise": {"classification": "benign"}}
        assert self.calc.calculate(data) == 0

    def test_abuseipdb_at_50_no_points(self) -> None:
        """Confidence must be *greater than* 50, not equal."""
        data = {"abuseipdb": {"abuse_confidence_score": 50}}
        assert self.calc.calculate(data) == 0

    def test_abuseipdb_at_51_gives_points(self) -> None:
        data = {"abuseipdb": {"abuse_confidence_score": 51}}
        assert self.calc.calculate(data) == 25

    # ------------------------------------------------------------------
    # Multi-source multiplier
    # ------------------------------------------------------------------

    def test_two_sources_apply_multiplier(self) -> None:
        data = {
            "virustotal": {"malicious_count": 1},
            "abuseipdb": {"abuse_confidence_score": 90},
        }
        # (30 + 25) * 1.5 = 82.5 → floor → 82
        assert self.calc.calculate(data) == 82

    def test_all_three_sources_apply_multiplier(self) -> None:
        data = {
            "virustotal": {"malicious_count": 5},
            "abuseipdb": {"abuse_confidence_score": 100},
            "greynoise": {"classification": "malicious"},
        }
        # (30 + 25 + 20) * 1.5 = 112.5 → floor → 112 → cap → 100
        assert self.calc.calculate(data) == 100

    def test_vt_and_greynoise_multiplier(self) -> None:
        data = {
            "virustotal": {"malicious_count": 2},
            "greynoise": {"classification": "malicious"},
        }
        # (30 + 20) * 1.5 = 75
        assert self.calc.calculate(data) == 75

    def test_one_source_no_multiplier(self) -> None:
        """Only one source flagging → no multiplier."""
        data = {
            "virustotal": {"malicious_count": 1},
            "greynoise": {"classification": "benign"},
        }
        assert self.calc.calculate(data) == 30

    # ------------------------------------------------------------------
    # Cap at 100
    # ------------------------------------------------------------------

    def test_score_never_exceeds_100(self) -> None:
        data = {
            "virustotal": {"malicious_count": 999},
            "abuseipdb": {"abuse_confidence_score": 100},
            "greynoise": {"classification": "malicious"},
        }
        assert self.calc.calculate(data) <= 100

    # ------------------------------------------------------------------
    # Edge cases: missing keys in provider dicts
    # ------------------------------------------------------------------

    def test_vt_missing_malicious_count_key(self) -> None:
        data = {"virustotal": {"reputation": -5}}
        assert self.calc.calculate(data) == 0

    def test_greynoise_missing_classification_key(self) -> None:
        data = {"greynoise": {"noise": True}}
        assert self.calc.calculate(data) == 0

    def test_abuseipdb_missing_confidence_key(self) -> None:
        data = {"abuseipdb": {"total_reports": 10}}
        assert self.calc.calculate(data) == 0
