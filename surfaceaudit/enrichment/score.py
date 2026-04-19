"""Correlation risk score calculator for enrichment data."""

from __future__ import annotations

import math


class CorrelationScoreCalculator:
    """Computes the 0-100 correlation risk score from enrichment data.

    The score is derived from weighted signals across enrichment providers:
    - VirusTotal malicious detections > 0 → +30 points
    - AbuseIPDB abuse confidence score > 50 → +25 points
    - GreyNoise classification == "malicious" → +20 points

    If two or more providers flag the IP as malicious/abusive, a 1.5x
    multiplier is applied before capping at 100.
    """

    VT_MALICIOUS_POINTS = 30
    ABUSEIPDB_POINTS = 25
    GREYNOISE_MALICIOUS_POINTS = 20
    MULTI_SOURCE_MULTIPLIER = 1.5

    def calculate(self, enrichment_data: dict[str, dict]) -> int:
        """Sum weighted signals, apply multi-source multiplier if >=2
        providers flag malicious, cap at 100.

        Returns 0 when *enrichment_data* is empty or contains no
        actionable signals.
        """
        if not enrichment_data:
            return 0

        base_sum = 0
        malicious_source_count = 0

        # VirusTotal: malicious_count > 0
        vt = enrichment_data.get("virustotal")
        if vt and vt.get("malicious_count", 0) > 0:
            base_sum += self.VT_MALICIOUS_POINTS
            malicious_source_count += 1

        # AbuseIPDB: abuse_confidence_score > 50
        abuseipdb = enrichment_data.get("abuseipdb")
        if abuseipdb and abuseipdb.get("abuse_confidence_score", 0) > 50:
            base_sum += self.ABUSEIPDB_POINTS
            malicious_source_count += 1

        # GreyNoise: classification == "malicious"
        greynoise = enrichment_data.get("greynoise")
        if greynoise and greynoise.get("classification") == "malicious":
            base_sum += self.GREYNOISE_MALICIOUS_POINTS
            malicious_source_count += 1

        # Multi-source multiplier
        multiplier = (
            self.MULTI_SOURCE_MULTIPLIER
            if malicious_source_count >= 2
            else 1.0
        )

        score = int(math.floor(base_sum * multiplier))
        return min(score, 100)
