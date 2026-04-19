"""SARIF v2.1.0 output formatter for SurfaceAudit scan reports."""

from __future__ import annotations

import json
from typing import Any

from surfaceaudit.models import RiskLevel, ScanReport


class SARIFFormatter:
    """Serializes a ScanReport into SARIF v2.1.0 JSON."""

    SCHEMA_URI = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
    SARIF_VERSION = "2.1.0"

    def format(self, report: ScanReport, tool_version: str) -> str:
        """Produce a SARIF JSON string from a ScanReport.

        Maps each VulnerabilityIndicator to a SARIF result:
        - ruleId = indicator.category
        - message.text = indicator.description
        - level = _map_severity(indicator.severity)

        Args:
            report: The scan report to serialize.
            tool_version: The SurfaceAudit package version string.

        Returns:
            A SARIF v2.1.0 JSON string.
        """
        results: list[dict[str, Any]] = []
        rules_seen: dict[str, dict[str, Any]] = {}

        for asset in report.assets:
            for vuln in asset.vulnerabilities:
                # Track unique rules for the driver.rules array
                if vuln.category not in rules_seen:
                    rules_seen[vuln.category] = {
                        "id": vuln.category,
                        "shortDescription": {"text": vuln.category},
                    }

                results.append({
                    "ruleId": vuln.category,
                    "level": self._map_severity(vuln.severity),
                    "message": {"text": vuln.description},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": asset.ip},
                            }
                        }
                    ],
                })

        sarif: dict[str, Any] = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SurfaceAudit",
                            "version": tool_version,
                            "rules": list(rules_seen.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    @staticmethod
    def _map_severity(risk: RiskLevel) -> str:
        """Map RiskLevel to SARIF level: HIGH → error, MEDIUM → warning, LOW → note."""
        mapping = {
            RiskLevel.HIGH: "error",
            RiskLevel.MEDIUM: "warning",
            RiskLevel.LOW: "note",
        }
        return mapping[risk]
