"""AI-powered scan analysis using Google Gemma 4 via the Gemini API.

Provides three capabilities:
1. Executive scan summary — natural language overview of scan results
2. Remediation recommendations — actionable fix guidance per vulnerability
3. Watch mode anomaly explanation — context for detected changes
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from surfaceaudit.models import AssessedAsset, ScanDiff, ScanReport

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "gemma-4-31b-it"


class AIAnalyzer:
    """Generates AI-powered analysis from scan results.

    Uses Google Gemma 4 31B via the Gemini API. Requires the
    ``google-genai`` package and a valid API key.
    """

    def __init__(self, api_key: str, model: str = _DEFAULT_MODEL) -> None:
        self._api_key = api_key
        self._model = model
        self._client = None

    def _get_client(self):
        """Lazy-init the genai client."""
        if self._client is None:
            try:
                import truststore
                truststore.inject_into_ssl()
            except ImportError:
                pass
            from google import genai
            self._client = genai.Client(api_key=self._api_key)
        return self._client

    def _generate(self, system: str, prompt: str) -> str:
        """Send a prompt to Gemma and return the text response."""
        from google.genai import types

        client = self._get_client()
        try:
            response = client.models.generate_content(
                model=self._model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system,
                ),
            )
            return response.text or ""
        except Exception:
            logger.exception("AI analysis failed")
            return ""

    # ------------------------------------------------------------------
    # 1. Executive Scan Summary
    # ------------------------------------------------------------------

    def summarize_scan(self, report: "ScanReport") -> str:
        """Generate a natural language executive summary of scan results."""
        scan_data = self._build_scan_context(report)

        system = (
            "You are a senior cybersecurity analyst writing an executive "
            "briefing. Be concise, factual, and actionable. Use plain "
            "language that a CISO can understand. Do not use markdown "
            "headers. Structure your response as 2-3 short paragraphs."
        )

        prompt = (
            "Analyze this external attack surface scan and write an "
            "executive summary.\n\n"
            f"SCAN DATA:\n{scan_data}\n\n"
            "Include: total assets found, asset types, risk distribution, "
            "key findings, threat intelligence highlights (enrichment data "
            "if present), and top recommended actions."
        )

        return self._generate(system, prompt)

    # ------------------------------------------------------------------
    # 2. Remediation Recommendations
    # ------------------------------------------------------------------

    def recommend_remediations(
        self, assets: list["AssessedAsset"]
    ) -> str:
        """Generate remediation recommendations for discovered vulnerabilities."""
        vuln_data = self._build_vuln_context(assets)
        if not vuln_data.strip():
            return "No vulnerabilities found — no remediation needed."

        system = (
            "You are a cybersecurity remediation specialist. For each "
            "vulnerability, provide: (1) a one-line explanation of the "
            "risk, (2) specific remediation steps, (3) the MITRE ATT&CK "
            "technique ID if applicable. Be concise and actionable. "
            "Format each vulnerability as a numbered item."
        )

        prompt = (
            "Generate remediation recommendations for these findings "
            "from an external attack surface scan.\n\n"
            f"FINDINGS:\n{vuln_data}"
        )

        return self._generate(system, prompt)

    # ------------------------------------------------------------------
    # 3. Watch Mode Anomaly Explanation
    # ------------------------------------------------------------------

    def explain_changes(self, diff: "ScanDiff") -> str:
        """Explain what detected changes likely mean in context."""
        diff_data = self._build_diff_context(diff)
        if not diff_data.strip():
            return "No changes detected between scans."

        system = (
            "You are a threat intelligence analyst explaining "
            "infrastructure changes detected between two scans. "
            "For each change category, explain what it likely means, "
            "whether it's concerning, and what action to take. "
            "Be concise — 1-2 sentences per change."
        )

        prompt = (
            "Explain these changes detected between two consecutive "
            "attack surface scans.\n\n"
            f"CHANGES:\n{diff_data}"
        )

        return self._generate(system, prompt)

    # ------------------------------------------------------------------
    # 4. Full Markdown Report
    # ------------------------------------------------------------------

    def generate_markdown_report(
        self,
        report: "ScanReport",
        assessed: list["AssessedAsset"],
    ) -> str:
        """Generate a complete markdown analysis report.

        Combines the executive summary and remediation recommendations
        into a single markdown document with scan metadata.
        """
        from datetime import datetime, timezone

        timestamp = report.metadata.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        targets = ", ".join(report.metadata.query_parameters)

        # Generate AI sections
        summary = self.summarize_scan(report)
        remediations = self.recommend_remediations(assessed)

        # Build asset table
        asset_rows = []
        for a in report.assets[:50]:
            risk_score = ""
            if hasattr(a, "correlation_risk_score"):
                risk_score = str(a.correlation_risk_score)
            asset_rows.append(
                f"| {a.ip} | {a.hostname or '-'} | {a.asset_type.value} "
                f"| {', '.join(str(p) for p in a.ports)} "
                f"| {a.risk_level.value.upper()} "
                f"| {len(a.vulnerabilities)} | {risk_score} |"
            )

        asset_table = "\n".join(asset_rows)
        remaining = ""
        if len(report.assets) > 50:
            remaining = f"\n*... and {len(report.assets) - 50} more assets*\n"

        md = f"""# SurfaceAudit Scan Report

**Generated:** {timestamp}
**Targets:** {targets}
**Total Assets:** {report.summary.total_assets}
**Scan Duration:** {report.metadata.scan_duration_seconds}s
**AI Model:** {self._model}

---

## Executive Summary

{summary}

---

## Asset Inventory

| IP | Hostname | Type | Ports | Risk | Vulns | Correlation Score |
|---|---|---|---|---|---|---|
{asset_table}
{remaining}
**Risk Distribution:** {_format_risk_dist(report.summary.assets_by_risk)}

---

## Remediation Recommendations

{remediations}

---

## Threat Intelligence Summary

"""

        # Add enrichment summary if available
        enriched_count = sum(
            1 for a in report.assets
            if hasattr(a, "enrichment_data") and a.enrichment_data
        )
        if enriched_count > 0:
            md += f"{enriched_count} of {len(report.assets)} assets were enriched with external threat intelligence.\n\n"

            # Aggregate enrichment stats
            vt_clean = vt_flagged = 0
            gn_malicious = gn_benign = gn_unknown = 0
            abuse_flagged = abuse_clean = 0

            for a in report.assets:
                if not hasattr(a, "enrichment_data") or not a.enrichment_data:
                    continue
                vt = a.enrichment_data.get("virustotal", {})
                if vt.get("malicious_count", 0) > 0:
                    vt_flagged += 1
                else:
                    vt_clean += 1

                gn = a.enrichment_data.get("greynoise", {})
                cls = gn.get("classification", "unknown")
                if cls == "malicious":
                    gn_malicious += 1
                elif cls == "benign":
                    gn_benign += 1
                else:
                    gn_unknown += 1

                ab = a.enrichment_data.get("abuseipdb", {})
                if ab.get("abuse_confidence_score", 0) > 50:
                    abuse_flagged += 1
                else:
                    abuse_clean += 1

            md += f"| Provider | Clean | Flagged |\n|---|---|---|\n"
            md += f"| VirusTotal | {vt_clean} | {vt_flagged} |\n"
            md += f"| GreyNoise | {gn_benign + gn_unknown} | {gn_malicious} |\n"
            md += f"| AbuseIPDB | {abuse_clean} | {abuse_flagged} |\n"
        else:
            md += "Enrichment was not enabled for this scan. Run with `--enrich` to include threat intelligence data.\n"

        md += "\n---\n\n*Report generated by SurfaceAudit with AI analysis powered by Google Gemma 4.*\n"

        return md

    # ------------------------------------------------------------------
    # Context builders
    # ------------------------------------------------------------------

    def _build_scan_context(self, report: "ScanReport") -> str:
        """Build a compact text representation of scan results for the LLM."""
        lines = []
        lines.append(f"Total assets: {report.summary.total_assets}")
        lines.append(f"Assets by type: {json.dumps(report.summary.assets_by_type)}")
        lines.append(f"Assets by risk: {json.dumps(report.summary.assets_by_risk)}")
        lines.append("")

        for asset in report.assets[:30]:  # cap to avoid token overflow
            parts = [f"IP: {asset.ip}"]
            if asset.hostname:
                parts.append(f"Host: {asset.hostname}")
            parts.append(f"Type: {asset.asset_type.value}")
            parts.append(f"Risk: {asset.risk_level.value}")
            parts.append(f"Ports: {asset.ports}")

            if asset.vulnerabilities:
                vuln_strs = [
                    f"{v.category}: {v.description} ({v.severity.value})"
                    for v in asset.vulnerabilities
                ]
                parts.append(f"Vulns: {'; '.join(vuln_strs)}")

            # Include enrichment data if present (EnrichedAsset)
            if hasattr(asset, "correlation_risk_score"):
                parts.append(f"Correlation Risk Score: {asset.correlation_risk_score}")
            if hasattr(asset, "enrichment_data") and asset.enrichment_data:
                enrichment_summary = {}
                for provider, data in asset.enrichment_data.items():
                    enrichment_summary[provider] = {
                        k: v for k, v in data.items()
                        if k in (
                            "malicious_count", "reputation",
                            "abuse_confidence_score", "total_reports",
                            "classification", "noise", "riot",
                            "subdomains",
                        )
                    }
                parts.append(f"Enrichment: {json.dumps(enrichment_summary)}")

            lines.append(" | ".join(parts))

        if len(report.assets) > 30:
            lines.append(f"... and {len(report.assets) - 30} more assets")

        return "\n".join(lines)

    def _build_vuln_context(self, assets: list["AssessedAsset"]) -> str:
        """Build a compact vulnerability list for the LLM."""
        seen = set()
        lines = []
        for asset in assets:
            for v in asset.vulnerabilities:
                key = (v.category, v.description)
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    f"- [{v.severity.value.upper()}] {v.category}: "
                    f"{v.description} (found on {asset.ip}:{asset.ports})"
                )
        return "\n".join(lines)

    def _build_diff_context(self, diff: "ScanDiff") -> str:
        """Build a compact diff summary for the LLM."""
        lines = []

        if diff.new_assets:
            lines.append(f"NEW ASSETS ({len(diff.new_assets)}):")
            for a in diff.new_assets[:10]:
                lines.append(
                    f"  - {a.ip} ({a.hostname or 'no hostname'}) "
                    f"ports={a.ports} risk={a.risk_level.value}"
                )

        if diff.removed_assets:
            lines.append(f"REMOVED ASSETS ({len(diff.removed_assets)}):")
            for a in diff.removed_assets[:10]:
                lines.append(
                    f"  - {a.ip} ({a.hostname or 'no hostname'}) "
                    f"ports={a.ports}"
                )

        if hasattr(diff, "risk_increase_assets") and diff.risk_increase_assets:
            lines.append(
                f"RISK INCREASES ({len(diff.risk_increase_assets)}):"
            )
            for old, new in diff.risk_increase_assets[:10]:
                lines.append(
                    f"  - {new.ip}: {old.risk_level.value} → "
                    f"{new.risk_level.value}"
                )

        if diff.changed_assets:
            lines.append(f"CHANGED ASSETS ({len(diff.changed_assets)}):")
            for old, new in diff.changed_assets[:10]:
                lines.append(
                    f"  - {new.ip}: ports {old.ports} → {new.ports}"
                )

        return "\n".join(lines)


def _format_risk_dist(risk_dict: dict[str, int]) -> str:
    """Format risk distribution as a readable string."""
    parts = [f"{k.upper()}: {v}" for k, v in risk_dict.items() if v > 0]
    return ", ".join(parts) if parts else "None"
