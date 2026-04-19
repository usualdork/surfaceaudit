"""CLI entry point for SurfaceAudit."""

from __future__ import annotations

# Use the macOS/Windows/Linux system certificate store instead of
# relying on OpenSSL's bundled CA certificates.
try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

import os
import sys
import time
from datetime import datetime, timezone

import click

from surfaceaudit.assessor import VulnerabilityAssessor
from surfaceaudit.classifier import AssetClassifier
from surfaceaudit.config import ScanConfig
from surfaceaudit.errors import ConfigurationError, ScannerError
from surfaceaudit.history import ScanHistoryManager
from surfaceaudit.models import ScanMetadata
from surfaceaudit.providers import ProviderRegistry
from surfaceaudit.report import ReportEncryptor, ReportFormatter, ReportGenerator
from surfaceaudit.rules import RuleEngine
from surfaceaudit.ui.rich_ui import RichUI


@click.group()
def main() -> None:
    """SurfaceAudit — Open-source external attack surface management."""


@main.command()
@click.option("--config", "config_path", type=click.Path(), default=None, help="Config file path (JSON/YAML)")
@click.option("--api-key", envvar="SHODAN_API_KEY", default=None, help="API key for the data source provider")
@click.option("--targets", multiple=True, help="Domain/IP/org targets")
@click.option("--provider", default=None, help="Data source provider (default: shodan)")
@click.option("--rules-dir", default=None, help="Custom rules directory path")
@click.option("--exclude-rules", default=None, help="Comma-separated rule IDs to exclude")
@click.option("--tags", "filter_tags", default=None, help="Comma-separated tags to filter rules")
@click.option("--min-severity", default=None, type=click.Choice(["info", "low", "medium", "high", "critical"], case_sensitive=False), help="Minimum rule severity")
@click.option("--enrich", is_flag=True, default=False, help="Enable enrichment after assessment")
@click.option("--ai-key", envvar="GEMINI_API_KEY", default=None, help="Gemini API key for AI analysis (auto-enabled when set)")
@click.option("--no-ai", is_flag=True, default=False, help="Disable AI analysis even when API key is available")
@click.option("--output-format", type=click.Choice(["json", "csv", "html", "sarif"]), default=None, help="Output format")
@click.option("--output-file", type=click.Path(), default=None, help="Output file path")
@click.option("--encrypt", is_flag=True, default=False, help="Encrypt report at rest")
@click.option("--redact", is_flag=True, default=False, help="Redact sensitive info")
def scan(
    config_path: str | None,
    api_key: str | None,
    targets: tuple[str, ...],
    provider: str | None,
    rules_dir: str | None,
    exclude_rules: str | None,
    filter_tags: str | None,
    min_severity: str | None,
    enrich: bool,
    ai_key: str | None,
    no_ai: bool,
    output_format: str | None,
    output_file: str | None,
    encrypt: bool,
    redact: bool,
) -> None:
    """Run a full infrastructure scan."""
    try:
        ui = RichUI()

        # ---- Build configuration ----
        cfg = _build_config(
            config_path, api_key, targets, output_format,
            output_file, encrypt, redact, provider, rules_dir,
        )

        # ---- Resolve provider ----
        provider_cls = ProviderRegistry.get(cfg.provider)
        data_provider = provider_cls()

        # ---- Authenticate ----
        ui.console.print("[bold]Authenticating with provider…[/bold]")
        data_provider.authenticate(cfg.api_key)
        ui.console.print("[green]Authentication successful.[/green]")

        # ---- Credits ----
        credits_before = data_provider.get_credits()
        ui.console.print(f"Available credits: {credits_before}")

        # ---- Load rule engine (always v2, with optional filters) ----
        from surfaceaudit.rules.v2.engine import RuleEngineV2

        engine_v2 = RuleEngineV2()
        exclude_ids = [r.strip() for r in exclude_rules.split(",")] if exclude_rules else None
        tags_list = [t.strip() for t in filter_tags.split(",")] if filter_tags else None
        dirs = [cfg.rules_dir] if cfg.rules_dir else None
        engine_v2.load(
            rules_dirs=dirs,
            tags=tags_list,
            min_severity=min_severity,
            exclude_ids=exclude_ids,
        )

        # ---- Discover with progress ----
        ui.console.print(f"Discovering assets for {len(cfg.targets)} target(s)…")
        start_time = time.time()
        raw_assets = data_provider.discover(cfg.targets)
        ui.console.print(f"Discovered {len(raw_assets)} raw asset(s).")

        # ---- Classify ----
        classifier = AssetClassifier(engine_v2=engine_v2)
        classified = [classifier.classify(ra) for ra in raw_assets]
        ui.display_classified_assets(classified)

        # ---- Assess ----
        assessor = VulnerabilityAssessor(engine_v2=engine_v2)
        assessed = [assessor.assess(ca) for ca in classified]
        ui.display_assessed_assets(assessed)

        # ---- Enrich (optional) ----
        if enrich:
            assessed = _run_enrichment(cfg, assessed)

        scan_duration = time.time() - start_time

        # ---- Generate report ----
        metadata = ScanMetadata(
            timestamp=datetime.now(tz=timezone.utc),
            query_parameters=list(cfg.targets),
            api_credits_used=0,
            scan_duration_seconds=round(scan_duration, 2),
        )
        generator = ReportGenerator()
        report = generator.generate(assessed, metadata, cfg)

        # ---- Display summary ----
        ui.display_summary(report.summary)

        # ---- AI Analysis (auto-enabled when key is available) ----
        resolved_ai_key = ai_key or cfg.ai.api_key
        if resolved_ai_key and not no_ai:
            md_path = _run_ai_analysis(resolved_ai_key, cfg.ai.model, report, assessed, ui)
            if md_path:
                ui.console.print(f"[green]AI report written to {md_path}[/green]")

        # ---- Format ----
        formatter = ReportFormatter()
        fmt = cfg.output_format
        if fmt == "csv":
            output_content = formatter.to_csv(report)
        elif fmt == "html":
            output_content = formatter.to_html(report)
        elif fmt == "sarif":
            output_content = formatter.to_sarif(report)
        else:
            output_content = formatter.to_json(report)

        output_bytes = output_content.encode("utf-8")

        # ---- Encrypt (optional) ----
        if cfg.encrypt_reports:
            password = click.prompt("Encryption password", hide_input=True)
            encryptor = ReportEncryptor()
            output_bytes = encryptor.encrypt(output_bytes, password)

        # ---- Write output ----
        if cfg.output_file:
            _write_output_file(cfg.output_file, output_bytes)
            ui.console.print(f"Report written to {cfg.output_file}")
        else:
            if cfg.encrypt_reports:
                sys.stdout.buffer.write(output_bytes)
            else:
                click.echo(output_content)

        # ---- Save to history ----
        history_mgr = ScanHistoryManager(storage_dir=".scan_history")
        history_path = history_mgr.save(report)
        ui.console.print(f"Scan saved to history: {history_path}")

        # ---- Credits (after) ----
        credits_after = data_provider.get_credits()
        used = credits_before - credits_after
        ui.console.print(f"Credits used: {used}  |  Remaining: {credits_after}")

    except ScannerError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc


@main.command()
@click.argument("report1", type=click.Path(exists=True))
@click.argument("report2", type=click.Path(exists=True))
def compare(report1: str, report2: str) -> None:
    """Compare two scan reports and display differences."""
    try:
        ui = RichUI()
        history_mgr = ScanHistoryManager(storage_dir=".scan_history")
        report_a = history_mgr.load(report1)
        report_b = history_mgr.load(report2)
        diff = history_mgr.compare(report_a, report_b)
        ui.display_diff(diff)

    except ScannerError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc


@main.command()
@click.option("--config", "config_path", type=click.Path(exists=True), required=True, help="YAML config file with watch/notification settings")
def watch(config_path: str) -> None:
    """Run a scan, compare against last saved scan, and notify on changes."""
    try:
        from surfaceaudit.notifications.dispatcher import NotificationDispatcher as ND
        from surfaceaudit.notifications.providers import (
            DiscordNotifier,
            GenericWebhookNotifier,
            SlackNotifier,
        )
        from surfaceaudit.watch import WatchMode

        ui = RichUI()

        # ---- Load configuration ----
        cfg = ScanConfig.from_file(config_path)

        # ---- Resolve provider ----
        provider_cls = ProviderRegistry.get(cfg.provider)
        data_provider = provider_cls()

        # ---- Authenticate ----
        ui.console.print("[bold]Authenticating with provider…[/bold]")
        data_provider.authenticate(cfg.api_key)
        ui.console.print("[green]Authentication successful.[/green]")

        # ---- Load rule engine ----
        rule_engine = RuleEngine(rules_dir=cfg.rules_dir)
        rule_engine.load()

        # ---- Discover ----
        ui.console.print(f"Discovering assets for {len(cfg.targets)} target(s)…")
        start_time = time.time()
        raw_assets = data_provider.discover(cfg.targets)
        ui.console.print(f"Discovered {len(raw_assets)} raw asset(s).")

        # ---- Classify ----
        classifier = AssetClassifier(rule_engine=rule_engine)
        classified = [classifier.classify(ra) for ra in raw_assets]

        # ---- Assess ----
        assessor = VulnerabilityAssessor(rule_engine=rule_engine)
        assessed = [assessor.assess(ca) for ca in classified]

        # ---- Enrich (if enabled in config) ----
        if cfg.enrichment.enabled:
            assessed = _run_enrichment(cfg, assessed)

        scan_duration = time.time() - start_time

        # ---- Generate report ----
        metadata = ScanMetadata(
            timestamp=datetime.now(tz=timezone.utc),
            query_parameters=list(cfg.targets),
            api_credits_used=0,
            scan_duration_seconds=round(scan_duration, 2),
        )
        generator = ReportGenerator()
        report = generator.generate(assessed, metadata, cfg)

        # ---- Build notification dispatcher ----
        notification_providers: list[tuple] = []
        for nc in cfg.watch.notifications:
            notifier = _build_notifier(nc)
            if notifier is not None:
                notification_providers.append((notifier, nc.on))

        dispatcher = ND(providers=notification_providers)

        # ---- Run watch cycle ----
        history_dir = cfg.watch.history_dir
        history_mgr = ScanHistoryManager(storage_dir=history_dir)
        watch_mode = WatchMode(
            config=cfg,
            history_manager=history_mgr,
            dispatcher=dispatcher,
        )
        diff = watch_mode.run(current_report=report)

        # ---- Display diff ----
        ui.display_diff(diff)
        ui.console.print("[green]Watch cycle complete.[/green]")

    except ScannerError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc


@main.command("save-config")
@click.option("--output", type=click.Path(), required=True, help="Output config file path")
@click.option("--api-key", envvar="SHODAN_API_KEY", default=None, help="API key")
@click.option("--targets", multiple=True, help="Domain/IP/org targets")
@click.option("--provider", default=None, help="Data source provider")
@click.option("--rules-dir", default=None, help="Custom rules directory path")
@click.option("--output-format", type=click.Choice(["json", "csv", "html", "sarif"]), default=None, help="Output format")
@click.option("--output-file", type=click.Path(), default=None, help="Output file path for scans")
@click.option("--encrypt", is_flag=True, default=False, help="Encrypt reports")
@click.option("--redact", is_flag=True, default=False, help="Redact sensitive info")
def save_config(
    output: str,
    api_key: str | None,
    targets: tuple[str, ...],
    provider: str | None,
    rules_dir: str | None,
    output_format: str | None,
    output_file: str | None,
    encrypt: bool,
    redact: bool,
) -> None:
    """Save current configuration to a file."""
    try:
        cfg = _build_config(
            None, api_key, targets, output_format,
            output_file, encrypt, redact, provider, rules_dir,
        )
        cfg.save(output)
        click.echo(f"Configuration saved to {output}")
    except ScannerError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1) from exc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_config(
    config_path: str | None,
    api_key: str | None,
    targets: tuple[str, ...],
    output_format: str | None,
    output_file: str | None,
    encrypt: bool,
    redact: bool,
    provider: str | None = None,
    rules_dir: str | None = None,
) -> ScanConfig:
    """Build a ScanConfig from file + CLI overrides, or purely from CLI args."""
    cli_overrides: dict = {}
    if api_key is not None:
        cli_overrides["api_key"] = api_key
    if targets:
        cli_overrides["targets"] = list(targets)
    if output_format is not None:
        cli_overrides["output_format"] = output_format
    if output_file is not None:
        cli_overrides["output_file"] = output_file
    if encrypt:
        cli_overrides["encrypt_reports"] = True
    if redact:
        cli_overrides["redact_sensitive"] = True
    if provider is not None:
        cli_overrides["provider"] = provider
    if rules_dir is not None:
        cli_overrides["rules_dir"] = rules_dir

    if config_path:
        file_cfg = ScanConfig.from_file(config_path)
        file_dict = file_cfg.model_dump()
        return ScanConfig.merge(file_dict, cli_overrides)

    # No config file — build entirely from CLI args
    if "api_key" not in cli_overrides:
        raise ConfigurationError("API key is required (--api-key or SHODAN_API_KEY)")
    if "targets" not in cli_overrides:
        raise ConfigurationError("At least one target is required (--targets)")

    defaults: dict = {}
    if "output_format" not in cli_overrides:
        defaults["output_format"] = "json"

    return ScanConfig(**{**defaults, **cli_overrides})


def _build_notifier(nc):
    """Build a notification provider from a NotificationConfig."""
    from surfaceaudit.notifications.providers import (
        DiscordNotifier,
        GenericWebhookNotifier,
        SlackNotifier,
    )

    if nc.type == "slack" and nc.webhook_url:
        return SlackNotifier(webhook_url=nc.webhook_url)
    if nc.type == "discord" and nc.webhook_url:
        return DiscordNotifier(webhook_url=nc.webhook_url)
    if nc.type == "webhook" and nc.url:
        return GenericWebhookNotifier(url=nc.url)
    return None


def _run_enrichment(cfg: ScanConfig, assessed: list) -> list:
    """Run the enrichment pipeline on assessed assets.

    Returns a list of :class:`EnrichedAsset` objects (which extend
    ``AssessedAsset``) so downstream report generation works unchanged.
    """
    from surfaceaudit.enrichment.cache import EnrichmentCache
    from surfaceaudit.enrichment.manager import (
        EnrichmentConfig as EMEnrichmentConfig,
        EnrichmentManager,
        EnrichmentProviderConfig as EMProviderConfig,
    )
    from surfaceaudit.models import EnrichedAsset

    em_config = EMEnrichmentConfig(
        enabled=True,
        providers={
            name: EMProviderConfig(
                enabled=pc.enabled,
                api_key=pc.api_key,
            )
            for name, pc in cfg.enrichment.providers.items()
        },
        cache_dir=cfg.enrichment.cache_dir,
        cache_ttl_hours=cfg.enrichment.cache_ttl_hours,
    )
    cache = EnrichmentCache(
        cache_dir=em_config.cache_dir,
        ttl_hours=em_config.cache_ttl_hours,
    )
    manager = EnrichmentManager(config=em_config, cache=cache)

    # Register enabled providers
    _register_enrichment_providers(manager, cfg)

    results = manager.enrich(assessed)

    # Convert EnrichedAssetResult → EnrichedAsset (extends AssessedAsset)
    enriched_assets: list[EnrichedAsset] = []
    for r in results:
        orig = r.original_asset
        enriched_assets.append(
            EnrichedAsset(
                ip=orig.ip,
                hostname=orig.hostname,
                asset_type=orig.asset_type,
                os=orig.os,
                services=list(orig.services),
                geolocation=orig.geolocation,
                ports=list(orig.ports),
                vulnerabilities=list(orig.vulnerabilities),
                risk_level=orig.risk_level,
                correlation_risk_score=r.correlation_risk_score,
                enrichment_data=r.enrichment_data,
                discovered_subdomains=r.discovered_subdomains,
            )
        )
    return enriched_assets


def _register_enrichment_providers(manager, cfg: ScanConfig) -> None:
    """Register enrichment providers based on config."""
    from surfaceaudit.enrichment.providers.abuseipdb import AbuseIPDBProvider
    from surfaceaudit.enrichment.providers.crtsh import CrtshProvider
    from surfaceaudit.enrichment.providers.greynoise import GreyNoiseProvider
    from surfaceaudit.enrichment.providers.virustotal import VirusTotalProvider

    provider_map = {
        "crtsh": lambda pc: CrtshProvider(),
        "virustotal": lambda pc: VirusTotalProvider(api_key=pc.api_key or ""),
        "greynoise": lambda pc: GreyNoiseProvider(api_key=pc.api_key or ""),
        "abuseipdb": lambda pc: AbuseIPDBProvider(api_key=pc.api_key or ""),
    }

    for name, pc in cfg.enrichment.providers.items():
        if name in provider_map and pc.enabled:
            manager.register_provider(provider_map[name](pc))


def _write_output_file(path: str, data: bytes) -> None:
    """Write *data* to *path* with owner-only permissions (0o600)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def _run_ai_analysis(ai_key: str, model: str, report, assessed: list, ui) -> str | None:
    """Run AI-powered analysis, write markdown report, return the file path."""
    try:
        from surfaceaudit.ai.analyzer import AIAnalyzer

        analyzer = AIAnalyzer(api_key=ai_key, model=model)

        ui.console.print("\n[bold cyan]AI-Powered Analysis (Gemma 4)[/bold cyan]")
        ui.console.print("[dim]Generating AI report…[/dim]")

        md_content = analyzer.generate_markdown_report(report, assessed)

        if not md_content:
            ui.console.print("[yellow]AI analysis returned empty — skipping.[/yellow]")
            return None

        # Determine markdown file path — alongside the JSON output
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        md_path = f"surfaceaudit_report_{timestamp}.md"

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        # Also print the executive summary to the terminal
        summary_start = md_content.find("## Executive Summary")
        remediation_start = md_content.find("## Remediation")
        if summary_start != -1 and remediation_start != -1:
            summary_section = md_content[summary_start:remediation_start].strip()
            # Strip the header line
            summary_lines = summary_section.split("\n", 2)
            if len(summary_lines) > 2:
                ui.console.print(f"\n[bold]Executive Summary[/bold]\n{summary_lines[2].strip()}")

        return md_path

    except Exception:
        import logging
        logging.getLogger(__name__).exception("AI analysis failed")
        ui.console.print("[yellow]AI analysis encountered an error — skipping.[/yellow]")
        return None
