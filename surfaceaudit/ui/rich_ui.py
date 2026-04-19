"""Rich terminal UI components for SurfaceAudit."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn
from rich.table import Table

from surfaceaudit.models import (
    AssessedAsset,
    ClassifiedAsset,
    ReportSummary,
    RiskLevel,
    ScanDiff,
)


class RichUI:
    """Terminal UI components using the rich library."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def create_progress(self, total: int) -> Progress:
        """Create a progress bar for the discovery phase."""
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Discovering assets..."),
            BarColumn(),
            MofNCompleteColumn(),
            console=self.console,
        )
        progress.add_task("discovery", total=total)
        return progress

    def display_classified_assets(self, assets: list[ClassifiedAsset]) -> None:
        """Render classified assets as a colored table."""
        table = Table(title="Classified Assets", show_lines=True)
        table.add_column("IP", style="cyan")
        table.add_column("Hostname", style="white")
        table.add_column("Asset Type", style="magenta")
        table.add_column("Ports", style="blue")
        table.add_column("OS", style="green")

        for asset in assets:
            table.add_row(
                asset.ip,
                asset.hostname or "",
                asset.asset_type.value,
                ", ".join(str(p) for p in asset.ports),
                asset.os or "",
            )

        self.console.print(table)

    def display_assessed_assets(self, assets: list[AssessedAsset]) -> None:
        """Render assessed assets with risk-colored levels."""
        table = Table(title="Assessed Assets", show_lines=True)
        table.add_column("IP", style="cyan")
        table.add_column("Hostname", style="white")
        table.add_column("Risk Level")
        table.add_column("Vulnerabilities", style="white")
        table.add_column("Ports", style="blue")

        for asset in assets:
            color = self.risk_color(asset.risk_level)
            table.add_row(
                asset.ip,
                asset.hostname or "",
                f"[{color}]{asset.risk_level.value.upper()}[/{color}]",
                str(len(asset.vulnerabilities)),
                ", ".join(str(p) for p in asset.ports),
            )

        self.console.print(table)

    @staticmethod
    def risk_color(level: RiskLevel) -> str:
        """Map risk level to color: HIGH→red, MEDIUM→yellow, LOW→green."""
        return {
            RiskLevel.HIGH: "red",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.LOW: "green",
        }[level]

    def display_summary(self, summary: ReportSummary) -> None:
        """Render a summary panel with totals by type and risk."""
        lines: list[str] = [
            f"[bold]Total Assets:[/bold] {summary.total_assets}",
            "",
            "[bold]By Type:[/bold]",
        ]
        for asset_type, count in summary.assets_by_type.items():
            lines.append(f"  {asset_type}: {count}")

        lines.append("")
        lines.append("[bold]By Risk Level:[/bold]")
        for risk, count in summary.assets_by_risk.items():
            color = self.risk_color(RiskLevel(risk)) if risk in {r.value for r in RiskLevel} else "white"
            lines.append(f"  [{color}]{risk.upper()}[/{color}]: {count}")

        panel = Panel("\n".join(lines), title="Scan Summary", border_style="blue")
        self.console.print(panel)

    def display_diff(self, diff: ScanDiff) -> None:
        """Render scan diff with green/red/yellow coloring."""
        table = Table(title="Scan Diff", show_lines=True)
        table.add_column("Status")
        table.add_column("IP", style="cyan")
        table.add_column("Hostname", style="white")
        table.add_column("Risk Level")
        table.add_column("Details")

        for asset in diff.new_assets:
            color = self.risk_color(asset.risk_level)
            table.add_row(
                "[green]NEW[/green]",
                asset.ip,
                asset.hostname or "",
                f"[{color}]{asset.risk_level.value.upper()}[/{color}]",
                "",
            )

        for asset in diff.removed_assets:
            color = self.risk_color(asset.risk_level)
            table.add_row(
                "[red]REMOVED[/red]",
                asset.ip,
                asset.hostname or "",
                f"[{color}]{asset.risk_level.value.upper()}[/{color}]",
                "",
            )

        for old, new in diff.changed_assets:
            old_color = self.risk_color(old.risk_level)
            new_color = self.risk_color(new.risk_level)

            risk_increased = _risk_order(new.risk_level) > _risk_order(old.risk_level)
            arrow = " [red]↑[/red]" if risk_increased else ""

            detail = (
                f"[{old_color}]{old.risk_level.value.upper()}[/{old_color}] → "
                f"[{new_color}]{new.risk_level.value.upper()}[/{new_color}]{arrow}"
            )

            table.add_row(
                "[yellow]CHANGED[/yellow]",
                new.ip,
                new.hostname or "",
                f"[{new_color}]{new.risk_level.value.upper()}[/{new_color}]",
                detail,
            )

        self.console.print(table)


def _risk_order(level: RiskLevel) -> int:
    """Return numeric order for risk comparison (higher = more severe)."""
    return {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}[level]
