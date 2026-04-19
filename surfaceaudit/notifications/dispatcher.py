"""Notification dispatcher: filters events and sends to providers."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from surfaceaudit.models import AssessedAsset, RiskLevel, ScanDiff
from surfaceaudit.notifications.providers import BaseNotificationProvider

logger = logging.getLogger(__name__)

# Event types produced by a ScanDiff
EVENT_NEW_ASSETS = "new_assets"
EVENT_REMOVED_ASSETS = "removed_assets"
EVENT_RISK_INCREASE = "risk_increase"

_ALL_EVENTS = {EVENT_NEW_ASSETS, EVENT_REMOVED_ASSETS, EVENT_RISK_INCREASE}


class NotificationDispatcher:
    """Iterates providers, filters by event type, formats payload, sends.

    Each provider is paired with an ``on`` list of event types.  An empty
    ``on`` list means the provider receives all event types.
    """

    def __init__(
        self, providers: list[tuple[BaseNotificationProvider, list[str]]]
    ) -> None:
        self._providers = providers

    def dispatch(
        self, diff: ScanDiff, config_path: str, diff_report_path: str
    ) -> None:
        """Send notifications for each event type present in *diff*."""
        events = self._events_from_diff(diff)
        for event, assets in events:
            payload = self._build_payload(event, assets, config_path, diff_report_path)
            for provider, on_list in self._providers:
                if on_list and event not in on_list:
                    continue
                try:
                    provider.send(payload)
                except Exception:
                    logger.error(
                        "Provider %s failed for event %s",
                        provider.name(),
                        event,
                        exc_info=True,
                    )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _events_from_diff(
        diff: ScanDiff,
    ) -> list[tuple[str, list[AssessedAsset]]]:
        """Return a list of ``(event_type, asset_list)`` pairs for non-empty
        categories in the diff."""
        events: list[tuple[str, list[AssessedAsset]]] = []
        if diff.new_assets:
            events.append((EVENT_NEW_ASSETS, diff.new_assets))
        if diff.removed_assets:
            events.append((EVENT_REMOVED_ASSETS, diff.removed_assets))
        if diff.risk_increase_assets:
            # Use the *new* version of each risk-increase asset
            events.append(
                (EVENT_RISK_INCREASE, [new for _, new in diff.risk_increase_assets])
            )
        return events

    @staticmethod
    def _build_payload(
        event: str,
        assets: list[AssessedAsset],
        config_path: str,
        diff_report_path: str,
    ) -> dict:
        """Build the standard notification JSON payload."""
        details = []
        for a in assets:
            details.append(
                {
                    "ip": a.ip,
                    "hostname": a.hostname,
                    "ports": list(a.ports),
                    "risk": a.risk_level.value if isinstance(a.risk_level, RiskLevel) else str(a.risk_level),
                }
            )

        summary = f"{len(assets)} {event.replace('_', ' ')}"

        return {
            "tool": "SurfaceAudit",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "event": event,
            "summary": summary,
            "details": details,
            "scan_config": config_path,
            "diff_report_path": diff_report_path,
        }
