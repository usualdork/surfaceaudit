"""Watch mode: scan → diff → notify for SurfaceAudit."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from surfaceaudit.history import ScanHistoryManager
from surfaceaudit.models import (
    AssessedAsset,
    RiskLevel,
    ScanDiff,
    ScanReport,
    to_serializable_dict,
)

logger = logging.getLogger(__name__)

_UTC = timezone.utc

# Risk level ordering: LOW < MEDIUM < HIGH
RISK_LEVEL_ORDER: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
}


# ---------------------------------------------------------------------------
# Notification dispatcher protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class NotificationDispatcher(Protocol):
    """Protocol for dispatching notifications about scan diffs."""

    def dispatch(
        self, diff: ScanDiff, config_path: str, diff_report_path: str
    ) -> None: ...


class _NullDispatcher:
    """No-op dispatcher used when no notification system is configured."""

    def dispatch(
        self, diff: ScanDiff, config_path: str, diff_report_path: str
    ) -> None:
        pass


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------

def compute_diff(
    previous: list[AssessedAsset], current: list[AssessedAsset]
) -> ScanDiff:
    """Compute categorised differences between two asset lists.

    Categories:
    * **new_assets** – IP in *current* but not in *previous*.
    * **removed_assets** – IP in *previous* but not in *current*.
    * **risk_increase_assets** – IP in both, current risk level strictly
      higher than previous (LOW < MEDIUM < HIGH).
    * **changed_assets** – IP in both, port list or service configuration
      differs (but not already captured as risk_increase).
    """
    prev_map: dict[str, AssessedAsset] = {a.ip: a for a in previous}
    curr_map: dict[str, AssessedAsset] = {a.ip: a for a in current}

    new_assets = [curr_map[ip] for ip in curr_map if ip not in prev_map]
    removed_assets = [prev_map[ip] for ip in prev_map if ip not in curr_map]

    risk_increase_assets: list[tuple[AssessedAsset, AssessedAsset]] = []
    changed_assets: list[tuple[AssessedAsset, AssessedAsset]] = []

    for ip in prev_map:
        if ip not in curr_map:
            continue
        old, new = prev_map[ip], curr_map[ip]

        old_rank = RISK_LEVEL_ORDER.get(old.risk_level, 0)
        new_rank = RISK_LEVEL_ORDER.get(new.risk_level, 0)

        if new_rank > old_rank:
            risk_increase_assets.append((old, new))
        elif _asset_changed(old, new):
            changed_assets.append((old, new))

    return ScanDiff(
        new_assets=new_assets,
        removed_assets=removed_assets,
        changed_assets=changed_assets,
        risk_increase_assets=risk_increase_assets,
    )


def _asset_changed(old: AssessedAsset, new: AssessedAsset) -> bool:
    """Return True if ports or service configuration differs."""
    if sorted(old.ports) != sorted(new.ports):
        return True
    old_services = sorted(
        [(s.port, s.protocol, s.name, s.version) for s in old.services]
    )
    new_services = sorted(
        [(s.port, s.protocol, s.name, s.version) for s in new.services]
    )
    return old_services != new_services


# ---------------------------------------------------------------------------
# WatchMode
# ---------------------------------------------------------------------------

class WatchMode:
    """Runs scan → load latest history → compute diff → save → notify."""

    def __init__(
        self,
        config: object,
        history_manager: ScanHistoryManager,
        dispatcher: NotificationDispatcher | None = None,
    ) -> None:
        self._config = config
        self._history = history_manager
        self._dispatcher: NotificationDispatcher = dispatcher or _NullDispatcher()
        self._history_dir = self._history._storage_dir

        # Ensure history dir exists
        os.makedirs(self._history_dir, exist_ok=True)

    def run(self, current_report: ScanReport | None = None) -> ScanDiff:
        """Execute the full watch cycle.

        If *current_report* is provided it is used directly (useful for
        testing).  Otherwise a scan would be executed — but that is left
        to the CLI layer to wire up.

        Returns the computed ``ScanDiff``.
        """
        if current_report is None:
            raise ValueError(
                "current_report must be provided (scan execution is "
                "handled by the CLI layer)"
            )

        # 1. Load latest previous scan
        previous_report = self._load_latest_scan()

        # 2. Compute diff
        previous_assets = previous_report.assets if previous_report else []
        diff = compute_diff(previous_assets, current_report.assets)

        # 3. Save current scan to history
        self._history.save(current_report)

        # 4. Save diff as timestamped JSON
        diff_path = self._save_diff(diff)

        # 5. Dispatch notifications
        config_path = getattr(self._config, "config_path", "")
        if not isinstance(config_path, str):
            config_path = ""
        self._dispatcher.dispatch(diff, config_path, diff_path)

        return diff

    def _load_latest_scan(self) -> ScanReport | None:
        """Find and load the most recent scan JSON from history_dir."""
        if not os.path.isdir(self._history_dir):
            return None

        json_files = sorted(
            f
            for f in os.listdir(self._history_dir)
            if f.startswith("scan_") and f.endswith(".json")
        )

        if not json_files:
            return None

        latest = json_files[-1]
        path = os.path.join(self._history_dir, latest)
        try:
            return self._history.load(path)
        except Exception:
            logger.warning("Failed to load previous scan %s", path, exc_info=True)
            return None

    def _save_diff(self, diff: ScanDiff) -> str:
        """Persist *diff* as a timestamped JSON file. Returns the path."""
        timestamp = datetime.now(tz=_UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"diff_{timestamp}.json"
        path = os.path.join(self._history_dir, filename)

        data = to_serializable_dict(diff)
        content = json.dumps(data, indent=2)

        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, content.encode("utf-8"))
        finally:
            os.close(fd)

        return path
