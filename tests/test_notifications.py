"""Unit tests for notification providers and dispatcher."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from surfaceaudit.models import (
    AssessedAsset,
    AssetType,
    GeoLocation,
    RiskLevel,
    ScanDiff,
    Service,
)
from surfaceaudit.notifications.providers import (
    BaseNotificationProvider,
    DiscordNotifier,
    GenericWebhookNotifier,
    SlackNotifier,
)
from surfaceaudit.notifications.dispatcher import (
    EVENT_NEW_ASSETS,
    EVENT_REMOVED_ASSETS,
    EVENT_RISK_INCREASE,
    NotificationDispatcher,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_asset(
    ip: str = "1.2.3.4",
    hostname: str | None = "host.example.com",
    ports: list[int] | None = None,
    risk: RiskLevel = RiskLevel.LOW,
) -> AssessedAsset:
    return AssessedAsset(
        ip=ip,
        hostname=hostname,
        asset_type=AssetType.WEB_SERVER,
        os="Linux",
        services=[Service(port=80, protocol="tcp", name="http")],
        geolocation=GeoLocation(country="US"),
        ports=ports or [80],
        vulnerabilities=[],
        risk_level=risk,
    )


class RecordingProvider(BaseNotificationProvider):
    """Test double that records sent payloads."""

    def __init__(self, provider_name: str = "test") -> None:
        self._name = provider_name
        self.sent: list[dict] = []

    def name(self) -> str:
        return self._name

    def send(self, payload: dict) -> None:
        self.sent.append(payload)


class FailingProvider(BaseNotificationProvider):
    """Provider that always raises."""

    def name(self) -> str:
        return "failing"

    def send(self, payload: dict) -> None:
        raise RuntimeError("boom")


# ---------------------------------------------------------------------------
# Tests: BaseNotificationProvider
# ---------------------------------------------------------------------------


class TestBaseNotificationProvider:
    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            BaseNotificationProvider()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# Tests: SlackNotifier
# ---------------------------------------------------------------------------


class TestSlackNotifier:
    def test_name(self):
        s = SlackNotifier("https://hooks.slack.com/test")
        assert s.name() == "slack"

    @patch("surfaceaudit.notifications.providers.urllib.request.urlopen")
    def test_send_posts_json(self, mock_urlopen: MagicMock):
        mock_urlopen.return_value.__enter__ = MagicMock()
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
        s = SlackNotifier("https://hooks.slack.com/test")
        payload = {"tool": "SurfaceAudit", "event": "new_assets"}
        s.send(payload)
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Content-type") == "application/json"
        assert json.loads(req.data) == payload

    @patch(
        "surfaceaudit.notifications.providers.urllib.request.urlopen",
        side_effect=Exception("network error"),
    )
    def test_send_logs_error_without_raising(self, mock_urlopen: MagicMock):
        s = SlackNotifier("https://hooks.slack.com/test")
        # Should not raise
        s.send({"event": "test"})


# ---------------------------------------------------------------------------
# Tests: DiscordNotifier
# ---------------------------------------------------------------------------


class TestDiscordNotifier:
    def test_name(self):
        d = DiscordNotifier("https://discord.com/api/webhooks/test")
        assert d.name() == "discord"

    @patch("surfaceaudit.notifications.providers.urllib.request.urlopen")
    def test_send_wraps_in_content(self, mock_urlopen: MagicMock):
        mock_urlopen.return_value.__enter__ = MagicMock()
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
        d = DiscordNotifier("https://discord.com/api/webhooks/test")
        payload = {"tool": "SurfaceAudit", "event": "new_assets"}
        d.send(payload)
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data)
        assert "content" in body
        assert json.loads(body["content"]) == payload

    @patch(
        "surfaceaudit.notifications.providers.urllib.request.urlopen",
        side_effect=Exception("network error"),
    )
    def test_send_logs_error_without_raising(self, mock_urlopen: MagicMock):
        d = DiscordNotifier("https://discord.com/api/webhooks/test")
        d.send({"event": "test"})


# ---------------------------------------------------------------------------
# Tests: GenericWebhookNotifier
# ---------------------------------------------------------------------------


class TestGenericWebhookNotifier:
    def test_name(self):
        w = GenericWebhookNotifier("https://example.com/hook")
        assert w.name() == "webhook"

    @patch("surfaceaudit.notifications.providers.urllib.request.urlopen")
    def test_send_posts_json(self, mock_urlopen: MagicMock):
        mock_urlopen.return_value.__enter__ = MagicMock()
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
        w = GenericWebhookNotifier("https://example.com/hook")
        payload = {"tool": "SurfaceAudit", "event": "removed_assets"}
        w.send(payload)
        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Content-type") == "application/json"
        assert json.loads(req.data) == payload

    @patch(
        "surfaceaudit.notifications.providers.urllib.request.urlopen",
        side_effect=Exception("network error"),
    )
    def test_send_logs_error_without_raising(self, mock_urlopen: MagicMock):
        w = GenericWebhookNotifier("https://example.com/hook")
        w.send({"event": "test"})


# ---------------------------------------------------------------------------
# Tests: NotificationDispatcher — event filtering
# ---------------------------------------------------------------------------


class TestDispatcherEventFiltering:
    def test_empty_on_list_sends_all_events(self):
        provider = RecordingProvider()
        dispatcher = NotificationDispatcher([(provider, [])])
        diff = ScanDiff(
            new_assets=[_make_asset(ip="1.1.1.1")],
            removed_assets=[_make_asset(ip="2.2.2.2")],
            changed_assets=[],
            risk_increase_assets=[],
        )
        dispatcher.dispatch(diff, "/cfg.yaml", "/diff.json")
        assert len(provider.sent) == 2  # new_assets + removed_assets

    def test_on_list_filters_events(self):
        provider = RecordingProvider()
        dispatcher = NotificationDispatcher([(provider, ["new_assets"])])
        diff = ScanDiff(
            new_assets=[_make_asset(ip="1.1.1.1")],
            removed_assets=[_make_asset(ip="2.2.2.2")],
            changed_assets=[],
            risk_increase_assets=[],
        )
        dispatcher.dispatch(diff, "/cfg.yaml", "/diff.json")
        assert len(provider.sent) == 1
        assert provider.sent[0]["event"] == "new_assets"

    def test_no_matching_events_sends_nothing(self):
        provider = RecordingProvider()
        dispatcher = NotificationDispatcher([(provider, ["risk_increase"])])
        diff = ScanDiff(
            new_assets=[_make_asset(ip="1.1.1.1")],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[],
        )
        dispatcher.dispatch(diff, "/cfg.yaml", "/diff.json")
        assert len(provider.sent) == 0

    def test_risk_increase_event(self):
        provider = RecordingProvider()
        dispatcher = NotificationDispatcher([(provider, [])])
        old = _make_asset(ip="1.1.1.1", risk=RiskLevel.LOW)
        new = _make_asset(ip="1.1.1.1", risk=RiskLevel.HIGH)
        diff = ScanDiff(
            new_assets=[],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[(old, new)],
        )
        dispatcher.dispatch(diff, "/cfg.yaml", "/diff.json")
        assert len(provider.sent) == 1
        assert provider.sent[0]["event"] == "risk_increase"


# ---------------------------------------------------------------------------
# Tests: NotificationDispatcher — payload format
# ---------------------------------------------------------------------------


class TestDispatcherPayload:
    def test_payload_has_required_fields(self):
        provider = RecordingProvider()
        dispatcher = NotificationDispatcher([(provider, [])])
        diff = ScanDiff(
            new_assets=[_make_asset(ip="1.1.1.1")],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[],
        )
        dispatcher.dispatch(diff, "/cfg.yaml", "/diff.json")
        payload = provider.sent[0]
        required = {"tool", "timestamp", "event", "summary", "details", "scan_config", "diff_report_path"}
        assert required.issubset(payload.keys())

    def test_payload_tool_is_surfaceaudit(self):
        provider = RecordingProvider()
        dispatcher = NotificationDispatcher([(provider, [])])
        diff = ScanDiff(
            new_assets=[_make_asset()],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[],
        )
        dispatcher.dispatch(diff, "/cfg.yaml", "/diff.json")
        assert provider.sent[0]["tool"] == "SurfaceAudit"

    def test_payload_details_structure(self):
        provider = RecordingProvider()
        dispatcher = NotificationDispatcher([(provider, [])])
        asset = _make_asset(ip="10.0.0.1", hostname="web.local", ports=[80, 443], risk=RiskLevel.HIGH)
        diff = ScanDiff(
            new_assets=[asset],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[],
        )
        dispatcher.dispatch(diff, "/cfg.yaml", "/diff.json")
        details = provider.sent[0]["details"]
        assert len(details) == 1
        d = details[0]
        assert d["ip"] == "10.0.0.1"
        assert d["hostname"] == "web.local"
        assert d["ports"] == [80, 443]
        assert d["risk"] == "high"

    def test_payload_json_serializable(self):
        provider = RecordingProvider()
        dispatcher = NotificationDispatcher([(provider, [])])
        diff = ScanDiff(
            new_assets=[_make_asset()],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[],
        )
        dispatcher.dispatch(diff, "/cfg.yaml", "/diff.json")
        # Should not raise
        json.dumps(provider.sent[0])

    def test_payload_config_and_diff_paths(self):
        provider = RecordingProvider()
        dispatcher = NotificationDispatcher([(provider, [])])
        diff = ScanDiff(
            new_assets=[_make_asset()],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[],
        )
        dispatcher.dispatch(diff, "/my/config.yaml", "/my/diff.json")
        p = provider.sent[0]
        assert p["scan_config"] == "/my/config.yaml"
        assert p["diff_report_path"] == "/my/diff.json"


# ---------------------------------------------------------------------------
# Tests: NotificationDispatcher — error handling
# ---------------------------------------------------------------------------


class TestDispatcherErrorHandling:
    def test_provider_failure_does_not_halt(self):
        failing = FailingProvider()
        recording = RecordingProvider()
        dispatcher = NotificationDispatcher([(failing, []), (recording, [])])
        diff = ScanDiff(
            new_assets=[_make_asset()],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[],
        )
        dispatcher.dispatch(diff, "/cfg.yaml", "/diff.json")
        # The recording provider should still receive the payload
        assert len(recording.sent) == 1

    def test_empty_diff_sends_nothing(self):
        provider = RecordingProvider()
        dispatcher = NotificationDispatcher([(provider, [])])
        diff = ScanDiff(
            new_assets=[],
            removed_assets=[],
            changed_assets=[],
            risk_increase_assets=[],
        )
        dispatcher.dispatch(diff, "/cfg.yaml", "/diff.json")
        assert len(provider.sent) == 0

    def test_multiple_providers_different_filters(self):
        p1 = RecordingProvider("p1")
        p2 = RecordingProvider("p2")
        dispatcher = NotificationDispatcher([
            (p1, ["new_assets"]),
            (p2, ["removed_assets"]),
        ])
        diff = ScanDiff(
            new_assets=[_make_asset(ip="1.1.1.1")],
            removed_assets=[_make_asset(ip="2.2.2.2")],
            changed_assets=[],
            risk_increase_assets=[],
        )
        dispatcher.dispatch(diff, "/cfg.yaml", "/diff.json")
        assert len(p1.sent) == 1
        assert p1.sent[0]["event"] == "new_assets"
        assert len(p2.sent) == 1
        assert p2.sent[0]["event"] == "removed_assets"
