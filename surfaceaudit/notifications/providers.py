"""Notification providers: Slack, Discord, and generic webhook."""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class BaseNotificationProvider(ABC):
    """Abstract base class for notification providers."""

    @abstractmethod
    def name(self) -> str:
        """Return the human-readable provider name."""
        ...

    @abstractmethod
    def send(self, payload: dict) -> None:
        """Send the notification payload. Logs errors without raising."""
        ...


class SlackNotifier(BaseNotificationProvider):
    """Posts JSON payloads to a Slack incoming webhook URL."""

    def __init__(self, webhook_url: str) -> None:
        self._webhook_url = webhook_url

    def name(self) -> str:
        return "slack"

    def send(self, payload: dict) -> None:
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self._webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10):
                pass
        except Exception:
            logger.error(
                "Slack notification failed for %s", self._webhook_url, exc_info=True
            )


class DiscordNotifier(BaseNotificationProvider):
    """Posts JSON payloads wrapped in ``{"content": ...}`` to a Discord webhook."""

    def __init__(self, webhook_url: str) -> None:
        self._webhook_url = webhook_url

    def name(self) -> str:
        return "discord"

    def send(self, payload: dict) -> None:
        try:
            wrapped = {"content": json.dumps(payload)}
            data = json.dumps(wrapped).encode("utf-8")
            req = urllib.request.Request(
                self._webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10):
                pass
        except Exception:
            logger.error(
                "Discord notification failed for %s",
                self._webhook_url,
                exc_info=True,
            )


class GenericWebhookNotifier(BaseNotificationProvider):
    """Posts the standard JSON payload to an arbitrary URL."""

    def __init__(self, url: str) -> None:
        self._url = url

    def name(self) -> str:
        return "webhook"

    def send(self, payload: dict) -> None:
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self._url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10):
                pass
        except Exception:
            logger.error(
                "Webhook notification failed for %s", self._url, exc_info=True
            )
