"""Error types and retry handling for SurfaceAudit."""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)


class ScannerError(Exception):
    """Base exception for all scanner errors."""


class AuthenticationError(ScannerError):
    """Raised when API key validation fails."""


class APIError(ScannerError):
    """Raised when an API returns an error response."""


class ConfigurationError(ScannerError):
    """Raised when configuration parameters are invalid."""


class RetryHandler:
    """Executes a callable with exponential backoff retries.

    The handler will attempt the function once initially, then retry up to
    ``max_retries`` additional times on failure.  The delay between retries
    follows exponential backoff: ``base_delay * 2 ** attempt`` where *attempt*
    is the zero-based retry index.
    """

    def __init__(self, max_retries: int = 3, base_delay: float = 1.0) -> None:
        self.max_retries = max_retries
        self.base_delay = base_delay

    def execute_with_retry(self, func: Callable[..., Any], *args: Any) -> Any:
        """Call *func* with retry logic.

        Args:
            func: The callable to execute.
            *args: Positional arguments forwarded to *func*.

        Returns:
            The return value of *func* on success.

        Raises:
            The last exception raised by *func* after all attempts are
            exhausted.
        """
        last_exception: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                return func(*args)
            except Exception as exc:
                last_exception = exc
                if attempt < self.max_retries:
                    delay = self.base_delay * (2 ** attempt)
                    logger.warning(
                        "Attempt %d/%d failed: %s. Retrying in %.1fs…",
                        attempt + 1,
                        self.max_retries + 1,
                        exc,
                        delay,
                    )
                    time.sleep(delay)
                else:
                    logger.error(
                        "All %d attempts failed. Last error: %s",
                        self.max_retries + 1,
                        exc,
                    )

        # This should be unreachable, but satisfies the type checker.
        raise last_exception  # type: ignore[misc]
