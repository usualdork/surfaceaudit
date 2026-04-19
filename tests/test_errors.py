"""Unit tests for surfaceaudit.errors module."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from surfaceaudit.errors import (
    APIError,
    AuthenticationError,
    ConfigurationError,
    RetryHandler,
    ScannerError,
)


# ---------------------------------------------------------------------------
# Exception hierarchy tests
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    def test_scanner_error_is_exception(self):
        assert issubclass(ScannerError, Exception)

    def test_authentication_error_is_scanner_error(self):
        assert issubclass(AuthenticationError, ScannerError)

    def test_api_error_is_scanner_error(self):
        assert issubclass(APIError, ScannerError)

    def test_configuration_error_is_scanner_error(self):
        assert issubclass(ConfigurationError, ScannerError)

    def test_errors_carry_message(self):
        for cls in (ScannerError, AuthenticationError, APIError, ConfigurationError):
            err = cls("something went wrong")
            assert str(err) == "something went wrong"


# ---------------------------------------------------------------------------
# RetryHandler tests
# ---------------------------------------------------------------------------

class TestRetryHandler:
    def test_success_on_first_attempt(self):
        handler = RetryHandler(max_retries=3, base_delay=1.0)
        result = handler.execute_with_retry(lambda: 42)
        assert result == 42

    @patch("surfaceaudit.errors.time.sleep")
    def test_success_after_retries(self, mock_sleep):
        call_count = 0

        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("fail")
            return "ok"

        handler = RetryHandler(max_retries=3, base_delay=1.0)
        result = handler.execute_with_retry(flaky)

        assert result == "ok"
        assert call_count == 3
        # Two retries → two sleeps
        assert mock_sleep.call_count == 2

    @patch("surfaceaudit.errors.time.sleep")
    def test_raises_after_all_attempts_exhausted(self, mock_sleep):
        handler = RetryHandler(max_retries=2, base_delay=1.0)

        with pytest.raises(RuntimeError, match="always fails"):
            handler.execute_with_retry(lambda: (_ for _ in ()).throw(RuntimeError("always fails")))

    @patch("surfaceaudit.errors.time.sleep")
    def test_total_attempts_equals_max_retries_plus_one(self, mock_sleep):
        call_count = 0

        def always_fail():
            nonlocal call_count
            call_count += 1
            raise RuntimeError("boom")

        handler = RetryHandler(max_retries=3, base_delay=0.5)

        with pytest.raises(RuntimeError):
            handler.execute_with_retry(always_fail)

        # 1 initial + 3 retries = 4 total
        assert call_count == 4

    @patch("surfaceaudit.errors.time.sleep")
    def test_exponential_backoff_delays(self, mock_sleep):
        handler = RetryHandler(max_retries=3, base_delay=1.0)

        with pytest.raises(RuntimeError):
            handler.execute_with_retry(lambda: (_ for _ in ()).throw(RuntimeError("fail")))

        delays = [call.args[0] for call in mock_sleep.call_args_list]
        # base_delay * 2^attempt → 1.0, 2.0, 4.0
        assert delays == [1.0, 2.0, 4.0]

    @patch("surfaceaudit.errors.time.sleep")
    def test_custom_base_delay(self, mock_sleep):
        handler = RetryHandler(max_retries=2, base_delay=0.5)

        with pytest.raises(RuntimeError):
            handler.execute_with_retry(lambda: (_ for _ in ()).throw(RuntimeError("fail")))

        delays = [call.args[0] for call in mock_sleep.call_args_list]
        # 0.5 * 2^0 = 0.5, 0.5 * 2^1 = 1.0
        assert delays == [0.5, 1.0]

    def test_forwards_arguments_to_func(self):
        handler = RetryHandler(max_retries=0, base_delay=1.0)
        result = handler.execute_with_retry(lambda a, b: a + b, 3, 4)
        assert result == 7

    @patch("surfaceaudit.errors.time.sleep")
    def test_zero_retries_calls_once(self, mock_sleep):
        call_count = 0

        def fail():
            nonlocal call_count
            call_count += 1
            raise ValueError("nope")

        handler = RetryHandler(max_retries=0, base_delay=1.0)

        with pytest.raises(ValueError):
            handler.execute_with_retry(fail)

        assert call_count == 1
        mock_sleep.assert_not_called()
