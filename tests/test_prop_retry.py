# Feature: shodan-infrastructure-scanner, Property 9: Retry handler respects max attempts
"""Property-based test for RetryHandler max-attempts behaviour.

**Validates: Requirements 6.2**

For any function that fails consistently, the retry handler should invoke it
exactly max_retries + 1 times (1 initial + max_retries retries) before raising
an error.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from surfaceaudit.errors import RetryHandler


@settings(max_examples=100)
@given(max_retries=st.integers(min_value=0, max_value=10))
@patch("surfaceaudit.errors.time.sleep")
def test_retry_handler_respects_max_attempts(mock_sleep, max_retries: int) -> None:
    """The handler must call the function exactly max_retries + 1 times when it always fails."""
    call_count = 0

    def always_fails() -> None:
        nonlocal call_count
        call_count += 1
        raise RuntimeError("permanent failure")

    handler = RetryHandler(max_retries=max_retries, base_delay=1.0)

    with pytest.raises(RuntimeError, match="permanent failure"):
        handler.execute_with_retry(always_fails)

    expected_calls = max_retries + 1
    assert call_count == expected_calls, (
        f"Expected {expected_calls} calls for max_retries={max_retries}, got {call_count}"
    )
    # sleep is called between retries, so exactly max_retries times
    assert mock_sleep.call_count == max_retries

    # Reset for next hypothesis example
    mock_sleep.reset_mock()
