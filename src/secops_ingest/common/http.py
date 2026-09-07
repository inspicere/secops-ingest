"""HTTP helpers shared by connectors.

Requires the `http` extra:  pip install secops-ingest[http]
"""

from __future__ import annotations

import random
import time
from typing import Callable, TypeVar

try:
    import httpx
except ImportError as exc:  # pragma: no cover - depends on extra
    raise ImportError(
        "HTTP helpers require the 'http' extra: pip install secops-ingest[http]"
    ) from exc

T = TypeVar("T")

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


class RetryBudgetExhausted(RuntimeError):
    """All retries were consumed. Fail loudly rather than retry forever."""


def with_retries(
    fn: Callable[[], T],
    *,
    attempts: int = 5,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Call `fn`, retrying transient HTTP failures with jittered backoff.

    Only retries idempotent reads. Jitter matters: without it, several workers
    failing against the same vendor retry in lockstep and sustain the overload.
    """
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            return fn()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code not in RETRYABLE_STATUS:
                raise
            last = exc
            retry_after = exc.response.headers.get("Retry-After")
            delay = _delay(attempt, base_delay, max_delay, retry_after)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last = exc
            delay = _delay(attempt, base_delay, max_delay, None)
        if attempt < attempts - 1:
            sleep(delay)
    raise RetryBudgetExhausted(f"gave up after {attempts} attempts") from last


def _delay(attempt: int, base: float, cap: float, retry_after: str | None) -> float:
    if retry_after:
        try:
            return min(float(retry_after), cap)   # honour the server's own hint
        except ValueError:
            pass
    return min(cap, base * (2 ** attempt)) * (0.5 + random.random() / 2)
