"""HTTP helpers shared by connectors.

Requires the `http` extra:  pip install secops-ingest[http]
"""

from __future__ import annotations

import logging
import math
import random
import time
from collections.abc import Callable
from typing import TypeVar

try:
    import httpx
except ImportError as exc:  # pragma: no cover - depends on extra
    raise ImportError(
        "HTTP helpers require the 'http' extra: pip install secops-ingest[http]"
    ) from exc

from . import context, obs

log = logging.getLogger(__name__)

T = TypeVar("T")

RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})

#: Statuses that mean the credential, not the request, is the problem. Never
#: retried, but announced as `auth.failed`: a revoked or rotated key is the one
#: vendor failure an operator can fix and the one a FAILED row alone misnames.
AUTH_STATUS = frozenset({401, 403})

#: Longest single sleep while a run is in progress, so a stop request is
#: noticed within about this long rather than after a 60-second backoff.
_STOP_POLL_SEC = 1.0


class RetryBudgetExhausted(RuntimeError):
    """All retries were consumed. Fail loudly rather than retry forever."""


class RetryableResponse(RuntimeError):
    """A 200 whose body says the answer is incomplete, e.g. failed shards.

    Raised by a connector inside the function it hands to `with_retries`, so a
    partial answer is retried like a 503 and, if it persists, fails the run
    rather than being landed and advanced past. The message must not carry
    URLs or vendor text: `_brief` logs it.
    """


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

    INSIDE A RUN, A STOP IS OBSERVED HERE. execute() checks its deadline and
    SIGTERM between records, but a connector can sit inside one page for
    attempts x timeout + backoff -- fourteen minutes for xdr_alerts against a
    503 storm -- and systemd's stop timeout SIGKILLs long before that, leaving a
    RUNNING row. So every attempt, and every second of backoff, first asks the
    run whether to stop, and raises StopRequested if so. Every connector pages
    through this function, so this is also "between pages". Outside a run there
    is nothing to ask and the behaviour is unchanged.
    """
    last: Exception | None = None
    for attempt in range(attempts):
        context.raise_if_stopping()
        try:
            return fn()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status in AUTH_STATUS:
                _emit(obs.AUTH_FAILED, status=status)
            if status not in RETRYABLE_STATUS:
                raise
            last = exc
            retry_after = exc.response.headers.get("Retry-After")
            delay = _delay(attempt, base_delay, max_delay, retry_after)
        except (httpx.TimeoutException, httpx.TransportError, RetryableResponse) as exc:
            last = exc
            delay = _delay(attempt, base_delay, max_delay, None)
        if attempt < attempts - 1:
            # Say something. A silent retry loop against a slow endpoint is
            # indistinguishable from a hang: five 60-second timeouts produce
            # five minutes of nothing, and the first thing anyone does is kill
            # it and start guessing.
            log.warning(
                "attempt %d/%d failed (%s: %s); retrying in %.1fs",
                attempt + 1, attempts, type(last).__name__, _brief(last), delay,
            )
            limited = isinstance(last, httpx.HTTPStatusError) and \
                last.response.status_code == 429
            _emit(obs.RATE_LIMITED if limited else obs.RETRY,
                  attempt=attempt + 1, attempts=attempts, reason=_brief(last),
                  delay_sec=round(delay, 1))
            _sleep(sleep, delay)
    _emit(obs.RETRY_EXHAUSTED, attempts=attempts, reason=_brief(last))
    raise RetryBudgetExhausted(f"gave up after {attempts} attempts") from last


def report_auth_failure(status: int) -> None:
    """Emit `auth.failed` for a connector that maps 401/403 itself.

    with_retries announces these for every connector that raises
    HTTPStatusError. One that turns a 401 into its own error type before
    with_retries sees it (KSAT, to keep the URL out of the message) calls this.
    """
    _emit(obs.AUTH_FAILED, status=status)


def _emit(event: str, **fields: object) -> None:
    obs.emit(event, context.source_name(), context.run_id(), **fields)


def _sleep(sleep: Callable[[float], None], delay: float) -> None:
    """Back off, in slices short enough to notice a stop, when inside a run."""
    if context.current() is None:
        sleep(delay)
        return
    remaining = delay
    while remaining > 0:
        context.raise_if_stopping()
        step = min(_STOP_POLL_SEC, remaining)
        sleep(step)
        remaining -= step


def _brief(exc: Exception | None) -> str:
    """A short reason. Full exception text can carry URLs and headers."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    if isinstance(exc, RetryableResponse):
        return str(exc)
    return type(exc).__name__ if exc else "unknown"


def _delay(attempt: int, base: float, cap: float, retry_after: str | None) -> float:
    if retry_after:
        try:
            hint = float(retry_after)
        except ValueError:
            hint = None
        # Honour the server's own hint, but only a sane one. A negative value
        # reaches time.sleep as ValueError -- an unrelated-looking failure
        # instead of a backoff -- and NaN or inf would sleep oddly or forever.
        if hint is not None and math.isfinite(hint) and hint >= 0:
            return min(hint, cap)
    return min(cap, base * (2.0**attempt)) * (0.5 + random.random() / 2)
