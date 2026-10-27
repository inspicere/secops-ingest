"""with_retries: stopping inside a retry loop, saying so, and sane backoff.

THE PROBLEMS THIS COVERS. execute() checks its deadline and SIGTERM between
records, but a connector can sit inside a single page for attempts x timeout +
backoff -- about fourteen minutes for xdr_alerts against a 503 storm -- while
systemd's stop timeout is 90 seconds. The stop was noticed only after SIGKILL,
which leaves a RUNNING row. And none of the retry, rate-limit, give-up or 401
outcomes produced a structured event, so the alert vocabulary in common.obs was
never emitted by anything.
"""

from __future__ import annotations

import json
import math
from typing import Any

import pytest

httpx = pytest.importorskip("httpx", reason="needs the 'http' extra")

from secops_ingest.common import context, obs  # noqa: E402
from secops_ingest.common.http import (  # noqa: E402
    RetryableResponse,
    RetryBudgetExhausted,
    _delay,
    with_retries,
)


def _status(code: int, headers: dict[str, str] | None = None) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://vendor.example.com/api")
    response = httpx.Response(code, headers=headers or {}, request=request)
    return httpx.HTTPStatusError(f"HTTP {code}", request=request, response=response)


def _events(capsys: pytest.CaptureFixture[str]) -> list[dict[str, Any]]:
    out = capsys.readouterr().out
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


class _Failing:
    def __init__(self, exc: Exception, times: int = 99) -> None:
        self.exc = exc
        self.times = times
        self.calls = 0

    def __call__(self) -> str:
        self.calls += 1
        if self.calls <= self.times:
            raise self.exc
        return "ok"


# -- stopping ----------------------------------------------------------------

def test_a_stop_requested_during_backoff_ends_the_loop_not_the_budget() -> None:
    """The point: SIGTERM mid-retry must not wait out five attempts."""
    stop: dict[str, str | None] = {"why": None}
    slept: list[float] = []

    def sleep(seconds: float) -> None:
        slept.append(seconds)
        stop["why"] = "SIGTERM"          # the signal lands during the first backoff

    fn = _Failing(_status(503))
    ctx = context.RunContext(source="xdr_alerts", should_stop=lambda: stop["why"])
    with context.running(ctx), pytest.raises(context.StopRequested) as raised:
        with_retries(fn, attempts=5, base_delay=30, max_delay=60, sleep=sleep)

    assert raised.value.reason == "SIGTERM"
    assert fn.calls == 1, "no second request after the stop"
    assert slept == [1.0], "the backoff is sliced, so the stop is seen within a second"


def test_a_stop_before_the_request_sends_nothing() -> None:
    """Every connector pages through with_retries, so this is 'between pages'."""
    fn = _Failing(_status(503), times=0)
    ctx = context.RunContext(source="wazuh", should_stop=lambda: "the 1500s deadline")
    with context.running(ctx), pytest.raises(context.StopRequested):
        with_retries(fn)
    assert fn.calls == 0


def test_outside_a_run_nothing_changes() -> None:
    """No context: no stop check and an unsliced sleep, as before the hook."""
    slept: list[float] = []
    fn = _Failing(_status(503), times=1)
    assert with_retries(fn, base_delay=8, max_delay=8, sleep=slept.append) == "ok"
    assert len(slept) == 1 and slept[0] >= 4.0


def test_a_broken_stop_check_does_not_fail_the_request() -> None:
    def boom() -> str | None:
        raise RuntimeError("bug in the stop check")

    with context.running(context.RunContext(source="s", should_stop=boom)):
        assert with_retries(lambda: "ok") == "ok"


# -- events ------------------------------------------------------------------

@pytest.mark.parametrize("code", [401, 403])
def test_an_auth_failure_is_announced_and_not_retried(
    code: int, capsys: pytest.CaptureFixture[str]
) -> None:
    fn = _Failing(_status(code))
    with context.running(context.RunContext(source="defectdojo", run_id=9)):
        with pytest.raises(httpx.HTTPStatusError):
            with_retries(fn, sleep=lambda s: None)

    assert fn.calls == 1
    (event,) = _events(capsys)
    assert event["event"] == obs.AUTH_FAILED
    assert (event["source"], event["run_id"], event["status"]) == ("defectdojo", 9, code)
    assert event["alertable"] is True


def test_retries_rate_limits_and_exhaustion_are_announced(
    capsys: pytest.CaptureFixture[str],
) -> None:
    fn = _Failing(_status(429, {"Retry-After": "0"}), times=1)
    with context.running(context.RunContext(source="xsoar")):
        with_retries(fn, sleep=lambda s: None)
        with pytest.raises(RetryBudgetExhausted):
            with_retries(_Failing(_status(502)), attempts=2, sleep=lambda s: None)

    assert [e["event"] for e in _events(capsys)] == [
        obs.RATE_LIMITED, obs.RETRY, obs.RETRY_EXHAUSTED,
    ]


def test_a_retryable_response_is_retried_like_a_503() -> None:
    fn = _Failing(RetryableResponse("partial result: 1 of 3 shard(s) failed"), times=2)
    assert with_retries(fn, sleep=lambda s: None) == "ok"
    assert fn.calls == 3


# -- Retry-After ---------------------------------------------------------------

@pytest.mark.parametrize("hint", ["-1", "nan", "inf", "-inf", "Wed, 21 Oct 2026 07:28:00 GMT"])
def test_an_unusable_retry_after_falls_back_to_backoff(hint: str) -> None:
    """A negative hint reached time.sleep as ValueError, failing the run with an
    unrelated-looking error instead of backing off."""
    delay = _delay(0, 1.0, 60.0, hint)
    assert math.isfinite(delay) and 0.5 <= delay <= 1.0


def test_a_sane_retry_after_is_honoured_up_to_the_cap() -> None:
    assert _delay(0, 1.0, 60.0, "7") == 7.0
    assert _delay(0, 1.0, 60.0, "600") == 60.0
    assert _delay(0, 1.0, 60.0, "0") == 0.0
