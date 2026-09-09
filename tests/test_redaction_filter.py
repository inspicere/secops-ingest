"""Regression tests for RedactingFilter's handling of log arguments.

The filter previously scrubbed each argument individually, which forced every
argument through str() and broke any record using a numeric format specifier.
Logging swallows that as a "Logging error" and discards the line, so a component
whose only job is to make logs safe was silently deleting them instead.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

import pytest

from secops_ingest import redaction
from secops_ingest.redaction import PLACEHOLDER, RedactingFilter


@pytest.fixture
def registry() -> Iterator[None]:
    """The secret registry is process-wide; isolate each test from the others."""
    saved = set(redaction._REGISTRY)
    redaction._REGISTRY.clear()
    yield
    redaction._REGISTRY.clear()
    redaction._REGISTRY.update(saved)


def record(msg: str, *args: object, **kw: object) -> logging.LogRecord:
    return logging.LogRecord(
        name="t", level=logging.INFO, pathname=__file__, lineno=1,
        msg=msg, args=args or None, exc_info=kw.get("exc_info"),  # type: ignore[arg-type]
    )


def test_numeric_format_specifiers_survive_redaction(registry: None) -> None:
    """The regression. httpx logs 'HTTP Request: ... "%s %d %s"'.

    Stringifying the status code makes %d raise TypeError, logging catches it,
    and the line is lost — so the symptom is silence, not an error.
    """
    f = RedactingFilter()
    f.register("supersecretvalue")
    rec = record('HTTP Request: %s %s "%s %d %s"', "GET", "http://x/y", "HTTP/1.1", 200, "OK")
    assert f.filter(rec) is True
    assert rec.getMessage() == 'HTTP Request: GET http://x/y "HTTP/1.1 200 OK"'


def test_float_specifier_survives(registry: None) -> None:
    f = RedactingFilter()
    f.register("supersecretvalue")
    rec = record("page records=%d in %.1fs", 25, 0.4)
    assert f.filter(rec) is True
    assert rec.getMessage() == "page records=25 in 0.4s"


def test_secret_in_a_string_argument_is_redacted(registry: None) -> None:
    f = RedactingFilter()
    f.register("supersecretvalue")
    rec = record("connecting with %s", "supersecretvalue")
    f.filter(rec)
    assert "supersecretvalue" not in rec.getMessage()
    assert PLACEHOLDER in rec.getMessage()


def test_secret_inside_a_non_string_argument_is_redacted(registry: None) -> None:
    """Rendering first is strictly more thorough than scrubbing each argument.

    A secret carried inside a dict would previously have been stringified into
    the output without being examined.
    """
    f = RedactingFilter()
    f.register("supersecretvalue")
    rec = record("headers=%s", {"Authorization": "Token supersecretvalue"})
    f.filter(rec)
    assert "supersecretvalue" not in rec.getMessage()


def test_secret_in_an_exception_traceback_is_redacted(registry: None) -> None:
    """The Formatter renders exceptions after filters run, so it must be
    pre-rendered here or the traceback escapes redaction entirely."""
    f = RedactingFilter()
    f.register("supersecretvalue")
    try:
        raise ValueError("failed auth with supersecretvalue")
    except ValueError:
        import sys

        rec = record("boom", exc_info=sys.exc_info())
    f.filter(rec)
    assert rec.exc_text is not None
    assert "supersecretvalue" not in rec.exc_text
    assert PLACEHOLDER in rec.exc_text


def test_no_registered_secrets_leaves_the_record_alone(registry: None) -> None:
    """With nothing to redact the filter must not touch args at all."""
    f = RedactingFilter()
    rec = record("count=%d", 7)
    assert f.filter(rec) is True
    assert rec.args == (7,)
    assert rec.getMessage() == "count=7"


def test_filter_survives_a_record_it_cannot_render(registry: None) -> None:
    """A malformed record is the caller's bug; redaction must not eat it."""
    f = RedactingFilter()
    f.register("supersecretvalue")
    rec = record("%d items", "not-a-number")
    assert f.filter(rec) is True


def test_end_to_end_through_a_handler(registry: None, caplog: pytest.LogCaptureFixture) -> None:
    """The whole point: a formatted line reaches a handler with no secret in it."""
    f = RedactingFilter()
    f.register("supersecretvalue")
    logger = logging.getLogger("redaction_e2e")
    logger.addFilter(f)
    with caplog.at_level(logging.INFO, logger="redaction_e2e"):
        logger.info("auth=%s status=%d", "supersecretvalue", 200)
    logger.removeFilter(f)
    assert "supersecretvalue" not in caplog.text
    assert "status=200" in caplog.text
