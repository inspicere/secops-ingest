"""Logging redaction.

Second line of defence. The first is not putting secrets in log statements;
this catches the case where a value reaches a log record via an exception,
a dict dump, or a third-party library.
"""

from __future__ import annotations

import logging
import traceback

#: Process-wide registry. Credentials are registered once when fetched, so any
#: code path that persists text - not only logging - can scrub it.
_REGISTRY: set[str] = set()
MIN_LENGTH = 8
PLACEHOLDER = "***REDACTED***"


def register_secret(value: str | None) -> None:
    """Register a value for redaction everywhere in this process."""
    if value and len(value) >= MIN_LENGTH:
        _REGISTRY.add(value)


def scrub(text: str) -> str:
    """Remove any registered secret from `text`.

    Used before persisting exception text: vendor client errors routinely embed
    request URLs (which some APIs put tokens in) and echo auth material from
    4xx bodies, and error_summary is written to the database.
    """
    for value in _REGISTRY:
        if value in text:
            text = text.replace(value, PLACEHOLDER)
    return text


class RedactingFilter(logging.Filter):
    """Replace known secret values anywhere in a log record.

    Register values as they are fetched::

        redactor = RedactingFilter()
        logging.getLogger().addFilter(redactor)
        redactor.register(provider.get("wazuh-indexer-password"))
    """

    #: Values shorter than this are not redacted - they would match too much
    #: unrelated text and make logs unreadable.
    MIN_LENGTH = 8

    def __init__(self, placeholder: str = PLACEHOLDER) -> None:
        super().__init__()
        self._values = _REGISTRY          # shared with scrub()
        self._placeholder = placeholder

    def register(self, value: str | None) -> None:
        register_secret(value)

    def _scrub(self, text: str) -> str:
        for value in self._values:
            if value in text:
                text = text.replace(value, self._placeholder)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        if not self._values:
            return True

        # Render the message here, scrub the result, then clear args.
        #
        # The obvious implementation scrubs each argument in place, and breaks
        # every record using a numeric format specifier: scrubbing forces each
        # argument through str(), and "%d" % "200" raises TypeError. Logging
        # catches that, writes "--- Logging error ---" to stderr, and DISCARDS
        # the line. So the failure of a component whose entire job is to make
        # logs safe is a missing log line -- which is the worst shape it could
        # take, and cost an evening of mistaking a slow API for a hang.
        #
        # Rendering first is also strictly more thorough. A secret that reaches
        # a record inside a non-string argument -- a dict of headers, a mapping
        # of connection parameters -- is caught here, where per-argument
        # scrubbing would have stringified it into the output unexamined.
        try:
            rendered = record.getMessage()
        except Exception:  # pragma: no cover - defensive  # noqa: BLE001
            # Redaction must never itself be the reason a line disappears. A
            # record that cannot render is the caller's bug, and their
            # traceback to see.
            return True

        record.msg = self._scrub(rendered)
        record.args = ()

        # Pre-render the traceback so the Formatter uses this scrubbed copy
        # rather than formatting the exception itself afterwards, where a filter
        # can no longer reach it. This is what makes the module docstring's
        # claim about exceptions true.
        if record.exc_info and not record.exc_text:
            record.exc_text = self._scrub(
                "".join(traceback.format_exception(*record.exc_info))
            ).rstrip("\n")

        return True
