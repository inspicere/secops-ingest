"""Logging redaction.

Second line of defence. The first is not putting secrets in log statements;
this catches the case where a value reaches a log record via an exception,
a dict dump, or a third-party library.
"""

from __future__ import annotations

import logging


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
        redactor.register(provider.get("phisher-api-token"))
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
        if isinstance(record.msg, str):
            record.msg = self._scrub(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._scrub(str(v)) for k, v in record.args.items()}
            else:
                record.args = tuple(self._scrub(str(a)) for a in record.args)
        return True
