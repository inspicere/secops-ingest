"""Serialising vendor records for a jsonb column.

PostgreSQL's jsonb cannot represent a NUL character inside a string. It is
valid JSON and invalid jsonb, and the insert fails with:

    unsupported Unicode escape sequence
    DETAIL: \\u0000 cannot be converted to text.

This is not a theoretical edge case for security tooling. Scanners capture raw
response bytes, and a single embedded-device banner is enough:

    Server: Allegro-Software-RomPager/4.62\\r\\n\\u0000

One such record in fifty thousand aborts an entire backfill, hours in, having
written nothing for that run. Connectors therefore serialise through `to_json`
rather than calling json.dumps directly.
"""

from __future__ import annotations

import json
import logging
from typing import Any

log = logging.getLogger(__name__)

NUL = "\x00"


def strip_nuls(value: Any) -> Any:
    """Recursively remove NUL characters from strings in a decoded structure.

    Stripping happens BEFORE serialisation, on the Python object. Doing it
    afterwards, on the JSON text, would mean editing the six-character escape
    `\\u0000` out of a string that could legitimately contain those characters
    -- a literal backslash-u-zeros in the data is indistinguishable from an
    escaped NUL once serialised, so the naive text replacement corrupts data it
    was never meant to touch.
    """
    if isinstance(value, str):
        return value.replace(NUL, "") if NUL in value else value
    if isinstance(value, dict):
        return {k: strip_nuls(v) for k, v in value.items()}
    if isinstance(value, list):
        return [strip_nuls(v) for v in value]
    return value


def _contains_nul(value: Any) -> bool:
    if isinstance(value, str):
        return NUL in value
    if isinstance(value, dict):
        return any(_contains_nul(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_nul(v) for v in value)
    return False


def to_json(record: Any, *, identifier: str | None = None) -> str:
    """Serialise a record for a jsonb column, dropping NULs if present.

    Dropping is deliberate rather than failing the record. A NUL in a captured
    banner carries no meaning worth an outage, and the alternatives are worse:
    rejecting the record loses a real finding, and failing the run loses every
    other record alongside it.

    It is logged, because silently altering stored data should never be
    invisible -- someone comparing a warehouse row against the vendor's UI
    deserves to be able to find out why they differ.
    """
    if _contains_nul(record):
        log.warning(
            "record %s contains NUL characters; stripped for jsonb storage",
            identifier if identifier is not None else "<unknown>",
        )
        record = strip_nuls(record)
    return json.dumps(record)
