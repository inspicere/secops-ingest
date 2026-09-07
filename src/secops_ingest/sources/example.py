"""Reference connector.

Emits synthetic records so the full path — fetch, land, watermark, run
bookkeeping — can be exercised without any vendor API or credential. Also the
worked example of the Source contract for anyone writing a new connector.

    python -m secops_ingest example --dry-run
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator


class ExampleSource:
    name = "example"
    table = "raw_phisher.messages"

    #: Records to emit per run. Kept small; this exists to prove wiring.
    count = int(os.environ.get("SECOPS_EXAMPLE_COUNT", "25"))

    def authenticate(self) -> Any:
        # A real connector fetches from the secret backend here, once per run,
        # and holds the value in memory only.
        return {"token": "not-a-real-credential"}

    def fetch(self, creds: Any, cursor: str | None) -> Iterator[dict]:
        """Yield synthetic records strictly newer than `cursor`.

        Anchored to the top of the current hour rather than to `now()`, so two
        runs inside the same hour produce byte-identical records. That is what
        makes upsert idempotency testable: with a `now()` anchor every run mints
        new ids and a re-run always looks like it inserted correctly.
        """
        base = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        for i in range(self.count):
            created = base - timedelta(minutes=i)
            record = {
                "id": hashlib.sha256(created.isoformat().encode()).hexdigest()[:24],
                "createdAt": created.isoformat().replace("+00:00", "Z"),
                "updatedAt": created.isoformat().replace("+00:00", "Z"),
                "status": ["new", "triaged", "resolved"][i % 3],
                "category": ["clean", "spam", "threat"][i % 3],
                "severity": ["low", "medium", "high"][i % 3],
            }
            if cursor and record["updatedAt"] <= cursor:
                continue
            yield record

    def to_row(self, record: dict, run_id: int) -> tuple:
        # _event_time comes from createdAt, which never changes. The watermark
        # uses updatedAt; partitioning on that would move rows between
        # partitions whenever a record is updated.
        return (
            record["id"],
            json.dumps(record),
            record["createdAt"],
            run_id or None,
        )

    def watermark_of(self, record: dict) -> Any:
        return record["updatedAt"]


SOURCE = ExampleSource()
