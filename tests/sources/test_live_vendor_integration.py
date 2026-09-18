"""Integration tests for the Cortex connectors against LIVE vendor tenants.

WHY THIS EXISTS, GIVEN THE OFFLINE SUITE ALREADY COVERS THESE CONNECTORS.

The offline tests drive `fetch()` with recorders returning fixtures that this
repository wrote. A fixture agrees with the connector by construction, so the
one class of defect they structurally cannot catch is the most likely one: a
field that is named differently in the real payload, or absent from it. A
connector can pass every offline test and raise KeyError on its first scheduled
run. These tests map genuine vendor records through the whole contract --
authenticate -> fetch -> to_row -> watermark_of -- so that failure lands here.

OPT-IN IS DELIBERATE AND IS **NOT** THE PATTERN USED BY THE VAULT TESTS.

`test_vault_backend_integration.py` skips unless VAULT_ADDR is set, which is
safe because CI points it at a throwaway OpenBao container. These tests talk to
a PRODUCTION security platform. Gating them the same way would make the CI job
that starts OpenBao -- and therefore sets VAULT_ADDR -- begin calling a real
tenant. So they require their own explicit switch, and CI never sets it:

    SECOPS_LIVE_VENDOR_TESTS=1 \
    VAULT_ADDR=... VAULT_TOKEN=... \
    SECOPS_SECRETS_BACKEND=vault SECOPS_VAULT_PREFIX=secops/ \
    pytest tests/sources/test_live_vendor_integration.py -v

READ-ONLY AND BOUNDED. Nothing is written to any warehouse and no vendor state
is modified. Each connector's generator is consumed with islice, so a run costs
a few pages rather than a backfill -- which matters for the alerts connector,
whose collection is measured in millions.

Credentials resolve through whichever secret backend is configured; nothing
here reads a credential directly, and no assertion prints a secret or a tenant
hostname.
"""

from __future__ import annotations

import itertools
import os
import time
from typing import Any

import pytest

pytest.importorskip("httpx", reason="needs the 'http' extra")

# Imported after importorskip: these modules pull in common.http, which raises
# ImportError without the 'http' extra. E402 is not enabled in this project, so
# no suppression is needed -- and adding one would fail RUF100.
from secops_ingest.sources import (
    xdr,
    xdr_alerts,
    xdr_endpoints,
    xsoar,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("SECOPS_LIVE_VENDOR_TESTS") != "1",
    reason="SECOPS_LIVE_VENDOR_TESTS is not 1; these call production vendor APIs",
)

#: Consume only a handful of records per connector. The point is to exercise the
#: mapping against real payloads, not to measure throughput.
SAMPLE = 5

_NOW_MS = int(time.time() * 1000)


def _recent_iso(days: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400))


#: (module, cursor). The cursor is chosen to keep each run to a page or two.
#: `xdr_endpoints` takes None because it is a snapshot source and ignores the
#: cursor by design.
CONNECTORS = [
    pytest.param(xsoar, _recent_iso(2), id="xsoar"),
    pytest.param(xdr, str(_NOW_MS - 7 * 86_400_000), id="xdr"),
    pytest.param(xdr_alerts, str(_NOW_MS - 900_000), id="xdr_alerts"),
    pytest.param(xdr_endpoints, None, id="xdr_endpoints"),
]


@pytest.fixture(scope="module")
def _require_backend() -> None:
    if not os.environ.get("SECOPS_SECRETS_BACKEND"):
        pytest.skip("SECOPS_SECRETS_BACKEND is unset; no way to resolve credentials")


@pytest.mark.parametrize(("module", "cursor"), CONNECTORS)
def test_authenticate_returns_standard_headers(
    module: Any, cursor: str | None, _require_backend: None
) -> None:
    """Standard auth sends the key AND the key's numeric id.

    A tenant that had been switched to Advanced keys would fail here rather than
    on the next scheduled run.
    """
    headers = module.SOURCE.authenticate()
    assert set(headers) == {"Authorization", "x-xdr-auth-id", "Content-Type"}
    assert headers["x-xdr-auth-id"], "the numeric key id is required, not optional"
    # Never assert on the key's value; length only, so a failure message cannot
    # carry the credential into a log.
    assert len(headers["Authorization"]) > 0


@pytest.mark.parametrize(("module", "cursor"), CONNECTORS)
def test_real_records_map_through_the_full_contract(
    module: Any, cursor: str | None, _require_backend: None
) -> None:
    """The test the offline suite cannot be: real payloads, real field names."""
    source = module.SOURCE
    creds = source.authenticate()
    records = list(itertools.islice(source.fetch(creds, cursor), SAMPLE))
    if not records:
        pytest.skip(f"{source.name}: no records in the sampled window")

    for record in records:
        source_id, payload, event_time, run_id = source.to_row(record, 0)

        assert source_id, f"{source.name}: empty source_id breaks the upsert key"
        assert isinstance(payload, str), (
            f"{source.name}: to_json must return a str for the jsonb column"
        )
        assert event_time is not None, (
            f"{source.name}: a null _event_time cannot be a partition key"
        )
        assert run_id is None, "run_id 0 must map to NULL, not 0"

        mark = source.watermark_of(record)
        assert mark is not None, (
            f"{source.name}: a null watermark stalls the cursor forever"
        )


@pytest.mark.parametrize(("module", "cursor"), CONNECTORS)
def test_the_upsert_key_is_unique_within_a_page(
    module: Any, cursor: str | None, _require_backend: None
) -> None:
    """Duplicate keys inside one batch abort the whole upsert.

    PostgreSQL rejects an INSERT ... ON CONFLICT DO UPDATE that touches the same
    row twice in one statement, so a source emitting two records with the same
    (source_id, _event_time) fails the entire run, not just that record.
    """
    source = module.SOURCE
    creds = source.authenticate()
    records = list(itertools.islice(source.fetch(creds, cursor), SAMPLE))
    if not records:
        pytest.skip(f"{source.name}: no records in the sampled window")

    keys = [(r[0], r[2]) for r in (source.to_row(rec, 0) for rec in records)]
    assert len(set(keys)) == len(keys), (
        f"{source.name}: duplicate (source_id, _event_time) within one page"
    )


@pytest.mark.parametrize(("module", "cursor"), CONNECTORS)
def test_the_watermark_orders_against_itself(
    module: Any, cursor: str | None, _require_backend: None
) -> None:
    """A watermark the ordering helper cannot parse silently stops advancing.

    `common.watermark.comparable` falls back to string ordering and logs a
    warning for anything it cannot read as a timestamp or an epoch -- which is
    safe but means the cursor is being compared by a rule nobody intended. Assert
    the real values parse into something orderable of a single type.
    """
    from secops_ingest.common.watermark import comparable

    source = module.SOURCE
    creds = source.authenticate()
    records = list(itertools.islice(source.fetch(creds, cursor), SAMPLE))
    if not records:
        pytest.skip(f"{source.name}: no records in the sampled window")

    marks = [comparable(source.watermark_of(r)) for r in records]
    assert len({type(m) for m in marks}) == 1, (
        f"{source.name}: mixed watermark types across one page; `newer()` refuses "
        "to order across types and would stop advancing the cursor"
    )
    assert not any(isinstance(m, str) for m in marks), (
        f"{source.name}: watermark fell back to string ordering, which is unsafe "
        "across format changes"
    )
