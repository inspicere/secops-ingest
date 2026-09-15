"""Targets come from every pack, not just core."""

from __future__ import annotations

import pytest

from secops_ingest.packs.model import Pack
from secops_ingest.packs.registry import DuplicateTarget, all_targets
from secops_ingest.schema import InvalidIdentifier
from secops_ingest.transform.base import Target

VENDOR_TARGET = Target(
    name="vendor_things",
    raw_table="raw_vendor.things",
    fact_table="mart_fact_vendor_things",
    fact_date_expr="seen_at",
    # Target.__post_init__ rejects an upsert that does not reference %(since)s,
    # and rejects an uncast "%(since)s IS NULL". Both rules apply to test
    # fixtures too, so this is the minimum that constructs.
    upsert_sql="INSERT INTO mart_fact_vendor_things SELECT %(since)s::timestamptz",
)
VENDOR = Pack(
    name="vendor", version="0.1.0", requires_core=">=0",
    sources={"things": "vendor.things:SOURCE"}, targets=(VENDOR_TARGET,),
)


def test_core_targets_are_present() -> None:
    names = set(all_targets())
    assert {"example_messages"} <= names


def test_pack_targets_are_merged() -> None:
    from secops_ingest.builtin import PACK as BUILTIN

    targets = all_targets({"builtin": BUILTIN, "vendor": VENDOR})
    assert targets["vendor_things"] is VENDOR_TARGET


def test_two_packs_claiming_one_target_name_is_fatal() -> None:
    other = Pack(
        name="other", version="0.1.0", requires_core=">=0",
        sources={"things": "other.things:SOURCE"}, targets=(VENDOR_TARGET,),
    )
    with pytest.raises(DuplicateTarget) as excinfo:
        all_targets({"vendor": VENDOR, "other": other})
    assert "vendor" in str(excinfo.value)
    assert "other" in str(excinfo.value)


def test_invalid_target_name_is_rejected_at_the_registry_boundary() -> None:
    # Target.__post_init__ does not check the name's shape -- it becomes an
    # argparse choice and a control.* column value only once it reaches the
    # registry, so that is where it must be validated. Constructing the
    # Target itself must still succeed; existing targets and the transform
    # runner are untouched by this rule.
    bad_target = Target(
        name="Bad-Name",
        raw_table="raw_vendor.things",
        fact_table="mart_fact_vendor_things",
        fact_date_expr="seen_at",
        upsert_sql="INSERT INTO mart_fact_vendor_things SELECT %(since)s::timestamptz",
    )
    pack = Pack(
        name="vendor", version="0.1.0", requires_core=">=0",
        sources={"things": "vendor.things:SOURCE"}, targets=(bad_target,),
    )
    with pytest.raises(InvalidIdentifier):
        all_targets({"vendor": pack})
