from __future__ import annotations

from secops_ingest.common.posture import current_posture


class WithPosture:
    class _P:
        value = "assured"

    posture = _P()


class WithoutPosture:
    pass


class Raising:
    @property
    def posture(self) -> str:
        raise RuntimeError("backend unreachable")


def test_reads_the_posture_from_a_mapped_provider():
    assert current_posture(WithPosture()) == "assured"


def test_a_provider_without_a_posture_records_none():
    assert current_posture(WithoutPosture()) is None


def test_a_failure_to_read_posture_does_not_fail_the_run():
    # The posture is a diagnostic. A run that ingested correctly must not be
    # recorded as FAILED because a label could not be determined.
    assert current_posture(Raising()) is None


def test_none_provider_records_none():
    assert current_posture(None) is None
