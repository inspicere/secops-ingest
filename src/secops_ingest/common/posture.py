"""Which secret posture produced a run.

Kept apart from `common.run` so that importing it pulls in nothing that needs an
optional extra. `common.run` reaches `psycopg` through `db`, and the transform
runner needs this function without that dependency.
"""

from __future__ import annotations


def current_posture(provider: object | None) -> str | None:
    """Return the provider's declared posture, or None.

    Never raises. The posture is a diagnostic written alongside a run; a run
    that ingested correctly must not be recorded as FAILED because reading a
    label failed. A provider with no posture -- env, file, vault -- yields
    None, which reads as "not declared" rather than as a claim.
    """
    try:
        posture = getattr(provider, "posture", None)
        if posture is None:
            return None
        return str(getattr(posture, "value", posture))
    except Exception:  # noqa: BLE001 - a diagnostic must not fail the run
        return None
