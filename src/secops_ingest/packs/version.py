"""Core-version range checking, without a dependency.

`packaging` is not in the standard library, and core has none. Rather than take
a dependency for one comparison, ranges use a restricted grammar: a
comma-separated list of clauses over dotted numeric releases.

    ">=0.2,<0.3"

Anything outside that grammar is rejected rather than guessed at. Pre-releases,
epochs, local versions and `~=` are unsupported on purpose -- a pack pinning a
pre-release of the core is a situation to notice, not one to resolve silently.
"""

from __future__ import annotations

import re
from collections.abc import Callable

_RELEASE = re.compile(r"[0-9]+(?:\.[0-9]+)*")
_CLAUSE = re.compile(r"(>=|<=|==|>|<)\s*([0-9]+(?:\.[0-9]+)*)")


class InvalidVersionSpec(ValueError):
    """A version or range lies outside the supported grammar."""


def parse_version(text: str) -> tuple[int, ...]:
    """Turn a dotted numeric release into a comparable tuple."""
    if not _RELEASE.fullmatch(text or ""):
        raise InvalidVersionSpec(f"not a plain numeric version: {text!r}")
    return tuple(int(part) for part in text.split("."))


def _aligned(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Zero-pad the shorter tuple so 0.2 and 0.2.0 compare equal."""
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


_OPS: dict[str, Callable[[tuple[int, ...], tuple[int, ...]], bool]] = {
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
}


def matches(version: str, spec: str) -> bool:
    """True if `version` satisfies every clause in `spec`.

    Raises:
        InvalidVersionSpec: the range or the version is outside the grammar.
    """
    actual = parse_version(version)
    clauses = [c.strip() for c in (spec or "").split(",") if c.strip()]
    if not clauses:
        raise InvalidVersionSpec(f"empty version range: {spec!r}")
    for clause in clauses:
        found = _CLAUSE.fullmatch(clause)
        if not found:
            raise InvalidVersionSpec(f"unsupported clause {clause!r} in range {spec!r}")
        left, right = _aligned(actual, parse_version(found.group(2)))
        if not _OPS[found.group(1)](left, right):
            return False
    return True


def describe_drift(stored: str, installed: str) -> str | None:
    """One line saying how the warehouse's recorded pack version differs from
    the installed one, or None when they agree.

    This is the comparison `control.pack.version` exists for. An upgrade that
    pip resolved to nothing exits 0 and looks like success; the only trace it
    leaves is that the version recorded at the last `enable` and the version
    actually installed now disagree -- or, after a re-enable, that they agree on
    the OLD version, which `pack list` shows plainly beside the installed one.
    Versions outside the numeric grammar are still compared, as text, because a
    difference is worth reporting even when it cannot be ordered.
    """
    if stored == installed:
        return None
    try:
        older = parse_version(stored) < parse_version(installed)
    except InvalidVersionSpec:
        return f"warehouse records {stored}, installed is {installed}"
    if older:
        return (
            f"warehouse records {stored}, installed is {installed}: "
            "re-run `enable` to record the upgrade"
        )
    return (
        f"warehouse records {stored}, installed is OLDER at {installed}: "
        "this host did not get the upgrade another host recorded"
    )
