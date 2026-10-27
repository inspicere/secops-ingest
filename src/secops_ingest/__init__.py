"""Pull security-vendor telemetry into PostgreSQL."""

from __future__ import annotations

#: Kept in step with `version` in pyproject.toml (tests/test_version.py fails
#: when they differ). Duplicated deliberately: the test suite runs from src/
#: without installing the package, so importlib.metadata cannot be the single
#: source of truth here.
#:
#: Bump it on every release that changes behaviour (CONTRIBUTING.md). It is
#: what a pack's `requires_core` is checked against and what `pack list`
#: compares with control.pack.version, so a version that never moves makes
#: both checks unable to tell one ref from another. Not derived from git: a
#: dev/local suffix such as 0.1.1.dev3+g9a8353a is outside the numeric grammar
#: packs/version.py accepts, and discovery would refuse to start at all.
__version__ = "0.1.0"
