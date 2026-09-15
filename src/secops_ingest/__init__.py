"""Pull security-vendor telemetry into PostgreSQL."""

from __future__ import annotations

#: Kept in step with `version` in pyproject.toml. Duplicated deliberately: the
#: test suite runs from src/ without installing the package, so
#: importlib.metadata cannot be the single source of truth here.
__version__ = "0.1.0"
