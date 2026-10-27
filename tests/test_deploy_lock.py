"""requirements/deploy.txt must stay in step with pyproject.toml.

The lock is what a deployment installs with --require-hashes. A dependency
added to an extra but not to the lock fails that install ("hashes are required
for all requirements") -- loudly, at deploy time, which is the safe direction
-- but it is cheaper to fail here. And a pin outside the range pyproject.toml
declares would mean the deployed worker runs a version the package never
claimed to support.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from secops_ingest.packs.version import matches

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "requirements" / "deploy.txt"
#: The extras the deployment installs (ingest_extras in the Ansible role).
DEPLOYED_EXTRAS = ("postgres", "http")

_PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^ ;\\]+)")
_REQ = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(.*)$")


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in LOCK.read_text().splitlines():
        found = _PIN.match(line)
        if found:
            pins[_normalise(found.group(1))] = found.group(2)
    return pins


def _declared() -> list[tuple[str, str]]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    out: list[tuple[str, str]] = []
    for extra in DEPLOYED_EXTRAS:
        for requirement in project["optional-dependencies"][extra]:
            found = _REQ.match(requirement)
            assert found, requirement
            out.append((_normalise(found.group(1)), found.group(2)))
    return out


def test_every_pin_carries_a_hash() -> None:
    blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", LOCK.read_text())
    pinned = [b for b in blocks if _PIN.match(b)]
    assert pinned
    for block in pinned:
        assert "--hash=sha256:" in block, block.splitlines()[0]


@pytest.mark.parametrize(("name", "spec"), _declared())
def test_every_deployed_dependency_is_pinned_inside_its_declared_range(
    name: str, spec: str
) -> None:
    pins = _pins()
    assert name in pins, f"{name} is in pyproject.toml but not in {LOCK.name}"
    assert matches(pins[name], spec), f"{name}=={pins[name]} is outside {spec}"


@pytest.mark.parametrize(("name", "spec"), _declared())
def test_every_deployed_dependency_has_an_upper_bound(name: str, spec: str) -> None:
    assert "<" in spec, f"{name} has no upper bound: {spec!r}"
